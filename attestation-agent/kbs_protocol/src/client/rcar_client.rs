// Copyright (c) 2023 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

use anyhow::{bail, Context};
use async_trait::async_trait;
use kbs_types::{Challenge, ErrorInformation, Request};
use log::{debug, warn};
use rcgen::{Certificate, CertificateParams, KeyPair, SanType, PKCS_RSA_SHA256};
use reqwest::Identity;
use resource_uri::ResourceUri;
use rustls::{ClientConfig, RootCertStore};
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::{Digest, Sha384};

use std::{io::Cursor, time::Duration};

use crate::{
    api::KbsClientCapabilities,
    client::{
        ClientTee, KbsClient, KBS_GET_RESOURCE_MAX_ATTEMPT, KBS_PREFIX, KBS_PROTOCOL_VERSION,
    },
    Error, Result,
};

/// When executing get token, RCAR handshake should retry if failed to
/// make the logic robust. This constant is the max retry times.
const RCAR_MAX_ATTEMPT: i32 = 5;

/// The interval (seconds) between RCAR handshake retries.
const RCAR_RETRY_TIMEOUT_SECOND: u64 = 1;

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct Attestation {
    pub csr: String,
    #[serde(rename = "tee-evidence")]
    pub tee_evidence: String,
    pub id: String,
}

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct Response {
    pub crt: String,
}

impl KbsClient {
    /// Export TEE public key csr as specific structure.
    fn export_csr(&self) -> anyhow::Result<String> {
        let mut params = CertificateParams::default();
        let key_pair_pem = self.tee_key.to_pkcs8_pem()?;
        params.key_pair = Some(KeyPair::from_pem(&key_pair_pem)?);
        params.alg = &PKCS_RSA_SHA256;
        params.subject_alt_names = vec![SanType::URI(self.id.to_string())];

        let cert = Certificate::from_params(params)?;
        let csr = cert.serialize_request_pem()?;
        Ok(csr)
    }

    /// Perform RCAR handshake with the given kbs host. If succeeds, the client will
    /// store the token.
    ///
    /// Note: if RCAR succeeds, the http client will record the cookie with the kbs server,
    /// which means that this client can be then used to retrieve resources.
    async fn rcar_handshake(&mut self) -> anyhow::Result<String> {
        let auth_endpoint = format!("{}/{KBS_PREFIX}/auth", self.kbs_host_url);

        let tee = match &self._tee {
            ClientTee::Unitialized => {
                let tee = self.provider.get_tee_type().await?;
                self._tee = ClientTee::_Initializated(tee);
                tee
            }
            ClientTee::_Initializated(tee) => *tee,
        };

        let extra_params = json!({
            "id": self.id,
        });
        let request = Request {
            version: String::from(KBS_PROTOCOL_VERSION),
            tee,
            extra_params: serde_json::to_string(&extra_params)?,
        };

        debug!("send auth request to {auth_endpoint}");

        let challenge = self
            .http_client
            .post(auth_endpoint)
            .header("Content-Type", "application/json")
            .json(&request)
            .send()
            .await?
            .json::<Challenge>()
            .await?;

        debug!("get challenge: {challenge:#?}");
        let csr = self.export_csr()?;
        let runtime_data = json!({
            "csr": csr,
            "nonce": challenge.nonce,
        });
        let runtime_data =
            serde_json::to_string(&runtime_data).context("serialize runtime data failed")?;
        let evidence = self.generate_evidence(runtime_data).await?;
        debug!("get evidence with challenge: {evidence}");

        let attest_endpoint = format!("{}/{KBS_PREFIX}/attest", self.kbs_host_url);
        let attest = Attestation {
            csr,
            id: self.id.clone(),
            tee_evidence: evidence,
        };

        debug!("send attest request.");
        let attest_response = self
            .http_client
            .post(attest_endpoint)
            .header("Content-Type", "application/json")
            .json(&attest)
            .send()
            .await?;

        match attest_response.status() {
            reqwest::StatusCode::OK => {
                let resp = attest_response.json::<Response>().await?;
                self.tee_key_cert = Some(resp.crt.clone());
                return Ok(resp.crt);
            }
            reqwest::StatusCode::UNAUTHORIZED => {
                let error_info = attest_response.json::<ErrorInformation>().await?;
                bail!("KBS attest unauthorized, Error Info: {:?}", error_info);
            }
            _ => {
                bail!(
                    "KBS Server Internal Failed, Response: {:?}",
                    attest_response.text().await?
                );
            }
        }
    }

    async fn generate_evidence(&mut self, runtime_data: String) -> Result<String> {
        let mut hasher = Sha384::new();
        hasher.update(runtime_data);

        let ehd = hasher.finalize().to_vec();

        let tee_evidence = self
            .provider
            .get_evidence(ehd)
            .await
            .map_err(|e| Error::GetEvidence(e.to_string()))?;

        Ok(tee_evidence)
    }

    fn resource_client(&self, tee_key_cert: String) -> anyhow::Result<reqwest::Client> {
        let identity_cert = format!("{}\n{tee_key_cert}", *self.tee_key.to_pkcs8_pem()?);
        let identity = Identity::from_pem(identity_cert.as_bytes())?;

        let kbs_cert = &self.kbs_certs[0];

        let mut cursor = Cursor::new(kbs_cert);
        let kbs_cert_chain = rustls_pemfile::certs(&mut cursor)?;

        let mut cursor = Cursor::new(tee_key_cert);
        let client_key_cert_chain: Vec<_> = rustls_pemfile::certs(&mut cursor)?
            .into_iter()
            .map(rustls::Certificate)
            .collect();

        let client_key_pem = self.tee_key.to_pkcs1_pem()?;
        let mut cursor = Cursor::new(client_key_pem);
        let private_key = rustls_pemfile::rsa_private_keys(&mut cursor)?.remove(0);
        let private_key = rustls::PrivateKey(private_key);

        let mut kbs_cert_chain_store = RootCertStore::empty();
        kbs_cert_chain_store.add_parsable_certificates(&kbs_cert_chain);

        let tls_config = ClientConfig::builder()
            .with_safe_defaults()
            .with_root_certificates(kbs_cert_chain_store)
            .with_client_auth_cert(client_key_cert_chain, private_key)?;

        // let tls_config =
        let mut http_client_builder = reqwest::Client::builder()
            .cookie_store(false)
            .user_agent(format!(
                "attestation-agent-kbs-client/{}",
                env!("CARGO_PKG_VERSION")
            ))
            .timeout(Duration::from_secs(60))
            .use_rustls_tls()
            .use_preconfigured_tls(tls_config);
        for customer_root_cert in &self.kbs_certs {
            let cert = reqwest::Certificate::from_pem(customer_root_cert.as_bytes())?;
            http_client_builder = http_client_builder.add_root_certificate(cert);
        }

        let http_client = http_client_builder.identity(identity).build()?;

        Ok(http_client)
    }
}

#[async_trait]
impl KbsClientCapabilities for KbsClient {
    async fn get_resource(&mut self, resource_uri: ResourceUri) -> Result<Vec<u8>> {
        let remote_url = format!(
            "{}/resource/{}/{}/{}",
            self.kbs_host_url, resource_uri.repository, resource_uri.r#type, resource_uri.tag
        );

        let tee_key_cert = match &self.tee_key_cert {
            Some(cert) => cert.clone(),
            None => {
                let mut times = 1;
                loop {
                    if times >= RCAR_MAX_ATTEMPT {
                        return Err(Error::RcarHandshake(format!("Retried max times.")));
                    }

                    match self
                        .rcar_handshake()
                        .await
                        .map_err(|e| Error::RcarHandshake(e.to_string()))
                    {
                        Ok(cert) => break cert,
                        Err(_) => warn!("RCAR retry for {times} times."),
                    };
                    times = times + 1;
                    tokio::time::sleep(Duration::from_secs(RCAR_RETRY_TIMEOUT_SECOND)).await;
                }
            }
        };

        let http_client = self
            .resource_client(tee_key_cert)
            .map_err(|e| Error::RcarHandshake(format!("cannot prepare https client: {e}")))?;

        for attempt in 1..=KBS_GET_RESOURCE_MAX_ATTEMPT {
            debug!("KBS client: trying to request KBS, attempt {attempt}");

            let res = http_client
                .get(&remote_url)
                .send()
                .await
                .map_err(|e| Error::HttpError(format!("get resource: {e}")))?;

            match res.status() {
                reqwest::StatusCode::OK => {
                    let payload_data = res
                        .bytes()
                        .await
                        .map_err(|e| Error::HttpError(format!("get resource bytes failed :{e}")))?
                        .to_vec();
                    return Ok(payload_data);
                }
                reqwest::StatusCode::UNAUTHORIZED => {
                    warn!("No permission to the resource: {resource_uri:?}");

                    return Err(Error::UnAuthorized);
                }
                reqwest::StatusCode::NOT_FOUND => {
                    let errorinfo = format!(
                        "KBS resource Not Found (Error 404): {:#?}",
                        res.json::<ErrorInformation>()
                            .await
                            .map_err(|e| Error::KbsResponseDeserializationFailed(e.to_string()))?
                    );

                    return Err(Error::ResourceNotFound(errorinfo));
                }
                _ => {
                    let errorinfo = format!(
                        "KBS Server Internal Failed, Response: {:#?}",
                        res.json::<ErrorInformation>()
                            .await
                            .map_err(|e| Error::KbsResponseDeserializationFailed(e.to_string()))?
                    );

                    return Err(Error::KbsInternalError(errorinfo));
                }
            }
        }

        Err(Error::UnAuthorized)
    }
}
