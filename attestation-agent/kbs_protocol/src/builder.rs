// Copyright (c) 2023 Microsoft Corporation
// Copyright (c) 2023 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

use std::time::Duration;

use anyhow::*;
use crypto::rsa::RSAKeyPair;

use crate::{aa_client::AAClient, client::ClientTee};

use super::client::KbsClient;

const KBS_REQ_TIMEOUT_SEC: u64 = 60;

pub struct KbsClientBuilder {
    kbs_certs: Vec<String>,
    kbs_host_url: String,
    tee_key: Option<String>,
    tee_key_cert: Option<String>,
    id: Option<String>,
}

impl KbsClientBuilder {
    pub fn new(kbs_host_url: &str) -> Self {
        Self {
            kbs_certs: vec![],
            kbs_host_url: kbs_host_url.trim_end_matches('/').to_string(),
            tee_key: None,
            tee_key_cert: None,
            id: None,
        }
    }

    pub fn add_kbs_cert(mut self, cert_pem: &str) -> Self {
        self.kbs_certs.push(cert_pem.to_string());
        self
    }

    pub fn set_tee_key_cert(mut self, cert: &str) -> Self {
        self.tee_key_cert = Some(cert.to_string());
        self
    }

    pub fn set_id(mut self, id: &str) -> Self {
        self.id = Some(id.to_string());
        self
    }

    pub fn set_tee_key(mut self, tee_key: &str) -> Self {
        self.tee_key = Some(tee_key.to_string());
        self
    }

    pub fn build(self) -> Result<KbsClient> {
        let mut http_client_builder = reqwest::Client::builder()
            .cookie_store(true)
            .user_agent(format!(
                "attestation-agent-kbs-client/{}",
                env!("CARGO_PKG_VERSION")
            ))
            .timeout(Duration::from_secs(KBS_REQ_TIMEOUT_SEC));

        for customer_root_cert in &self.kbs_certs {
            let cert = reqwest::Certificate::from_pem(customer_root_cert.as_bytes())?;
            http_client_builder = http_client_builder.add_root_certificate(cert);
        }

        #[cfg(feature = "rust-crypto")]
        {
            http_client_builder = http_client_builder.use_rustls_tls();
        }

        let tee_key = match self.tee_key {
            Some(key) => RSAKeyPair::from_pkcs1_pem(&key[..])?,
            None => RSAKeyPair::new()?,
        };

        let id = self.id.unwrap_or("spiffe://test".to_string());

        let provider = AAClient::new()?;
        let client = KbsClient {
            _tee: ClientTee::Unitialized,
            tee_key_cert: self.tee_key_cert,
            tee_key,
            provider,
            http_client: http_client_builder
                .build()
                .context("Build KBS http client")?,
            kbs_host_url: self.kbs_host_url,
            kbs_certs: self.kbs_certs,
            id,
        };

        Ok(client)
    }
}
