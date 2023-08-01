use anyhow::*;
use reqwest::{header::HeaderMap, ClientBuilder};

use super::client_util::{OpenapiUtilClient as UtilClient, RequestEntity, ResponseEntity};
use super::config::Config;
use super::credential::Credential;
use super::models::*;

pub struct Client {
    config: Config,
    credential: Credential,
}

impl Client {
    pub fn new(config: Config, credential: Credential) -> Self {
        Client { config, credential }
    }

    pub async fn encrypt(&self, request: &EncryptRequest) -> Result<EncryptResponse> {
        // request.validate()?;
        let req_body_bytes = UtilClient::get_serialized_encrypt_request(request)?;

        println!("request start!");
        let resp_entity = self
            .do_request(
                "Encrypt",
                "dkms-gcs-0.2",
                &self.config,
                &self.credential,
                &req_body_bytes,
                &request.request_headers,
            )
            .await?;
        println!("request done!");
        let encrypt_response = UtilClient::parse_encrypt_response(&resp_entity)?;
        println!("parse response done!");
        Ok(encrypt_response)
    }

    pub async fn decrypt(&self, request: &DecryptRequest) -> Result<DecryptResponse> {
        // request.validate()?;
        let req_body_bytes = UtilClient::get_serialized_decrypt_request(request)?;
        let resp_entity = self
            .do_request(
                "Decrypt",
                "dkms-gcs-0.2",
                &self.config,
                &self.credential,
                &req_body_bytes,
                &request.request_headers,
            )
            .await?;
        let decrypt_response = UtilClient::parse_decrypt_response(&resp_entity)?;
        Ok(decrypt_response)
    }

    async fn do_request(
        &self,
        api_name: &str,
        api_version: &str,
        config: &Config,
        credential: &Credential,
        req_body_bytes: &Vec<u8>,
        // runtime: &Runtime,
        request_headers: &HeaderMap,
    ) -> Result<ResponseEntity> {
        let mut headers = HeaderMap::new();
        headers.insert("Accept", "application/x-protobuf".parse()?);
        headers.insert(
            "Host",
            UtilClient::get_host(&config.region_id, &config.endpoint).parse()?,
        );
        for (key, value) in request_headers {
            headers.insert(key.clone(), value.clone());
        }
        headers.insert("Date", UtilClient::get_date_utcstring()?.parse()?);
        headers.insert("user-agent", UtilClient::get_user_agent().parse()?);
        headers.insert("x-kms-apiversion", api_version.to_string().parse()?);
        headers.insert("x-kms-apiname", api_name.parse()?);
        headers.insert("x-kms-signaturemethod", config.signature_method.parse()?);
        headers.insert(
            "x-kms-acccesskeyid",
            credential.get_access_key_id()?.parse()?,
        );
        headers.insert("Content-Type", "application/x-protobuf".parse()?);
        headers.insert(
            "Content-Length",
            UtilClient::get_content_length(req_body_bytes).parse()?,
        );
        headers.insert(
            "Content-Sha256",
            UtilClient::get_content_sha256(req_body_bytes).parse()?,
        );

        let mut request = RequestEntity {
            host: "".to_owned(),
            method: config.method.clone(),
            pathname: "/".to_string(),
            headers,
            body: req_body_bytes.clone(),
            version: "".to_owned(),
            timeout: None,
        };

        let str_to_sign = UtilClient::get_string_to_sign(&request)?;
        request.headers.insert(
            "Authorization",
            credential.get_signature(&str_to_sign)?.parse()?,
        );

        // build http client.
        let mut http_client_builder = ClientBuilder::new();
        if let Some(timeout) = request.timeout {
            http_client_builder = http_client_builder.timeout(timeout);
        }
        println!("endpoint: {}", config.endpoint);
        let http_client = http_client_builder
            .danger_accept_invalid_certs(true) // disable ssl only for dev
            .build()?
            .request(
                request
                    .method
                    .parse()
                    .map_err(|e| anyhow!("Invalid HTTP method: {}", e))?,
                format!("{}://{}", config.protocol, config.endpoint),
            );

        println!("request header: {:?}", request.headers);
        println!("request body: {:?}", request.body);

        // send request.
        let response = http_client
            .headers(request.headers)
            .body(request.body)
            .send()
            .await?;

        // check HTTP StatusCode.
        if !response.status().is_success() {
            println!("request fail!");
            let body_bytes = response.bytes().await?.to_vec();
            let resp_map = UtilClient::get_err_message(&body_bytes)?;
            return Err(anyhow!(
                // "code: {}, message: {}, data: [ httpCode: {}, requestId: {}, hostId: {} ]",
                "code: {}, message: {}, data: [ httpCode: null, requestId: {}, hostId: null ]",
                resp_map.get("Code").ok_or_else(|| anyhow!("no Code"))?,
                resp_map
                    .get("Message")
                    .ok_or_else(|| anyhow!("no Message"))?,
                // response.status(),
                resp_map
                    .get("RequestId")
                    .ok_or_else(|| anyhow!("no RequestId"))?,
                // resp_map.get("HostId").ok_or_else(||anyhow!("no HostId"))?,
            ));
        }

        let body_bytes = response.bytes().await?.to_vec();
        let response_headers = HeaderMap::new();
        // return response.
        Ok(ResponseEntity {
            body_bytes,
            headers: response_headers,
        })
    }
}