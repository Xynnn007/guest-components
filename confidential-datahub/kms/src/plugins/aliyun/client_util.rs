use anyhow::*;
use chrono::{DateTime, Utc};
use hex;
use prost::Message;
use reqwest::header::HeaderMap;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::convert::AsRef;
use std::str;
use std::string::ToString;
use std::time::Duration;

use super::models;

pub mod dkms_pb3 {
    tonic::include_proto!("dkms_api");
}

/// request.
#[derive(Clone, Debug, Default)]
pub struct RequestEntity {
    pub host: String,
    pub method: String,
    pub pathname: String,
    pub headers: HeaderMap,
    pub body: Vec<u8>,
    pub version: String,
    pub timeout: Option<Duration>,
}

// response
#[derive(Clone, Debug, Default)]
pub struct ResponseEntity {
    pub body_bytes: Vec<u8>,
    pub headers: HeaderMap,
}

pub struct OpenapiUtilClient {}

impl OpenapiUtilClient {
    pub fn get_host(region_id: &str, endpoint: &str) -> String {
        if !endpoint.is_empty() {
            endpoint.to_string()
        } else if !region_id.is_empty() {
            "cn-hangzhou".to_string()
        } else {
            format!("kms-instance.{}.aliyuncs.com", region_id)
        }
    }

    pub fn get_err_message(msg: &[u8]) -> Result<HashMap<String, String>> {
        println!("error message: {}", String::from_utf8_lossy(msg));
        let mut result = HashMap::new();
        let error = dkms_pb3::Error::decode(msg)?;
        result.insert("Code".to_string(), error.error_code.to_string());
        result.insert("Message".to_string(), error.error_message.to_string());
        result.insert("RequestId".to_string(), error.request_id);
        Ok(result)
    }

    pub fn get_string_to_sign(request: &RequestEntity) -> Result<String> {
        let method = request.method.clone();
        let pathname = request.pathname.clone();
        let headers = &request.headers;
        // let query = &request.query;
        let query = HashMap::new();
        let content_sha256 = headers
            .get("content-sha256")
            .ok_or_else(|| anyhow!("no content-sha256"))?
            .to_str()?;
        let content_type = headers
            .get("content-type")
            .ok_or_else(|| anyhow!("no content-type"))?
            .to_str()?;
        let date = headers
            .get("date")
            .ok_or_else(|| anyhow!("no date"))?
            .to_str()?;
        let header = format!(
            "{}\n{}\n{}\n{}\n",
            method, content_sha256, content_type, date
        );
        let canonicalized_headers = OpenapiUtilClient::_get_canonicalized_headers(headers)?;
        let canonicalized_resource =
            OpenapiUtilClient::_get_canonicalized_resource(&pathname, &query);
        println!("header: {}", header);
        println!("canonicalized_headers: {}", canonicalized_headers);
        println!("canonicalized_resource: {}", canonicalized_resource);
        Ok(format!(
            "{}{}{}",
            header, canonicalized_headers, canonicalized_resource
        ))
    }

    fn _get_canonicalized_headers(headers: &HeaderMap) -> Result<String> {
        let prefix = "x-kms-";
        let mut keys: Vec<String> = headers.keys().map(|key| key.to_string()).collect();
        keys.sort();
        let mut result_list: Vec<String> = Vec::new();
        for key in keys {
            if key.starts_with(prefix) {
                result_list.push(key.clone());
                result_list.push(":".to_string());
                result_list.push(
                    headers
                        .get(key)
                        .ok_or_else(|| anyhow!("no key"))?
                        .to_str()?
                        .trim()
                        .to_string(),
                );
                result_list.push("\n".to_string());
            }
        }
        Ok(result_list.join(""))
    }

    fn _get_canonicalized_resource(pathname: &str, query: &HashMap<String, String>) -> String {
        let mut path: Vec<String> = Vec::new();
        if pathname.is_empty() {
            return "/".to_owned();
        }
        if query.is_empty() {
            return pathname.to_owned();
        }
        path.push(pathname.to_string());
        path.push("?".to_string());
        OpenapiUtilClient::_get_canonicalized_query_string(
            &mut path,
            query,
            &query.keys().map(|k| k.to_owned()).collect::<Vec<String>>(),
        )
    }

    fn _get_canonicalized_query_string(
        path: &mut Vec<String>,
        query: &HashMap<String, String>,
        keys: &Vec<String>,
    ) -> String {
        if query.is_empty() || keys.is_empty() {
            return path.join("");
        }
        let mut sorted_keys = keys.clone();
        sorted_keys.sort();
        for key in sorted_keys {
            path.push(key.clone());
            let value = query.get(&key).unwrap().to_string();
            if !value.is_empty() {
                path.push("=".to_string());
                path.push(value);
            }
            path.push("&".to_string());
        }
        path.pop();
        path.join("")
    }

    pub fn get_content_length<T: AsRef<[u8]> + ?Sized>(req_body: &T) -> String {
        format!("{}", req_body.as_ref().len())
    }

    pub fn get_content_sha256<T: AsRef<[u8]> + ?Sized>(req_body: &T) -> String {
        let mut hasher = Sha256::new();
        hasher.update(req_body.as_ref());
        let hash_result = hasher.finalize();
        hex::encode_upper(hash_result)
    }

    // pub fn to_hex_string(byte_array: &[u8]) -> String {
    //     hex::encode_upper(byte_array)
    // }

    pub fn get_date_utcstring() -> Result<String> {
        let now: DateTime<Utc> = Utc::now();
        let rfc1123_time = now.format("%a, %d %b %Y %H:%M:%S GMT").to_string();
        Ok(rfc1123_time)
    }

    pub fn get_user_agent() -> String {
        concat!(env!("CARGO_PKG_NAME"), "/", env!("CARGO_PKG_VERSION")).into()
    }

    pub fn get_serialized_encrypt_request(req_body: &models::EncryptRequest) -> Result<Vec<u8>> {
        let mut encrypt_request = dkms_pb3::EncryptRequest::default();
        if let Some(key_id) = &req_body.key_id {
            encrypt_request.key_id = key_id.clone();
        }
        if let Some(plaintext) = &req_body.plaintext {
            encrypt_request.plaintext = plaintext.clone();
        }
        if let Some(algorithm) = &req_body.algorithm {
            encrypt_request.algorithm = algorithm.clone();
        }
        if let Some(iv) = &req_body.iv {
            encrypt_request.iv = iv.clone();
        }
        if let Some(aad) = &req_body.aad {
            encrypt_request.aad = aad.clone();
        }
        if let Some(padding_mode) = &req_body.padding_mode {
            encrypt_request.padding_mode = padding_mode.clone();
        }
        let mut serialized = Vec::new();
        encrypt_request.encode(&mut serialized)?;
        Ok(serialized)
    }

    pub fn parse_encrypt_response(resp_entity: &ResponseEntity) -> Result<models::EncryptResponse> {
        let resp_body: &[u8] = &resp_entity.body_bytes;
        let encrypt_response = dkms_pb3::EncryptResponse::decode(resp_body)?;
        println!("decode done");
        let result = models::EncryptResponse {
            response_headers: resp_entity.headers.clone(),
            key_id: Some(encrypt_response.key_id),
            ciphertext_blob: Some(encrypt_response.ciphertext_blob),
            iv: Some(encrypt_response.iv),
            algorithm: Some(encrypt_response.algorithm),
            padding_mode: Some(encrypt_response.padding_mode),
            response_id: Some(encrypt_response.request_id),
        };
        Ok(result)
    }

    pub fn get_serialized_decrypt_request(req_body: &models::DecryptRequest) -> Result<Vec<u8>> {
        let mut decrypt_request = dkms_pb3::DecryptRequest::default();
        if let Some(key_id) = &req_body.key_id {
            decrypt_request.key_id = key_id.clone();
        }
        if let Some(ciphertext_blob) = &req_body.ciphertext_blob {
            decrypt_request.ciphertext_blob = ciphertext_blob.clone();
        }
        if let Some(algorithm) = &req_body.algorithm {
            decrypt_request.algorithm = algorithm.clone();
        }
        if let Some(iv) = &req_body.iv {
            decrypt_request.iv = iv.clone();
        }
        if let Some(aad) = &req_body.aad {
            decrypt_request.aad = aad.clone();
        }
        if let Some(padding_mode) = &req_body.padding_mode {
            decrypt_request.padding_mode = padding_mode.clone();
        }
        let mut serialized = Vec::new();
        decrypt_request.encode(&mut serialized)?;
        Ok(serialized)
    }

    pub fn parse_decrypt_response(resp_entity: &ResponseEntity) -> Result<models::DecryptResponse> {
        let resp_body: &[u8] = &resp_entity.body_bytes;
        let decrypt_response = dkms_pb3::DecryptResponse::decode(resp_body)?;
        let result = models::DecryptResponse {
            response_headers: resp_entity.headers.clone(),
            key_id: Some(decrypt_response.key_id),
            plaintext: Some(decrypt_response.plaintext),
            algorithm: Some(decrypt_response.algorithm),
            padding_mode: Some(decrypt_response.padding_mode),
            request_id: Some(decrypt_response.request_id),
        };
        Ok(result)
    }
}
