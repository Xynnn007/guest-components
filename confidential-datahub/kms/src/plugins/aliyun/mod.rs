// Copyright (c) 2023 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

//! This is a Aliyun KMS implementation.
//!
//! Aliyun KMS uses KMS from Alibaba Cloud to support all functions.
//! The product detail can be found here: https://www.alibabacloud.com/product/kms.

// use std::collections::HashSet;

use std::collections::HashMap;

use async_trait::async_trait;
use base64::{encode, decode};
use reqwest::header::HeaderMap;

use crate::{Result, Error};
use crate::{Encryptor, Decryptor, Setter, Getter};
use crate::api::Annotations;

mod client;
mod client_util;
mod config;
mod credential;
mod models;

use self::{config::Config, credential::Credential};
use client::Client as DKMSClient;
use models::*;

/// A Aliyun KMS Encryptor implementation
pub struct SimpleAliyunKmsEncryptor {
    annotation: Annotations,
    client: DKMSClient,
}

impl SimpleAliyunKmsEncryptor {
    pub fn new(annotations: &Annotations) -> Result<Self> {
        let config = Config {
            protocol: "https".to_owned(),
            endpoint: annotations.get("endpoint").ok_or_else(|| Error::KeyNotFound("endpoint".to_string()))?.to_owned(),
            region_id: annotations.get("region_id").ok_or_else(|| Error::KeyNotFound("region_id".to_string()))?.to_owned(),
            method: "POST".to_owned(),
            signature_method: "RSA_PKCS1_SHA_256".to_owned(),
        };
        let credential = Credential {
            key_file_dir: annotations.get("key_file_dir").ok_or_else(|| Error::KeyNotFound("key_file_dir".to_string()))?.to_owned(),
            client_key_id: annotations.get("client_key_id").ok_or_else(|| Error::KeyNotFound("client_key_id".to_string()))?.to_owned(),
        };
        Ok(Self {
            annotation: annotations.clone(),
            client: DKMSClient::new(config, credential), 
        })
    }

    pub fn export_annotation(&self) -> HashMap<String, String> {
        self.annotation.clone()
    }
}

#[async_trait]
impl Encryptor for SimpleAliyunKmsEncryptor {
    async fn encrypt(&mut self, _data: &[u8], _keyid: &str) -> Result<(Vec<u8>, Annotations)> {
        let request = EncryptRequest {
            request_headers: HeaderMap::new(),
            key_id: Some(_keyid.to_string()),
            plaintext: Some(_data.to_vec()),
            algorithm: Some("AES_GCM".to_string()),
            aad: None,
            iv: None,
            padding_mode: None,
        };

        let response = self
            .client
            .encrypt(&request)
            .await
            .map_err(|e| Error::EncryptError(e.to_string()))?;
        let data = response
            .ciphertext_blob
            .ok_or_else(|| Error::EncryptError("encrypt response has no ciphertext_blob".to_string()))?;
        let iv = response
            .iv
            .ok_or_else(|| Error::EncryptError("encrypt response has no iv".to_string()))?;
        let mut annotation: Annotations = self.export_annotation();
        annotation.insert("iv".into(), encode(iv));
        Ok((data, annotation))
    }
}

/// A Aliyun KMS Decryptor implementation
pub struct SimpleAliyunKmsDecryptor {
    annotation: Annotations,
    client: DKMSClient,
}

impl SimpleAliyunKmsDecryptor {
    pub fn new(annotations: &Annotations) -> Result<Self> {
        let config = Config {
            protocol: "https".to_owned(),
            endpoint: annotations.get("endpoint").ok_or_else(|| Error::KeyNotFound("endpoint".to_string()))?.to_owned(),
            region_id: annotations.get("region_id").ok_or_else(|| Error::KeyNotFound("region_id".to_string()))?.to_owned(),
            method: "POST".to_owned(),
            signature_method: "RSA_PKCS1_SHA_256".to_owned(),
        };
        let credential = Credential {
            key_file_dir: annotations.get("key_file_dir").ok_or_else(|| Error::KeyNotFound("key_file_dir".to_string()))?.to_owned(),
            client_key_id: annotations.get("client_key_id").ok_or_else(|| Error::KeyNotFound("client_key_id".to_string()))?.to_owned(),
        };
        Ok(Self {
            annotation: annotations.clone(),
            client: DKMSClient::new(config, credential), 
        })
    }

    pub fn export_annotation(&self) -> HashMap<String, String> {
        self.annotation.clone()
    }
}

#[async_trait]
impl Decryptor for SimpleAliyunKmsDecryptor {
    async fn decrypt(&mut self, ciphertext: &[u8], keyid: &str) -> Result<Vec<u8>> {
        let request = DecryptRequest {
            request_headers: HeaderMap::new(),
            key_id: Some(keyid.to_string()),
            ciphertext_blob: Some(ciphertext.to_vec()),
            algorithm: Some("AES_GCM".to_string()),
            aad: None,
            iv: Some(decode(self.annotation.get("iv").ok_or_else(|| Error::KeyNotFound("endpoint".to_string()))?.to_owned()).map_err(|e| Error::Base64Error(e.to_string()))?),
            padding_mode: None,
        };

        let response = self
            .client
            .decrypt(&request)
            .await
            .map_err(|e| Error::DecryptError(e.to_string()))?;
        let data = response
            .plaintext
            .ok_or_else(|| Error::DecryptError("decrypt response has no plaintext".to_string()))?;
        Ok(data)
    }
}

/// A Aliyun KMS Setter implementation
pub struct SimpleAliyunKmsSetter {
    _client: DKMSClient,
}

#[async_trait]
impl Setter for SimpleAliyunKmsSetter {
    async fn set_secret(&mut self, name: &str, value: &str) -> Result<(Vec<u8>, Annotations)> {
        !unimplemented!()
    }
}

/// A Aliyun KMS Getter implementation
pub struct SimpleAliyunKmsGetter {
    client: DKMSClient,
}

#[async_trait]
impl Getter for SimpleAliyunKmsGetter {
    async fn get_secret(&mut self, name: &str) -> Result<Vec<u8>> {
        unimplemented!()
    }
}

#[cfg(test)]
mod tests {
    use rstest::rstest;

    use crate::api::Annotations;
    use crate::{Encryptor, Decryptor};
    use crate::plugins::aliyun::{SimpleAliyunKmsEncryptor, SimpleAliyunKmsDecryptor};

    #[ignore]
    #[rstest]
    #[case(b"this is a test plaintext")]
    #[case(b"this is a another test plaintext")]
    #[tokio::test]
    async fn key_lifetime(#[case] plaintext: &[u8]) {
        let encryptor_annotation: Annotations = [
            ("protocol".to_owned(), "https".to_owned()),
            ("endpoint".to_owned(), "kst-shh6****.cryptoservice.kms.aliyuncs.com".to_owned()),
            ("region_id".to_owned(), "cn-shanghai".to_owned()),
            ("method".to_owned(), "POST".to_owned()),
            ("signature_method".to_owned(), "RSA_PKCS1_SHA_256".to_owned()),
            ("key_file_dir".to_owned(), "src/plugins/aliyun/key".to_owned()),
            ("client_key_id".to_owned(), "KAAP.f4c8****".to_owned()),
            ("key_id".to_owned(), "key-shh6****".to_owned()),
        ].iter().cloned().collect();
            
        let encryptor_keyid = encryptor_annotation.get("key_id").unwrap();
        let mut encryptor = SimpleAliyunKmsEncryptor::new(&encryptor_annotation).unwrap();
        let (ciphertext, decryptor_annotation) = encryptor.encrypt(plaintext, &encryptor_keyid).await.expect("encrypt");

        let decryptor_keyid = decryptor_annotation.get("key_id").unwrap();
        let mut decryptor = SimpleAliyunKmsDecryptor::new(&decryptor_annotation).unwrap();
        let decrypted = decryptor.decrypt(&ciphertext, &decryptor_keyid).await.expect("decrypt");

        assert_eq!(decrypted, plaintext);
    }

    #[ignore]
    #[tokio::test]
    async fn encrypt_and_decrpty_with_different_keyid() {
        let encryptor_annotation: Annotations = [
            ("protocol".to_owned(), "https".to_owned()),
            ("endpoint".to_owned(), "kst-shh6****.cryptoservice.kms.aliyuncs.com".to_owned()),
            ("region_id".to_owned(), "cn-shanghai".to_owned()),
            ("method".to_owned(), "POST".to_owned()),
            ("signature_method".to_owned(), "RSA_PKCS1_SHA_256".to_owned()),
            ("key_file_dir".to_owned(), "src/plugins/aliyun/key".to_owned()),
            ("client_key_id".to_owned(), "KAAP.f4c8****".to_owned()),
            ("key_id".to_owned(), "key-shh6****".to_owned()),
        ].iter().cloned().collect();

        let encryptor_keyid = encryptor_annotation.get("key_id").unwrap();
        let plaintext = b"encrypt_and_decrpty_with_different_keyid";
        let mut encryptor = SimpleAliyunKmsEncryptor::new(&encryptor_annotation).unwrap();
        let (ciphertext, decryptor_annotation) = encryptor.encrypt(plaintext, &encryptor_keyid).await.expect("encrypt");

        let decryptor_keyid = "key-shh6****".to_owned();
        let mut decryptor = SimpleAliyunKmsDecryptor::new(&decryptor_annotation).unwrap();
        let decrypted = decryptor.decrypt(&ciphertext, &decryptor_keyid).await;

        assert!(decrypted.is_err())
    }
}
