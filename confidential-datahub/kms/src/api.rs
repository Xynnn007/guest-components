// Copyright (c) 2023 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

//! # Api definitions for KMS/Vault drivers
//!
//! To establish a connection between the client and the KMS/Vault server, two
//! kinds of parameters are required:
//! - Public parameters: like Region Id of the KMS/Vault, Instance Id of the KMS,
//! etc. They are not confidential and can be seen by anyone. [`Annotations`]
//! is a key-value hashmap. It is to include all the public parameters. The
//! hashmap style makes it flexible for different kinds of KMSes/Vaults. The `new()`
//! function should take a [`Annotations`] as input parameter.
//! - Private parameters: like the credential to access (e.g. access key).
//! These parameters should be captured inside the logic of `new()` rather
//! than the input parameter. it is strongly recommended that private parameters
//! be read from the encrypted filesystem, e.g. `/run/*` which is in TEE's
//! encrypted memory.
//!
//! ## APIs
//! - `Decryptor`: KMS's decrypt API.
//! - `Encryptor`: KMS's encrypt API.
//! - `Getter`: Vault's get secret API.
//! - `Setter`: Vault's set secret API.
//!
//! The rationality to distinguish these four different traits:
//! - `Decryptor` and `Getter` are used in-pod, while `Encryptor` and `Setter`
//! are used userside. They do not need to a same object to implement this.

use crate::Result;

use std::collections::HashMap;

use async_trait::async_trait;

/// Option is extra information from KMS API response.
/// Because the fields are not uniformed, we put them into a key-value map.
pub type EncryptOption = HashMap<String, String>;
pub type SetSecretOption = HashMap<String, String>;

#[async_trait]
pub trait Decryptor: Send + Sync {
    /// Use the key of `keyid` to decrypt the `ciphertext` slice inside KMS, and then
    /// return the plaintext of the `data`. The decryption operation should occur
    /// inside KMS.
    async fn decrypt(&mut self, ciphertext: &[u8], keyid: &str) -> Result<Vec<u8>>;
}

#[async_trait]
pub trait Encryptor: Send + Sync {
    /// Use the key of `keyid` to encrypt the `data` slice inside KMS, and then
    /// return the ciphertext of the `data`. The encryption operation should occur
    /// inside KMS.
    ///
    /// The returned [`EncryptOption`] is the public parameters of the 'encrypt' api.
    async fn encrypt(&mut self, _data: &[u8], _keyid: &str) -> Result<(Vec<u8>, EncryptOption)>;
}

#[async_trait]
pub trait Getter: Send + Sync {
    /// Get secret. Different secret manager will use different parameters inside
    /// `annotations`.
    async fn get_secret(&mut self, name: &str) -> Result<Vec<u8>>;
}

#[async_trait]
pub trait Setter: Send + Sync {
    /// Get secret. Different secret manager will use different parameters inside
    /// `annotations`.
    ///
    /// The returned [`SetSecretOption`] is the public parameters of the 'set_secret' api.
    async fn set_secret(&mut self, name: &str, value: &str) -> Result<(Vec<u8>, SetSecretOption)>;
}
