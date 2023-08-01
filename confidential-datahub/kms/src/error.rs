// Copyright (c) 2023 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

use thiserror::Error;

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Error, Debug)]
pub enum Error {
    #[error("failed to encrypt: {0}")]
    EncryptError(String),

    #[error("failed to decrypt: {0}")]
    DecryptError(String),

    #[error("failed to find key: {0}")]
    KeyNotFound(String),

    #[error("base64 error: {0}")]
    Base64Error(String),
}
