// Copyright (c) 2026 Confidential Containers Authors
//
// SPDX-License-Identifier: Apache-2.0
//

use thiserror::Error;

pub type Result<T> = std::result::Result<T, CdfError>;

#[derive(Error, Debug)]
pub enum CdfError {
    #[error("CDF mount failed: {0}")]
    MountFailed(#[from] anyhow::Error),

    #[error("illegal key scheme for CDF (expect kbs://, sealed., or file://)")]
    IllegalKeyScheme,

    #[error("failed to get K_root: {source}")]
    GetKeyFailed { source: anyhow::Error },

    #[error("no device specified (need deviceId or devicePath)")]
    NoDeviceSpecified,

    #[error("illegal deviceId (expect MAJ:MIN)")]
    IllegalDeviceId,

    #[error(transparent)]
    Serde(#[from] serde_json::Error),

    #[error(transparent)]
    Io(#[from] std::io::Error),
}
