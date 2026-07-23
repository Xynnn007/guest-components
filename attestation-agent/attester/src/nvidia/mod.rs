// Copyright (c) 2025 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0
//

use super::{Attester, TeeEvidence};
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use strum::{Display, EnumString};

cfg_if::cfg_if! {
    if #[cfg(target_arch = "x86_64")] {
        mod x86_64;
        use x86_64 as platform;
    } else {
        mod unsupported;
        use unsupported as platform;
    }
}

pub use platform::detect_platform;
use platform::get_device_evidence;

const NVIDIA_NONCE_SIZE: usize = 32;

#[derive(Debug, Deserialize, Display, EnumString, PartialEq, Serialize)]
#[serde(rename_all(serialize = "UPPERCASE"))]
#[strum(ascii_case_insensitive)]
enum Architecture {
    #[serde(alias = "BLACKWELL")]
    Blackwell,
    #[serde(alias = "HOPPER")]
    Hopper,
    LS10,
}

/// NRAS knows about "switch" and "gpu" but the expected evidence
/// content is the same. nvidia-attester can compose a list of
/// all CC enabled nvml/nscq devices using this evidence struct.
#[derive(Deserialize, Serialize)]
struct NvDeviceReportAndCert {
    arch: Architecture,
    #[serde(default = "default_uuid")]
    uuid: String,
    evidence: String,
    certificate: String,
}

/// UUID isn't used for attestation and isn't reported by the NVAT
/// bindings. To maintain backwards comptability, keep UUID in the
/// struct, but don't require it.
fn default_uuid() -> String {
    "unknown".to_string()
}

#[derive(Serialize)]
struct NvDeviceEvidence {
    device_evidence_list: Vec<NvDeviceReportAndCert>,
}

#[derive(Debug, Default)]
pub struct NvAttester {}

#[async_trait::async_trait]
impl Attester for NvAttester {
    /// Generate evidence for the NVIDIA devices. A 32 byte nonce is taken from the first 32
    /// report_data bytes. report_data shorter than 32 bytes is zero padded.
    async fn get_evidence(&self, mut report_data: Vec<u8>) -> Result<TeeEvidence> {
        if report_data.len() < NVIDIA_NONCE_SIZE {
            report_data.resize(NVIDIA_NONCE_SIZE, 0);
        }

        let nonce: [u8; NVIDIA_NONCE_SIZE] = report_data[0..NVIDIA_NONCE_SIZE].try_into()?;

        let device_evidence_list = get_device_evidence(Some(nonce))?;

        let full_evidence = NvDeviceEvidence {
            device_evidence_list,
        };

        serde_json::to_value(&full_evidence).context("Serialize NVIDIA evidence failed")
    }
}
