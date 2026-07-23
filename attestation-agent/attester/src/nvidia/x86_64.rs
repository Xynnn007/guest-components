// Copyright (c) 2025 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0
//

//! NVIDIA device evidence collection backed by the NVAT SDK,
//! which is only supported on x86_64.

use anyhow::{anyhow, Result};
use nv_attestation_sdk::{GpuEvidenceSource, Nonce, NvatSdk, SdkOptions, SwitchEvidenceSource};
use std::sync::OnceLock;
use tracing::warn;

use super::{NvDeviceReportAndCert, NVIDIA_NONCE_SIZE};

static INIT: OnceLock<Result<()>> = OnceLock::new();

/// The NVAT SDK should be initialized exactly once.
/// The SDK object should not be dropped until all calls
/// to the SDK are finished.
/// Since we have no way of knowing when there will be no
/// more calls to the SDK, keep the SDK object indefinitely.
/// This shouldn't cause any problems in the CoCo use case.
fn ensure_sdk_init() -> Result<()> {
    INIT.get_or_init(|| -> Result<()> {
        let opts = SdkOptions::new()?;
        let sdk = NvatSdk::init(opts)?;
        std::mem::forget(sdk);
        Ok(())
    })
    .as_ref()
    .map_err(|e| anyhow!("Failed to initialize SDK: {e}"))?;

    Ok(())
}

pub fn detect_platform() -> bool {
    if ensure_sdk_init().is_err() {
        warn!("NVIDIA Attestation SDK could not be initialized.");
        return false;
    };

    match get_device_evidence(None) {
        Ok(ev) => !ev.is_empty(),
        Err(e) => {
            warn!("NVIDIA device detection failed due to: {}", e.to_string());
            false
        }
    }
}

/// Internal helper for getting evidence from NVIDIA devices.
pub fn get_device_evidence(
    report_data: Option<[u8; NVIDIA_NONCE_SIZE]>,
) -> Result<Vec<NvDeviceReportAndCert>> {
    ensure_sdk_init()?;

    let nonce = match report_data {
        Some(data_vec) => Nonce::from_hex(&hex::encode(data_vec))?,
        None => Nonce::generate(32)?,
    };

    let mut evidence = vec![];

    match GpuEvidenceSource::from_nvml() {
        Ok(gpu_source) => match gpu_source.collect(&nonce) {
            Ok(gpu_evidence) => {
                if !gpu_evidence.is_empty() {
                    let gpu_evidence: Vec<NvDeviceReportAndCert> =
                        serde_json::from_str(&gpu_evidence.to_json()?)?;
                    evidence.extend(gpu_evidence);
                }
            }
            Err(e) => warn!("Failed to get gpu evidence: {}", e),
        },
        Err(e) => warn!("Failed to initialize gpu evidence source: {}", e),
    }

    match SwitchEvidenceSource::from_nscq() {
        Ok(switch_source) => match switch_source.collect(&nonce) {
            Ok(switch_evidence) => {
                if !switch_evidence.is_empty() {
                    let switch_evidence: Vec<NvDeviceReportAndCert> =
                        serde_json::from_str(&switch_evidence.to_json()?)?;
                    evidence.extend(switch_evidence);
                }
            }
            Err(e) => warn!("Failed to get switch evidence: {}", e),
        },
        Err(e) => warn!("Failed to initialize switch evidence source: {}", e),
    }

    Ok(evidence)
}
