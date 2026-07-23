// Copyright (c) 2025 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0
//

//! Fallback for architectures where the NVAT SDK is not available.
//! NVIDIA devices are never detected and no evidence is collected.

use anyhow::{bail, Result};
use tracing::warn;

use super::{NvDeviceReportAndCert, NVIDIA_NONCE_SIZE};

pub fn detect_platform() -> bool {
    warn!("NVIDIA attestation is only support on x86 for now. NVIDIA devices will not be attested if they are present.");
    false
}

pub fn get_device_evidence(
    _report_data: Option<[u8; NVIDIA_NONCE_SIZE]>,
) -> Result<Vec<NvDeviceReportAndCert>> {
    bail!("NVIDIA attestation is only support on x86 for now. NVIDIA devices will not be attested if they are present.");
}
