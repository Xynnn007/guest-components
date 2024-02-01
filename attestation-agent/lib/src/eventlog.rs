// Copyright (c) 2024 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

use std::io;

use cc_measurement::{CcEventHeader, TpmlDigestValues, TpmtHa, TpmuHa, TPML_ALG_SHA384};
use thiserror::Error;
use tokio::{
    fs::{self, File},
    io::AsyncWriteExt,
};
use zerocopy::AsBytes;

#[repr(u32)]
#[derive(Copy, Clone)]
pub enum HashAlgorithm {
    Sha256 = 0x000b,
}

const MAX_HASH_LENGTH: usize = 64;
pub const SHA384_DIGEST_SIZE: usize = 48;

#[repr(C, packed)]
pub struct ImageEvent {
    hash_algorithm: HashAlgorithm,
    manifest_digest: [u8; MAX_HASH_LENGTH],
}

impl ImageEvent {
    pub fn new(hash_algorithm: HashAlgorithm, data: &[u8]) -> Self {
        let len = std::cmp::min(data.len(), MAX_HASH_LENGTH);
        let mut manifest_digest = [0u8; MAX_HASH_LENGTH];
        for i in 0..len {
            manifest_digest[i] = data[i];
        }
        Self {
            hash_algorithm,
            manifest_digest,
        }
    }

    pub fn as_bytes(&self) -> &[u8] {
        let ptr = self as *const ImageEvent as *const u8;
        let data_len = match self.hash_algorithm {
            HashAlgorithm::Sha256 => std::mem::size_of::<[u8; 32]>(),
        };
        unsafe { std::slice::from_raw_parts(ptr, data_len + std::mem::size_of::<HashAlgorithm>()) }
    }
}

/// The CoCo Events can be a TdTcgPcclientTaggedEvent.
/// The `tagged_even_id` starting from 0, will correspond to the events
/// defined by the following enum types.
///
/// Concrete `tagged_event_data` and `tagged_event_data_size`
/// definitions should be upon each events.
#[repr(u32)]
pub enum CoCoEventType {
    /// `tagged_event_data` will be in the following format
    /// ```plaintext
    /// 0        3                               15
    /// +---------+-------------------------------+
    /// |algorithm|           digest              |
    /// +---------+-------------------------------+
    /// |                 digest ...              |
    /// +-----------------------------------------+
    /// ```
    /// The first 4 bytes indicates the hash algorithm of the manifest.
    /// The rest are bytes of the digest value. The length of the digest
    /// value is determined by the hash algorithm, e.g. sha256 -> 32 Bytes.
    ///
    /// The hash algorithm identifiers follows Table 9 in
    /// [Trusted Platform Module Library](https://trustedcomputinggroup.org/wp-content/uploads/TCG_TPM2_r1p59_Part2_Structures_pub.pdf)
    DeployImage = 1,
}

impl CoCoEventType {
    pub fn from_le_bytes(bytes: &[u8]) -> Result<Self, EventlogError> {
        if bytes.len() != 4 {
            return Err(EventlogError::IllegalCoCoEventType);
        }

        let bytes = bytes.try_into().expect("must be 4 bytes");
        let kind = u32::from_le_bytes(bytes);
        match kind {
            1 => Ok(CoCoEventType::DeployImage),
            _ => Err(EventlogError::IllegalCoCoEventType),
        }
    }
}

/// S.t. the first two fields of TdTcgPcclientTaggedEvent defined in section 9.4.2 of
/// [TCG PC Client Specific Platform Firmware Profile Specification](https://trustedcomputinggroup.org/wp-content/uploads/TCG_PCClient_PFP_r1p05_05_3feb20.pdf)
#[repr(C, packed)]
pub struct CoCoEventHeader {
    tagged_event_id: CoCoEventType,
    tagged_event_data_size: u32,
}

impl CoCoEventHeader {
    pub fn as_bytes(&self) -> &[u8] {
        let ptr = self as *const CoCoEventHeader as *const u8;
        unsafe { std::slice::from_raw_parts(ptr, std::mem::size_of::<Self>()) }
    }
}

/// S.t. TdTcgPcclientTaggedEvent defined in section 9.4.2 of
/// [TCG PC Client Specific Platform Firmware Profile Specification](https://trustedcomputinggroup.org/wp-content/uploads/TCG_PCClient_PFP_r1p05_05_3feb20.pdf)
#[repr(C, packed)]
#[derive()]
pub struct CoCoEvent<'a> {
    pub header: CoCoEventHeader,
    pub tagged_event_data: &'a [u8],
}

impl<'a> CoCoEvent<'a> {
    pub fn new(tagged_event_id: CoCoEventType, tagged_event_data: &'a [u8]) -> Self {
        Self {
            header: CoCoEventHeader {
                tagged_event_id,
                tagged_event_data_size: tagged_event_data.len() as u32,
            },
            tagged_event_data,
        }
    }

    pub fn size(&self) -> u32 {
        std::mem::size_of::<CoCoEventHeader>() as u32 + self.header.tagged_event_data_size
    }

    pub fn hash_sha384(&self) -> [u8; SHA384_DIGEST_SIZE] {
        use sha2::{Digest, Sha384};

        let mut digest = Sha384::new();
        digest.update(self.header.as_bytes());
        digest.update(self.tagged_event_data);
        digest.finalize().into()
    }

    pub fn from_bytes(bytes: &'a [u8]) -> Result<Self, EventlogError> {
        if bytes.len() < std::mem::size_of::<CoCoEventHeader>() {
            return Err(EventlogError::IllegalCoCoEventFormat);
        }

        let tagged_event_id = CoCoEventType::from_le_bytes(&bytes[0..4])?;
        let tagged_event_data_size =
            u32::from_le_bytes(bytes[4..8].try_into().expect("must be 4 bytes"));
        let tagged_event_data = &bytes[8..];
        Ok(Self {
            header: CoCoEventHeader {
                tagged_event_id,
                tagged_event_data_size,
            },
            tagged_event_data,
        })
    }
}

#[derive(Error, Debug)]
pub enum EventlogError {
    #[error("failed to write to eventlog file: {0}")]
    EventLogFileIO(#[from] io::Error),

    #[error("Given data is not a legal CoCoEventData")]
    IllegalCoCoEventFormat,

    #[error("Given data is not a legal CoCoEventType")]
    IllegalCoCoEventType,
}

pub struct EventLogWriter {
    file: File,
}

const EV_EVENT_TAG: u32 = 0x00000006;

impl EventLogWriter {
    pub async fn new(event_log_path: &str) -> Result<Self, EventlogError> {
        let file = fs::OpenOptions::new()
            .write(true)
            .create(true)
            .open(event_log_path)
            .await?;
        Ok(Self { file })
    }

    pub async fn write_event_entry(&mut self, event: CoCoEvent<'_>) -> Result<(), EventlogError> {
        // log TCG CC event
        // Let's always use PCR 19 to record events from AA
        let cc_event_header = CcEventHeader {
            mr_index: 19,
            event_type: EV_EVENT_TAG,
            digest: TpmlDigestValues {
                count: 1,
                digests: [TpmtHa {
                    hash_alg: TPML_ALG_SHA384,
                    digest: TpmuHa {
                        sha384: event.hash_sha384(),
                    },
                }],
            },
            event_size: event.size(),
        };

        self.file.write_all(cc_event_header.as_bytes()).await?;
        self.file.write_all(event.header.as_bytes()).await?;
        self.file.write_all(event.tagged_event_data).await?;

        Ok(())
    }
}
