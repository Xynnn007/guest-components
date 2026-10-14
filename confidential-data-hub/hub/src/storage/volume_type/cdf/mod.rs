// Copyright (c) 2026 Confidential Containers Authors
//
// SPDX-License-Identifier: Apache-2.0
//

//! CDF (`volume_type=cdf`) SecureMount — fail-closed open of a GPT CDF v1 volume.
//!
//! See confidential-disk-format design §4 / §6 and CoCo user story:
//! deployment locator overrides optional on-disk `Contract.key_locator`;
//! never format on open failure; optional expected UUID check before key use.

pub mod error;

use super::SecureMount;
use crate::storage::drivers::filesystem::{FsFormatter, FsType};
use crate::storage::drivers::luks2::Luks2Formatter;
use crate::{secret};

use anyhow::{anyhow, bail, Context};
use async_trait::async_trait;
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use error::{CdfError, Result};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use kms::{Annotations, ProviderSettings};
use nix::mount::{mount, MsFlags};
use resource_uri::ResourceUri;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::process::Command;
use tempfile::NamedTempFile;
use tokio::fs::File;
use tokio::io::{AsyncBufReadExt, BufReader};
use tracing::{debug, info, warn};
use uuid::Uuid;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

const MAGIC: &[u8; 8] = b"CDF1\0\0\0\0";
const SUPERBLOCK_SIZE: usize = 4096;
const CONTRACT_OFFSET: u32 = 4096;
const FLAG_AUTHENTICATED: u32 = 1 << 0;

const TYPE_META: &str = "4ca88ee1-60f4-4b6b-899e-dae026ced8e8";
const TYPE_VERITY: &str = "9620d886-ff76-4ccd-9b09-3a938a18dc0d";
const TYPE_DATA: &str = "e4ff66b9-eebf-4675-b8a0-836ca79919ce";

const INFO_MAC: &[u8] = b"cdf-v1/meta-mac";
const INFO_LUKS: &[u8] = b"cdf-v1/luks";

type HmacSha256 = Hmac<Sha256>;

#[derive(Default)]
pub struct Cdf {
    mount_points: Vec<String>,
    cryptsetup_names: Vec<String>,
    temp_paths: Vec<String>,
}

#[derive(Debug, Default)]
struct CdfParameters {
    device_id: Option<String>,
    device_path: Option<String>,
    /// Deployment locator (kbs://…). Overrides on-disk Contract.key_locator.
    kbs_key_id: Option<String>,
    expected_uuid: Option<String>,
    expected_profile: Option<String>,
    filesystem_type: Option<String>,
    mkfs_if_empty: Option<String>,
    mapper_name: Option<String>,
}

fn opt_get(options: &HashMap<String, String>, keys: &[&str]) -> Option<String> {
    for k in keys {
        if let Some(v) = options.get(*k) {
            let t = v.trim();
            if !t.is_empty() {
                return Some(t.to_string());
            }
        }
    }
    None
}

fn parse_parameters(options: &HashMap<String, String>) -> CdfParameters {
    CdfParameters {
        device_id: opt_get(options, &["deviceId", "device_id"]),
        device_path: opt_get(options, &["devicePath", "device_path"]),
        kbs_key_id: opt_get(
            options,
            &["kbsKeyId", "cdf.kbs-key-id", "key", "kbs-key-id"],
        ),
        expected_uuid: opt_get(
            options,
            &["expectedUuid", "cdf.expected-volume-uuid", "expected-volume-uuid"],
        ),
        expected_profile: opt_get(options, &["expectedProfile", "cdf.profile", "profile"]),
        filesystem_type: opt_get(
            options,
            &["filesystemType", "cdf.fstype", "fstype"],
        ),
        mkfs_if_empty: opt_get(options, &["mkfsIfEmpty", "cdf.mkfs-if-empty", "mkfs-if-empty"]),
        mapper_name: opt_get(options, &["mapperName", "mapper_name"]),
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
enum Profile {
    Plain,
    #[serde(rename = "crypt+integrity")]
    CryptIntegrity,
    Verity,
    #[serde(rename = "verity+crypt")]
    VerityCrypt,
}

impl Profile {
    fn as_str(&self) -> &'static str {
        match self {
            Self::Plain => "plain",
            Self::CryptIntegrity => "crypt+integrity",
            Self::Verity => "verity",
            Self::VerityCrypt => "verity+crypt",
        }
    }

    fn needs_luks(&self) -> bool {
        matches!(self, Self::CryptIntegrity | Self::VerityCrypt)
    }

    fn is_authenticated(&self) -> bool {
        !matches!(self, Self::Plain)
    }

    fn is_ro(&self) -> bool {
        matches!(self, Self::Verity | Self::VerityCrypt)
    }

    fn parse(s: &str) -> anyhow::Result<Self> {
        Ok(match s {
            "plain" => Self::Plain,
            "crypt+integrity" | "crypt-integrity" => Self::CryptIntegrity,
            "verity" => Self::Verity,
            "verity+crypt" | "verity-crypt" => Self::VerityCrypt,
            other => bail!("unknown CDF profile {other:?}"),
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Contract {
    format: String,
    volume_uuid: Uuid,
    meta_generation: u64,
    profile: Profile,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    key_locator: Option<String>,
    data: ContractData,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ContractData {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    luks2_header_b64: Option<String>,
    #[serde(default)]
    luks2_subsystem: String,
    #[serde(default)]
    integrity: String,
    #[serde(default)]
    cipher: String,
}

#[derive(Debug, Clone)]
struct Superblock {
    volume_uuid: Uuid,
    flags: u32,
    contract_offset: u32,
    contract_size: u32,
    meta_generation: u64,
    mac: [u8; 32],
}

impl Superblock {
    fn encode_for_mac(&self) -> [u8; SUPERBLOCK_SIZE] {
        let mut buf = [0u8; SUPERBLOCK_SIZE];
        buf[0..8].copy_from_slice(MAGIC);
        buf[8..10].copy_from_slice(&1u16.to_le_bytes());
        buf[10..12].copy_from_slice(&0u16.to_le_bytes());
        buf[12..28].copy_from_slice(self.volume_uuid.as_bytes());
        buf[28..32].copy_from_slice(&self.flags.to_le_bytes());
        buf[32..36].copy_from_slice(&self.contract_offset.to_le_bytes());
        buf[36..40].copy_from_slice(&self.contract_size.to_le_bytes());
        buf[40..48].copy_from_slice(&self.meta_generation.to_le_bytes());
        // mac field left zero for MAC input
        buf
    }

    fn decode(buf: &[u8]) -> anyhow::Result<Self> {
        if buf.len() < SUPERBLOCK_SIZE {
            bail!("superblock too short");
        }
        if &buf[0..8] != MAGIC {
            bail!("not a CDF v1 superblock (bad magic)");
        }
        let version_major = u16::from_le_bytes(buf[8..10].try_into()?);
        if version_major != 1 {
            bail!("unsupported CDF major version {version_major}");
        }
        let mut uuid_bytes = [0u8; 16];
        uuid_bytes.copy_from_slice(&buf[12..28]);
        let mut mac = [0u8; 32];
        mac.copy_from_slice(&buf[48..80]);
        Ok(Self {
            volume_uuid: Uuid::from_bytes(uuid_bytes),
            flags: u32::from_le_bytes(buf[28..32].try_into()?),
            contract_offset: u32::from_le_bytes(buf[32..36].try_into()?),
            contract_size: u32::from_le_bytes(buf[36..40].try_into()?),
            meta_generation: u64::from_le_bytes(buf[40..48].try_into()?),
            mac,
        })
    }
}

#[derive(Zeroize, ZeroizeOnDrop)]
struct RootKey([u8; 32]);

#[derive(Zeroize, ZeroizeOnDrop)]
struct MacKey([u8; 32]);

#[derive(Zeroize, ZeroizeOnDrop)]
struct LuksKey([u8; 32]);

impl RootKey {
    fn from_bytes(data: &[u8]) -> anyhow::Result<Self> {
        if data.len() == 32 {
            let mut out = [0u8; 32];
            out.copy_from_slice(data);
            return Ok(Self(out));
        }
        let trimmed = std::str::from_utf8(data)
            .unwrap_or("")
            .trim()
            .as_bytes();
        if trimmed.len() == 64 && trimmed.iter().all(|b| b.is_ascii_hexdigit()) {
            let decoded = hex::decode(trimmed).context("decode hex K_root")?;
            let mut out = [0u8; 32];
            out.copy_from_slice(&decoded);
            return Ok(Self(out));
        }
        // Passphrase-style material: hash to 32 bytes (matches cdf-gpt demo).
        let digest = Sha256::digest(data);
        let mut out = [0u8; 32];
        out.copy_from_slice(&digest);
        Ok(Self(out))
    }

    fn derive(&self, volume_uuid: &[u8; 16]) -> anyhow::Result<(MacKey, LuksKey)> {
        Ok((
            MacKey(hkdf_expand(&self.0, volume_uuid, INFO_MAC)?),
            LuksKey(hkdf_expand(&self.0, volume_uuid, INFO_LUKS)?),
        ))
    }
}

fn hkdf_expand(ikm: &[u8], salt: &[u8], info: &[u8]) -> anyhow::Result<[u8; 32]> {
    let hk = Hkdf::<Sha256>::new(Some(salt), ikm);
    let mut okm = [0u8; 32];
    hk.expand(info, &mut okm)
        .map_err(|_| anyhow!("HKDF expand failed"))?;
    Ok(okm)
}

fn verify_mac(k_mac: &MacKey, sb: &Superblock, contract: &[u8]) -> bool {
    let sb_bytes = sb.encode_for_mac();
    let mut mac = HmacSha256::new_from_slice(&k_mac.0).expect("HMAC key length");
    mac.update(&sb_bytes);
    mac.update(contract);
    let result = mac.finalize().into_bytes();
    result
        .iter()
        .zip(sb.mac.iter())
        .fold(0u8, |acc, (a, b)| acc | (a ^ b))
        == 0
}

async fn get_plaintext_key(key_uri: &str) -> Result<Zeroizing<Vec<u8>>> {
    let key = if key_uri.starts_with("sealed.") {
        secret::unseal_secret(key_uri.as_bytes())
            .await
            .map_err(|source| CdfError::GetKeyFailed {
                source: source.into(),
            })?
    } else if ResourceUri::try_from(key_uri).is_ok() {
        kms::new_getter("kbs", ProviderSettings::default())
            .await
            .map_err(|source| CdfError::GetKeyFailed {
                source: source.into(),
            })?
            .get_secret(key_uri, &Annotations::default())
            .await
            .map_err(|source| CdfError::GetKeyFailed {
                source: source.into(),
            })?
    } else if key_uri.starts_with("file://") {
        let path = key_uri.trim_start_matches("file://");
        tokio::fs::read(path).await?
    } else {
        return Err(CdfError::IllegalKeyScheme);
    };
    Ok(Zeroizing::new(key))
}

fn parse_device_id(device_id: &str) -> Result<(u32, u32)> {
    let parts: Vec<&str> = device_id.split(':').collect();
    if parts.len() != 2 {
        return Err(CdfError::IllegalDeviceId);
    }
    let major = parts[0]
        .parse::<u32>()
        .map_err(|_| CdfError::IllegalDeviceId)?;
    let minor = parts[1]
        .parse::<u32>()
        .map_err(|_| CdfError::IllegalDeviceId)?;
    Ok((major, minor))
}

async fn get_device_path(major: u32, minor: u32) -> Result<String> {
    let uevent_path = format!("/sys/dev/block/{}:{}/uevent", major, minor);
    let file = File::open(uevent_path).await?;
    let reader = BufReader::new(file);
    let mut lines = reader.lines();
    while let Ok(Some(line)) = lines.next_line().await {
        if let Some(name) = line.strip_prefix("DEVNAME=") {
            return Ok(format!("/dev/{}", name));
        }
    }
    Err(CdfError::MountFailed(anyhow!(
        "DEVNAME not found for {major}:{minor}"
    )))
}

struct Discovered {
    meta: PathBuf,
    data: PathBuf,
}

fn partprobe(dev: &Path) {
    let _ = Command::new("partprobe")
        .arg(dev)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status();
    let _ = Command::new("partx")
        .args(["-u"])
        .arg(dev)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status();
    std::thread::sleep(std::time::Duration::from_millis(200));
}

fn partition_path(block_dev: &Path, index: u32) -> anyhow::Result<PathBuf> {
    let s = block_dev.to_string_lossy();
    let candidates = if s.chars().last().map(|c| c.is_ascii_digit()).unwrap_or(false) {
        vec![
            PathBuf::from(format!("{s}p{index}")),
            PathBuf::from(format!("{s}{index}")),
        ]
    } else {
        vec![
            PathBuf::from(format!("{s}{index}")),
            PathBuf::from(format!("{s}p{index}")),
        ]
    };
    for p in &candidates {
        if p.exists() {
            return Ok(p.clone());
        }
    }
    // Last resort: wait briefly and retry first candidate.
    std::thread::sleep(std::time::Duration::from_millis(300));
    for p in &candidates {
        if p.exists() {
            return Ok(p.clone());
        }
    }
    bail!(
        "partition {index} of {} not found (tried {:?})",
        block_dev.display(),
        candidates
    )
}

fn extract_type_guid(info: &str) -> Option<String> {
    for line in info.lines() {
        let line = line.trim();
        if let Some(rest) = line.strip_prefix("Partition GUID code:") {
            let token = rest.trim().split_whitespace().next()?;
            return Some(token.to_lowercase());
        }
    }
    None
}

fn discover(block_dev: &Path) -> anyhow::Result<Discovered> {
    partprobe(block_dev);
    let mut meta_idx = None;
    let mut data_idx = None;
    for idx in 1u32..=8 {
        let out = Command::new("sgdisk")
            .args(["-i", &idx.to_string()])
            .arg(block_dev)
            .output()
            .context("run sgdisk -i")?;
        if !out.status.success() {
            continue;
        }
        let info = String::from_utf8_lossy(&out.stdout);
        if info.contains("does not exist") || info.contains("Partition GUID code: 00000000") {
            continue;
        }
        let type_uuid = extract_type_guid(&info).unwrap_or_default();
        if type_uuid == TYPE_META {
            meta_idx = Some(idx);
        } else if type_uuid == TYPE_DATA {
            data_idx = Some(idx);
        } else if type_uuid == TYPE_VERITY {
            // verity profiles not yet activated in CDH MVP
            debug!(partition = idx, "found CDF verity partition");
        }
    }
    let meta_index = meta_idx.context("CDF meta partition not found")?;
    let data_index = data_idx.context("CDF data partition not found")?;
    Ok(Discovered {
        meta: partition_path(block_dev, meta_index)?,
        data: partition_path(block_dev, data_index)?,
    })
}

fn read_meta(meta_dev: &Path) -> anyhow::Result<(Superblock, Vec<u8>, Contract)> {
    let mut f = std::fs::File::open(meta_dev).with_context(|| format!("open {}", meta_dev.display()))?;
    let mut sb_buf = [0u8; SUPERBLOCK_SIZE];
    f.read_exact(&mut sb_buf)?;
    if sb_buf.iter().all(|b| *b == 0) {
        bail!("meta partition is empty (all zeros); refusing to open");
    }
    let sb = Superblock::decode(&sb_buf)?;
    if sb.contract_offset != CONTRACT_OFFSET {
        bail!("unexpected contract_offset {}", sb.contract_offset);
    }
    if sb.contract_size == 0 || sb.contract_size > 28 * 1024 * 1024 {
        bail!("implausible contract_size {}", sb.contract_size);
    }
    f.seek(SeekFrom::Start(sb.contract_offset as u64))?;
    let mut contract_bytes = vec![0u8; sb.contract_size as usize];
    f.read_exact(&mut contract_bytes)?;
    let contract: Contract = serde_json::from_slice(&contract_bytes).context("parse Contract")?;
    Ok((sb, contract_bytes, contract))
}

fn has_filesystem(device: &str) -> bool {
    // blkid exit 2 = no filesystem; treat any positive detection as present.
    match Command::new("blkid").arg(device).output() {
        Ok(out) => out.status.success() && !out.stdout.is_empty(),
        Err(_) => false,
    }
}

impl Cdf {
    async fn real_mount(
        &mut self,
        options: &HashMap<String, String>,
        _flags: &[String],
        mount_point: &str,
    ) -> Result<()> {
        let parameters = parse_parameters(options);

        let device_path = match (parameters.device_id, parameters.device_path) {
            (Some(device_id), _) => {
                let (maj, min) = parse_device_id(&device_id)?;
                get_device_path(maj, min).await?
            }
            (_, Some(device_path)) => device_path,
            _ => return Err(CdfError::NoDeviceSpecified),
        };

        let disc = discover(Path::new(&device_path)).map_err(CdfError::MountFailed)?;
        let (sb, contract_bytes, contract) =
            read_meta(&disc.meta).map_err(CdfError::MountFailed)?;

        if let Some(expected) = parameters
            .expected_uuid
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
        {
            let want = Uuid::parse_str(expected)
                .map_err(|e| CdfError::MountFailed(anyhow!("bad expectedUuid: {e}")))?;
            if want != sb.volume_uuid {
                return Err(CdfError::MountFailed(anyhow!(
                    "expected-volume-uuid mismatch: want {want}, disk has {}",
                    sb.volume_uuid
                )));
            }
        }

        if let Some(ep) = parameters
            .expected_profile
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
        {
            let want = Profile::parse(ep).map_err(CdfError::MountFailed)?;
            if want != contract.profile {
                return Err(CdfError::MountFailed(anyhow!(
                    "expected profile {} but Contract has {}",
                    want.as_str(),
                    contract.profile.as_str()
                )));
            }
        }

        let locator = parameters
            .kbs_key_id
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(|s| s.to_string())
            .or_else(|| {
                contract
                    .key_locator
                    .as_deref()
                    .map(str::trim)
                    .filter(|s| !s.is_empty())
                    .map(|s| s.to_string())
            })
            .ok_or_else(|| {
                CdfError::MountFailed(anyhow!(
                    "no key locator: set kbsKeyId / cdf.kbs-key-id or Contract.key_locator"
                ))
            })?;

        debug!(%locator, "CDF fetching K_root");
        let key_bytes = get_plaintext_key(&locator).await?;
        let root = RootKey::from_bytes(&key_bytes).map_err(CdfError::MountFailed)?;
        let (k_mac, k_luks) = root
            .derive(sb.volume_uuid.as_bytes())
            .map_err(CdfError::MountFailed)?;

        if contract.profile.is_authenticated() {
            if sb.flags & FLAG_AUTHENTICATED == 0 {
                return Err(CdfError::MountFailed(anyhow!(
                    "authenticated profile required but flags.AUTHENTICATED=0"
                )));
            }
            if !verify_mac(&k_mac, &sb, &contract_bytes) {
                return Err(CdfError::MountFailed(anyhow!(
                    "MAC verification failed; refusing to open (fail-closed)"
                )));
            }
        }
        if contract.volume_uuid != sb.volume_uuid || contract.meta_generation != sb.meta_generation
        {
            return Err(CdfError::MountFailed(anyhow!(
                "Contract identity fields disagree with Superblock"
            )));
        }

        if matches!(contract.profile, Profile::Verity | Profile::VerityCrypt) {
            return Err(CdfError::MountFailed(anyhow!(
                "CDH CDF MVP supports plain|crypt+integrity only; got {}",
                contract.profile.as_str()
            )));
        }

        let mapper_name = parameters
            .mapper_name
            .unwrap_or_else(|| format!("cdf-{}", Uuid::new_v4()));
        let mapped = if contract.profile.needs_luks() {
            if contract.data.cipher != "aes-xts-plain64" && !contract.data.cipher.is_empty() {
                return Err(CdfError::MountFailed(anyhow!(
                    "cipher {} not allow-listed",
                    contract.data.cipher
                )));
            }
            let header_b64 = contract
                .data
                .luks2_header_b64
                .as_ref()
                .ok_or_else(|| CdfError::MountFailed(anyhow!("missing luks2_header_b64")))?;
            let header = B64
                .decode(header_b64)
                .map_err(|e| CdfError::MountFailed(anyhow!("decode LUKS header: {e}")))?;

            let mut hdr = NamedTempFile::new().map_err(CdfError::Io)?;
            hdr.write_all(&header).map_err(CdfError::Io)?;
            hdr.flush().map_err(CdfError::Io)?;
            let hdr_path = hdr.path().to_string_lossy().to_string();

            let formatter = Luks2Formatter::default().with_integrity(true);
            let passphrase = Zeroizing::new(k_luks.0.to_vec());
            formatter
                .open_device(
                    disc.data.to_str().unwrap(),
                    Some(&hdr_path),
                    &mapper_name,
                    passphrase,
                )
                .map_err(|e| CdfError::MountFailed(e))?;
            drop(hdr);
            self.cryptsetup_names.push(mapper_name.clone());
            format!("/dev/mapper/{mapper_name}")
        } else {
            disc.data.to_string_lossy().to_string()
        };

        let mkfs_if_empty = parameters
            .mkfs_if_empty
            .as_deref()
            .map(|s| s == "true" || s == "1")
            .unwrap_or(false);

        if mkfs_if_empty && !has_filesystem(&mapped) {
            if contract.profile.is_ro() {
                return Err(CdfError::MountFailed(anyhow!(
                    "mkfs-if-empty set but profile is read-only"
                )));
            }
            info!(%mapped, "CDF mapper has no FS; mkfs.ext4 (integrity-compatible)");
            let formatter = FsFormatter {
                fs_type: FsType::Ext4,
                force: true,
                args: vec![
                    "-E".into(),
                    "lazy_itable_init=0,lazy_journal_init=0".into(),
                ],
            };
            // Prefer integrity-compatible path for crypt+integrity.
            if contract.profile.needs_luks() {
                formatter
                    .format_integrity_compatible(&mapped)
                    .map_err(|e| CdfError::MountFailed(e))?;
            } else {
                formatter
                    .format(&mapped)
                    .map_err(|e| CdfError::MountFailed(e))?;
            }
        }

        std::fs::create_dir_all(mount_point)?;
        let mut flags = MsFlags::empty();
        if contract.profile.is_ro() {
            flags |= MsFlags::MS_RDONLY;
        }
        let fstype = parameters
            .filesystem_type
            .as_deref()
            .unwrap_or("ext4");
        mount(
            Some(mapped.as_str()),
            mount_point,
            Some(fstype),
            flags,
            None::<&str>,
        )
        .map_err(|e| CdfError::MountFailed(anyhow!("mount {mapped} -> {mount_point}: {e}")))?;
        self.mount_points.push(mount_point.to_string());
        info!(%mount_point, %mapped, uuid = %sb.volume_uuid, "CDF volume mounted");
        Ok(())
    }

    pub async fn umount(&mut self) -> Result<()> {
        for mp in &self.mount_points {
            if let Err(e) = nix::mount::umount(&mp[..]) {
                warn!(mount_point = %mp, error = %e, "umount failed");
            }
        }
        for name in &self.cryptsetup_names {
            let formatter = Luks2Formatter::default();
            if let Err(e) = formatter.close_device(name) {
                warn!(mapper = %name, error = %e, "cryptsetup close failed");
            }
        }
        for path in &self.temp_paths {
            let _ = tokio::fs::remove_file(path).await;
        }
        Ok(())
    }
}

#[async_trait]
impl SecureMount for Cdf {
    async fn mount(
        &mut self,
        options: &HashMap<String, String>,
        flags: &[String],
        mount_point: &str,
    ) -> super::Result<()> {
        self.real_mount(options, flags, mount_point)
            .await
            .map_err(|e| e.into())
    }
}
