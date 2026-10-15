// Copyright (c) 2026 Confidential Containers Authors
//
// SPDX-License-Identifier: Apache-2.0
//

//! CDF (`volume_type=cdf`) SecureMount for GPT CDF v1 volumes.
//!
//! The host supplies the disk, so everything read from it is untrusted:
//! - a disk with sealed CDF metadata is only ever opened (MAC verified under
//!   `K_root`, then checked against the guest policy); it is never formatted;
//! - a blank disk is initialized here, in the guest, and only when the guest
//!   policy allows creating a volume for the requested key locator;
//! - anything else is refused.
//!
//! See confidential-disk-format design §4 / §6.

pub mod error;
pub mod policy;

use super::SecureMount;
use crate::secret;
use crate::storage::drivers::filesystem::{FsFormatter, FsType};

use anyhow::{anyhow, Context};
use async_trait::async_trait;
use cdf::{Activated, CreateRequest, DiskState, Profile, RootKey};
use error::{CdfError, Result};
use kms::{Annotations, ProviderSettings};
use nix::mount::{mount, MsFlags};
use policy::Policy;
use resource_uri::ResourceUri;
use std::collections::HashMap;
use std::path::Path;
use tokio::fs::File;
use tokio::io::{AsyncBufReadExt, BufReader};
use tracing::{debug, info, warn};
use uuid::Uuid;
use zeroize::Zeroizing;

#[derive(Default)]
pub struct Cdf {
    mount_points: Vec<String>,
    activated: Vec<Activated>,
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
            &[
                "expectedUuid",
                "cdf.expected-volume-uuid",
                "expected-volume-uuid",
            ],
        ),
        expected_profile: opt_get(options, &["expectedProfile", "cdf.profile", "profile"]),
        filesystem_type: opt_get(options, &["filesystemType", "cdf.fstype", "fstype"]),
        mapper_name: opt_get(options, &["mapperName", "mapper_name"]),
    }
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

async fn get_root_key(locator: &str) -> Result<RootKey> {
    debug!(%locator, "CDF fetching K_root");
    let key_bytes = get_plaintext_key(locator).await?;
    Ok(RootKey::from_bytes(&key_bytes)?)
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

fn mkfs(device: &Path, profile: Profile) -> anyhow::Result<()> {
    let device = device
        .to_str()
        .with_context(|| format!("non-UTF-8 device path {}", device.display()))?;
    let formatter = FsFormatter {
        fs_type: FsType::Ext4,
        force: true,
        args: vec!["-E".into(), "lazy_itable_init=0,lazy_journal_init=0".into()],
    };
    if profile.needs_luks() {
        formatter.format_integrity_compatible(device)
    } else {
        formatter.format(device)
    }
}

impl Cdf {
    /// Initialize a blank disk as a new CDF volume, if the policy allows it.
    async fn create_on_blank(
        &self,
        block_dev: &Path,
        policy: &Policy,
        parameters: &CdfParameters,
    ) -> Result<RootKey> {
        let locator = parameters.kbs_key_id.as_deref().ok_or_else(|| {
            anyhow!("disk is blank and no key locator (kbsKeyId / cdf.kbs-key-id) was given")
        })?;
        let entry = policy
            .entry(locator)
            .filter(|e| e.may_create())
            .ok_or_else(|| {
                anyhow!(
                    "disk is blank but policy does not allow creating a volume for {locator}; \
                     refusing (a bound volume may have been wiped)"
                )
            })?;
        if let Some(uuid) = &parameters.expected_uuid {
            return Err(anyhow!("expected volume {uuid} but disk is blank").into());
        }
        let profile = entry.profile()?.unwrap_or(Profile::CryptIntegrity);
        if !matches!(profile, Profile::Plain | Profile::CryptIntegrity) {
            return Err(anyhow!("cannot create profile {profile} in the guest").into());
        }
        if let Some(want) = &parameters.expected_profile {
            if Profile::parse(want)? != profile {
                return Err(anyhow!(
                    "requested profile {want} differs from policy profile {profile}"
                )
                .into());
            }
        }
        if let Some(fs) = &parameters.filesystem_type {
            if fs != FsType::Ext4.as_ref() {
                return Err(anyhow!("cannot create a {fs} filesystem; only ext4").into());
            }
        }

        let root = get_root_key(locator).await?;
        let populate = |dev: &Path| mkfs(dev, profile);
        let created = cdf::create(CreateRequest {
            block_dev,
            profile,
            root: &root,
            key_locator: Some(locator.to_string()),
            from_image: None,
            populate: Some(&populate),
            force: false,
        })?;
        warn!(
            volume_uuid = %created.volume_uuid,
            %locator,
            %profile,
            "CDF volume created on blank disk; add volume_uuid to the policy's volume_uuids \
             for this locator to bind it"
        );
        Ok(root)
    }

    async fn real_mount(
        &mut self,
        options: &HashMap<String, String>,
        _flags: &[String],
        mount_point: &str,
    ) -> Result<()> {
        let parameters = parse_parameters(options);

        let device_path = match (&parameters.device_id, &parameters.device_path) {
            (Some(device_id), _) => {
                let (maj, min) = parse_device_id(device_id)?;
                get_device_path(maj, min).await?
            }
            (_, Some(device_path)) => device_path.clone(),
            _ => return Err(CdfError::NoDeviceSpecified),
        };
        let block_dev = Path::new(&device_path);
        let policy = Policy::load()?;

        let mut root = None;
        let disc = match cdf::probe(block_dev)? {
            DiskState::Sealed(disc) => disc,
            DiskState::Blank => {
                root = Some(
                    self.create_on_blank(block_dev, &policy, &parameters)
                        .await?,
                );
                match cdf::probe(block_dev)? {
                    DiskState::Sealed(disc) => disc,
                    other => {
                        return Err(anyhow!("freshly created volume probes as {other:?}").into())
                    }
                }
            }
            DiskState::Foreign(why) => {
                return Err(anyhow!(
                    "disk is neither blank nor CDF ({why}); refusing to open or overwrite"
                )
                .into())
            }
        };

        let inspected = cdf::inspect(disc)?;
        if let Some(expected) = &parameters.expected_uuid {
            let want = Uuid::parse_str(expected).context("bad expectedUuid")?;
            if want != inspected.superblock.volume_uuid {
                return Err(anyhow!(
                    "expected-volume-uuid mismatch: want {want}, disk has {}",
                    inspected.superblock.volume_uuid
                )
                .into());
            }
        }

        let locator = parameters
            .kbs_key_id
            .clone()
            .or_else(|| {
                inspected
                    .contract
                    .key_locator
                    .as_deref()
                    .map(str::trim)
                    .filter(|s| !s.is_empty())
                    .map(str::to_string)
            })
            .ok_or_else(|| {
                anyhow!("no key locator: set kbsKeyId / cdf.kbs-key-id or Contract.key_locator")
            })?;
        let root = match root {
            Some(root) => root,
            None => get_root_key(&locator).await?,
        };

        let verified = cdf::verify(inspected, &root)?;
        let profile = verified.contract.profile;
        if let Some(entry) = policy.entry(&locator) {
            entry.check_open(&verified.volume_uuid, profile)?;
        }
        if let Some(want) = &parameters.expected_profile {
            let want = Profile::parse(want)?;
            if want != profile {
                return Err(anyhow!("expected profile {want} but Contract has {profile}").into());
            }
        }

        let mapper_name = parameters
            .mapper_name
            .clone()
            .unwrap_or_else(|| format!("cdf-{}", Uuid::new_v4()));
        let activated = cdf::activate(&verified, &mapper_name)?;

        let mut flags = MsFlags::empty();
        if profile.is_ro() {
            flags |= MsFlags::MS_RDONLY;
        }
        let fstype = parameters.filesystem_type.as_deref().unwrap_or("ext4");
        let mounted = std::fs::create_dir_all(mount_point)
            .map_err(CdfError::from)
            .and_then(|_| {
                mount(
                    Some(&activated.mapped),
                    mount_point,
                    Some(fstype),
                    flags,
                    None::<&str>,
                )
                .map_err(|e| {
                    anyhow!(
                        "mount {} -> {mount_point}: {e} (volumes are never formatted on open)",
                        activated.mapped.display()
                    )
                    .into()
                })
            });
        if let Err(e) = mounted {
            if let Err(close_err) = activated.close() {
                warn!(error = %close_err, "failed to close CDF mappings after mount failure");
            }
            return Err(e);
        }

        info!(
            %mount_point,
            mapped = %activated.mapped.display(),
            uuid = %verified.volume_uuid,
            %profile,
            "CDF volume mounted"
        );
        self.mount_points.push(mount_point.to_string());
        self.activated.push(activated);
        Ok(())
    }

    pub async fn umount(&mut self) -> Result<()> {
        for mp in &self.mount_points {
            if let Err(e) = nix::mount::umount(&mp[..]) {
                warn!(mount_point = %mp, error = %e, "umount failed");
            }
        }
        for activated in &self.activated {
            if let Err(e) = activated.close() {
                warn!(mapped = %activated.mapped.display(), error = %e, "CDF close failed");
            }
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
