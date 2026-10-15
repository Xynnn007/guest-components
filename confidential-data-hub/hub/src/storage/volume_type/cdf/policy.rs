// Copyright (c) 2026 Confidential Containers Authors
//
// SPDX-License-Identifier: Apache-2.0
//

//! Guest-side CDF volume policy.
//!
//! The host decides which disk is attached and which key locator is
//! requested, but it can also wipe a disk at will. Whether a blank disk may be
//! initialized, and which volume UUIDs a locator may open, therefore comes
//! from a file that is part of the measured guest rootfs.
//!
//! ```json
//! {
//!   "volumes": [
//!     {
//!       "key_locator": "kbs:///default/cdf/my-pvc-key",
//!       "allow_create": false,
//!       "volume_uuids": ["936f0392-e2bc-4c31-bbc8-dbc1fe780f08"],
//!       "profile": "crypt+integrity"
//!     }
//!   ]
//! }
//! ```
//!
//! A locator that is not listed may open any volume whose metadata
//! authenticates under its key, but never creates one.

use anyhow::{bail, Context, Result};
use cdf::Profile;
use serde::Deserialize;
use std::path::PathBuf;
use uuid::Uuid;

pub const DEFAULT_POLICY_PATH: &str = "/etc/cdf/policy.json";
pub const POLICY_PATH_ENV: &str = "CDF_POLICY_PATH";

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Policy {
    #[serde(default)]
    pub volumes: Vec<VolumePolicy>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VolumePolicy {
    pub key_locator: String,
    /// A blank disk requested with this locator may be initialized.
    #[serde(default)]
    pub allow_create: bool,
    /// If non-empty, only these volumes may be opened with this locator.
    #[serde(default)]
    pub volume_uuids: Vec<Uuid>,
    /// Profile to create with and to require on open.
    #[serde(default)]
    pub profile: Option<String>,
}

impl Policy {
    /// A missing file is an empty policy; an unreadable or malformed one is an error.
    pub fn load() -> Result<Self> {
        let path = std::env::var_os(POLICY_PATH_ENV)
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from(DEFAULT_POLICY_PATH));
        match std::fs::read(&path) {
            Ok(bytes) => serde_json::from_slice(&bytes)
                .with_context(|| format!("parse CDF policy {}", path.display())),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Self::default()),
            Err(e) => Err(e).with_context(|| format!("read CDF policy {}", path.display())),
        }
    }

    pub fn entry(&self, key_locator: &str) -> Option<&VolumePolicy> {
        let key_locator = key_locator.trim();
        self.volumes
            .iter()
            .find(|v| v.key_locator.trim() == key_locator)
    }
}

impl VolumePolicy {
    pub fn profile(&self) -> Result<Option<Profile>> {
        self.profile
            .as_deref()
            .map(Profile::parse)
            .transpose()
            .with_context(|| format!("policy for {}", self.key_locator))
    }

    pub fn check_open(&self, volume_uuid: &Uuid, profile: Profile) -> Result<()> {
        if !self.volume_uuids.is_empty() && !self.volume_uuids.contains(volume_uuid) {
            bail!(
                "volume {volume_uuid} is not allowed for {} by policy",
                self.key_locator
            );
        }
        if let Some(want) = self.profile()? {
            if want != profile {
                bail!("policy requires profile {want} but volume has {profile}");
            }
        }
        Ok(())
    }

    /// A bound locator (non-empty `volume_uuids`) never creates, even with
    /// `allow_create`: a blank disk there means the volume was wiped.
    pub fn may_create(&self) -> bool {
        self.allow_create && self.volume_uuids.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy(json: &str) -> Policy {
        serde_json::from_str(json).unwrap()
    }

    #[test]
    fn bound_locator_rejects_other_uuid_and_never_creates() {
        let u = Uuid::new_v4();
        let p = policy(&format!(
            r#"{{"volumes":[{{"key_locator":"kbs:///a/b/c","allow_create":true,"volume_uuids":["{u}"]}}]}}"#
        ));
        let e = p.entry(" kbs:///a/b/c ").unwrap();
        assert!(!e.may_create());
        assert!(e.check_open(&u, Profile::CryptIntegrity).is_ok());
        assert!(e
            .check_open(&Uuid::new_v4(), Profile::CryptIntegrity)
            .is_err());
    }

    #[test]
    fn unbound_locator_creates_and_profile_is_enforced() {
        let p = policy(
            r#"{"volumes":[{"key_locator":"kbs:///a/b/c","allow_create":true,"profile":"crypt+integrity"}]}"#,
        );
        let e = p.entry("kbs:///a/b/c").unwrap();
        assert!(e.may_create());
        assert!(e.check_open(&Uuid::new_v4(), Profile::Plain).is_err());
        assert!(p.entry("kbs:///other").is_none());
    }

    #[test]
    fn unknown_fields_are_rejected() {
        assert!(serde_json::from_str::<Policy>(
            r#"{"volumes":[{"key_locator":"x","allow_creat":true}]}"#
        )
        .is_err());
    }
}
