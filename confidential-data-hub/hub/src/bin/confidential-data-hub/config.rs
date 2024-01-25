// Copyright (c) 2024 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

use std::env;

use anyhow::*;
use config::{Config, File};
use serde::Deserialize;

const DEFAULT_CDH_SOCKET_ADDR: &str = "unix:///run/confidential-containers/cdh.sock";

#[derive(Deserialize, Debug)]
pub struct KbsConfig {
    pub name: String,

    pub url: String,

    pub kbs_cert: Option<String>,
}

#[derive(Deserialize, Debug)]
pub struct Credential {
    pub resource_url: String,
    pub path: String,
}

#[derive(Deserialize, Debug)]
pub struct CdhConfig {
    pub kbc: KbsConfig,

    pub credentials: Vec<Credential>,

    pub socket: String,
}

impl TryFrom<&str> for CdhConfig {
    type Error = anyhow::Error;

    /// Load `CdhConfig` from a configuration file. Supported formats are all formats supported by the
    /// `config` crate.
    fn try_from(config_path: &str) -> Result<Self, Self::Error> {
        let c = Config::builder()
            .set_default("socket", DEFAULT_CDH_SOCKET_ADDR)?
            .add_source(File::with_name(config_path))
            .build()?;

        c.try_deserialize()
            .map_err(|e| anyhow!("invalid config: {e:?}"))
    }
}

impl CdhConfig {
    pub fn apply(&self) {
        // KBS configurations
        env::set_var(
            "AA_KBC_PARAMS",
            format!("{}::{}", self.kbc.name, self.kbc.url),
        );
        if let Some(kbs_cert) = &self.kbc.kbs_cert {
            env::set_var("KBS_PUBLICKEY_CERT", kbs_cert);
        }
    }
}
