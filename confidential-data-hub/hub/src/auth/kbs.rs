// Copyright (c) 2023 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

//! This module helps to get confidential resources that will be used
//! by Confidential Data Hub from KBS, i.e. credentials used by KMSes.

use kms::{plugins::kbs::KbcClient, Annotations, Getter};
use log::debug;
use tokio::fs;

use crate::{hub::Hub, Error, Result};

impl Hub {
    pub(crate) async fn init_kbs_resources(&self) -> Result<()> {
        let mut kbs_client = KbcClient::new()
            .await
            .map_err(|e| Error::InitializationFailed(format!("kbs client creation failed: {e}")))?;

        for (k, v) in &self.credentials {
            let content = kbs_client
                .get_secret(v, &Annotations::default())
                .await
                .map_err(|e| {
                    Error::InitializationFailed(format!("kbs client get resource failed: {e}"))
                })?;

            debug!("Get config item {k} from KBS");
            fs::write(k, content).await.map_err(|e| {
                Error::InitializationFailed(format!("write kbs initialization file failed: {e:?}"))
            })?;
        }

        Ok(())
    }
}
