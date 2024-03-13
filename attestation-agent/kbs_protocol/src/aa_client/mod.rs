// Copyright (c) 2024 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

pub mod attestation_agent;
pub mod attestation_agent_ttrpc;

use attestation_agent::{GetEvidenceRequest, GetTeeTypeRequest};
use attestation_agent_ttrpc::AttestationAgentServiceClient;

use anyhow::{Context, Result};
use kbs_types::Tee;
use ttrpc::context;

const SOCKET_PATH: &str =
    "unix:///run/confidential-containers/attestation-agent/attestation-agent.sock";

pub struct AAClient {
    gtclient: AttestationAgentServiceClient,
}

impl AAClient {
    pub fn new() -> Result<Self> {
        let inner = ttrpc::asynchronous::Client::connect(SOCKET_PATH)?;
        let gtclient = AttestationAgentServiceClient::new(inner);
        Ok(Self { gtclient })
    }

    pub async fn get_evidence(&mut self, runtime_data: Vec<u8>) -> Result<String> {
        let req = GetEvidenceRequest {
            RuntimeData: runtime_data,
            ..Default::default()
        };
        let res = self
            .gtclient
            .get_evidence(context::with_timeout(50 * 1000 * 1000 * 1000), &req)
            .await?;
        // .context("get evidence failed")?;

        let evidence = String::from_utf8(res.Evidence)?;

        Ok(evidence)
    }

    pub async fn get_tee_type(&self) -> Result<Tee> {
        let req = GetTeeTypeRequest {
            ..Default::default()
        };
        let res = self
            .gtclient
            .get_tee_type(context::with_timeout(50 * 1000 * 1000 * 1000), &req)
            .await
            .context("get tee type failed")?;
        let tee = serde_json::from_str(&res.Tee)?;
        Ok(tee)
    }
}
