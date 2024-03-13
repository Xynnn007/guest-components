// Copyright (c) 2023 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

//! # KBS Clients
//!
//! There are two different kinds of KBS clients:
//! - `RCAR Client`: s.t. `KbsClient<Box<dyn EvidenceProvider>>`. It can
//! perform RCAR handshaking, get token and get resource using the
//! authenticated http session.
//! - `Token Client`: s.t. `KbsClient<Box<dyn TokenProvider>>`. It is a
//! simpler client. It can only get resource with a valid token as its
//! authentication materials.

pub mod rcar_client;

use crypto::rsa::RSAKeyPair;
use kbs_types::Tee;

use crate::aa_client::AAClient;

pub(crate) enum ClientTee {
    Unitialized,
    _Initializated(Tee),
}

/// This Client is used to connect to the remote KBS.
pub struct KbsClient {
    /// TEE Type
    pub(crate) _tee: ClientTee,

    /// The asymmetric key pair inside the TEE
    pub(crate) tee_key: RSAKeyPair,

    pub(crate) tee_key_cert: Option<String>,

    pub(crate) provider: AAClient,

    /// Http client
    pub(crate) http_client: reqwest::Client,

    /// KBS Host URL
    pub(crate) kbs_host_url: String,

    pub(crate) kbs_certs: Vec<String>,

    pub(crate) id: String,
}

pub const KBS_PROTOCOL_VERSION: &str = "0.1.0";

pub const KBS_GET_RESOURCE_MAX_ATTEMPT: u64 = 3;

pub const KBS_PREFIX: &str = "rcar";
