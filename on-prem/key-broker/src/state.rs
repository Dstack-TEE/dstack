// SPDX-FileCopyrightText: © 2025 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: BUSL-1.1

use tokio::sync::RwLock;

use crate::{config::Config, slot::SlotStore};

pub struct AppState {
    /// Raw 32-byte X25519 transport private scalar for the current courier
    /// session (used to HPKE-open the sealed root). Never leaves TEE memory.
    pub transport_secret: RwLock<Option<[u8; 32]>>,
    pub transport_pub: RwLock<Option<[u8; 32]>>,
    pub auth_bundle: RwLock<Option<serde_json::Value>>,
    pub root_ready: RwLock<bool>,
    pub config: Config,
    pub slots: SlotStore,
    /// PEM of the KMS root CA cert, loaded from /kms/root-ca.crt if present.
    pub kms_ca_cert: RwLock<Option<String>>,
}
