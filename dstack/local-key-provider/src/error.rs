// SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

use std::io;

use thiserror::Error;

#[derive(Debug, Error)]
pub enum ProviderError {
    #[error("invalid request: {0}")]
    InvalidRequest(String),

    #[error("invalid JSON protocol message: {0}")]
    Json(#[from] serde_json::Error),

    #[error("network I/O failed: {0}")]
    Network(#[from] io::Error),

    #[error("failed to parse {kind} quote: {reason}")]
    QuoteParse { kind: &'static str, reason: String },

    #[error("TDX quote verification failed: {0}")]
    QuoteVerification(String),

    #[error("SGX and TDX quoting-enclave identifiers do not match")]
    QeIdMismatch,

    #[error("invalid public key in TDX report data")]
    InvalidPublicKey,

    #[error("cryptographic operation failed: {0}")]
    Crypto(String),

    #[error("attestation I/O failed while {operation}: {source}")]
    AttestationIo {
        operation: &'static str,
        #[source]
        source: io::Error,
    },

    #[error("permission denied while {operation}; process restart required: {source}")]
    RestartRequired {
        operation: &'static str,
        #[source]
        source: io::Error,
    },

    #[error("internal synchronization failed: {0}")]
    Synchronization(&'static str),
}

impl ProviderError {
    pub fn requires_restart(&self) -> bool {
        matches!(self, Self::RestartRequired { .. })
    }
}
