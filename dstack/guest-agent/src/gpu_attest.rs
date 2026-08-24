// SPDX-FileCopyrightText: © 2025 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

//! On-demand GPU attestation for the `AttestGpu` RPC.
//!
//! Running `nvattest` is expensive in a way most RPCs are not: it spawns a
//! process and talks to the GPU through the driver. The gate below serialises
//! collection so concurrent callers do not compete for the same devices.

use std::time::Duration;

use anyhow::{bail, Result};
use tokio::sync::Mutex;

/// Serialises GPU evidence collection.
///
/// Results are deliberately not shared between waiters: each caller supplies
/// its own nonce, and handing back evidence that answers somebody else's
/// challenge is exactly the confusion this API exists to avoid.
pub struct GpuAttestor {
    timeout: Duration,
    run_lock: Mutex<()>,
}

impl GpuAttestor {
    pub fn new() -> Self {
        Self {
            timeout: nvattest::DEFAULT_TIMEOUT,
            run_lock: Mutex::new(()),
        }
    }

    /// Attest against `nonce`, or explain why not.
    pub async fn attest(&self, nonce: &[u8]) -> Result<Vec<u8>> {
        if nonce.len() != nvattest::NONCE_LEN {
            bail!(
                "nonce must be exactly {} bytes, got {}",
                nvattest::NONCE_LEN,
                nonce.len()
            );
        }
        if !nvattest::available() {
            bail!("GPU attestation is not available in this image");
        }
        // Held across the whole run, so a second caller waits rather than
        // starting a competing nvattest against the same devices.
        let _guard = self.run_lock.lock().await;
        let (_, evidence) = nvattest::collect_evidence(nonce, self.timeout).await?;
        Ok(evidence)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn a_wrong_length_nonce_is_rejected_before_anything_expensive() {
        let attestor = GpuAttestor::new();
        let err = attestor.attest(&[0u8; 16]).await.unwrap_err().to_string();
        assert!(err.contains("exactly 32 bytes"), "{err}");
    }
}
