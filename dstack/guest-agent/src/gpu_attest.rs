// SPDX-FileCopyrightText: © 2025 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

//! On-demand GPU attestation for the `AttestGpu` RPC.
//!
//! Running `nvattest` is expensive in a way most RPCs are not: it spawns a
//! process and talks to the GPU through the driver. The gate below serialises
//! collection so concurrent callers do not compete for the same devices.

use std::path::{Path, PathBuf};
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
    /// The binary whose presence says this image can attest a GPU.
    ///
    /// A field rather than a call to `nvattest::available()` so a test can pin
    /// the unavailable answer on a host that happens to have nvattest
    /// installed -- otherwise that test would spawn a real collection against
    /// whatever GPUs the host has.
    nvattest: PathBuf,
    run_lock: Mutex<()>,
}

impl GpuAttestor {
    pub fn new() -> Self {
        Self::with_nvattest_path(nvattest::NVATTEST)
    }

    /// `pub(crate)` so the handler tests can build a state that is
    /// deterministically without GPU support, whatever the host running
    /// them has installed.
    pub(crate) fn with_nvattest_path(path: impl AsRef<Path>) -> Self {
        Self {
            timeout: nvattest::DEFAULT_TIMEOUT,
            nvattest: path.as_ref().to_path_buf(),
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
        if !self.nvattest.exists() {
            // 501, not the 400 an uncoded error would report. The request is
            // well-formed and no other request would succeed: this image ships
            // no nvattest, so the capability is absent for the lifetime of the
            // CVM. A caller that reads 400 retries with different arguments
            // forever; one that reads 501 stops and falls back.
            //
            // Safe to say now because `AttestGpu` is v1-only and has never
            // shipped in a release -- no client is reading 400 here today.
            ra_rpc::bail!(501, "GPU attestation is not available in this image");
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

    /// A malformed nonce is the caller's fault; an image without nvattest is
    /// not. The two must not answer with the same status.
    ///
    /// The nonce here is well-formed, so this reaches the availability check
    /// rather than stopping at the length check above.
    #[tokio::test]
    async fn an_image_without_nvattest_answers_not_implemented() {
        let attestor = GpuAttestor::with_nvattest_path("/nonexistent/nvattest");
        let err = attestor.attest(&[0u8; 32]).await.unwrap_err();
        assert!(
            err.to_string().contains("not available in this image"),
            "{err}"
        );
        assert_eq!(ra_rpc::code_of(&err), Some(501));

        let malformed = attestor.attest(&[0u8; 16]).await.unwrap_err();
        assert_eq!(ra_rpc::code_of(&malformed), None, "a bad nonce stays a 400");
    }
}
