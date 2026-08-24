// SPDX-FileCopyrightText: © 2025 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

//! On-demand GPU attestation for the `AttestGpu` RPC.
//!
//! Running `nvattest` is expensive in a way most RPCs are not: it spawns a
//! process, fetches OCSP and RIM collateral from NVIDIA (the SDK's cache is
//! per-process, so a subprocess starts cold every time), and can take minutes
//! on a slow link. The agent's socket is mode 0777, so any container in the
//! CVM can reach it.
//!
//! The CVM is a single trust domain, so a container hammering this endpoint is
//! only hurting its own deployment -- that is not the concern. The concern is
//! that a retry loop would hammer *NVIDIA's* services from every dstack CVM
//! running the buggy app, and would keep a wedged GPU tool respawning. So the
//! gate below serialises attestations and enforces a cooldown between them.

use std::time::{Duration, Instant};

use anyhow::{bail, Result};
use tokio::sync::Mutex;

/// Minimum spacing between two attestations. Chosen against what the call
/// actually costs: a cold collateral fetch is seconds, so a caller polling
/// faster than this is not learning anything new, only generating load.
pub const COOLDOWN: Duration = Duration::from_secs(10);

/// Serialises `nvattest` runs and rate-limits them.
///
/// Results are deliberately not shared between waiters: each caller supplies
/// its own nonce, and handing back evidence that answers somebody else's
/// challenge is exactly the confusion this API exists to avoid.
pub struct GpuAttestor {
    proxy_url: Option<String>,
    timeout: Duration,
    cooldown: Duration,
    last_run: Mutex<Option<Instant>>,
}

impl GpuAttestor {
    pub fn new(proxy_url: Option<String>) -> Self {
        Self {
            proxy_url,
            timeout: nvattest::DEFAULT_TIMEOUT,
            cooldown: COOLDOWN,
            last_run: Mutex::new(None),
        }
    }

    #[cfg(test)]
    fn with_cooldown(cooldown: Duration) -> Self {
        Self {
            proxy_url: None,
            timeout: nvattest::DEFAULT_TIMEOUT,
            cooldown,
            last_run: Mutex::new(None),
        }
    }

    /// Attest against `nonce`, or explain why not.
    pub async fn attest(&self, nonce: &[u8]) -> Result<nvattest::CollectedAttestation> {
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
        let mut last_run = self.last_run.lock().await;
        check_cooldown(*last_run, Instant::now(), self.cooldown)?;
        let result =
            nvattest::collect_and_appraise(nonce, self.proxy_url.as_deref(), self.timeout).await;
        // Stamp on failure too: a failing GPU is the case most likely to be
        // retried in a tight loop, and the most expensive to retry.
        *last_run = Some(Instant::now());
        result
    }
}

/// Reject a call that arrives before the cooldown has elapsed.
fn check_cooldown(last_run: Option<Instant>, now: Instant, cooldown: Duration) -> Result<()> {
    let Some(last_run) = last_run else {
        return Ok(());
    };
    let elapsed = now.saturating_duration_since(last_run);
    if elapsed < cooldown {
        let wait = (cooldown - elapsed).as_secs() + 1;
        bail!("GPU attestation was run too recently; retry in {wait}s");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn first_call_is_always_allowed() {
        assert!(check_cooldown(None, Instant::now(), COOLDOWN).is_ok());
    }

    #[test]
    fn a_call_inside_the_cooldown_is_rejected_with_a_wait_hint() {
        let now = Instant::now();
        let last = now - Duration::from_secs(3);
        let err = check_cooldown(Some(last), now, Duration::from_secs(10))
            .unwrap_err()
            .to_string();
        assert!(err.contains("retry in"), "{err}");
    }

    #[test]
    fn a_call_after_the_cooldown_is_allowed() {
        let now = Instant::now();
        let last = now - Duration::from_secs(11);
        assert!(check_cooldown(Some(last), now, Duration::from_secs(10)).is_ok());
    }

    #[tokio::test]
    async fn a_wrong_length_nonce_is_rejected_before_anything_expensive() {
        let attestor = GpuAttestor::with_cooldown(Duration::from_secs(0));
        let err = attestor.attest(&[0u8; 16]).await.unwrap_err().to_string();
        assert!(err.contains("exactly 32 bytes"), "{err}");
        // Rejected on arity, so it must not have consumed the rate limit.
        assert!(attestor.last_run.lock().await.is_none());
    }
}
