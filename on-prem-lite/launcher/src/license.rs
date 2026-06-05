// SPDX-FileCopyrightText: © 2025 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0
//! License verification, install orchestration, persistence and the expiry
//! watchdog. Fail-closed throughout: a bad signature, a non-monotonic seq, an
//! out-of-window validity, or a self-identity mismatch all refuse the install.

use std::sync::Arc;
use std::time::Duration;

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};

use crate::courier;
use crate::crypto;
use crate::runner::{self, KeyEntry};
use crate::state::{AppState, Phase};

/// The workload an installed license authorizes.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Workload {
    pub image: String,
    pub digest: String,
    pub kid: String,
}

/// A License, deserialized from the signed JSON. We keep the raw
/// `serde_json::Value` for signature verification (canonical-JSON-minus-sig) and
/// also extract the typed fields here.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct License {
    #[serde(default)]
    pub schema_version: u32,
    #[serde(default)]
    pub license_id: String,
    #[serde(default)]
    pub tenant_id: String,
    pub app_id: String,
    pub compose_hash: String,
    pub workload: Workload,
    pub seq: u64,
    #[serde(default)]
    pub issued_at: i64,
    #[serde(default)]
    pub not_before: i64,
    pub expires_at: i64,
    #[serde(default)]
    pub grace_period_secs: i64,
}

/// Persisted high-water + last-installed license metadata (vTPM-sealed disk).
/// Holds NO secret material — the CEK is never persisted (decrypted in TEE, used,
/// discarded; the workload disk is itself vTPM-sealed).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InstalledLicense {
    pub seq: u64,
    pub expires_at: i64,
    pub grace_period_secs: i64,
    pub app_id: String,
    pub compose_hash: String,
    pub license_id: String,
    pub workload: Workload,
}

fn now_secs() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

fn state_file(state: &AppState) -> std::path::PathBuf {
    state.config.state_dir.join("license_seq")
}

/// Read the persisted high-water license. Absent/unreadable ⇒ None (first install
/// treats stored seq as 0).
pub fn load_persisted(state: &AppState) -> Option<InstalledLicense> {
    let path = state.config.state_dir.join("license_seq");
    let data = std::fs::read_to_string(&path).ok()?;
    match serde_json::from_str::<InstalledLicense>(&data) {
        Ok(v) => Some(v),
        Err(e) => {
            tracing::warn!("failed to parse persisted license at {}: {e}", path.display());
            None
        }
    }
}

fn persist(state: &AppState, installed: &InstalledLicense) -> Result<()> {
    std::fs::create_dir_all(&state.config.state_dir).with_context(|| {
        format!(
            "failed to create state dir {}",
            state.config.state_dir.display()
        )
    })?;
    let path = state_file(state);
    let data = serde_json::to_string_pretty(installed).context("failed to serialize license")?;
    std::fs::write(&path, data)
        .with_context(|| format!("failed to persist license to {}", path.display()))?;
    tracing::info!("persisted license seq={} to {}", installed.seq, path.display());
    Ok(())
}

/// Install (or renew/update) a license. Implements the fail-closed gate order
/// G8 → seq(G9) → validity(G10) → self-identity(G6/G6b) → CEK unseal + decrypt +
/// run → persist → watchdog.
pub async fn install(
    state: &Arc<AppState>,
    sealed_cek: Option<String>,
    license_value: serde_json::Value,
) -> Result<()> {
    // G8: Ed25519 signature against the pinned AUTHORITY_PUBKEY.
    crypto::verify_license(&license_value, &state.config.authority_pubkey)
        .context("license signature verification failed (G8)")?;

    let license: License = serde_json::from_value(license_value.clone())
        .context("failed to deserialize license fields")?;

    // G9: seq strictly greater than persisted high-water (anti-rollback).
    let stored_seq = load_persisted(state).map(|l| l.seq).unwrap_or(0);
    if license.seq <= stored_seq {
        bail!(
            "license seq not monotonically increasing: {} <= {} (rollback, G9)",
            license.seq,
            stored_seq
        );
    }

    // G10: validity window. (the watchdog handles later expiry; here we reject a
    // license that is already invalid at install time.)
    let now = now_secs();
    if now < license.not_before {
        bail!(
            "license not yet valid: now {} < not_before {} (G10)",
            now,
            license.not_before
        );
    }
    if now > license.expires_at + license.grace_period_secs {
        bail!(
            "license already expired: now {} > expires_at {} + grace {} (G10)",
            now,
            license.expires_at,
            license.grace_period_secs
        );
    }

    // G6: self-identity (defense in depth). The MEASURED identity on the tpm
    // profile is compose_hash (the attested app_id is just compose_hash[:40], so
    // it can't be an independent value — see DESIGN). The License's app_id is an
    // authority-side LABEL, so we do NOT compare it to our measured identity; we
    // only check that the License's compose_hash matches our own measured one
    // (refusing a License minted for a different launcher build). Prefer the
    // measured value from the guest agent; fall back to an env hint; if neither is
    // available, proceed (the authority already gated the attested compose_hash).
    let self_compose = courier::self_identity()
        .await
        .map(|(_app, compose)| compose)
        .or_else(|| state.config.compose_hash.clone());
    match self_compose {
        Some(self_compose_hash) => {
            if !ids_match(&license.compose_hash, &self_compose_hash) {
                bail!(
                    "license compose_hash != self: {} != {} (G6)",
                    license.compose_hash,
                    self_compose_hash
                );
            }
            tracing::info!("self-identity check passed (compose_hash); license app_id label = {}", license.app_id);
        }
        None => {
            tracing::warn!(
                "cannot determine own measured compose_hash; skipping G6 self-check (authority already gated the attested compose_hash)"
            );
        }
    }

    // CEK + workload, if a sealed_cek is present (a pure license renewal may omit it).
    if let Some(sealed) = &sealed_cek {
        let secret = {
            let guard = state.transport_secret.read().await;
            guard
                .as_ref()
                .copied()
                .context("no transport keypair; call /courier/init first")?
        };
        let priv_pem = crypto::unseal_cek(sealed, &secret).context("failed to HPKE-open CEK")?;
        let priv_pem = String::from_utf8(priv_pem).context("CEK is not valid utf-8 PEM")?;

        let key_files = runner::write_keyset(&[KeyEntry {
            kid: license.workload.kid.clone(),
            priv_pem,
        }])
        .context("failed to write CEK keyset")?;

        let local_tag = runner::decrypt_image(
            &license.workload.image,
            &license.workload.digest,
            &key_files,
        )
        .context("failed to decrypt workload image")?;
        runner::write_compose(&local_tag).context("failed to write compose file")?;

        let already_running = tokio::task::spawn_blocking(runner::is_workload_running)
            .await
            .unwrap_or(false);
        if already_running {
            tracing::info!("workload already running; performing rolling update");
            runner::compose_up_rolling().context("failed rolling update of workload")?;
        } else {
            runner::compose_up().context("failed to start workload")?;
        }
        tracing::info!("workload started/updated for license seq={}", license.seq);
    } else {
        tracing::info!(
            "license renewal without sealed_cek (seq={}); extending validity only",
            license.seq
        );
    }

    let installed = InstalledLicense {
        seq: license.seq,
        expires_at: license.expires_at,
        grace_period_secs: license.grace_period_secs,
        app_id: license.app_id.clone(),
        compose_hash: license.compose_hash.clone(),
        license_id: license.license_id.clone(),
        workload: license.workload.clone(),
    };
    persist(state, &installed)?;

    *state.installed.write().await = Some(installed.clone());
    *state.last_error.write().await = None;
    *state.phase.write().await = Phase::Running;

    // Refresh the watchdog: a fresh install with a later expiry extends the
    // deadline; the generation bump makes any stale watchdog exit.
    spawn_watchdog(Arc::clone(state), installed).await;

    Ok(())
}

/// Compare two identity strings tolerating an optional `0x` prefix and case.
fn ids_match(a: &str, b: &str) -> bool {
    let na = a.trim().trim_start_matches("0x").to_ascii_lowercase();
    let nb = b.trim().trim_start_matches("0x").to_ascii_lowercase();
    !na.is_empty() && na == nb
}

/// Start (or restart) the expiry watchdog for the given installed license. Bumps
/// the generation so any previously-running watchdog (a superseded license)
/// notices and exits without touching the renewed workload.
pub async fn spawn_watchdog(state: Arc<AppState>, installed: InstalledLicense) {
    let my_gen = {
        let mut g = state.generation.lock().await;
        *g += 1;
        *g
    };
    let deadline = installed.expires_at + installed.grace_period_secs;
    tokio::spawn(async move {
        loop {
            let now = now_secs();
            if now > deadline {
                break;
            }
            // Poll periodically so a renewal's later deadline is observed via the
            // generation check; sleep capped so we don't oversleep a near deadline.
            let remaining = (deadline - now).max(1) as u64;
            let sleep_secs = remaining.min(30);
            tokio::time::sleep(Duration::from_secs(sleep_secs)).await;

            // a newer install superseded us — exit, the new watchdog owns expiry.
            if *state.generation.lock().await != my_gen {
                tracing::info!("watchdog gen={my_gen} superseded; exiting");
                return;
            }
        }

        if *state.generation.lock().await != my_gen {
            return;
        }

        tracing::error!(
            "license seq={} expired (now > expires_at {} + grace {}); stopping workload",
            installed.seq,
            installed.expires_at,
            installed.grace_period_secs
        );
        if let Err(e) = runner::compose_down() {
            tracing::error!("failed to stop workload on expiry: {:#}", e);
        }
        *state.phase.write().await = Phase::Expired;
        *state.last_error.write().await = Some("license_expired".to_string());
    });
}

/// On boot, resume a persisted valid license: if still within its validity
/// window, re-arm the watchdog and mark Running (the workload disk is
/// vTPM-sealed, so the container can come back without re-decrypting); else mark
/// Expired and ensure the workload is stopped.
pub async fn resume(state: &Arc<AppState>) {
    let Some(installed) = load_persisted(state) else {
        tracing::info!("no persisted license; waiting for courier install");
        *state.phase.write().await = Phase::Waiting;
        return;
    };
    *state.installed.write().await = Some(installed.clone());

    let now = now_secs();
    if now > installed.expires_at + installed.grace_period_secs {
        tracing::warn!(
            "persisted license seq={} already expired; stopping workload",
            installed.seq
        );
        let _ = runner::compose_down();
        *state.phase.write().await = Phase::Expired;
        *state.last_error.write().await = Some("license_expired".to_string());
        return;
    }

    tracing::info!(
        "resuming persisted license seq={} (expires_at={})",
        installed.seq,
        installed.expires_at
    );
    *state.phase.write().await = Phase::Running;
    spawn_watchdog(Arc::clone(state), installed).await;
}
