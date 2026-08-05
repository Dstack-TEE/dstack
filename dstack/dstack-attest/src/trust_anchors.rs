// SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

//! Trust anchors published inside a guest, and the checks that make them
//! trustworthy to read.
//!
//! A CVM must never let its host pick the trust anchor that verifies remote
//! attestation. The host sits outside the trust boundary, so a host-supplied
//! root would let it stand up a fake key provider and hand the guest keys it
//! never earned.
//!
//! An image that must verify non-production evidence still needs external
//! roots, so that handoff runs entirely inside the guest: `dstack-tee-simulator`
//! derives them from its seed and writes them to [`ANCHOR_DIR`], a tmpfs
//! directory the host cannot reach. Only the development image ships the
//! simulator, and image contents are measured, so on a production image nothing
//! ever creates that directory and the vendor production roots are the only
//! reachable outcome.
//!
//! [`crate::default_verifier`] is the only thing that should act on what
//! [`load_anchors`] returns.

use std::{
    os::unix::fs::MetadataExt as _,
    path::{Path, PathBuf},
};

use anyhow::{bail, Context, Result};

use crate::attestation::RootCaPaths;

/// Guest tmpfs directory carrying locally published trust anchors.
pub const ANCHOR_DIR: &str = "/run/dstack/attestation";

const ROOTS_FILE: &str = "roots.json";

/// Path of the published [`RootCaPaths`] within a trust anchor directory.
///
/// The publisher writes it; [`load_anchors`] is the only reader.
pub fn roots_path(dir: &Path) -> PathBuf {
    dir.join(ROOTS_FILE)
}

/// Load trust anchors published inside this guest, if any.
///
/// Returns `Ok(None)` when nothing published anchors, which is the only outcome
/// on a production image.
pub fn load_anchors(dir: &Path) -> Result<Option<RootCaPaths>> {
    let path = roots_path(dir);
    if !path.exists() {
        return Ok(None);
    }
    ensure_owned_and_unwritable(dir, "trust anchor directory")?;
    let meta = ensure_owned_and_unwritable(&path, "published roots")?;
    if !meta.is_file() {
        bail!("published roots is not a regular file");
    }
    let root_ca: RootCaPaths =
        serde_json::from_slice(&fs_err::read(&path).context("failed to read published roots")?)
            .context("failed to parse published roots")?;
    for root in [
        &root_ca.tdx,
        &root_ca.gcp_tpm,
        &root_ca.aws_nitro_enclave,
        &root_ca.aws_nitro_tpm,
        &root_ca.sev_snp_milan,
        &root_ca.sev_snp_genoa,
        &root_ca.sev_snp_turin,
    ]
    .into_iter()
    .flatten()
    {
        // Confining every root to the published directory keeps a stale or
        // tampered file from redirecting the verifier at a host-shared root.
        if root.parent() != Some(dir) || root.file_name().is_none() {
            bail!(
                "trust anchor {} is outside {}",
                root.display(),
                dir.display()
            );
        }
        ensure_owned_and_unwritable(root, "trust anchor")?;
    }
    Ok(Some(root_ca))
}

/// Reject anything this process does not own or that others could rewrite.
///
/// Symlink metadata, not the followed target: a symlink planted by another user
/// would otherwise pass the check while resolving somewhere unowned.
fn ensure_owned_and_unwritable(path: &Path, what: &str) -> Result<std::fs::Metadata> {
    let meta = fs_err::symlink_metadata(path)
        .with_context(|| format!("failed to stat {what} {}", path.display()))?;
    let euid = rustix::process::geteuid().as_raw();
    if meta.uid() != euid {
        bail!(
            "{what} {} is owned by uid {} instead of {euid}",
            path.display(),
            meta.uid()
        );
    }
    if meta.mode() & 0o022 != 0 {
        bail!(
            "{what} {} is writable by group or others (mode {:o})",
            path.display(),
            meta.mode() & 0o7777
        );
    }
    Ok(meta)
}

#[cfg(test)]
mod tests {
    use super::*;
    // Mirrors what `crate::default_verifier` does with a loaded set, so the
    // published roots are proven usable by the real verifier.
    use crate::attestation::{AttestationVerifier, AttestationVerifierConfig};
    use std::os::unix::fs::PermissionsExt as _;

    fn sample_root() -> String {
        let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
        let mut params = rcgen::CertificateParams::new(vec![]).unwrap();
        params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        params.self_signed(&key).unwrap().pem()
    }

    /// Stand in for the publisher, which lives in `dstack-tee-simulator`.
    fn publish(dir: &Path, tdx_root: &str) -> RootCaPaths {
        fs_err::create_dir_all(dir).unwrap();
        fs_err::set_permissions(dir, std::fs::Permissions::from_mode(0o700)).unwrap();
        let root = dir.join("tdx-root-ca.pem");
        safe_write::safe_write_with_mode(&root, tdx_root.as_bytes(), 0o600).unwrap();
        let root_ca = RootCaPaths {
            tdx: Some(root),
            ..Default::default()
        };
        write_roots(dir, &root_ca);
        root_ca
    }

    fn write_roots(dir: &Path, root_ca: &RootCaPaths) {
        safe_write::safe_write_with_mode(
            roots_path(dir),
            serde_json::to_vec(root_ca).unwrap(),
            0o600,
        )
        .unwrap();
    }

    fn verifier_for(root_ca: RootCaPaths) -> Result<AttestationVerifier> {
        AttestationVerifier::load(&AttestationVerifierConfig {
            insecure_allow_external_trust_anchors: true,
            urls: Default::default(),
            root_ca,
        })
    }

    #[test]
    fn absent_directory_selects_production_roots() {
        let dir = tempfile::tempdir().unwrap();
        assert!(load_anchors(&dir.path().join("missing")).unwrap().is_none());
    }

    #[test]
    fn published_roots_round_trip() {
        let dir = tempfile::tempdir().unwrap();
        let dir = dir.path().join("attestation");
        let published = publish(&dir, &sample_root());

        let root_ca = load_anchors(&dir).unwrap().expect("anchors should load");
        assert_eq!(root_ca.tdx, published.tdx);
        assert_eq!(root_ca.gcp_tpm, None);
        // What was published must be loadable by the real verifier.
        verifier_for(root_ca).unwrap();
    }

    #[test]
    fn a_malformed_root_fails_verifier_construction() {
        let dir = tempfile::tempdir().unwrap();
        let dir = dir.path().join("attestation");
        publish(&dir, "not a certificate");
        let root_ca = load_anchors(&dir).unwrap().unwrap();
        assert!(verifier_for(root_ca).is_err());
    }

    #[test]
    fn world_writable_roots_are_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let dir = dir.path().join("attestation");
        publish(&dir, &sample_root());
        fs_err::set_permissions(roots_path(&dir), std::fs::Permissions::from_mode(0o666)).unwrap();
        let error = load_anchors(&dir).unwrap_err().to_string();
        assert!(error.contains("writable by group or others"), "{error}");
    }

    #[test]
    fn trust_anchor_outside_the_directory_is_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let anchors = dir.path().join("attestation");
        let mut root_ca = publish(&anchors, &sample_root());
        root_ca.tdx = Some(dir.path().join("host-shared-root.pem"));
        write_roots(&anchors, &root_ca);
        let error = load_anchors(&anchors).unwrap_err().to_string();
        assert!(error.contains("is outside"), "{error}");
    }
}
