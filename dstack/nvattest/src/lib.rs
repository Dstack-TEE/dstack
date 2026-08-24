// SPDX-FileCopyrightText: © 2025 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

//! Thin wrapper around the NVIDIA `nvattest` CLI.
//!
//! Both the boot path (`dstack-util setup`) and the guest agent's on-demand
//! `AttestGpu` RPC shell out to the same binary with the same argument shape,
//! so the invocation, the proxy-URL rules and the output checks live here
//! rather than being written twice with two sets of bugs.
//!
//! What this crate does *not* do is decide what the evidence means. Appraisal
//! against a policy is the caller's, because the boot gate and a runtime
//! liveness check want different answers from the same bytes.

use std::{path::Path, process::Output, time::Duration};

use anyhow::{bail, Context, Result};
use serde::Deserialize;
use serde_json::Value;
use tracing::info;

/// The nvattest binary, installed into the rootfs by the nvattest recipe.
pub const NVATTEST: &str = "/usr/bin/nvattest";

/// NVIDIA's relying-party policy that tolerates a cached OCSP responder nonce.
/// Only used when a collateral proxy is configured.
pub const TRUST_OUTPOST_POLICY: &str = "/usr/share/nvattest/policies/allow_trust_outpost_ocsp.rego";

/// SPDM fixes the GPU evidence nonce at 32 bytes. The SDK rejects anything
/// else, so callers get a clear error here instead of a CLI parse failure.
pub const NONCE_LEN: usize = 32;

/// Long enough for a cold collateral fetch on a slow link, short enough that a
/// wedged driver cannot hang the caller forever.
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(300);

/// Raw `nvattest attest --format json` output plus the nonce it answered.
#[derive(Debug)]
pub struct Attestation {
    /// Exact stdout bytes. Callers that bind evidence to a measurement must
    /// hash these, not a re-serialization of the parsed claims.
    pub output: Vec<u8>,
    /// Hex-encoded nonce passed to nvattest, echoed back as `eat_nonce`.
    pub nonce: String,
    /// Parsed claims, one per attested device.
    pub claims: Vec<Value>,
}

#[derive(Deserialize)]
struct NvattestOutput {
    result_code: i64,
    claims: Vec<Value>,
}

#[derive(Deserialize)]
struct NonceClaim {
    #[serde(rename = "eat_nonce")]
    eat_nonce: String,
    #[serde(rename = "x-nvidia-gpu-attestation-report-nonce-match")]
    nonce_match: bool,
}

/// True when this image can attest a GPU at all.
pub fn available() -> bool {
    Path::new(NVATTEST).exists()
}

/// Validate a collateral proxy URL. Rejects anything carrying credentials or a
/// path, so a misconfigured value cannot smuggle a different endpoint past the
/// `{proxy}/ocsp` and `{proxy}/v1/rim/...` construction below.
pub fn normalize_proxy_url(proxy_url: Option<&str>) -> Result<Option<String>> {
    let Some(proxy_url) = proxy_url.map(str::trim).filter(|url| !url.is_empty()) else {
        return Ok(None);
    };
    let parsed = url::Url::parse(proxy_url).context("invalid NVIDIA attestation proxy URL")?;
    if !matches!(parsed.scheme(), "http" | "https") || parsed.host_str().is_none() {
        bail!("NVIDIA attestation proxy must be an absolute HTTP(S) URL");
    }
    if parsed.query().is_some()
        || parsed.fragment().is_some()
        || !parsed.username().is_empty()
        || parsed.password().is_some()
        || parsed.path() != "/"
    {
        bail!(
            "NVIDIA attestation proxy URL must not contain credentials, path, query, or fragment"
        );
    }
    Ok(Some(parsed.as_str().trim_end_matches('/').to_string()))
}

/// Build the CLI arguments for a local (self-verifying) GPU attestation.
pub fn args(nonce: &str, proxy_url: Option<&str>) -> Result<Vec<String>> {
    let mut args = vec![
        "attest".to_string(),
        "--device".to_string(),
        "gpu".to_string(),
        "--verifier".to_string(),
        "local".to_string(),
        "--nonce".to_string(),
        nonce.to_string(),
        "--format".to_string(),
        "json".to_string(),
    ];
    if let Some(proxy_url) = normalize_proxy_url(proxy_url)? {
        args.extend([
            "--ocsp-url".to_string(),
            format!("{proxy_url}/ocsp"),
            "--rim-url".to_string(),
            proxy_url,
            "--relying-party-policy".to_string(),
            TRUST_OUTPOST_POLICY.to_string(),
        ]);
    }
    Ok(args)
}

/// Run a command with a bounded timeout, killing the child if it expires so a
/// wedged GPU tool cannot outlive the caller that gave up on it.
pub async fn run_command(program: &str, args: &[&str], timeout: Duration) -> Result<Output> {
    let child = tokio::process::Command::new(program)
        .args(args)
        .kill_on_drop(true)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .with_context(|| format!("failed to run {program}"))?;
    tokio::time::timeout(timeout, child.wait_with_output())
        .await
        .with_context(|| format!("{program} timed out"))?
        .with_context(|| format!("failed to run {program}"))
}

/// Run `nvattest` against `nonce` and return its raw output.
///
/// `nonce` must be exactly [`NONCE_LEN`] bytes; it is passed through verbatim
/// so a caller can compare its own challenge against `eat_nonce` without
/// reversing any transform.
///
/// Verifies only that nvattest succeeded and that every claim answers this
/// nonce. Everything else -- device counts, CC state, application policy --
/// is appraisal, and belongs to the caller.
pub async fn attest(
    nonce: &[u8],
    proxy_url: Option<&str>,
    timeout: Duration,
) -> Result<Attestation> {
    let (nonce, output) = run(nonce, proxy_url, timeout).await?;
    check_status(&output)?;
    let claims = check_nonce(&output.stdout, &nonce)?;
    Ok(Attestation {
        output: output.stdout,
        nonce,
        claims,
    })
}

/// Run `nvattest` and hand back its raw output *whatever its exit status*,
/// along with the hex nonce it was given.
///
/// Errors only when the tool could not be run at all. The boot gate persists
/// stdout before judging the status, so a failed appraisal still leaves
/// evidence on disk to debug; that is why the status check is separate.
pub async fn run(
    nonce: &[u8],
    proxy_url: Option<&str>,
    timeout: Duration,
) -> Result<(String, Output)> {
    if !available() {
        bail!("nvattest is not available in this image");
    }
    if nonce.len() != NONCE_LEN {
        bail!(
            "gpu attestation nonce must be {NONCE_LEN} bytes, got {}",
            nonce.len()
        );
    }
    let nonce = hex_encode(nonce);
    let args = args(&nonce, proxy_url)?;
    if args.iter().any(|arg| arg == "--relying-party-policy")
        && !Path::new(TRUST_OUTPOST_POLICY).is_file()
    {
        bail!("NVIDIA attestation proxy is configured but {TRUST_OUTPOST_POLICY} is missing");
    }
    let borrowed = args.iter().map(String::as_str).collect::<Vec<_>>();
    let output = run_command(NVATTEST, &borrowed, timeout).await?;
    if !output.stderr.is_empty() {
        info!("nvattest: {}", truncated_lossy(&output.stderr, 2048));
    }
    Ok((nonce, output))
}

/// Turn a non-zero nvattest exit into an error carrying a bounded stderr tail.
pub fn check_status(output: &Output) -> Result<()> {
    if !output.status.success() {
        bail!(
            "nvattest exited with {}: {}",
            output.status,
            truncated_lossy(&output.stderr, 512),
        );
    }
    Ok(())
}

/// Require a successful result and one fresh claim per device answering `nonce`.
pub fn check_nonce(stdout: &[u8], nonce: &str) -> Result<Vec<Value>> {
    let parsed: NvattestOutput =
        serde_json::from_slice(stdout).context("failed to parse nvattest JSON output")?;
    if parsed.result_code != 0 {
        bail!(
            "nvattest JSON result is not successful (result_code={})",
            parsed.result_code
        );
    }
    if parsed.claims.is_empty() {
        bail!("nvattest returned no GPU claims");
    }
    for (index, claim) in parsed.claims.iter().enumerate() {
        let nonce_claim: NonceClaim = serde_json::from_value(claim.clone())
            .with_context(|| format!("invalid GPU claim at index {index}"))?;
        if nonce_claim.eat_nonce != nonce || !nonce_claim.nonce_match {
            bail!("gpu claim at index {index} does not answer the requested nonce");
        }
    }
    Ok(parsed.claims)
}

fn hex_encode(bytes: &[u8]) -> String {
    use std::fmt::Write;
    bytes
        .iter()
        .fold(String::with_capacity(bytes.len() * 2), |mut out, b| {
            let _ = write!(out, "{b:02x}");
            out
        })
}

/// Truncate on a character boundary so a huge or binary stderr cannot flood logs.
pub fn truncated_lossy(bytes: &[u8], limit: usize) -> String {
    let text = String::from_utf8_lossy(bytes);
    match text.char_indices().nth(limit) {
        Some((end, _)) => format!("{}...", &text[..end]),
        None => text.into_owned(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn claim(nonce: &str, matched: bool) -> String {
        format!(
            r#"{{"eat_nonce":"{nonce}","x-nvidia-gpu-attestation-report-nonce-match":{matched}}}"#
        )
    }

    fn output(result_code: i64, claims: &[String]) -> Vec<u8> {
        format!(
            r#"{{"result_code":{result_code},"claims":[{}]}}"#,
            claims.join(",")
        )
        .into_bytes()
    }

    #[test]
    fn accepts_claims_answering_the_requested_nonce() {
        let nonce = "aa".repeat(NONCE_LEN);
        let out = output(0, &[claim(&nonce, true), claim(&nonce, true)]);
        assert_eq!(check_nonce(&out, &nonce).unwrap().len(), 2);
    }

    #[test]
    fn rejects_a_claim_answering_a_different_nonce() {
        let nonce = "aa".repeat(NONCE_LEN);
        let stale = "bb".repeat(NONCE_LEN);
        let out = output(0, &[claim(&nonce, true), claim(&stale, true)]);
        let err = check_nonce(&out, &nonce).unwrap_err().to_string();
        assert!(err.contains("does not answer the requested nonce"), "{err}");
    }

    #[test]
    fn rejects_a_claim_whose_device_reported_no_nonce_match() {
        let nonce = "aa".repeat(NONCE_LEN);
        let out = output(0, &[claim(&nonce, false)]);
        assert!(check_nonce(&out, &nonce).is_err());
    }

    #[test]
    fn rejects_unsuccessful_and_empty_results() {
        let nonce = "aa".repeat(NONCE_LEN);
        assert!(check_nonce(&output(1, &[claim(&nonce, true)]), &nonce).is_err());
        assert!(check_nonce(&output(0, &[]), &nonce).is_err());
    }

    #[tokio::test]
    async fn rejects_a_nonce_of_the_wrong_length() {
        let err = attest(&[0u8; 16], None, DEFAULT_TIMEOUT)
            .await
            .unwrap_err()
            .to_string();
        // Length is checked before the binary is, so this holds off-target too.
        assert!(
            err.contains("32 bytes") || err.contains("not available"),
            "{err}"
        );
    }

    #[test]
    fn proxy_url_rules() {
        assert_eq!(normalize_proxy_url(None).unwrap(), None);
        assert_eq!(normalize_proxy_url(Some("  ")).unwrap(), None);
        assert_eq!(
            normalize_proxy_url(Some("http://10.0.2.2:8090/")).unwrap(),
            Some("http://10.0.2.2:8090".to_string())
        );
        for bad in [
            "ftp://host/",
            "file:///tmp/proxy",
            "https://user@example.com",
            "http://user:pw@host/",
            "https://example.com/base",
            "https://example.com?q=1",
            "not-a-url",
        ] {
            assert!(
                normalize_proxy_url(Some(bad)).is_err(),
                "{bad} must be rejected"
            );
        }
    }

    #[test]
    fn proxy_routes_ocsp_and_rim_and_selects_outpost_policy() {
        let proxied = args("aa", Some("http://10.0.2.2:8090/")).unwrap();
        assert!(proxied
            .windows(2)
            .any(|w| w == ["--ocsp-url", "http://10.0.2.2:8090/ocsp"]));
        assert!(proxied
            .windows(2)
            .any(|w| w == ["--rim-url", "http://10.0.2.2:8090"]));
        assert!(proxied
            .windows(2)
            .any(|w| w == ["--relying-party-policy", TRUST_OUTPOST_POLICY]));

        let direct = args("aa", None).unwrap();
        assert!(!direct.iter().any(|a| a == "--ocsp-url"));
        assert!(!direct.iter().any(|a| a == "--relying-party-policy"));
    }

    #[test]
    fn truncation_is_bounded_and_utf8_safe() {
        assert_eq!(truncated_lossy(b"abc", 10), "abc");
        assert_eq!(truncated_lossy(b"abcdef", 3), "abc...");
        assert_eq!(
            truncated_lossy("\u{4f60}\u{597d}".as_bytes(), 1),
            "\u{4f60}..."
        );
    }
}
