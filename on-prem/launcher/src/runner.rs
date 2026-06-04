use anyhow::{Context, Result};
use std::path::PathBuf;
use std::process::Command;

use crate::sidecar::KeyEntry;

const COMPOSE_FILE: &str = "/tmp/business-compose.yaml";
/// Directory the leased private-key PEMs are written to, for skopeo's
/// `--decryption-key`. On tmpfs (/run) so the keys never touch persistent disk.
const KEYSET_DIR: &str = "/run/cek";

/// Write each leased private key to its own PEM file and return the paths.
/// skopeo/ocicrypt (native JWE) is handed all of them and decrypts with
/// whichever is the image's recipient. FAIL-CLOSED on an empty keyset.
pub fn write_keyset(keyset: &[KeyEntry]) -> Result<Vec<PathBuf>> {
    if keyset.is_empty() {
        anyhow::bail!("refusing to write an empty keyset (fail-closed)");
    }
    std::fs::create_dir_all(KEYSET_DIR)
        .with_context(|| format!("failed to create keyset dir {KEYSET_DIR}"))?;
    // clear any stale keys from a previous lease so revoked keys don't linger
    if let Ok(entries) = std::fs::read_dir(KEYSET_DIR) {
        for e in entries.flatten() {
            if e.path().extension().is_some_and(|x| x == "pem") {
                let _ = std::fs::remove_file(e.path());
            }
        }
    }
    let mut paths = Vec::with_capacity(keyset.len());
    for k in keyset {
        // kid is authority-generated (hex / caller-chosen); keep the filename safe.
        let safe: String = k
            .kid
            .chars()
            .map(|c| if c.is_ascii_alphanumeric() || c == '-' || c == '_' { c } else { '_' })
            .collect();
        let path = PathBuf::from(KEYSET_DIR).join(format!("{safe}.pem"));
        std::fs::write(&path, &k.priv_pem)
            .with_context(|| format!("failed to write key {}", path.display()))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600));
        }
        paths.push(path);
    }
    tracing::info!("wrote {} decryption key(s) to {}", paths.len(), KEYSET_DIR);
    Ok(paths)
}

/// Pull a JWE-encrypted image by digest and decrypt it into a docker-archive.
/// Pulling by `@<digest>` enforces digest verification (exactly the manifest
/// the version pointer named); ocicrypt (native JWE) tries each leased private
/// key (`key_files`, from `write_keyset`) and decrypts with the one that is the
/// image's recipient — fails closed if none match. Returns the local docker tag.
pub fn decrypt_image(
    encrypted_ref: &str,
    image_digest: &str,
    key_files: &[PathBuf],
) -> Result<String> {
    if key_files.is_empty() {
        anyhow::bail!("no decryption keys leased (fail-closed)");
    }
    let local_tag = "dstack-workload:current".to_string();
    let archive = "/tmp/dstack-workload.tar";
    let src = format!("docker://{encrypted_ref}@{image_digest}");
    tracing::info!("decrypting {src} → docker-archive:{archive}");

    // Decrypt into a docker-archive tar rather than straight into the daemon:
    // skopeo's bundled docker-daemon client pins API 1.41, which the dstack
    // host dockerd (min API 1.44) rejects. The tar avoids the daemon entirely;
    // `docker load` (newer CLI) then negotiates the API version correctly.
    let mut args = vec!["copy".to_string()];
    // Hand ocicrypt every leased private key; it picks the image's recipient.
    for kf in key_files {
        args.push("--decryption-key".to_string());
        args.push(kf.to_string_lossy().into_owned());
    }
    // Authenticate skopeo to the customer's private registry via the cloud seam
    // (GCP Artifact Registry over PGA today). None → anonymous pull.
    if let Some(auth) = crate::cloud::registry_auth_token() {
        args.push("--src-creds".to_string());
        args.push(format!("{}:{}", auth.username, auth.token));
    }
    args.push(src);
    args.push(format!("docker-archive:{archive}:{local_tag}"));

    let status = Command::new("skopeo")
        .args(&args)
        .status()
        .context("failed to exec skopeo copy (decrypt)")?;
    if !status.success() {
        anyhow::bail!(
            "skopeo decrypt failed (exit {}) — no leased key is the image's recipient, or unauthorized digest",
            status.code().unwrap_or(-1)
        );
    }

    // load the decrypted tar into the host docker daemon via the modern CLI
    let load = Command::new("docker")
        .args(["load", "-i", archive])
        .status()
        .context("failed to exec docker load")?;
    if !load.success() {
        anyhow::bail!("docker load failed (exit {})", load.code().unwrap_or(-1));
    }
    let _ = std::fs::remove_file(archive);
    Ok(local_tag)
}

pub fn write_compose(image_ref: &str) -> Result<()> {
    let content = format!(
        "services:\n  workload:\n    image: {image_ref}\n    restart: unless-stopped\n"
    );
    std::fs::write(COMPOSE_FILE, &content)
        .with_context(|| format!("failed to write compose file to {COMPOSE_FILE}"))?;
    tracing::info!("wrote compose file: {}", COMPOSE_FILE);
    Ok(())
}

pub fn compose_up() -> Result<()> {
    tracing::info!("running docker compose up");
    let status = Command::new("docker")
        .args(["compose", "-f", COMPOSE_FILE, "up", "-d"])
        .status()
        .context("failed to exec docker compose up")?;

    if !status.success() {
        anyhow::bail!(
            "docker compose up failed with exit code {}",
            status.code().unwrap_or(-1)
        );
    }
    Ok(())
}

pub fn compose_up_rolling() -> Result<()> {
    tracing::info!("running docker compose up (rolling update)");
    let status = Command::new("docker")
        .args([
            "compose", "-f", COMPOSE_FILE, "up", "-d", "--no-deps", "workload",
        ])
        .status()
        .context("failed to exec docker compose up rolling")?;

    if !status.success() {
        anyhow::bail!(
            "docker compose rolling update failed with exit code {}",
            status.code().unwrap_or(-1)
        );
    }
    Ok(())
}

pub fn compose_down() -> Result<()> {
    tracing::info!("running docker compose down");
    let status = Command::new("docker")
        .args(["compose", "-f", COMPOSE_FILE, "down"])
        .status()
        .context("failed to exec docker compose down")?;

    if !status.success() {
        anyhow::bail!(
            "docker compose down failed with exit code {}",
            status.code().unwrap_or(-1)
        );
    }
    Ok(())
}

pub fn is_workload_running() -> bool {
    let output = Command::new("docker")
        .args([
            "compose",
            "-f",
            COMPOSE_FILE,
            "ps",
            "--filter",
            "status=running",
            "--quiet",
        ])
        .output();

    match output {
        Ok(out) => {
            let stdout = String::from_utf8_lossy(&out.stdout);
            !stdout.trim().is_empty()
        }
        Err(_) => false,
    }
}
