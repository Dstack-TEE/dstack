use anyhow::{Context, Result};
use sha2::{Digest, Sha256};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::time::sleep;

mod cloud;
mod config;
mod gua;
mod key_broker;
mod kms;
mod runner;
mod status;

use config::Config;
use key_broker::{KeyBrokerClient, SharedKeyBrokerClient};

fn derive_instance_id(app_id: &str) -> String {
    let hostname = std::env::var("HOSTNAME").unwrap_or_else(|_| "launcher".to_string());
    let mut hasher = Sha256::new();
    hasher.update(app_id.as_bytes());
    hasher.update(b":");
    hasher.update(hostname.as_bytes());
    hex::encode(hasher.finalize())
}

#[tokio::main]
async fn main() -> Result<()> {
    // rustls 0.23 needs an explicit crypto provider for the mTLS key-broker client.
    rustls::crypto::ring::default_provider().install_default().ok();
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive("launcher=info".parse().unwrap()),
        )
        .init();

    let config = Config::from_env().context("failed to load config")?;
    tracing::info!("starting launcher for app_id={}", config.app_id);

    // Shared, read-only-from-outside status. Created up-front and the status
    // HTTP server started immediately, so the SSH-free status endpoint is
    // observable through startup (before the workload is even decrypted).
    let running_digest = Arc::new(Mutex::new(String::new()));
    let lease_id = Arc::new(Mutex::new(String::new()));
    let bundle_seq = Arc::new(Mutex::new(0u64));
    let last_error = Arc::new(Mutex::new(None::<String>));
    tokio::spawn(status::serve(
        status::StatusState {
            app_id: config.app_id.clone(),
            workload_image: config.workload_image.clone(),
            running_digest: Arc::clone(&running_digest),
            lease_id: Arc::clone(&lease_id),
            bundle_seq: Arc::clone(&bundle_seq),
            last_error: Arc::clone(&last_error),
        },
        config.status_port,
    ));

    // KMS root CA — the trust anchor for verifying the key-broker's mTLS server
    // cert. GetMeta is public; the CA it returns is what the launcher pins.
    tracing::info!("fetching kms metadata (root CA) from {}", config.kms_url);
    let meta = kms::get_meta(&config.kms_url)
        .await
        .context("failed to get kms meta")?;
    if meta.ca_cert.trim().is_empty() {
        anyhow::bail!("KMS GetMeta returned an empty ca_cert (fail-closed)");
    }
    tracing::info!("kms root CA retrieved ({} bytes)", meta.ca_cert.len());

    // RA-TLS client identity from the local guest agent. Because the workload CVM
    // runs key_provider=kms, the guest agent already obtained KMS-signed keys at
    // boot; get_tls_key issues a KMS-CA-signed client cert carrying the app_info
    // extension. The key-broker verifies it against the KMS CA (WebPkiClientVerifier)
    // and reads app_id/compose_hash/os_image from the extension. No fallback.
    tracing::info!("requesting RA-TLS client cert from guest agent ({})", config.dstack_sock);
    let (client_key_pem, cert_chain) = gua::get_tls_key(&config.dstack_sock)
        .await
        .context("failed to get RA-TLS client cert from guest agent")?;
    let client_cert_pem = cert_chain.join("\n");
    tracing::info!("RA-TLS client cert acquired ({} certs in chain)", cert_chain.len());

    let key_broker = Arc::new(
        KeyBrokerClient::new(
            config.key_broker_url.clone(),
            &meta.ca_cert,
            &client_cert_pem,
            &client_key_pem,
        )
        .context("failed to build mtls key-broker client")?,
    );

    tracing::info!("fetching initial version from key-broker");
    let version = key_broker
        .get_version(&config.app_id)
        .await
        .context("failed to get version from key-broker")?;
    let image_digest = version.current_image_digest.clone();
    *bundle_seq.lock().unwrap() = version.bundle_seq;
    tracing::info!(
        "initial image_digest={} bundle_seq={}",
        image_digest,
        version.bundle_seq
    );

    let instance_id = derive_instance_id(&config.app_id);
    tracing::info!("instance_id={}", instance_id);

    tracing::info!("acquiring lease from key-broker");
    let lease_resp = key_broker
        .acquire_lease(
            &config.app_id,
            &instance_id,
            &config.compose_hash,
            &image_digest,
        )
        .await
        .context("failed to acquire lease")?;
    tracing::info!("lease acquired: slot={}", lease_resp.lease);
    *lease_id.lock().unwrap() = lease_resp.lease.clone();
    *running_digest.lock().unwrap() = image_digest.clone();

    // Persist the leased private keys to tmpfs; ocicrypt (native JWE) tries each
    // and decrypts with the one that is the image's recipient.
    let key_files = runner::write_keyset(&lease_resp.keyset).context("failed to write leased keyset")?;
    tracing::info!("leased keyset with {} key(s)", key_files.len());
    // Pull the authorized encrypted image by digest and decrypt via the keyset.
    let local_tag = runner::decrypt_image(&config.workload_image, &image_digest, &key_files)
        .context("failed to decrypt workload image")?;
    runner::write_compose(&local_tag).context("failed to write compose file")?;

    tracing::info!("starting decrypted workload image: {}", local_tag);
    runner::compose_up().context("failed to start workload containers")?;
    tracing::info!("workload containers started");

    // running_digest / lease_id were created up-front (for the status server)
    // and populated above; the background tasks below share the same Arcs.
    let last_renewal = Arc::new(Mutex::new(Instant::now()));

    let key_broker_renewal = Arc::clone(&key_broker);
    let lease_id_renewal = Arc::clone(&lease_id);
    let last_renewal_clone = Arc::clone(&last_renewal);
    let instance_id_renewal = instance_id.clone();
    let grace_period = config.grace_period;
    let lease_ttl = config.lease_ttl;
    let workload_image_renewal = config.workload_image.clone();
    let compose_hash_renewal = config.compose_hash.clone();
    let app_id_renewal = config.app_id.clone();

    let renewal_handle = tokio::spawn(async move {
        let interval = Duration::from_secs(lease_ttl / 3);
        loop {
            sleep(interval).await;

            let slot_id = lease_id_renewal.lock().unwrap().clone();
            match key_broker_renewal
                .renew_lease(&slot_id, &instance_id_renewal)
                .await
            {
                Ok(()) => {
                    tracing::info!("lease renewed for slot={}", slot_id);
                    *last_renewal_clone.lock().unwrap() = Instant::now();
                }
                Err(e) => {
                    tracing::warn!("lease renewal failed: {:#}", e);
                    let elapsed = last_renewal_clone.lock().unwrap().elapsed().as_secs();
                    if elapsed > grace_period {
                        tracing::error!(
                            "lease expired after {}s grace period, stopping business containers",
                            grace_period
                        );
                        if let Err(e) = runner::compose_down() {
                            tracing::error!("failed to stop containers: {:#}", e);
                        }
                    }
                }
            }
        }
    });

    let key_broker_update = Arc::clone(&key_broker);
    let running_digest_update = Arc::clone(&running_digest);
    let lease_id_update = Arc::clone(&lease_id);
    let bundle_seq_update = Arc::clone(&bundle_seq);
    let last_error_update = Arc::clone(&last_error);
    let instance_id_update = instance_id.clone();
    let app_id_update = config.app_id.clone();
    let workload_image_update = config.workload_image.clone();
    let compose_hash_update = config.compose_hash.clone();
    let poll_interval = config.poll_interval;

    let update_handle = tokio::spawn(async move {
        let interval = Duration::from_secs(poll_interval);
        loop {
            sleep(interval).await;

            let version_result = key_broker_update.get_version(&app_id_update).await;
            let version = match version_result {
                Ok(v) => {
                    *bundle_seq_update.lock().unwrap() = v.bundle_seq;
                    *last_error_update.lock().unwrap() = None;
                    v
                }
                Err(e) => {
                    tracing::warn!("failed to poll version: {:#}", e);
                    *last_error_update.lock().unwrap() = Some("version_poll_failed".to_string());
                    continue;
                }
            };

            let current_digest = running_digest_update.lock().unwrap().clone();
            if version.current_image_digest == current_digest {
                continue;
            }

            let new_digest = version.current_image_digest.clone();
            tracing::info!(
                "new image available: {} -> {}",
                current_digest,
                new_digest
            );

            let new_lease = match key_broker_update
                .acquire_lease(
                    &app_id_update,
                    &instance_id_update,
                    &compose_hash_update,
                    &new_digest,
                )
                .await
            {
                Ok(l) => l,
                Err(e) => {
                    tracing::warn!("failed to acquire lease for new image: {:#}", e);
                    continue;
                }
            };

            let new_key_files = match runner::write_keyset(&new_lease.keyset) {
                Ok(p) => p,
                Err(e) => {
                    tracing::warn!("failed to write new keyset: {:#}", e);
                    continue;
                }
            };
            let local_tag = match runner::decrypt_image(
                &workload_image_update,
                &new_digest,
                &new_key_files,
            ) {
                Ok(t) => t,
                Err(e) => {
                    tracing::warn!("failed to decrypt new image: {:#}", e);
                    continue;
                }
            };
            if let Err(e) = runner::write_compose(&local_tag) {
                tracing::warn!("failed to write compose for update: {:#}", e);
                continue;
            }

            if let Err(e) = runner::compose_up_rolling() {
                tracing::warn!("rolling update failed: {:#}", e);
                let rollback_ref = format!("{}@{}", workload_image_update, current_digest);
                if let Err(e) = runner::write_compose(&rollback_ref) {
                    tracing::error!("failed to write rollback compose: {:#}", e);
                    continue;
                }
                if let Err(e) = runner::compose_up_rolling() {
                    tracing::error!("rollback also failed: {:#}", e);
                }
                continue;
            }

            tracing::info!("waiting 60s for health check after rolling update");
            sleep(Duration::from_secs(60)).await;

            if runner::is_workload_running() {
                tracing::info!("health check passed, update to {} successful", new_digest);
                *running_digest_update.lock().unwrap() = new_digest;
                *lease_id_update.lock().unwrap() = new_lease.lease;
            } else {
                tracing::warn!("health check failed after update, rolling back to {}", current_digest);
                let rollback_ref = format!("{}@{}", workload_image_update, current_digest);
                if let Err(e) = runner::write_compose(&rollback_ref) {
                    tracing::error!("failed to write rollback compose: {:#}", e);
                    continue;
                }
                if let Err(e) = runner::compose_up_rolling() {
                    tracing::error!("rollback failed: {:#}", e);
                }
            }
        }
    });

    tokio::try_join!(renewal_handle, update_handle)
        .context("background task failed")?;

    Ok(())
}
