use anyhow::{bail, Result};

pub struct Config {
    pub kms_url: String,
    pub key_broker_url: String,
    pub app_id: String,
    pub workload_image: String,
    pub lease_ttl: u64,
    pub poll_interval: u64,
    pub grace_period: u64,
    pub compose_hash: String,
    pub status_port: u16,
    pub dstack_sock: String,
}

impl Config {
    pub fn from_env() -> Result<Self> {
        let kms_url = std::env::var("KMS_URL").unwrap_or_else(|_| "http://kms:8000".to_string());
        let key_broker_url =
            std::env::var("KEY_BROKER_URL").unwrap_or_else(|_| "https://key-broker:8002".to_string());
        let app_id = std::env::var("APP_ID").unwrap_or_default();
        if app_id.is_empty() {
            bail!("APP_ID is required");
        }
        let workload_image = std::env::var("WORKLOAD_IMAGE").unwrap_or_default();
        if workload_image.is_empty() {
            bail!("WORKLOAD_IMAGE is required");
        }
        let lease_ttl = std::env::var("LEASE_TTL")
            .unwrap_or_else(|_| "3600".to_string())
            .parse::<u64>()
            .unwrap_or(3600);
        let poll_interval = std::env::var("POLL_INTERVAL")
            .unwrap_or_else(|_| "30".to_string())
            .parse::<u64>()
            .unwrap_or(30);
        let grace_period = std::env::var("GRACE_PERIOD")
            .unwrap_or_else(|_| "3600".to_string())
            .parse::<u64>()
            .unwrap_or(3600);
        let compose_hash = std::env::var("COMPOSE_HASH").unwrap_or_default();
        let status_port = std::env::var("STATUS_PORT")
            .unwrap_or_else(|_| "9100".to_string())
            .parse::<u16>()
            .unwrap_or(9100);
        let dstack_sock =
            std::env::var("DSTACK_SOCK").unwrap_or_else(|_| "/var/run/dstack.sock".to_string());

        Ok(Self {
            kms_url,
            key_broker_url,
            app_id,
            workload_image,
            lease_ttl,
            poll_interval,
            grace_period,
            compose_hash,
            status_port,
            dstack_sock,
        })
    }
}
