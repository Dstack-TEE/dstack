// SPDX-FileCopyrightText: © 2024-2025 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

use std::{collections::HashSet, ops::Deref, path::PathBuf};

use dstack_types::AppCompose;
use figment::Figment;
use fs_err as fs;
use load_config::load_config;
use serde::{de::Error, Deserialize};

pub const DEFAULT_CONFIG: &str = include_str!("../dstack.toml");

pub fn load_config_figment(config_file: Option<&str>) -> Figment {
    load_config_figment_with_default(DEFAULT_CONFIG, config_file)
}

pub fn load_config_figment_with_default(
    default_config: &str,
    config_file: Option<&str>,
) -> Figment {
    load_config("dstack", default_config, config_file, true)
}

#[derive(Debug, Clone, Copy, Deserialize)]
pub struct BindAddr {
    pub port: u16,
}

#[derive(Debug, Clone)]
pub struct AppComposeWrapper {
    pub app_compose: AppCompose,
    pub raw: String,
}

impl Deref for AppComposeWrapper {
    type Target = AppCompose;

    fn deref(&self) -> &Self::Target {
        &self.app_compose
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct Config {
    pub keys_file: String,
    #[serde(deserialize_with = "deserialize_app_compose", flatten)]
    pub app_compose: AppComposeWrapper,
    pub sys_config_file: PathBuf,
    pub data_disks: HashSet<PathBuf>,
}

fn deserialize_app_compose<'de, D>(deserializer: D) -> Result<AppComposeWrapper, D::Error>
where
    D: serde::Deserializer<'de>,
{
    #[derive(Debug, Clone, Deserialize)]
    struct Config {
        compose_file: String,
    }

    let config = Config::deserialize(deserializer)?;
    let content = fs::read_to_string(&config.compose_file)
        .map_err(|e| D::Error::custom(format!("Failed to read compose file: {e}")))?;
    let app_compose = serde_json::from_str(&content)
        .map_err(|e| D::Error::custom(format!("Failed to parse compose file: {e}")))?;
    Ok(AppComposeWrapper {
        app_compose,
        raw: content,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    const DEFAULT: &str = r#"
[default.core]
keys_file = "/default/keys.json"
compose_file = "/default/compose.json"
sys_config_file = "/default/sys-config.json"
data_disks = ["/"]
"#;

    fn compose(extra: &str) -> String {
        format!(r#"{{"manifest_version":2,"name":"entry-test","runner":"docker-compose"{extra}}}"#)
    }

    fn leaf(directory: &TempDir, compose_body: &str) -> String {
        let compose_path = directory.path().join("app-compose.json");
        fs::write(&compose_path, compose_body).unwrap();
        let config_path = directory.path().join("guest.toml");
        fs::write(
            &config_path,
            format!(
                r#"[default.core]
keys_file = "/leaf/keys.json"
compose_file = "{}"
sys_config_file = "/leaf/sys-config.json"
data_disks = ["/", "/data"]
"#,
                compose_path.display()
            ),
        )
        .unwrap();
        config_path.display().to_string()
    }

    fn extract(default: &str, path: &str) -> Result<Config, figment::Error> {
        load_config_figment_with_default(default, Some(path))
            .focus("core")
            .extract()
    }

    #[test]
    fn explicit_leaf_overrides_embedded_defaults() {
        let directory = TempDir::new().unwrap();
        let path = leaf(&directory, &compose(""));
        let config = extract(DEFAULT, &path).unwrap();
        assert_eq!(config.keys_file, "/leaf/keys.json");
        assert_eq!(
            config.sys_config_file,
            PathBuf::from("/leaf/sys-config.json")
        );
        assert_eq!(
            config.data_disks,
            [PathBuf::from("/"), PathBuf::from("/data")].into()
        );
    }

    #[test]
    fn compose_raw_bytes_and_unknown_fields_are_preserved() {
        let directory = TempDir::new().unwrap();
        let body = compose(r#","future_optional":{"nested":true}"#);
        let path = leaf(&directory, &body);
        let config = extract(DEFAULT, &path).unwrap();
        assert_eq!(config.app_compose.raw, body);
        assert_eq!(config.app_compose.name, "entry-test");
        assert_eq!(config.app_compose.runner, "docker-compose");
    }

    #[test]
    fn absent_optional_compose_fields_use_documented_defaults() {
        let directory = TempDir::new().unwrap();
        let path = leaf(&directory, &compose(""));
        let config = extract(DEFAULT, &path).unwrap();
        assert!(!config.app_compose.public_logs);
        assert!(config.app_compose.public_tcbinfo);
        assert!(config.app_compose.secure_time);
        assert!(config.app_compose.snapshotter.is_none());
        assert!(config.app_compose.requirements.is_none());
    }

    #[test]
    fn missing_compose_file_fails_before_state_construction() {
        let directory = TempDir::new().unwrap();
        let config_path = directory.path().join("guest.toml");
        fs::write(
            &config_path,
            r#"[default.core]
keys_file = "/leaf/keys.json"
compose_file = "/definitely/missing/app-compose.json"
sys_config_file = "/leaf/sys-config.json"
data_disks = ["/"]
"#,
        )
        .unwrap();
        let error = extract(DEFAULT, &config_path.display().to_string()).unwrap_err();
        assert!(error.to_string().contains("Failed to read compose file"));
    }

    #[test]
    fn malformed_or_required_field_missing_compose_fails_closed() {
        for body in [
            "{not-json",
            r#"{"manifest_version":2,"name":"missing-runner"}"#,
        ] {
            let directory = TempDir::new().unwrap();
            let path = leaf(&directory, body);
            let error = extract(DEFAULT, &path).unwrap_err();
            assert!(error.to_string().contains("Failed to parse compose file"));
        }
    }
}
