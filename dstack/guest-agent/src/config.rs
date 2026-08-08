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
    use std::path::Path;
    use tempfile::TempDir;

    const DEFAULTS: &str = r#"
[default.core]
keys_file = "/embedded/keys.json"
compose_file = "/embedded/compose.json"
sys_config_file = "/embedded/sys-config.json"
data_disks = ["/"]
"#;

    fn minimal_compose(extra: &str) -> String {
        format!(
            r#"{{
  "manifest_version": 2,
  "name": "config-entry-test",
  "runner": "docker-compose",
  "docker_compose_file": "services: {{}}"{extra}
}}"#
        )
    }

    fn leaf_config(directory: &Path, compose: &Path, extra: &str) -> PathBuf {
        let leaf = directory.join("guest.toml");
        fs::write(
            &leaf,
            format!(
                r#"
[default.core]
keys_file = "{directory}/keys.json"
compose_file = "{compose}"
sys_config_file = "{directory}/sys-config.json"
data_disks = ["/", "{directory}/data"]
{extra}
"#,
                directory = directory.display(),
                compose = compose.display(),
            ),
        )
        .unwrap();
        leaf
    }

    fn extract(defaults: &str, leaf: &Path) -> Result<Config, Box<figment::Error>> {
        load_config_figment_with_default(defaults, leaf.to_str())
            .extract_inner("core")
            .map_err(Box::new)
    }

    #[test]
    fn explicit_leaf_overrides_embedded_defaults() {
        let temporary = TempDir::new().unwrap();
        let compose = temporary.path().join("compose.json");
        fs::write(&compose, minimal_compose("")).unwrap();
        let leaf = leaf_config(temporary.path(), &compose, "");

        let config = extract(DEFAULTS, &leaf).unwrap();

        assert_eq!(
            config.keys_file,
            temporary.path().join("keys.json").display().to_string()
        );
        assert_eq!(
            config.sys_config_file,
            temporary.path().join("sys-config.json")
        );
        assert!(config.data_disks.contains(&PathBuf::from("/")));
        assert!(config.data_disks.contains(&temporary.path().join("data")));
    }

    #[test]
    fn compose_raw_bytes_and_unknown_fields_are_preserved() {
        let temporary = TempDir::new().unwrap();
        let compose = temporary.path().join("compose.json");
        let raw = minimal_compose(",\n  \"future_optional_field\": {\"enabled\": true}");
        fs::write(&compose, &raw).unwrap();
        let leaf = leaf_config(temporary.path(), &compose, "");

        let config = extract(DEFAULTS, &leaf).unwrap();

        assert_eq!(config.app_compose.raw, raw);
        assert_eq!(config.app_compose.name, "config-entry-test");
    }

    #[test]
    fn absent_optional_compose_fields_use_documented_defaults() {
        let temporary = TempDir::new().unwrap();
        let compose = temporary.path().join("compose.json");
        fs::write(&compose, minimal_compose("")).unwrap();
        let leaf = leaf_config(temporary.path(), &compose, "");

        let config = extract(DEFAULTS, &leaf).unwrap();

        assert!(!config.app_compose.public_logs);
        assert!(!config.app_compose.public_sysinfo);
        assert!(config.app_compose.public_tcbinfo);
        assert!(!config.app_compose.kms_enabled);
        assert!(!config.app_compose.gateway_enabled);
        assert!(config.app_compose.secure_time);
        assert_eq!(config.app_compose.swap_size, 0);
    }

    #[test]
    fn missing_compose_file_fails_before_state_construction() {
        let temporary = TempDir::new().unwrap();
        let missing = temporary.path().join("missing-compose.json");
        let leaf = leaf_config(temporary.path(), &missing, "");

        let error = extract(DEFAULTS, &leaf).unwrap_err().to_string();

        assert!(error.contains("Failed to read compose file"), "{error}");
    }

    #[test]
    fn malformed_or_required_field_missing_compose_fails_closed() {
        let temporary = TempDir::new().unwrap();
        let compose = temporary.path().join("compose.json");
        let leaf = leaf_config(temporary.path(), &compose, "");

        fs::write(&compose, "{not-json").unwrap();
        let malformed = extract(DEFAULTS, &leaf).unwrap_err().to_string();
        assert!(
            malformed.contains("Failed to parse compose file"),
            "{malformed}"
        );

        fs::write(
            &compose,
            r#"{"manifest_version":2,"runner":"docker-compose"}"#,
        )
        .unwrap();
        let missing = extract(DEFAULTS, &leaf).unwrap_err().to_string();
        assert!(
            missing.contains("Failed to parse compose file"),
            "{missing}"
        );
        assert!(missing.contains("missing field `name`"), "{missing}");
    }
}
