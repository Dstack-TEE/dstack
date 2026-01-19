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
    load_config("dstack", DEFAULT_CONFIG, config_file, true)
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
    #[serde(default)]
    pub pccs_url: Option<String>,
    pub simulator: Simulator,
    // List of disks to be shown in the dashboard
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

#[derive(Debug, Clone, Deserialize)]
pub struct Simulator {
    pub enabled: bool,
    pub attestation_file: String,
}
