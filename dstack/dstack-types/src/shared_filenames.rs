// SPDX-FileCopyrightText: © 2025 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

pub const APP_COMPOSE: &str = "app-compose.json";
pub const APP_KEYS: &str = ".appkeys.json";
pub const SYS_CONFIG: &str = ".sys-config.json";
pub const USER_CONFIG: &str = ".user-config";
pub const ENCRYPTED_ENV: &str = ".encrypted-env";
pub const DECRYPTED_ENV: &str = ".decrypted-env";
pub const DECRYPTED_ENV_JSON: &str = ".decrypted-env.json";
pub const INSTANCE_INFO: &str = ".instance_info";
pub const HOST_SHARED_DIR: &str = "/dstack/.host-shared";
pub const HOST_SHARED_DIR_NAME: &str = ".host-shared";
pub const HOST_SHARED_DISK_LABEL: &str = "DSTACKSHR";

/// Environment variable overriding the host-shared directory location.
pub const HOST_SHARED_DIR_ENV: &str = "DSTACK_HOST_SHARED_DIR";

/// Directory the guest reads host-shared files from.
///
/// `dstack-util setup` runs before `/dstack` is bind-mounted to the work dir,
/// so it exports [`HOST_SHARED_DIR_ENV`] pointing at the real copy directory.
/// Everything that reads host-shared files (including the attestation quote
/// path) honors it, falling back to the canonical [`HOST_SHARED_DIR`].
pub fn host_shared_dir() -> std::path::PathBuf {
    std::env::var_os(HOST_SHARED_DIR_ENV)
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| std::path::PathBuf::from(HOST_SHARED_DIR))
}

pub mod compat_v3 {
    pub const SYS_CONFIG: &str = "config.json";
    pub const ENCRYPTED_ENV: &str = "encrypted-env";
}
