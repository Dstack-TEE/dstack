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

pub mod compat_v3 {
    pub const SYS_CONFIG: &str = "config.json";
    pub const ENCRYPTED_ENV: &str = "encrypted-env";
}
