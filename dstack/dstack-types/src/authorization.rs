// SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

//! Operations performed by the attested subject of an authorization request.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthorizationOperation {
    Bootstrap,
    Serve,
    ExportKmsKeys,
    ImportKmsKeys,
    GetAppKey,
    GetAppCert,
}

impl AuthorizationOperation {
    pub fn is_kms(self) -> bool {
        matches!(
            self,
            Self::Bootstrap | Self::Serve | Self::ExportKmsKeys | Self::ImportKmsKeys
        )
    }
}
