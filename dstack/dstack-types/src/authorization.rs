// SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

//! Operations performed by the attested subject of an authorization request.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthorizationOperation {
    KmsBootstrap,
    KmsServe,
    KmsExportKeys,
    KmsImportKeys,
    AppGetKey,
    AppGetCert,
}

impl AuthorizationOperation {
    pub fn is_kms(self) -> bool {
        matches!(
            self,
            Self::KmsBootstrap | Self::KmsServe | Self::KmsExportKeys | Self::KmsImportKeys
        )
    }
}
