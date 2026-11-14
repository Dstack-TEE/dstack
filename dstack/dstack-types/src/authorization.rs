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

    /// The `launchTicketHash` of `ticket`: `sha256(domain || ticket)`, with a
    /// domain per endpoint so that one ticket never admits both an app and a
    /// KMS instance.
    ///
    /// Shell equivalent: `printf 'dstack-launch-ticket/v1:%s' "$TICKET" | sha256sum`.
    pub fn launch_ticket_hash(self, ticket: &str) -> [u8; 32] {
        let domain = if self.is_kms() {
            "dstack-kms-launch-ticket/v1:"
        } else {
            "dstack-launch-ticket/v1:"
        };
        crate::sha256(format!("{domain}{ticket}").as_bytes())
    }
}

/// Shortest launch ticket a KMS accepts. Its hash is public, so a short ticket
/// can be recovered offline; length alone cannot prove entropy, so generate
/// tickets randomly.
pub const LAUNCH_TICKET_MIN_LEN: usize = 32;
/// Longest launch ticket a KMS accepts; sys-config must stay small.
pub const LAUNCH_TICKET_MAX_LEN: usize = 1024;

/// Refuse a ticket the KMS would refuse. Surrounding whitespace is refused
/// rather than trimmed: it changes the hash, so a pasted newline would
/// otherwise fail as an unknown ticket.
pub fn check_launch_ticket(ticket: &str) -> Result<(), String> {
    if !(LAUNCH_TICKET_MIN_LEN..=LAUNCH_TICKET_MAX_LEN).contains(&ticket.len()) {
        return Err(format!(
            "launch ticket must be {LAUNCH_TICKET_MIN_LEN} to {LAUNCH_TICKET_MAX_LEN} bytes, got {}",
            ticket.len()
        ));
    }
    if ticket.trim() != ticket {
        return Err("launch ticket has surrounding whitespace".into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Shared with vmm-cli's tests, which compute the hash the contracts allow.
    #[test]
    fn launch_ticket_hashes_are_domain_separated() {
        let ticket = "t".repeat(32);
        assert_eq!(
            hex::encode(AuthorizationOperation::AppGetCert.launch_ticket_hash(&ticket)),
            "8185a84114cfd5c0fb70e2233dee133cfa6467b58537ece8b27137828baabecc"
        );
        assert_eq!(
            hex::encode(AuthorizationOperation::KmsImportKeys.launch_ticket_hash(&ticket)),
            "a78c8aebf7e3ba7ead22d3e9e20827a53c89af8e61115a0e8c333b9e27f632ad"
        );
    }
}
