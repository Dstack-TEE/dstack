// SPDX-FileCopyrightText: © 2024-2025 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

//! Key-prefix admission policy for the replicated stores.
//!
//! Every gateway in a cluster shares one app_id, so mTLS proves only that a peer is
//! *some* gateway of this deployment — not that it is well-behaved. A peer that has
//! been compromised, or that is simply running buggy code, can otherwise write any key
//! it likes into the replicated namespace, and every other node will accept and persist
//! it forever (the data map is never truncated).
//!
//! wavekv 2.0 enforces admission inside `merge`, which covers both sync directions;
//! a check on the HTTP handler would only see inbound requests, not the entries that
//! arrive in a response. Rejected entries also park the round's ack adoption (rule R1),
//! so a peer sending inadmissible data keeps re-offering it rather than having it
//! silently dropped.

use wavekv::{types::Entry, Admission, AdmissionPolicy};

use super::keys;

/// Which store a policy guards. The two stores have disjoint schemas.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Store {
    Persistent,
    Ephemeral,
}

/// Accepts only the key shapes this gateway actually defines.
#[derive(Debug, Clone, Copy)]
pub struct GatewaySchema {
    store: Store,
}

impl GatewaySchema {
    pub fn new(store: Store) -> Self {
        Self { store }
    }

    fn permits(&self, key: &str) -> bool {
        match self.store {
            Store::Persistent => {
                key.starts_with(keys::INST_PREFIX)
                    || key.starts_with(keys::NODE_PREFIX)
                    || key.starts_with(keys::CERT_PREFIX)
                    || key.starts_with(keys::DNS_CRED_PREFIX)
                    || key.starts_with(keys::PEER_ADDR_PREFIX)
                    || key == keys::DNS_CRED_DEFAULT
                    || key == keys::GLOBAL_CERTBOT_CONFIG
                    || key == keys::GLOBAL_ACME_CREDENTIALS
                    || key == keys::GLOBAL_ACME_ATTESTATION
                    || key == keys::GLOBAL_ACME_ROTATION_LOCK
            }
            Store::Ephemeral => {
                key.starts_with(keys::CONN_PREFIX)
                    || key.starts_with(keys::HANDSHAKE_PREFIX)
                    || key.starts_with(keys::LAST_SEEN_NODE_PREFIX)
                    || key.starts_with(keys::PEER_ADDR_PREFIX)
            }
        }
    }
}

impl AdmissionPolicy for GatewaySchema {
    fn admit(&self, entry: &Entry) -> Admission {
        if self.permits(&entry.key) {
            Admission::Accept
        } else {
            Admission::Reject {
                reason: "key is outside the gateway schema for this store",
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wavekv::types::Metadata;

    fn entry(key: &str) -> Entry {
        Entry::new(key.to_string(), Some(b"v".to_vec()), Metadata::new(1, 1, 0))
    }

    fn admits(store: Store, key: &str) -> bool {
        GatewaySchema::new(store).admit(&entry(key)) == Admission::Accept
    }

    #[test]
    fn every_key_the_gateway_writes_is_admissible() {
        for key in [
            keys::inst("abc"),
            keys::node_info(1),
            keys::node_status(1),
            keys::zt_domain_config("example.com"),
            keys::cert_data("example.com"),
            keys::cert_lock("example.com"),
            keys::cert_attestation_latest("example.com"),
            keys::cert_attestation_history("example.com", 42),
            keys::dns_cred("cred"),
            keys::peer_addr(1),
            keys::DNS_CRED_DEFAULT.to_string(),
            keys::GLOBAL_CERTBOT_CONFIG.to_string(),
            keys::GLOBAL_ACME_CREDENTIALS.to_string(),
            keys::GLOBAL_ACME_ATTESTATION.to_string(),
            keys::GLOBAL_ACME_ROTATION_LOCK.to_string(),
        ] {
            assert!(
                admits(Store::Persistent, &key),
                "the persistent schema must admit a key the gateway itself writes: {key}"
            );
        }

        for key in [
            keys::conn("inst", 1),
            keys::handshake("inst", 1),
            keys::last_seen_node(1, 2),
            keys::peer_addr(1),
        ] {
            assert!(
                admits(Store::Ephemeral, &key),
                "the ephemeral schema must admit a key the gateway itself writes: {key}"
            );
        }
    }

    #[test]
    fn keys_outside_the_schema_are_refused() {
        for key in ["", "random", "../escape", "global/", "certificate/x"] {
            assert!(!admits(Store::Persistent, key), "accepted {key}");
            assert!(!admits(Store::Ephemeral, key), "accepted {key}");
        }
    }

    #[test]
    fn the_two_stores_do_not_accept_each_others_keys() {
        assert!(!admits(Store::Ephemeral, &keys::inst("abc")));
        assert!(!admits(Store::Ephemeral, &keys::cert_data("example.com")));
        assert!(!admits(Store::Persistent, &keys::conn("inst", 1)));
        assert!(!admits(Store::Persistent, &keys::last_seen_node(1, 2)));
    }
}
