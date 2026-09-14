// SPDX-FileCopyrightText: © 2024-2025 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

//! A CertBot client for requesting certificates from Let's Encrypt.
//!
//! This library provides a simple interface for requesting and managing SSL/TLS certificates
//! using the ACME protocol with Let's Encrypt as the Certificate Authority.
//!
//! # Features
//!
//! - Automatic certificate issuance and renewal
//! - DNS-01 challenge support (currently implemented for Cloudflare)
//! - DNS-PERSIST-01 challenge support, which needs no DNS provider credential
//! - Easy integration with existing Rust applications
//!
//! For more detailed information on the available methods and their usage, please refer
//! to the documentation of individual structs and functions.

pub use acme_client::{
    advisory_dns_wait, required_dns_records, AcmeAccount, AcmeClient, ChallengeKind,
    RequiredRecord, ValidationMethod,
};
pub use bot::{read_pubkey, CertBot, CertBotConfig};
pub use dns01_client::Dns01Client;
pub use dns_persist::{resolve_issuer_domain_name, LETS_ENCRYPT_ISSUER_DOMAIN_NAME};
pub use workdir::WorkDir;

mod acme_client;
mod bot;
mod dns01_client;
mod dns_persist;
mod http_client;
mod workdir;
