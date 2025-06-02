//! A CertBot client for requesting certificates from Let's Encrypt.
//!
//! This library provides a simple interface for requesting and managing SSL/TLS certificates
//! using the ACME protocol with Let's Encrypt as the Certificate Authority.
//!
//! # Features
//!
//! - Automatic certificate issuance and renewal
//! - DNS-01 challenge support (currently implemented for Cloudflare)
//! - Easy integration with existing Rust applications
//!
//! For more detailed information on the available methods and their usage, please refer
//! to the documentation of individual structs and functions.

pub use acme_client::AcmeClient;
pub use bot::{CertBot, CertBotConfig};
pub use dns01_client::Dns01Client;
pub use workdir::WorkDir;

mod acme_client;
mod bot;
mod dns01_client;
mod workdir;
