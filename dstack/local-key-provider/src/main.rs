// SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

mod crypto;
mod error;
mod gramine;
mod protocol;
mod provider;
mod server;

use std::{env, net::SocketAddr};

use error::ProviderError;
use provider::KeyProvider;
use server::Server;
use tracing::info;
use tracing_subscriber::EnvFilter;

const DEFAULT_ADDRESS: &str = "127.0.0.1:3443";

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), ProviderError> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| EnvFilter::new("local_key_provider=info")),
        )
        .init();

    let address = env::var("SEALING_PROVIDER_ADDR").unwrap_or_else(|_| DEFAULT_ADDRESS.into());
    let address: SocketAddr = address.parse().map_err(|error| {
        ProviderError::InvalidRequest(format!("invalid listen address: {error}"))
    })?;
    let provider = KeyProvider::from_env()?;

    info!("starting dstack local key provider");
    Server::new(address, provider).run().await
}
