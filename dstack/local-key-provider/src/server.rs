// SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

use std::{net::SocketAddr, process, sync::Arc, time::Duration};

use tokio::{net::TcpListener, sync::Semaphore, time::timeout};
use tracing::{error, info, warn};

use crate::{
    error::ProviderError,
    protocol::{read_request, write_response},
    provider::KeyProvider,
};

const CONNECTION_LIMIT: usize = 32;
const IO_TIMEOUT: Duration = Duration::from_secs(30);

pub struct Server {
    address: SocketAddr,
    provider: Arc<KeyProvider>,
}

impl Server {
    pub fn new(address: SocketAddr, provider: KeyProvider) -> Self {
        Self {
            address,
            provider: Arc::new(provider),
        }
    }

    pub async fn run(self) -> Result<(), ProviderError> {
        let listener = TcpListener::bind(self.address).await?;
        let connections = Arc::new(Semaphore::new(CONNECTION_LIMIT));
        info!(address = %self.address, "local key provider listening");

        loop {
            let (mut socket, peer) = listener.accept().await?;
            let Ok(permit) = connections.clone().try_acquire_owned() else {
                warn!(%peer, "connection limit reached; rejecting client");
                continue;
            };
            let provider = self.provider.clone();

            tokio::spawn(async move {
                let _permit = permit;
                let result = async {
                    let request = timeout(IO_TIMEOUT, read_request(&mut socket))
                        .await
                        .map_err(|_| {
                            ProviderError::InvalidRequest("request read timed out".into())
                        })??;
                    let response = provider.provision(&request.quote).await?;
                    timeout(IO_TIMEOUT, write_response(&mut socket, &response))
                        .await
                        .map_err(|_| {
                            ProviderError::InvalidRequest("response write timed out".into())
                        })??;
                    Ok::<(), ProviderError>(())
                }
                .await;

                if let Err(error) = result {
                    if error.requires_restart() {
                        error!(%peer, %error, "fatal Gramine attestation error");
                        process::exit(1);
                    }
                    warn!(%peer, %error, "key provisioning request failed");
                }
            });
        }
    }
}
