// SPDX-FileCopyrightText: © 2024 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

use crate::guest_api_client::GuestApiClient;
use http_client::prpc::PrpcClient;
use std::time::Duration;

pub type DefaultClient = GuestApiClient<PrpcClient>;

/// Largest response the host will read from a guest agent.
///
/// The peer is a tenant's CVM, which the host does not trust: without a bound,
/// one guest answering `SysInfo` or `ListContainers` with an endless body takes
/// the VMM down, and the VMM is the control plane for every other tenant on the
/// machine. Sized well above anything these methods legitimately return.
pub const MAX_RESPONSE_BYTES: usize = 16 * 1024 * 1024;

pub fn new_client(base_url: String) -> DefaultClient {
    DefaultClient::new(PrpcClient::new(base_url).with_max_response_bytes(MAX_RESPONSE_BYTES))
}

/// Both guards, because they defend against the same untrusted peer: the
/// timeout covers a guest that answers slowly, the bound covers one that
/// answers endlessly, and a caller wanting one has no reason to drop the other.
pub fn new_client_with_timeout(base_url: String, timeout: Duration) -> DefaultClient {
    DefaultClient::new(
        PrpcClient::new(base_url)
            .with_max_response_bytes(MAX_RESPONSE_BYTES)
            .with_request_timeout(timeout),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The VMM reaches a tenant's guest agent through the timeout constructor,
    /// so a bound that only the plain one applies protects nothing.
    #[test]
    fn the_timeout_client_is_still_bounded() {
        let client = PrpcClient::new("vsock://3:8000/api".to_string())
            .with_max_response_bytes(MAX_RESPONSE_BYTES)
            .with_request_timeout(Duration::from_secs(1));
        assert_eq!(client.max_response_bytes(), Some(MAX_RESPONSE_BYTES));
    }
}
