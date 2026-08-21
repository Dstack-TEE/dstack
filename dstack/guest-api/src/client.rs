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

pub fn new_client_with_timeout(base_url: String, timeout: Duration) -> DefaultClient {
    DefaultClient::new(PrpcClient::new(base_url).with_request_timeout(timeout))
}
