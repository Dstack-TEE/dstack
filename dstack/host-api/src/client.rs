// SPDX-FileCopyrightText: © 2024 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

use crate::host_api_client::HostApiClient;
use http_client::prpc::PrpcClient;

pub type DefaultClient = HostApiClient<PrpcClient>;

pub fn new_client(base_url: String) -> DefaultClient {
    DefaultClient::new(PrpcClient::new(base_url))
}
