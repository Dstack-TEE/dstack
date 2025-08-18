// SPDX-FileCopyrightText: © 2025 Created-for-a-purpose <rachitchahar@gmail.com>
// SPDX-FileCopyrightText: © 2025 Daniel Sharifi <daniel.sharifi@nearone.org>
// SPDX-FileCopyrightText: © 2025 tuddman <tuddman@users.noreply.github.com>
//
// SPDX-License-Identifier: Apache-2.0

use dstack_sdk::dstack_client::DstackClient;
use dstack_sdk::ethereum::to_account;
use dstack_sdk_types::dstack::GetKeyResponse;

#[tokio::test]
async fn test_async_to_keypair() {
    let client = DstackClient::new(None);
    let result = client
        .get_key(Some("test".to_string()), None)
        .await
        .expect("get_key failed");

    let _: &GetKeyResponse = &result;
    let _wallet = to_account(&result).expect("to_account failed");
}
