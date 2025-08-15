#![no_std]

// SPDX-FileCopyrightText: © 2025 Daniel Sharifi <danielsharifi@outlook.com>
//
// SPDX-License-Identifier: Apache-2.0

extern crate alloc;

use alloc::string::String;
use dstack_sdk_types::tappd::DeriveKeyResponse;

#[test]
fn test_no_std_compatibility() {
    // Create a mock response (this would normally come from the service)
    let response = DeriveKeyResponse {
        key: String::from(
            "-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQg...
-----END PRIVATE KEY-----",
        ),
        certificate_chain: alloc::vec![],
    };

    // We don't care if it fails to parse (invalid key), just that it compiles and runs in no_std
    let _ = response.decode_key();
}
