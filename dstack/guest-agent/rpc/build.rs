// SPDX-FileCopyrightText: © 2024-2025 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

#![allow(clippy::expect_used)]

fn main() {
    prpc_build::configure()
        .out_dir(std::env::var_os("OUT_DIR").expect("OUT_DIR not set"))
        .mod_prefix("super::")
        .build_scale_ext(false)
        .disable_package_emission()
        .enable_serde_extension()
        .field_attribute(
            ".dstack_guest.GetQuoteResponse.attestation",
            "#[serde(skip_serializing_if = \"::prost::alloc::vec::Vec::is_empty\")]",
        )
        .disable_service_name_emission()
        .compile_dir("./proto")
        .expect("failed to compile proto files");
}
