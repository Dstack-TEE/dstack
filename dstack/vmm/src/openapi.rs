// SPDX-FileCopyrightText: © 2025 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

use anyhow::{Context, Result};
use ra_rpc::openapi::{
    build_openapi_doc as build_doc, DescriptorSource, DocumentInfo, OpenApiDoc, ServiceConfig,
    SwaggerUiConfig,
};

pub fn build_openapi_doc(app_version: &str) -> Result<OpenApiDoc> {
    let info = DocumentInfo::new("dstack-vmm RPC", app_version.to_string())
        .with_description(
            "Auto-generated OpenAPI spec for the pRPC surfaces exposed by dstack-vmm.",
        )
        .add_server("/");

    let sources = vec![
        DescriptorSource::new(
            dstack_vmm_rpc::FILE_DESCRIPTOR_SET,
            vec![ServiceConfig::new("Vmm", "/prpc")],
        ),
        DescriptorSource::new(
            guest_api::FILE_DESCRIPTOR_SET,
            vec![ServiceConfig::new("ProxiedGuestApi", "/guest")],
        ),
    ];

    let ui = SwaggerUiConfig {
        title: "dstack-vmm RPC Explorer".to_string(),
        ..Default::default()
    };

    build_doc(&sources, &info, ui).context("failed to build OpenAPI document")
}
