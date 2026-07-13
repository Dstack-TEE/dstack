# Generating OpenAPI docs for pRPC services

This repository now ships a lightweight OpenAPI generator inside `ra-rpc`. It can
derive a specification (plus a Swagger UI test page) directly from the protobuf
descriptors that are already produced during the `prpc_build` step.

## 1. Enable the feature

Add the `openapi` feature when depending on `ra-rpc`:

```toml
[dependencies]
ra-rpc = { path = "../ra-rpc", features = ["openapi", "rocket"] }
```

The `rocket` feature is optional if you only need the JSON document and plan to
serve it through another framework.

## 2. Export the descriptor from your `*-rpc` crate

Every RPC crate already has access to `file_descriptor_set.bin`. Expose it so
that application binaries can include it:

```rust
pub const FILE_DESCRIPTOR_SET: &[u8] =
    include_bytes!(concat!(env!("OUT_DIR"), "/file_descriptor_set.bin"));
```

This repository now does that for all existing RPC crates.

## 3. Build and mount the document

```rust
use ra_rpc::openapi::{
    build_openapi_doc, DescriptorSource, DocumentInfo, ServiceConfig, SwaggerUiConfig,
};

fn openapi_doc() -> anyhow::Result<ra_rpc::openapi::OpenApiDoc> {
    let descriptor = dstack_guest_agent_rpc::FILE_DESCRIPTOR_SET;
    let sources = vec![DescriptorSource::new(
        descriptor,
        vec![
            // Mounts /prpc/Worker.Version (prefix is optional when you don't trim).
            ServiceConfig::new("Worker", "/prpc").with_method_prefix("Worker."),
        ],
    )];

    let info = DocumentInfo::new("Guest Worker API", env!("CARGO_PKG_VERSION"))
        .with_description("Auto generated from protobuf descriptors")
        .add_server("https://example.com/prpc");

    let ui = SwaggerUiConfig {
        title: "Guest Worker RPC".into(),
        ..Default::default()
    };

    build_openapi_doc(&sources, &info, ui)
}
```

Serving it through Rocket is one line:

```rust
let openapi = openapi_doc()?;
let rocket = ra_rpc::rocket_helper::mount_openapi_docs(rocket, openapi, "/rpc-docs");
```

* `GET /rpc-docs/openapi.json` returns the specification.
* `GET /rpc-docs/docs` serves a Swagger UI page backed by the same spec.

You can mount as many descriptor sources as you need (for example when the same
binary exposes both admin and user RPC stacks). Just add more `DescriptorSource`
entries that point to the relevant `FILE_DESCRIPTOR_SET` constants.
