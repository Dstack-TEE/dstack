// SPDX-FileCopyrightText: © 2025 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

//! A structural freeze on the v0.5.11 wire surface.
//!
//! `DstackGuest`, `Worker` and `Tappd` are closed: they are exactly what
//! v0.5.11 shipped, and every new capability belongs to `dstack.guest.v1`.
//! Reviewing that by eye is how three never-released methods and a handful of
//! fields accumulated on them between v0.5.11 and 0.6.0 in the first place.
//!
//! So this pins a digest of each frozen service's descriptor: its methods, and
//! the full field list of every message reachable from them. A *wire-compatible*
//! addition -- a new optional field, a new method -- changes the digest and
//! fails here, which is the point. Nothing else in the tree would notice.
//!
//! If this test fails, the fix is almost always to move the addition to
//! `agent_rpc_v1.proto`, not to update the digest.

use prost::Message;
use prost_types::{
    DescriptorProto, FileDescriptorProto, FileDescriptorSet, ServiceDescriptorProto,
};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;

fn descriptor_set() -> FileDescriptorSet {
    FileDescriptorSet::decode(dstack_guest_agent_rpc::FILE_DESCRIPTOR_SET)
        .expect("the embedded descriptor set must decode")
}

fn frozen_file(set: &FileDescriptorSet) -> &FileDescriptorProto {
    set.file
        .iter()
        .find(|file| file.package() == "dstack_guest")
        .expect("the frozen package must be present")
}

fn message<'a>(file: &'a FileDescriptorProto, name: &str) -> &'a DescriptorProto {
    file.message_type
        .iter()
        .find(|message| message.name() == name)
        .unwrap_or_else(|| panic!("frozen message {name} vanished"))
}

/// Render a message as one line per field: number, name, type, label.
///
/// Type and label are included so that changing a field's type or making it
/// repeated is caught, not just adding or removing one. Reserved ranges are
/// included too: dropping a `reserved` frees a number for silent reuse.
fn describe_message(file: &FileDescriptorProto, name: &str) -> String {
    let message = message(file, name);
    let mut out = format!("message {name}\n");
    let mut fields: Vec<String> = message
        .field
        .iter()
        .map(|field| {
            format!(
                "  {} {} type={:?} label={:?}\n",
                field.number(),
                field.name(),
                field.r#type(),
                field.label()
            )
        })
        .collect();
    fields.sort();
    out.extend(fields);
    for range in &message.reserved_range {
        out.push_str(&format!("  reserved {}..{}\n", range.start(), range.end()));
    }
    for name in &message.reserved_name {
        out.push_str(&format!("  reserved-name {name}\n"));
    }
    out
}

/// Render a service as its methods plus every message it can reach.
fn describe_service(file: &FileDescriptorProto, service: &ServiceDescriptorProto) -> String {
    let mut out = format!("service {}\n", service.name());
    let mut reachable = BTreeSet::new();
    for method in &service.method {
        out.push_str(&format!(
            "  rpc {}({}) returns ({})\n",
            method.name(),
            method.input_type(),
            method.output_type()
        ));
        for type_name in [method.input_type(), method.output_type()] {
            // `.dstack_guest.Foo` -> `Foo`; google.protobuf.Empty is not ours.
            if let Some(local) = type_name.strip_prefix(".dstack_guest.") {
                reachable.insert(local.to_string());
            }
        }
    }
    // One level of nesting is enough for this surface: the only message-typed
    // field on it is `HealthResponse.unhealthy`, which v1 owns now.
    for name in reachable.clone() {
        for field in &message(file, &name).field {
            if let Some(local) = field.type_name().strip_prefix(".dstack_guest.") {
                reachable.insert(local.to_string());
            }
        }
    }
    for name in &reachable {
        out.push_str(&describe_message(file, name));
    }
    out
}

fn digest(shape: &str) -> String {
    hex::encode(Sha256::digest(shape.as_bytes()))
}

/// The three frozen services, pinned.
///
/// Regenerate a digest only when you have confirmed against
/// `git show v0.5.11:guest-agent/rpc/proto/agent_rpc.proto` that the change is
/// comment-only or a `reserved` addition.
#[test]
fn the_frozen_services_match_their_pinned_shape() {
    let set = descriptor_set();
    let file = frozen_file(&set);
    let expected = [
        (
            "DstackGuest",
            "aa6b5814627a26284b12c180acb0eb13f91c3e57ce00952734fb358a729762f3",
        ),
        (
            "Worker",
            "e5e88ddbba3e9acd2ac68c6f5e3c99e394c1842be3d01395dd214972ada5bdc1",
        ),
        (
            "Tappd",
            "65c2e3b49f0ffbdcda4712f4b87b2ca4be386205e57e7956ddc56bec7616cffd",
        ),
    ];
    for (name, want) in expected {
        let service = file
            .service
            .iter()
            .find(|service| service.name() == name)
            .unwrap_or_else(|| panic!("frozen service {name} vanished"));
        let shape = describe_service(file, service);
        assert_eq!(
            digest(&shape),
            want,
            "the frozen {name} surface changed:\n{shape}"
        );
    }
}

/// The method lists, spelled out, so a failure above is readable without
/// reaching for the descriptor dump.
#[test]
fn the_frozen_services_expose_the_v0_5_11_methods() {
    let set = descriptor_set();
    let file = frozen_file(&set);
    let methods = |name: &str| -> Vec<String> {
        file.service
            .iter()
            .find(|service| service.name() == name)
            .unwrap_or_else(|| panic!("frozen service {name} vanished"))
            .method
            .iter()
            .map(|method| method.name().to_string())
            .collect()
    };
    assert_eq!(
        methods("DstackGuest"),
        [
            "GetTlsKey",
            "GetKey",
            "GetQuote",
            "Attest",
            "EmitEvent",
            "Info",
            "Sign",
            "Verify",
            "Version"
        ]
    );
    assert_eq!(
        methods("Worker"),
        ["Info", "Version", "GetAttestationForAppKey"]
    );
    assert_eq!(
        methods("Tappd"),
        [
            "DeriveKey",
            "DeriveK256Key",
            "TdxQuote",
            "RawQuote",
            "Info",
            "Version"
        ]
    );
}
