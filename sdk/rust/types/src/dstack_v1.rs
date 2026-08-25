// SPDX-FileCopyrightText: © 2025 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

//! Types for the `dstack.guest.v1` API surface.
//!
//! Separate from [`crate::dstack_v0`] because the two surfaces are separate
//! contracts, not versions of one type: v1's `GetKeyResponse` carries a public
//! key the v0 one has no field for, and its `InfoResponse` is flat where the v0
//! one nests a `tcb_info` document. Sharing a type between them would mean one
//! of the two lying about what the agent sent.
//!
//! Wire encoding follows the v0 convention: every protobuf `bytes` field is a
//! lowercase hex string in JSON. The Rust types do not: a `bytes` field is a
//! `Vec<u8>`, and the hex lives in the serde layer. v0 exposed the hex string
//! and a `decode_*` helper beside it, which made the wrong call the easy one --
//! `public_key` handed straight to a claim builder is 66 ASCII characters, not
//! a 33-byte key, and nothing objects until the chain fails to verify. Typing
//! the field as bytes makes that mistake unspellable.
//!
//! Fields carrying JSON documents (`app_compose`, `vm_config`,
//! `key_provider_info`, `boottime_gpu_evidence`) are plain strings and are
//! passed through unparsed.

use alloc::{string::String, vec::Vec};
use serde::{Deserialize, Serialize};

#[cfg(feature = "borsh_schema")]
use borsh::BorshSchema;
#[cfg(feature = "borsh")]
use borsh::{BorshDeserialize, BorshSerialize};

/// Serde for protobuf `repeated bytes`: a JSON array of lowercase hex strings.
///
/// [`hex::serde`] covers a single `bytes` field, but there is no serde
/// attribute that composes it element-wise over a `Vec`, so the repeated case
/// needs its own module. Deserialization is all-or-nothing: one malformed
/// element fails the whole field rather than silently yielding a short chain.
mod hex_vec {
    use alloc::{string::String, vec::Vec};
    use serde::{de::Error as _, Deserialize, Deserializer, Serialize, Serializer};

    pub fn serialize<S: Serializer>(items: &[Vec<u8>], serializer: S) -> Result<S::Ok, S::Error> {
        let encoded: Vec<String> = items.iter().map(hex::encode).collect();
        encoded.serialize(serializer)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Vec<Vec<u8>>, D::Error> {
        let encoded = Vec::<String>::deserialize(deserializer)?;
        encoded
            .iter()
            .map(hex::decode)
            .collect::<Result<Vec<Vec<u8>>, _>>()
            .map_err(D::Error::custom)
    }
}

/// Configuration for a certificate issuance request.
#[derive(Debug, bon::Builder, Serialize, Deserialize)]
#[cfg_attr(feature = "borsh", derive(BorshSerialize, BorshDeserialize))]
#[cfg_attr(feature = "borsh_schema", derive(BorshSchema))]
pub struct IssueCertConfig {
    /// The subject name for the certificate
    #[builder(into, default = String::new())]
    pub subject: String,
    /// Alternative names for the certificate
    #[builder(default = Vec::new())]
    pub alt_names: Vec<String>,
    /// Include the attestation quote in the certificate (RA-TLS)
    #[builder(default = false)]
    pub usage_ra_tls: bool,
    /// Whether the certificate may be used for server authentication
    #[builder(default = true)]
    pub usage_server_auth: bool,
    /// Whether the certificate may be used for client authentication
    #[builder(default = false)]
    pub usage_client_auth: bool,
    /// Include app info in the certificate
    #[builder(default = false)]
    pub with_app_info: bool,
    /// Validity start, seconds since the UNIX epoch
    #[serde(skip_serializing_if = "Option::is_none")]
    pub not_before: Option<u64>,
    /// Validity end, seconds since the UNIX epoch
    #[serde(skip_serializing_if = "Option::is_none")]
    pub not_after: Option<u64>,
}

/// A freshly issued certificate and the key that backs it.
#[derive(Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "borsh", derive(BorshSerialize, BorshDeserialize))]
#[cfg_attr(feature = "borsh_schema", derive(BorshSchema))]
pub struct IssueCertResponse {
    /// The private key the agent generated for this certificate, PEM-encoded.
    ///
    /// Fresh per call and not derived from the app identity: two identical
    /// requests produce two unrelated keys. [`super::dstack_v1`]'s `get_key` is
    /// the method that derives a stable, attestable key.
    pub key: String,
    /// The certificate chain, leaf first, each entry PEM-encoded
    pub certificate_chain: Vec<String>,
}

/// A derived application key with its signature chain.
#[derive(Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "borsh", derive(BorshSerialize, BorshDeserialize))]
#[cfg_attr(feature = "borsh_schema", derive(BorshSchema))]
pub struct GetKeyResponse {
    /// The derived private key. 32 bytes for both algorithms.
    #[serde(with = "hex::serde")]
    pub key: Vec<u8>,
    /// The corresponding public key. SEC1 compressed (33 bytes) for secp256k1,
    /// raw (32 bytes) for ed25519.
    ///
    /// This is the exact byte string the chain's first link commits to, so a
    /// relying party never has to re-derive it from `key`.
    #[serde(with = "hex::serde")]
    pub public_key: Vec<u8>,
    /// Two links: the app root key's signature over the v1 key claim, then the
    /// KMS root key's signature over the app root public key.
    ///
    /// `docs/guest-api-v1.md` specifies the claim encoding and the verification
    /// steps. Verifying is the relying party's job; this SDK does not do it.
    #[serde(with = "hex_vec")]
    pub signature_chain: Vec<Vec<u8>>,
}

/// Configuration for a v1 attestation request.
#[derive(Debug, bon::Builder, Serialize, Deserialize)]
#[cfg_attr(feature = "borsh", derive(BorshSerialize, BorshDeserialize))]
#[cfg_attr(feature = "borsh_schema", derive(BorshSchema))]
pub struct AttestConfig {
    /// The report data, at most 64 bytes. Hex-encoded on the wire.
    #[builder(into)]
    #[serde(with = "hex::serde")]
    pub report_data: Vec<u8>,
    /// Also return the boot-time GPU attestation evidence
    #[builder(default = false)]
    pub include_boottime_gpu_evidence: bool,
}

/// A versioned attestation.
#[derive(Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "borsh", derive(BorshSerialize, BorshDeserialize))]
#[cfg_attr(feature = "borsh_schema", derive(BorshSchema))]
pub struct AttestResponse {
    /// The attestation
    #[serde(with = "hex::serde")]
    pub attestation: Vec<u8>,
    /// Boot-time GPU attestation evidence. Empty unless the request asked for
    /// it and boot-time output exists, so absence is just the empty list.
    ///
    /// The same [`GpuEvidenceBundle`] shape `attest_gpu` returns, so one parser
    /// handles both. Dispatch on `format`: [`FORMAT_BOOTTIME`] is the record
    /// written at boot, [`FORMAT_ON_DEMAND`] is collected against a caller's
    /// nonce, and a verifier for one does not appraise the other.
    ///
    /// Each bundle's `evidence` is the nvattest output byte for byte. That
    /// exactness is the contract: the only thing binding this evidence to the
    /// boot is sha256 over precisely those bytes, compared against
    /// `evidence_sha256` in the measured `gpu-attestation` event after
    /// replaying the runtime event log. Re-serializing the JSON first changes
    /// the digest.
    ///
    /// Not bound to `report_data`: nvattest ran at boot against its own nonce.
    #[serde(default)]
    pub boottime_gpu_evidence: Vec<GpuEvidenceBundle>,
}

/// Vendor-native GPU evidence collected on demand.
#[derive(Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "borsh", derive(BorshSerialize, BorshDeserialize))]
#[cfg_attr(feature = "borsh_schema", derive(BorshSchema))]
pub struct AttestGpuResponse {
    /// Select a verifier by vendor and format, then check the signature,
    /// certificate chain, measurements, and the nonce embedded in the evidence.
    pub bundles: Vec<GpuEvidenceBundle>,
}

/// Evidence collected on demand, against a caller-chosen nonce.
pub const FORMAT_ON_DEMAND: &str = "nvidia-nvattest-collect-evidence-json-v1";

/// The evidence record nvattest wrote at boot.
pub const FORMAT_BOOTTIME: &str = "nvidia-nvattest-boottime-json-v1";

/// One vendor's evidence.
///
/// Shared by `attest_gpu` and `attest`'s boot-time evidence so a consumer
/// writes one parser for both; `(vendor, format)` says which is which.
#[derive(Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "borsh", derive(BorshSerialize, BorshDeserialize))]
#[cfg_attr(feature = "borsh_schema", derive(BorshSchema))]
pub struct GpuEvidenceBundle {
    /// Stable GPU vendor identifier, for example `nvidia`
    pub vendor: String,
    /// Vendor-specific evidence format and version
    pub format: String,
    /// Opaque vendor-native evidence bytes, verbatim as the vendor tool emitted
    /// them. Hex-encoded on the wire.
    #[serde(with = "hex::serde")]
    pub evidence: Vec<u8>,
}

/// Application identity and configuration.
///
/// Identity and configuration only, never attestation. The measurement
/// registers and the event log are deliberately absent: they are attestation
/// data, and this response arrives over a local socket with nothing vouching
/// for it. Ask `attest` and verify.
///
/// `mr_aggregated`, `os_image_hash` and `compose_hash` are the exception --
/// they identify *which* application and image this is, which is the question
/// `info` answers. They are still unattested.
#[derive(Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "borsh", derive(BorshSerialize, BorshDeserialize))]
#[cfg_attr(feature = "borsh_schema", derive(BorshSchema))]
pub struct InfoResponse {
    /// App ID
    #[serde(with = "hex::serde")]
    pub app_id: Vec<u8>,
    /// App name, from app-compose
    pub app_name: String,
    /// Compose hash: sha256 over the verbatim bytes of `app_compose`; do not
    /// re-serialize before hashing.
    #[serde(with = "hex::serde")]
    pub compose_hash: Vec<u8>,
    /// The app-compose document, exactly as deployed. Empty on the external
    /// surface unless the app set `public_tcbinfo`.
    #[serde(default)]
    pub app_compose: String,
    /// App instance ID
    #[serde(with = "hex::serde")]
    pub instance_id: Vec<u8>,
    /// Device ID. Identifies the host machine, not this instance.
    #[serde(with = "hex::serde")]
    pub device_id: Vec<u8>,
    /// OS image hash
    #[serde(default, with = "hex::serde")]
    pub os_image_hash: Vec<u8>,
    /// Aggregated measurement register value
    #[serde(default, with = "hex::serde")]
    pub mr_aggregated: Vec<u8>,
    /// The VM's hardware configuration, as a JSON document produced by the VMM
    #[serde(default)]
    pub vm_config: String,
    /// The key provider that supplied this app's keys, as a JSON document
    #[serde(default)]
    pub key_provider_info: String,
    /// Cloud provider sys_vendor
    #[serde(default)]
    pub cloud_vendor: String,
    /// Cloud provider product_name
    #[serde(default)]
    pub cloud_product: String,
}

/// The guest agent version.
#[derive(Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "borsh", derive(BorshSerialize, BorshDeserialize))]
#[cfg_attr(feature = "borsh_schema", derive(BorshSchema))]
pub struct VersionResponse {
    /// dstack version
    pub version: String,
    /// Git revision
    pub rev: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::{string::ToString, vec, vec::Vec};

    #[test]
    fn signature_chain_round_trips_through_hex() {
        let response = GetKeyResponse {
            key: vec![0x01; 32],
            public_key: vec![0x02; 33],
            signature_chain: vec![vec![0xaa, 0xbb], vec![0xcc]],
        };
        let json = serde_json::to_string(&response).expect("serializes");
        assert!(json.contains(r#""signature_chain":["aabb","cc"]"#));

        let decoded: GetKeyResponse = serde_json::from_str(&json).expect("deserializes");
        assert_eq!(decoded.key, response.key);
        assert_eq!(decoded.public_key, response.public_key);
        assert_eq!(decoded.signature_chain, response.signature_chain);
    }

    #[test]
    fn signature_chain_accepts_an_empty_list() {
        let json = r#"{"key":"01","public_key":"02","signature_chain":[]}"#;
        let decoded: GetKeyResponse = serde_json::from_str(json).expect("deserializes");
        assert!(decoded.signature_chain.is_empty());

        let reencoded = serde_json::to_string(&decoded).expect("serializes");
        assert!(reencoded.contains(r#""signature_chain":[]"#));
    }

    #[test]
    fn signature_chain_rejects_a_malformed_element() {
        let json = r#"{"key":"01","public_key":"02","signature_chain":["aabb","zz"]}"#;
        let err = serde_json::from_str::<GetKeyResponse>(json)
            .expect_err("a non-hex element fails the whole field");
        assert!(err.to_string().contains("Invalid character"), "{err}");
    }

    #[test]
    fn report_data_is_hex_on_the_wire() {
        let config = AttestConfig::builder()
            .report_data(vec![0xde, 0xad, 0xbe, 0xef])
            .build();
        let json = serde_json::to_string(&config).expect("serializes");
        assert!(json.contains(r#""report_data":"deadbeef""#), "{json}");
    }

    #[test]
    fn info_identity_fields_decode_to_bytes() {
        let json = r#"{
            "app_id": "0011",
            "app_name": "demo",
            "compose_hash": "2233",
            "instance_id": "4455",
            "device_id": "6677"
        }"#;
        let info: InfoResponse = serde_json::from_str(json).expect("deserializes");
        assert_eq!(info.app_id, vec![0x00, 0x11]);
        assert_eq!(info.compose_hash, vec![0x22, 0x33]);
        assert_eq!(info.instance_id, vec![0x44, 0x55]);
        assert_eq!(info.device_id, vec![0x66, 0x77]);
        assert_eq!(info.os_image_hash, Vec::<u8>::new());
        assert_eq!(info.mr_aggregated, Vec::<u8>::new());
    }
}
