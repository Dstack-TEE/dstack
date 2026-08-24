// SPDX-FileCopyrightText: © 2025 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

//! Types for the `dstack.guest.v1` API surface.
//!
//! Separate from [`crate::dstack`] because the two surfaces are separate
//! contracts, not versions of one type: v1's `GetKeyResponse` carries a public
//! key the v0 one has no field for, and its `InfoResponse` is flat where the v0
//! one nests a `tcb_info` document. Sharing a type between them would mean one
//! of the two lying about what the agent sent.
//!
//! Wire encoding follows the v0 convention: every protobuf `bytes` field is a
//! lowercase hex string in JSON, with a `decode_*` helper next to it. Fields
//! carrying JSON documents (`app_compose`, `vm_config`, `key_provider_info`,
//! `boottime_gpu_evidence`) are plain strings and are passed through unparsed.

use alloc::{string::String, vec::Vec};
use hex::FromHexError;
use serde::{Deserialize, Serialize};

#[cfg(feature = "borsh_schema")]
use borsh::BorshSchema;
#[cfg(feature = "borsh")]
use borsh::{BorshDeserialize, BorshSerialize};

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
    /// The derived private key, hex-encoded. 32 bytes for both algorithms.
    pub key: String,
    /// The corresponding public key, hex-encoded. SEC1 compressed (33 bytes)
    /// for secp256k1, raw (32 bytes) for ed25519.
    ///
    /// This is the exact byte string the chain's first link commits to, so a
    /// relying party never has to re-derive it from `key`.
    pub public_key: String,
    /// Two links, hex-encoded: the app root key's signature over the v1 key
    /// claim, then the KMS root key's signature over the app root public key.
    ///
    /// `docs/guest-api-v1.md` specifies the claim encoding and the verification
    /// steps. Verifying is the relying party's job; this SDK does not do it.
    pub signature_chain: Vec<String>,
}

impl GetKeyResponse {
    pub fn decode_key(&self) -> Result<Vec<u8>, FromHexError> {
        hex::decode(&self.key)
    }

    pub fn decode_public_key(&self) -> Result<Vec<u8>, FromHexError> {
        hex::decode(&self.public_key)
    }

    pub fn decode_signature_chain(&self) -> Result<Vec<Vec<u8>>, FromHexError> {
        self.signature_chain.iter().map(hex::decode).collect()
    }
}

/// Configuration for a v1 attestation request.
#[derive(Debug, bon::Builder, Serialize, Deserialize)]
#[cfg_attr(feature = "borsh", derive(BorshSerialize, BorshDeserialize))]
#[cfg_attr(feature = "borsh_schema", derive(BorshSchema))]
pub struct AttestConfig {
    /// The report data in hexadecimal format, at most 64 bytes once decoded
    #[builder(into)]
    pub report_data: String,
    /// Also return the boot-time GPU attestation evidence
    #[builder(default = false)]
    pub include_boottime_gpu_evidence: bool,
}

/// A versioned attestation.
#[derive(Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "borsh", derive(BorshSerialize, BorshDeserialize))]
#[cfg_attr(feature = "borsh_schema", derive(BorshSchema))]
pub struct AttestResponse {
    /// The attestation, hex-encoded
    pub attestation: String,
    /// Boot-time GPU attestation evidence. Empty unless the request asked for
    /// it and boot-time output exists, so absence is just the empty list.
    ///
    /// The same [`GpuEvidenceBundle`] shape `attest_gpu` returns, so one parser
    /// handles both. Dispatch on `format`: [`FORMAT_BOOTTIME`] is the record
    /// written at boot, [`FORMAT_ON_DEMAND`] is collected against a caller's
    /// nonce, and a verifier for one does not appraise the other.
    ///
    /// Each bundle's `evidence` decodes to the nvattest output byte for byte.
    /// That exactness is the contract: the only thing binding this evidence to
    /// the boot is sha256 over precisely those bytes, compared against
    /// `evidence_sha256` in the measured `gpu-attestation` event after
    /// replaying the runtime event log. Re-serializing the JSON first changes
    /// the digest.
    ///
    /// Not bound to `report_data`: nvattest ran at boot against its own nonce.
    #[serde(default)]
    pub boottime_gpu_evidence: Vec<GpuEvidenceBundle>,
}

impl AttestResponse {
    pub fn decode_attestation(&self) -> Result<Vec<u8>, FromHexError> {
        hex::decode(&self.attestation)
    }
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
    /// Hex-encoded opaque vendor-native evidence bytes
    pub evidence: String,
}

impl GpuEvidenceBundle {
    pub fn decode_evidence(&self) -> Result<Vec<u8>, FromHexError> {
        hex::decode(&self.evidence)
    }
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
    /// App ID, hex-encoded
    pub app_id: String,
    /// App name, from app-compose
    pub app_name: String,
    /// Compose hash, hex-encoded. sha256 over the verbatim bytes of
    /// `app_compose`; do not re-serialize before hashing.
    pub compose_hash: String,
    /// The app-compose document, exactly as deployed. Empty on the external
    /// surface unless the app set `public_tcbinfo`.
    #[serde(default)]
    pub app_compose: String,
    /// App instance ID, hex-encoded
    pub instance_id: String,
    /// Device ID, hex-encoded. Identifies the host machine, not this instance.
    pub device_id: String,
    /// OS image hash, hex-encoded
    #[serde(default)]
    pub os_image_hash: String,
    /// Aggregated measurement register value, hex-encoded
    #[serde(default)]
    pub mr_aggregated: String,
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

impl InfoResponse {
    pub fn decode_app_id(&self) -> Result<Vec<u8>, FromHexError> {
        hex::decode(&self.app_id)
    }

    pub fn decode_instance_id(&self) -> Result<Vec<u8>, FromHexError> {
        hex::decode(&self.instance_id)
    }

    pub fn decode_compose_hash(&self) -> Result<Vec<u8>, FromHexError> {
        hex::decode(&self.compose_hash)
    }
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
