// SPDX-FileCopyrightText: © 2025 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: BUSL-1.1

//! TPM 2.0 data types

use anyhow::{bail, Result};

use super::constants::*;
use super::marshal::*;

/// TPM2B_DIGEST - Variable length digest
#[derive(Debug, Clone, Default)]
pub struct Tpm2bDigest {
    pub buffer: Vec<u8>,
}

impl Tpm2bDigest {
    pub fn new(data: Vec<u8>) -> Self {
        Self { buffer: data }
    }

    pub fn empty() -> Self {
        Self { buffer: Vec::new() }
    }
}

impl Marshal for Tpm2bDigest {
    fn marshal(&self, buf: &mut CommandBuffer) {
        buf.put_tpm2b(&self.buffer);
    }
}

impl Unmarshal for Tpm2bDigest {
    fn unmarshal(buf: &mut ResponseBuffer) -> Result<Self> {
        Ok(Self {
            buffer: buf.get_tpm2b()?,
        })
    }
}

/// TPM2B_DATA - Variable length data
#[derive(Debug, Clone, Default)]
pub struct Tpm2bData {
    pub buffer: Vec<u8>,
}

impl Tpm2bData {
    pub fn new(data: Vec<u8>) -> Self {
        Self { buffer: data }
    }

    pub fn empty() -> Self {
        Self { buffer: Vec::new() }
    }
}

impl Marshal for Tpm2bData {
    fn marshal(&self, buf: &mut CommandBuffer) {
        buf.put_tpm2b(&self.buffer);
    }
}

impl Unmarshal for Tpm2bData {
    fn unmarshal(buf: &mut ResponseBuffer) -> Result<Self> {
        Ok(Self {
            buffer: buf.get_tpm2b()?,
        })
    }
}

/// TPM2B_SENSITIVE_DATA - Sensitive data for sealing
#[derive(Debug, Clone, Default)]
pub struct Tpm2bSensitiveData {
    pub buffer: Vec<u8>,
}

impl Tpm2bSensitiveData {
    pub fn new(data: Vec<u8>) -> Self {
        Self { buffer: data }
    }

    pub fn empty() -> Self {
        Self { buffer: Vec::new() }
    }
}

impl Marshal for Tpm2bSensitiveData {
    fn marshal(&self, buf: &mut CommandBuffer) {
        buf.put_tpm2b(&self.buffer);
    }
}

/// TPM2B_AUTH - Authorization value
#[derive(Debug, Clone, Default)]
pub struct Tpm2bAuth {
    pub buffer: Vec<u8>,
}

impl Tpm2bAuth {
    pub fn new(data: Vec<u8>) -> Self {
        Self { buffer: data }
    }

    pub fn empty() -> Self {
        Self { buffer: Vec::new() }
    }
}

impl Marshal for Tpm2bAuth {
    fn marshal(&self, buf: &mut CommandBuffer) {
        buf.put_tpm2b(&self.buffer);
    }
}

impl Unmarshal for Tpm2bAuth {
    fn unmarshal(buf: &mut ResponseBuffer) -> Result<Self> {
        Ok(Self {
            buffer: buf.get_tpm2b()?,
        })
    }
}

/// TPM2B_NONCE - Nonce value
pub type Tpm2bNonce = Tpm2bDigest;

/// TPM2B_MAX_NV_BUFFER - NV buffer
#[derive(Debug, Clone, Default)]
pub struct Tpm2bMaxNvBuffer {
    pub buffer: Vec<u8>,
}

impl Tpm2bMaxNvBuffer {
    pub fn new(data: Vec<u8>) -> Self {
        Self { buffer: data }
    }
}

impl Marshal for Tpm2bMaxNvBuffer {
    fn marshal(&self, buf: &mut CommandBuffer) {
        buf.put_tpm2b(&self.buffer);
    }
}

impl Unmarshal for Tpm2bMaxNvBuffer {
    fn unmarshal(buf: &mut ResponseBuffer) -> Result<Self> {
        Ok(Self {
            buffer: buf.get_tpm2b()?,
        })
    }
}

/// TPMS_PCR_SELECTION - PCR selection for a single hash algorithm
#[derive(Debug, Clone)]
pub struct TpmsPcrSelection {
    pub hash: TpmAlgId,
    pub pcr_select: Vec<u8>, // Bitmap of selected PCRs
}

impl TpmsPcrSelection {
    pub fn new(hash: TpmAlgId, pcrs: &[u32]) -> Self {
        // Calculate required size (at least 3 bytes for PCR 0-23)
        let max_pcr = pcrs.iter().max().copied().unwrap_or(0);
        let size = ((max_pcr / 8) + 1).max(3) as usize;
        let mut pcr_select = vec![0u8; size];

        for &pcr in pcrs {
            let byte_idx = (pcr / 8) as usize;
            let bit_idx = pcr % 8;
            if byte_idx < pcr_select.len() {
                pcr_select[byte_idx] |= 1 << bit_idx;
            }
        }

        Self { hash, pcr_select }
    }

    pub fn sha256(pcrs: &[u32]) -> Self {
        Self::new(TpmAlgId::Sha256, pcrs)
    }
}

impl Marshal for TpmsPcrSelection {
    fn marshal(&self, buf: &mut CommandBuffer) {
        buf.put_u16(self.hash.to_u16());
        buf.put_u8(self.pcr_select.len() as u8);
        buf.put_bytes(&self.pcr_select);
    }
}

impl Unmarshal for TpmsPcrSelection {
    fn unmarshal(buf: &mut ResponseBuffer) -> Result<Self> {
        let hash_alg = buf.get_u16()?;
        let hash = TpmAlgId::from_u16(hash_alg)
            .ok_or_else(|| anyhow::anyhow!("unknown hash algorithm: 0x{:04x}", hash_alg))?;
        let size = buf.get_u8()? as usize;
        let pcr_select = buf.get_bytes(size)?;
        Ok(Self { hash, pcr_select })
    }
}

/// TPML_PCR_SELECTION - List of PCR selections
#[derive(Debug, Clone, Default)]
pub struct TpmlPcrSelection {
    pub pcr_selections: Vec<TpmsPcrSelection>,
}

impl TpmlPcrSelection {
    pub fn new(selections: Vec<TpmsPcrSelection>) -> Self {
        Self {
            pcr_selections: selections,
        }
    }

    pub fn single(hash: TpmAlgId, pcrs: &[u32]) -> Self {
        Self {
            pcr_selections: vec![TpmsPcrSelection::new(hash, pcrs)],
        }
    }
}

impl Marshal for TpmlPcrSelection {
    fn marshal(&self, buf: &mut CommandBuffer) {
        buf.put_u32(self.pcr_selections.len() as u32);
        for sel in &self.pcr_selections {
            sel.marshal(buf);
        }
    }
}

impl Unmarshal for TpmlPcrSelection {
    fn unmarshal(buf: &mut ResponseBuffer) -> Result<Self> {
        let count = buf.get_u32()? as usize;
        let mut pcr_selections = Vec::with_capacity(count);
        for _ in 0..count {
            pcr_selections.push(TpmsPcrSelection::unmarshal(buf)?);
        }
        Ok(Self { pcr_selections })
    }
}

/// TPML_DIGEST - List of digests
#[derive(Debug, Clone, Default)]
pub struct TpmlDigest {
    pub digests: Vec<Tpm2bDigest>,
}

impl Unmarshal for TpmlDigest {
    fn unmarshal(buf: &mut ResponseBuffer) -> Result<Self> {
        let count = buf.get_u32()? as usize;
        let mut digests = Vec::with_capacity(count);
        for _ in 0..count {
            digests.push(Tpm2bDigest::unmarshal(buf)?);
        }
        Ok(Self { digests })
    }
}

/// TPMS_NV_PUBLIC - NV index public area
#[derive(Debug, Clone)]
pub struct TpmsNvPublic {
    pub nv_index: u32,
    pub name_alg: TpmAlgId,
    pub attributes: TpmaNv,
    pub auth_policy: Tpm2bDigest,
    pub data_size: u16,
}

impl TpmsNvPublic {
    pub fn new(nv_index: u32, data_size: u16, attributes: TpmaNv) -> Self {
        Self {
            nv_index,
            name_alg: TpmAlgId::Sha256,
            attributes,
            auth_policy: Tpm2bDigest::empty(),
            data_size,
        }
    }
}

impl Marshal for TpmsNvPublic {
    fn marshal(&self, buf: &mut CommandBuffer) {
        buf.put_u32(self.nv_index);
        buf.put_u16(self.name_alg.to_u16());
        buf.put_u32(self.attributes.0);
        self.auth_policy.marshal(buf);
        buf.put_u16(self.data_size);
    }
}

impl Unmarshal for TpmsNvPublic {
    fn unmarshal(buf: &mut ResponseBuffer) -> Result<Self> {
        let nv_index = buf.get_u32()?;
        let name_alg_raw = buf.get_u16()?;
        let name_alg = TpmAlgId::from_u16(name_alg_raw)
            .ok_or_else(|| anyhow::anyhow!("unknown algorithm: 0x{:04x}", name_alg_raw))?;
        let attributes = TpmaNv(buf.get_u32()?);
        let auth_policy = Tpm2bDigest::unmarshal(buf)?;
        let data_size = buf.get_u16()?;
        Ok(Self {
            nv_index,
            name_alg,
            attributes,
            auth_policy,
            data_size,
        })
    }
}

/// TPM2B_NV_PUBLIC - NV public with size prefix
#[derive(Debug, Clone)]
pub struct Tpm2bNvPublic {
    pub nv_public: TpmsNvPublic,
}

impl Marshal for Tpm2bNvPublic {
    fn marshal(&self, buf: &mut CommandBuffer) {
        let mut inner = CommandBuffer::new();
        self.nv_public.marshal(&mut inner);
        buf.put_tpm2b(inner.as_bytes());
    }
}

impl Unmarshal for Tpm2bNvPublic {
    fn unmarshal(buf: &mut ResponseBuffer) -> Result<Self> {
        let size = buf.get_u16()? as usize;
        if size == 0 {
            bail!("empty NV public");
        }
        let data = buf.get_bytes(size)?;
        let mut inner = ResponseBuffer::new(&data);
        let nv_public = TpmsNvPublic::unmarshal(&mut inner)?;
        Ok(Self { nv_public })
    }
}

/// TPMT_SYM_DEF - Symmetric algorithm definition
#[derive(Debug, Clone, Copy)]
pub struct TpmtSymDef {
    pub algorithm: TpmAlgId,
    pub key_bits: u16,
    pub mode: TpmAlgId,
}

impl TpmtSymDef {
    pub fn null() -> Self {
        Self {
            algorithm: TpmAlgId::Null,
            key_bits: 0,
            mode: TpmAlgId::Null,
        }
    }

    pub fn aes_128_cfb() -> Self {
        Self {
            algorithm: TpmAlgId::Aes,
            key_bits: 128,
            mode: TpmAlgId::Cfb,
        }
    }
}

impl Marshal for TpmtSymDef {
    fn marshal(&self, buf: &mut CommandBuffer) {
        buf.put_u16(self.algorithm.to_u16());
        if self.algorithm != TpmAlgId::Null {
            buf.put_u16(self.key_bits);
            buf.put_u16(self.mode.to_u16());
        }
    }
}

impl Unmarshal for TpmtSymDef {
    fn unmarshal(buf: &mut ResponseBuffer) -> Result<Self> {
        let alg = buf.get_u16()?;
        let algorithm = TpmAlgId::from_u16(alg)
            .ok_or_else(|| anyhow::anyhow!("unknown algorithm: 0x{:04x}", alg))?;
        if algorithm == TpmAlgId::Null {
            Ok(Self::null())
        } else {
            let key_bits = buf.get_u16()?;
            let mode_raw = buf.get_u16()?;
            let mode = TpmAlgId::from_u16(mode_raw)
                .ok_or_else(|| anyhow::anyhow!("unknown mode: 0x{:04x}", mode_raw))?;
            Ok(Self {
                algorithm,
                key_bits,
                mode,
            })
        }
    }
}

/// TPMT_SYM_DEF_OBJECT - Symmetric definition for objects
pub type TpmtSymDefObject = TpmtSymDef;

/// TPMS_SCHEME_HASH - Hash scheme
#[derive(Debug, Clone, Copy)]
pub struct TpmsSchemeHash {
    pub hash_alg: TpmAlgId,
}

/// TPMT_RSA_SCHEME - RSA signature scheme
#[derive(Debug, Clone, Copy)]
pub struct TpmtRsaScheme {
    pub scheme: TpmAlgId,
    pub hash_alg: Option<TpmAlgId>,
}

impl TpmtRsaScheme {
    pub fn null() -> Self {
        Self {
            scheme: TpmAlgId::Null,
            hash_alg: None,
        }
    }

    pub fn rsassa(hash: TpmAlgId) -> Self {
        Self {
            scheme: TpmAlgId::RsaSsa,
            hash_alg: Some(hash),
        }
    }
}

impl Marshal for TpmtRsaScheme {
    fn marshal(&self, buf: &mut CommandBuffer) {
        buf.put_u16(self.scheme.to_u16());
        if let Some(hash) = self.hash_alg {
            buf.put_u16(hash.to_u16());
        }
    }
}

/// TPMT_ECC_SCHEME - ECC signature scheme
#[derive(Debug, Clone, Copy)]
pub struct TpmtEccScheme {
    pub scheme: TpmAlgId,
    pub hash_alg: Option<TpmAlgId>,
}

impl TpmtEccScheme {
    pub fn null() -> Self {
        Self {
            scheme: TpmAlgId::Null,
            hash_alg: None,
        }
    }

    pub fn ecdsa(hash: TpmAlgId) -> Self {
        Self {
            scheme: TpmAlgId::EcDsa,
            hash_alg: Some(hash),
        }
    }
}

impl Marshal for TpmtEccScheme {
    fn marshal(&self, buf: &mut CommandBuffer) {
        buf.put_u16(self.scheme.to_u16());
        if let Some(hash) = self.hash_alg {
            buf.put_u16(hash.to_u16());
        }
    }
}

/// TPMT_SIG_SCHEME - Signature scheme (for Quote)
#[derive(Debug, Clone, Copy)]
pub struct TpmtSigScheme {
    pub scheme: TpmAlgId,
    pub hash_alg: Option<TpmAlgId>,
}

impl TpmtSigScheme {
    pub fn null() -> Self {
        Self {
            scheme: TpmAlgId::Null,
            hash_alg: None,
        }
    }
}

impl Marshal for TpmtSigScheme {
    fn marshal(&self, buf: &mut CommandBuffer) {
        buf.put_u16(self.scheme.to_u16());
        if let Some(hash) = self.hash_alg {
            buf.put_u16(hash.to_u16());
        }
    }
}

/// TPMS_RSA_PARMS - RSA key parameters
#[derive(Debug, Clone)]
pub struct TpmsRsaParms {
    pub symmetric: TpmtSymDefObject,
    pub scheme: TpmtRsaScheme,
    pub key_bits: u16,
    pub exponent: u32,
}

impl TpmsRsaParms {
    pub fn storage_key() -> Self {
        Self {
            symmetric: TpmtSymDef::aes_128_cfb(),
            scheme: TpmtRsaScheme::null(),
            key_bits: 2048,
            exponent: 0, // Default exponent (65537)
        }
    }
}

impl Marshal for TpmsRsaParms {
    fn marshal(&self, buf: &mut CommandBuffer) {
        self.symmetric.marshal(buf);
        self.scheme.marshal(buf);
        buf.put_u16(self.key_bits);
        buf.put_u32(self.exponent);
    }
}

/// TPMS_ECC_PARMS - ECC key parameters
#[derive(Debug, Clone)]
pub struct TpmsEccParms {
    pub symmetric: TpmtSymDefObject,
    pub scheme: TpmtEccScheme,
    pub curve_id: TpmEccCurve,
    pub kdf: TpmAlgId,
}

impl Marshal for TpmsEccParms {
    fn marshal(&self, buf: &mut CommandBuffer) {
        self.symmetric.marshal(buf);
        self.scheme.marshal(buf);
        buf.put_u16(self.curve_id.to_u16());
        buf.put_u16(self.kdf.to_u16()); // KDF scheme (usually NULL)
    }
}

/// TPMS_KEYEDHASH_PARMS - Keyed hash parameters (for sealed data)
#[derive(Debug, Clone, Copy)]
pub struct TpmsKeyedHashParms {
    pub scheme: TpmAlgId,
}

impl TpmsKeyedHashParms {
    pub fn null() -> Self {
        Self {
            scheme: TpmAlgId::Null,
        }
    }
}

impl Marshal for TpmsKeyedHashParms {
    fn marshal(&self, buf: &mut CommandBuffer) {
        buf.put_u16(self.scheme.to_u16());
    }
}

/// TPMT_PUBLIC - Public area template
#[derive(Debug, Clone)]
pub struct TpmtPublic {
    pub type_alg: TpmAlgId,
    pub name_alg: TpmAlgId,
    pub object_attributes: TpmaObject,
    pub auth_policy: Tpm2bDigest,
    pub parameters: TpmtPublicParms,
    pub unique: TpmtPublicUnique,
}

/// TPMU_PUBLIC_PARMS - Public parameters union
#[derive(Debug, Clone)]
pub enum TpmtPublicParms {
    Rsa(TpmsRsaParms),
    Ecc(TpmsEccParms),
    KeyedHash(TpmsKeyedHashParms),
}

impl Marshal for TpmtPublicParms {
    fn marshal(&self, buf: &mut CommandBuffer) {
        match self {
            TpmtPublicParms::Rsa(p) => p.marshal(buf),
            TpmtPublicParms::Ecc(p) => p.marshal(buf),
            TpmtPublicParms::KeyedHash(p) => p.marshal(buf),
        }
    }
}

/// TPMU_PUBLIC_ID - Unique identifier union
#[derive(Debug, Clone)]
pub enum TpmtPublicUnique {
    Rsa(Vec<u8>),          // TPM2B_PUBLIC_KEY_RSA
    Ecc(Vec<u8>, Vec<u8>), // TPMS_ECC_POINT (x, y)
    KeyedHash(Vec<u8>),    // TPM2B_DIGEST
}

impl Marshal for TpmtPublicUnique {
    fn marshal(&self, buf: &mut CommandBuffer) {
        match self {
            TpmtPublicUnique::Rsa(n) => buf.put_tpm2b(n),
            TpmtPublicUnique::Ecc(x, y) => {
                buf.put_tpm2b(x);
                buf.put_tpm2b(y);
            }
            TpmtPublicUnique::KeyedHash(d) => buf.put_tpm2b(d),
        }
    }
}

impl TpmtPublic {
    /// Create an RSA storage key template (SRK)
    pub fn rsa_storage_key() -> Self {
        Self {
            type_alg: TpmAlgId::Rsa,
            name_alg: TpmAlgId::Sha256,
            object_attributes: TpmaObject::new()
                .with_fixed_tpm()
                .with_fixed_parent()
                .with_sensitive_data_origin()
                .with_user_with_auth()
                .with_restricted()
                .with_decrypt(),
            auth_policy: Tpm2bDigest::empty(),
            parameters: TpmtPublicParms::Rsa(TpmsRsaParms::storage_key()),
            unique: TpmtPublicUnique::Rsa(Vec::new()),
        }
    }

    /// Create a sealed data object template
    pub fn sealed_object(policy_digest: Tpm2bDigest) -> Self {
        // If policy_digest is empty, use userWithAuth; otherwise use adminWithPolicy
        let object_attributes = if policy_digest.buffer.is_empty() {
            TpmaObject::new()
                .with_fixed_tpm()
                .with_fixed_parent()
                .with_user_with_auth()
        } else {
            TpmaObject::new()
                .with_fixed_tpm()
                .with_fixed_parent()
                .with_admin_with_policy()
        };

        Self {
            type_alg: TpmAlgId::KeyedHash,
            name_alg: TpmAlgId::Sha256,
            object_attributes,
            auth_policy: policy_digest,
            parameters: TpmtPublicParms::KeyedHash(TpmsKeyedHashParms::null()),
            unique: TpmtPublicUnique::KeyedHash(Vec::new()),
        }
    }
}

impl Marshal for TpmtPublic {
    fn marshal(&self, buf: &mut CommandBuffer) {
        buf.put_u16(self.type_alg.to_u16());
        buf.put_u16(self.name_alg.to_u16());
        buf.put_u32(self.object_attributes.0);
        self.auth_policy.marshal(buf);
        self.parameters.marshal(buf);
        self.unique.marshal(buf);
    }
}

/// TPM2B_PUBLIC - Public area with size prefix
#[derive(Debug, Clone)]
pub struct Tpm2bPublic {
    pub public_area: Vec<u8>, // Raw marshalled TPMT_PUBLIC
}

impl Tpm2bPublic {
    pub fn from_template(template: &TpmtPublic) -> Self {
        Self {
            public_area: template.to_bytes(),
        }
    }
}

impl Marshal for Tpm2bPublic {
    fn marshal(&self, buf: &mut CommandBuffer) {
        buf.put_tpm2b(&self.public_area);
    }
}

impl Unmarshal for Tpm2bPublic {
    fn unmarshal(buf: &mut ResponseBuffer) -> Result<Self> {
        let public_area = buf.get_tpm2b()?;
        Ok(Self { public_area })
    }
}

/// TPM2B_PRIVATE - Private area
#[derive(Debug, Clone)]
pub struct Tpm2bPrivate {
    pub buffer: Vec<u8>,
}

impl Tpm2bPrivate {
    pub fn new(data: Vec<u8>) -> Self {
        Self { buffer: data }
    }
}

impl Marshal for Tpm2bPrivate {
    fn marshal(&self, buf: &mut CommandBuffer) {
        buf.put_tpm2b(&self.buffer);
    }
}

impl Unmarshal for Tpm2bPrivate {
    fn unmarshal(buf: &mut ResponseBuffer) -> Result<Self> {
        Ok(Self {
            buffer: buf.get_tpm2b()?,
        })
    }
}

/// TPM2B_SENSITIVE_CREATE - Sensitive data for object creation
#[derive(Debug, Clone, Default)]
pub struct Tpm2bSensitiveCreate {
    pub user_auth: Tpm2bAuth,
    pub data: Tpm2bSensitiveData,
}

impl Tpm2bSensitiveCreate {
    pub fn with_data(data: Vec<u8>) -> Self {
        Self {
            user_auth: Tpm2bAuth::empty(),
            data: Tpm2bSensitiveData::new(data),
        }
    }

    pub fn empty() -> Self {
        Self::default()
    }
}

impl Marshal for Tpm2bSensitiveCreate {
    fn marshal(&self, buf: &mut CommandBuffer) {
        // First marshal the inner structure
        let mut inner = CommandBuffer::new();
        self.user_auth.marshal(&mut inner);
        self.data.marshal(&mut inner);
        // Then wrap with size
        buf.put_tpm2b(inner.as_bytes());
    }
}

/// TPMS_ATTEST - Attestation structure (returned by Quote)
#[derive(Debug, Clone)]
pub struct TpmsAttest {
    pub raw: Vec<u8>, // Keep raw bytes for signature verification
}

impl Unmarshal for TpmsAttest {
    fn unmarshal(buf: &mut ResponseBuffer) -> Result<Self> {
        // For Quote, we need the raw bytes for verification
        // The structure is variable length, so we capture everything
        let raw = buf.get_remaining();
        Ok(Self { raw })
    }
}

/// TPM2B_ATTEST - Attestation data with size prefix
#[derive(Debug, Clone)]
pub struct Tpm2bAttest {
    pub attestation_data: Vec<u8>,
}

impl Unmarshal for Tpm2bAttest {
    fn unmarshal(buf: &mut ResponseBuffer) -> Result<Self> {
        let attestation_data = buf.get_tpm2b()?;
        Ok(Self { attestation_data })
    }
}

/// TPMT_SIGNATURE - Signature structure
#[derive(Debug, Clone)]
pub struct TpmtSignature {
    pub raw: Vec<u8>, // Keep raw bytes for verification
}

impl Unmarshal for TpmtSignature {
    fn unmarshal(buf: &mut ResponseBuffer) -> Result<Self> {
        // Signature format depends on algorithm, capture remaining bytes
        let raw = buf.get_remaining();
        Ok(Self { raw })
    }
}

/// TPMT_TK_CREATION - Creation ticket
#[derive(Debug, Clone)]
pub struct TpmtTkCreation {
    pub tag: u16,
    pub hierarchy: u32,
    pub digest: Tpm2bDigest,
}

impl Unmarshal for TpmtTkCreation {
    fn unmarshal(buf: &mut ResponseBuffer) -> Result<Self> {
        let tag = buf.get_u16()?;
        let hierarchy = buf.get_u32()?;
        let digest = Tpm2bDigest::unmarshal(buf)?;
        Ok(Self {
            tag,
            hierarchy,
            digest,
        })
    }
}

/// TPM2B_CREATION_DATA - Creation data
#[derive(Debug, Clone)]
pub struct Tpm2bCreationData {
    pub data: Vec<u8>,
}

impl Unmarshal for Tpm2bCreationData {
    fn unmarshal(buf: &mut ResponseBuffer) -> Result<Self> {
        let data = buf.get_tpm2b()?;
        Ok(Self { data })
    }
}

/// TPMS_SENSITIVE_CREATE - Inner sensitive create structure
#[derive(Debug, Clone, Default)]
pub struct TpmsSensitiveCreate {
    pub user_auth: Tpm2bAuth,
    pub data: Tpm2bSensitiveData,
}

/// TPMT_HA - Hash value with algorithm
#[derive(Debug, Clone)]
pub struct TpmtHa {
    pub hash_alg: TpmAlgId,
    pub digest: Vec<u8>,
}

impl TpmtHa {
    pub fn sha256(digest: Vec<u8>) -> Self {
        Self {
            hash_alg: TpmAlgId::Sha256,
            digest,
        }
    }
}

impl Marshal for TpmtHa {
    fn marshal(&self, buf: &mut CommandBuffer) {
        buf.put_u16(self.hash_alg.to_u16());
        buf.put_bytes(&self.digest);
    }
}

/// TPML_DIGEST_VALUES - List of digest values for PCR extend
#[derive(Debug, Clone)]
pub struct TpmlDigestValues {
    pub digests: Vec<TpmtHa>,
}

impl TpmlDigestValues {
    pub fn single(digest: TpmtHa) -> Self {
        Self {
            digests: vec![digest],
        }
    }
}

impl Marshal for TpmlDigestValues {
    fn marshal(&self, buf: &mut CommandBuffer) {
        buf.put_u32(self.digests.len() as u32);
        for d in &self.digests {
            d.marshal(buf);
        }
    }
}
