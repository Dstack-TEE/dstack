// SPDX-FileCopyrightText: © 2025 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

use std::path::PathBuf;

use anyhow::{bail, Context as _, Result};
use aws_nitro_enclaves_nsm_api::api as nsm_api;
use hmac::{Hmac, Mac};
use or_panic::ResultOrPanic;
use rand::{rngs::OsRng, Rng, RngCore};
use rsa::{BigUint, Oaep, RsaPublicKey};
use sha2::{Digest as _, Sha256, Sha512};
use tpm2::{
    tpm_rh, ResponseBuffer as TpmResponseBuffer, TpmAlgId, TpmCommand, TpmContext, TpmaNv,
    TpmtPublic,
};

const TPM2_VENDOR_AWS_NSM_REQUEST: u32 = 0x20000001;
const TPM2_NV_INDEX_FIRST: u32 = 0x0100_0000;
const TPM2_NV_INDEX_LAST: u32 = 0x01ff_ffff;
const MESSAGE_BUFFER_SIZE: usize = 8192;
const MESSAGE_BUFFER_AUTH_SIZE: usize = 64;
const NONCE_SIZE: usize = 64;
const SALT_SIZE: usize = 32;
const RSA_DEFAULT_EXPONENT: u32 = 65_537;
const TPMA_SESSION_CONTINUE_SESSION: u8 = 1 << 0;

type HmacSha512 = Hmac<Sha512>;

pub(crate) fn attestation_document(report_data: &[u8]) -> Result<Vec<u8>> {
    let request = nsm_api::Request::Attestation {
        user_data: Some(report_data.to_vec().into()),
        nonce: None,
        public_key: None,
    };

    let device_path = tpm_device_path();
    let device_path = device_path
        .to_str()
        .context("invalid TPM device path")?
        .to_string();
    let mut tpm = TpmContext::new(Some(&device_path))?;

    let template = TpmtPublic::rsa_ek();
    let (ek_handle, ek_public) = tpm
        .create_primary(tpm_rh::ENDORSEMENT, &template)
        .context("failed to create NitroTPM endorsement key")?;
    let result = request_attestation_document(&mut tpm, ek_handle, &ek_public, &request);

    if let Err(error) = tpm.flush_context(ek_handle) {
        tracing::warn!(?error, "failed to flush NitroTPM endorsement key");
    }

    result
}

fn tpm_device_path() -> PathBuf {
    if let Some(path) = std::env::var_os("TPM_DEVICE") {
        return PathBuf::from(path);
    }
    if std::path::Path::new("/dev/tpmrm0").exists() {
        return PathBuf::from("/dev/tpmrm0");
    }
    PathBuf::from("/dev/tpm0")
}

fn request_attestation_document(
    tpm: &mut TpmContext,
    ek_handle: u32,
    ek_public: &[u8],
    request: &nsm_api::Request,
) -> Result<Vec<u8>> {
    let ek_public_key = rsa_public_key_from_tpm_public(ek_public)
        .context("failed to decode NitroTPM endorsement key public area")?;
    let message_buffer =
        MessageBuffer::from_request(tpm, request).context("failed to create NitroTPM buffer")?;

    let result = (|| {
        nsm_request(tpm, ek_handle, &ek_public_key, &message_buffer)
            .context("NitroTPM NSM vendor command failed")?;

        match message_buffer.read_response(tpm)? {
            nsm_api::Response::Attestation { document } => Ok(document),
            nsm_api::Response::Error(error) => bail!("NitroTPM NSM error response: {error:?}"),
            response => bail!("unexpected NitroTPM NSM response: {response:?}"),
        }
    })();

    if let Err(error) = tpm.nv_undefine(message_buffer.index) {
        tracing::warn!(
            ?error,
            index = format_args!("0x{:08x}", message_buffer.index),
            "failed to undefine NitroTPM message buffer"
        );
    }

    result
}

struct MessageBuffer {
    index: u32,
    auth: Vec<u8>,
    name: Vec<u8>,
}

impl MessageBuffer {
    fn from_request(tpm: &mut TpmContext, request: &nsm_api::Request) -> Result<Self> {
        let mut auth = vec![0u8; MESSAGE_BUFFER_AUTH_SIZE];
        OsRng.fill_bytes(&mut auth);

        let index = tpm
            .find_free_handle(TPM2_NV_INDEX_FIRST, TPM2_NV_INDEX_LAST)?
            .context("could not find free TPM NV index handle")?;
        let attributes = TpmaNv::new().with_auth_read().with_auth_write();

        let defined = tpm.nv_define_with_auth(
            index,
            MESSAGE_BUFFER_SIZE,
            &auth,
            TpmAlgId::Sha512,
            attributes,
        )?;
        if !defined {
            bail!("failed to define NitroTPM message buffer at 0x{index:08x}");
        }

        let mut request_bytes = Vec::new();
        ciborium::into_writer(request, &mut request_bytes)
            .context("failed to serialize NitroTPM NSM request")?;
        if request_bytes.len() > MESSAGE_BUFFER_SIZE {
            bail!(
                "NitroTPM NSM request is too large: {} > {}",
                request_bytes.len(),
                MESSAGE_BUFFER_SIZE
            );
        }
        tpm.nv_write_with_auth(index, &auth, &request_bytes)
            .context("failed to write NitroTPM NSM request")?;

        let (_, name) = tpm
            .nv_read_public_with_name(index)
            .context("failed to read NitroTPM message buffer name")?;

        Ok(Self { index, auth, name })
    }

    fn read_response(&self, tpm: &mut TpmContext) -> Result<nsm_api::Response> {
        let response = tpm
            .nv_read_with_auth(self.index, &self.auth)
            .context("failed to read NitroTPM NSM response")?;
        ciborium::from_reader(response.as_slice())
            .context("failed to deserialize NitroTPM NSM response")
    }
}

fn nsm_request(
    tpm: &mut TpmContext,
    salt_key_handle: u32,
    salt_public_key: &RsaPublicKey,
    message_buffer: &MessageBuffer,
) -> Result<()> {
    let auth_session = AuthSession::new(tpm, salt_key_handle, salt_public_key)?;
    let cp_hash = nsm_request_cp_hash(&message_buffer.name);
    let auth_area = auth_session.auth_area(&message_buffer.auth, &cp_hash);

    let mut cmd = TpmCommand::with_sessions_raw(TPM2_VENDOR_AWS_NSM_REQUEST);
    // NV auth
    cmd.add_handle(message_buffer.index);
    // NV index
    cmd.add_handle(message_buffer.index);
    // Authorization area
    cmd.add_auth_area(&auth_area);

    let response = tpm.execute_raw(&cmd.finalize())?;
    response
        .ensure_success()
        .context("NitroTPM NSM request failed")?;

    if let Err(error) = tpm.flush_context(auth_session.handle) {
        tracing::warn!(?error, "failed to flush NitroTPM auth session");
    }
    Ok(())
}

fn nsm_request_cp_hash(message_buffer_name: &[u8]) -> [u8; 64] {
    let mut hasher = Sha512::new();
    hasher.update(TPM2_VENDOR_AWS_NSM_REQUEST.to_be_bytes());
    hasher.update(message_buffer_name);
    hasher.update(message_buffer_name);
    hasher.finalize().into()
}

struct AuthSession {
    handle: u32,
    session_key: [u8; 64],
    nonce_tpm: Vec<u8>,
}

impl AuthSession {
    fn new(
        tpm: &mut TpmContext,
        salt_key_handle: u32,
        salt_public_key: &RsaPublicKey,
    ) -> Result<Self> {
        let mut nonce_caller = [0u8; NONCE_SIZE];
        let salt: [u8; SALT_SIZE] = OsRng.gen();
        OsRng.fill_bytes(&mut nonce_caller);

        let encrypted_salt = encrypt_salt(salt_public_key, &salt)?;
        let (handle, nonce_tpm) = tpm.start_hmac_auth_session_salted(
            salt_key_handle,
            &encrypted_salt,
            &nonce_caller,
            TpmAlgId::Sha512,
        )?;
        let session_key = derive_session_key(&salt, &nonce_tpm, &nonce_caller);

        Ok(Self {
            handle,
            session_key,
            nonce_tpm,
        })
    }

    fn auth_area(&self, auth_value: &[u8], cp_hash: &[u8; 64]) -> Vec<u8> {
        let mut nonce_caller = [0u8; NONCE_SIZE];
        OsRng.fill_bytes(&mut nonce_caller);

        let session_attributes = TPMA_SESSION_CONTINUE_SESSION;
        let auth_hmac = auth_hmac(
            &self.session_key,
            auth_value,
            cp_hash,
            &nonce_caller,
            &self.nonce_tpm,
            session_attributes,
        );

        let mut auth_area = Vec::new();
        auth_area.extend_from_slice(&self.handle.to_be_bytes());
        auth_area.extend_from_slice(&(nonce_caller.len() as u16).to_be_bytes());
        auth_area.extend_from_slice(&nonce_caller);
        auth_area.push(session_attributes);
        auth_area.extend_from_slice(&(auth_hmac.len() as u16).to_be_bytes());
        auth_area.extend_from_slice(&auth_hmac);
        auth_area
    }
}

fn encrypt_salt(salt_public_key: &RsaPublicKey, salt: &[u8; SALT_SIZE]) -> Result<Vec<u8>> {
    salt_public_key
        .encrypt(
            &mut OsRng,
            Oaep::new_with_label::<Sha256, _>("SECRET\0"),
            salt,
        )
        .context("failed to encrypt NitroTPM auth-session salt")
}

fn derive_session_key(salt: &[u8], nonce_tpm: &[u8], nonce_caller: &[u8]) -> [u8; 64] {
    let mut info = Vec::with_capacity(4 + nonce_tpm.len() + nonce_caller.len() + 4);
    info.extend_from_slice(b"ATH\0");
    info.extend_from_slice(nonce_tpm);
    info.extend_from_slice(nonce_caller);
    info.extend_from_slice(&512u32.to_be_bytes());
    kbkdf_ctr_hmac_sha512(salt, &info)
}

fn kbkdf_ctr_hmac_sha512(key: &[u8], info: &[u8]) -> [u8; 64] {
    let mut mac = HmacSha512::new_from_slice(key).or_panic("hmac accepts any key length");
    mac.update(&1u32.to_be_bytes());
    mac.update(info);
    mac.finalize().into_bytes().into()
}

fn auth_hmac(
    session_key: &[u8],
    auth_value: &[u8],
    cp_hash: &[u8; 64],
    nonce_caller: &[u8],
    nonce_tpm: &[u8],
    session_attributes: u8,
) -> [u8; 64] {
    let mut key = Vec::with_capacity(session_key.len() + auth_value.len());
    key.extend_from_slice(session_key);
    key.extend_from_slice(auth_value);

    let mut mac = HmacSha512::new_from_slice(&key).or_panic("hmac accepts any key length");
    mac.update(cp_hash);
    mac.update(nonce_caller);
    mac.update(nonce_tpm);
    mac.update(&[session_attributes]);
    mac.finalize().into_bytes().into()
}

fn rsa_public_key_from_tpm_public(public_area: &[u8]) -> Result<RsaPublicKey> {
    let mut buf = TpmResponseBuffer::new(public_area);

    let type_alg = buf.get_u16()?;
    if type_alg != TpmAlgId::Rsa.to_u16() {
        bail!("NitroTPM endorsement key is not RSA");
    }
    let _name_alg = buf.get_u16()?;
    let _object_attributes = buf.get_u32()?;
    let _auth_policy = buf.get_tpm2b()?;

    let symmetric_alg = buf.get_u16()?;
    if symmetric_alg != TpmAlgId::Null.to_u16() {
        let _key_bits = buf.get_u16()?;
        let _mode = buf.get_u16()?;
    }

    let scheme = buf.get_u16()?;
    if scheme != TpmAlgId::Null.to_u16() {
        let _hash_alg = buf.get_u16()?;
    }

    let _key_bits = buf.get_u16()?;
    let exponent = match buf.get_u32()? {
        0 => RSA_DEFAULT_EXPONENT,
        value => value,
    };
    let modulus = buf.get_tpm2b()?;

    RsaPublicKey::new(BigUint::from_bytes_be(&modulus), BigUint::from(exponent))
        .context("failed to build RSA public key from NitroTPM endorsement key")
}

#[cfg(test)]
mod tests {
    use super::*;
    use rsa::traits::PublicKeyParts;

    #[test]
    fn nsm_request_cp_hash_uses_vendor_command_and_two_handle_names() {
        let name: Vec<u8> = (0..68).collect();
        let expected: [u8; 64] = hex::decode(
            "c3869a4e945d90e6688365a59e14d2c5ab3d2b4579261a4a4377fe918d5d3509\
             33284223b6a569e384124d2bceb2173dac7a4171181efed7a5697d862174f9dc",
        )
        .unwrap()
        .try_into()
        .unwrap();

        assert_eq!(nsm_request_cp_hash(&name), expected);
    }

    #[test]
    fn auth_area_uses_hmac_session_layout() {
        let session_key = [0x42u8; 64];
        let nonce_tpm = vec![0x24u8; 64];
        let session = AuthSession {
            handle: 0x0200_0000,
            session_key,
            nonce_tpm,
        };
        let auth_value = [0x11u8; 64];
        let cp_hash = [0x33u8; 64];

        let auth_area = session.auth_area(&auth_value, &cp_hash);

        assert_eq!(&auth_area[0..4], &[0x02, 0x00, 0x00, 0x00]);
        assert_eq!(u16::from_be_bytes(auth_area[4..6].try_into().unwrap()), 64);
        let nonce_caller = &auth_area[6..70];
        assert_eq!(auth_area[70], TPMA_SESSION_CONTINUE_SESSION);
        assert_eq!(
            u16::from_be_bytes(auth_area[71..73].try_into().unwrap()),
            64
        );
        let expected_hmac = auth_hmac(
            &session.session_key,
            &auth_value,
            &cp_hash,
            nonce_caller,
            &session.nonce_tpm,
            TPMA_SESSION_CONTINUE_SESSION,
        );
        assert_eq!(&auth_area[73..137], expected_hmac.as_slice());
        assert_eq!(auth_area.len(), 137);
    }

    #[test]
    fn rsa_public_key_from_tpm_public_defaults_zero_exponent() {
        let mut modulus = vec![0xffu8; 256];
        modulus[255] = 0xfd;
        let public_area = rsa_public_area(&modulus, 0);

        let key = rsa_public_key_from_tpm_public(&public_area).unwrap();

        assert_eq!(key.n(), &BigUint::from_bytes_be(&modulus));
        assert_eq!(key.e(), &BigUint::from(RSA_DEFAULT_EXPONENT));
    }

    #[test]
    fn rsa_public_key_from_tpm_public_uses_explicit_exponent() {
        let mut modulus = vec![0xf3u8; 256];
        modulus[255] = 0xfb;
        let public_area = rsa_public_area(&modulus, 3);

        let key = rsa_public_key_from_tpm_public(&public_area).unwrap();

        assert_eq!(key.n(), &BigUint::from_bytes_be(&modulus));
        assert_eq!(key.e(), &BigUint::from(3u32));
    }

    fn rsa_public_area(modulus: &[u8], exponent: u32) -> Vec<u8> {
        let mut public_area = Vec::new();
        public_area.extend_from_slice(&TpmAlgId::Rsa.to_u16().to_be_bytes());
        public_area.extend_from_slice(&TpmAlgId::Sha256.to_u16().to_be_bytes());
        public_area.extend_from_slice(&0u32.to_be_bytes());
        public_area.extend_from_slice(&0u16.to_be_bytes());
        public_area.extend_from_slice(&TpmAlgId::Aes.to_u16().to_be_bytes());
        public_area.extend_from_slice(&128u16.to_be_bytes());
        public_area.extend_from_slice(&TpmAlgId::Cfb.to_u16().to_be_bytes());
        public_area.extend_from_slice(&TpmAlgId::Null.to_u16().to_be_bytes());
        public_area.extend_from_slice(&2048u16.to_be_bytes());
        public_area.extend_from_slice(&exponent.to_be_bytes());
        public_area.extend_from_slice(&(modulus.len() as u16).to_be_bytes());
        public_area.extend_from_slice(modulus);
        public_area
    }
}
