// SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

//! Cross-SDK `.sealed-env` fixtures kept at the monorepo SDK boundary.

use std::{fs, path::Path};

use base64::{engine::general_purpose::STANDARD, Engine};
use hpke::{aead::AesGcm256, kdf::HkdfSha256, kem::X25519HkdfSha256, Deserializable, Kem, OpModeR};

#[derive(serde::Deserialize)]
struct Envelope {
    version: u32,
    root_epoch: u32,
    app_epoch: u32,
    enc: String,
    ciphertext: String,
}

#[derive(serde::Deserialize)]
struct Fixture {
    private_key: String,
    env: serde_json::Value,
    sealed_env: Envelope,
}

#[test]
fn shared_sdk_fixtures_open_with_their_envelope_epochs() {
    let fixtures_dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("../fixtures/sealed-env");
    for producer in ["python", "javascript"] {
        let path = fixtures_dir.join(format!("{producer}.json"));
        let fixture = fs::read_to_string(&path)
            .unwrap_or_else(|err| panic!("failed to read {}: {err}", path.display()));
        let fixture: Fixture = serde_json::from_str(&fixture).unwrap();
        assert_eq!(fixture.sealed_env.version, 1, "{producer}");
        assert_eq!(fixture.sealed_env.root_epoch, 3, "{producer}");
        assert_eq!(fixture.sealed_env.app_epoch, 0, "{producer}");

        let private_key = hex::decode(&fixture.private_key).unwrap();
        let private_key = <X25519HkdfSha256 as Kem>::PrivateKey::from_bytes(&private_key).unwrap();
        let enc = STANDARD.decode(&fixture.sealed_env.enc).unwrap();
        let enc = <X25519HkdfSha256 as Kem>::EncappedKey::from_bytes(&enc).unwrap();
        let ciphertext = STANDARD.decode(&fixture.sealed_env.ciphertext).unwrap();
        let info = format!(
            "dstack-sealed-env-v1:{}:{}",
            fixture.sealed_env.root_epoch, fixture.sealed_env.app_epoch
        );
        let plaintext = hpke::single_shot_open::<AesGcm256, HkdfSha256, X25519HkdfSha256>(
            &OpModeR::Base,
            &private_key,
            &enc,
            info.as_bytes(),
            &ciphertext,
            &[],
        )
        .unwrap();
        let opened: serde_json::Value = serde_json::from_slice(&plaintext).unwrap();
        assert_eq!(
            opened,
            serde_json::json!({ "env": fixture.env }),
            "{producer}"
        );
    }
}
