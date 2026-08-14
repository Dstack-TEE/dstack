// SPDX-FileCopyrightText: © 2024 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

use aes_gcm::{
    aead::{Aead, Nonce, Payload},
    Aes256Gcm, KeyInit,
};
use anyhow::{anyhow, ensure, Context, Result};
use std::io::{Read, Write};
use x25519_dalek::{PublicKey, StaticSecret};

pub const STREAM_MAGIC: &[u8; 16] = b"dstack-stream-v1";
pub const DEFAULT_CHUNK_SIZE: usize = 1024 * 1024;
pub const MAX_CHUNK_SIZE: usize = 16 * 1024 * 1024;
const FINAL_CHUNK: u8 = 1;
const HEADER_LEN: usize = STREAM_MAGIC.len() + 32 + 8 + 4;

pub fn dh_agree(secret: [u8; 32], their_pubkey: [u8; 32]) -> [u8; 32] {
    let secret = StaticSecret::from(secret);
    let their_public = PublicKey::from(their_pubkey);
    let shared_secret = secret.diffie_hellman(&their_public);
    shared_secret.to_bytes()
}

pub fn dh_decrypt(secret: [u8; 32], ciphertext: &[u8]) -> Result<Vec<u8>> {
    // Extract components (matching JS implementation)
    let ephemeral_pubkey = ciphertext
        .get(..32)
        .ok_or(anyhow!("Invalid ephemeral public key length"))?
        .try_into()
        .map_err(|_| anyhow!("Invalid ephemeral public key length"))?;
    let iv = &ciphertext.get(32..44).ok_or(anyhow!("Invalid IV length"))?;
    let ciphertext = &ciphertext
        .get(44..)
        .ok_or(anyhow!("Invalid ciphertext length"))?;

    // Derive shared secret using X25519
    let shared_secret = dh_agree(secret, ephemeral_pubkey);
    if shared_secret.iter().all(|byte| *byte == 0) {
        return Err(anyhow!("invalid X25519 shared secret"));
    }

    // Create AES-GCM cipher
    let cipher = Aes256Gcm::new_from_slice(&shared_secret)
        .map_err(|e| anyhow!("Failed to create cipher: {}", e))?;

    // Decrypt using AES-GCM
    cipher
        .decrypt(Nonce::<Aes256Gcm>::from_slice(iv), ciphertext.as_ref())
        .map_err(|e| anyhow!("Decryption failed: {}", e))
}

fn stream_nonce(prefix: &[u8; 8], index: u32) -> [u8; 12] {
    let mut nonce = [0u8; 12];
    nonce[..8].copy_from_slice(prefix);
    nonce[8..].copy_from_slice(&index.to_be_bytes());
    nonce
}

fn stream_aad(header: &[u8; HEADER_LEN], index: u32, frame_header: &[u8; 5]) -> Vec<u8> {
    let mut aad = Vec::with_capacity(HEADER_LEN + 4 + frame_header.len());
    aad.extend_from_slice(header);
    aad.extend_from_slice(&index.to_be_bytes());
    aad.extend_from_slice(frame_header);
    aad
}

/// Encrypts a reader as independently authenticated chunks.
pub fn dh_encrypt_stream(
    remote_public_key: [u8; 32],
    mut input: impl Read,
    mut output: impl Write,
    chunk_size: usize,
) -> Result<()> {
    ensure!(
        (1..=MAX_CHUNK_SIZE).contains(&chunk_size),
        "Chunk size must be between 1 and {MAX_CHUNK_SIZE} bytes"
    );

    let mut ephemeral_secret = [0u8; 32];
    getrandom::fill(&mut ephemeral_secret).context("Failed to generate ephemeral secret")?;
    let ephemeral_secret = StaticSecret::from(ephemeral_secret);
    let ephemeral_public_key = PublicKey::from(&ephemeral_secret).to_bytes();
    let remote_public_key = PublicKey::from(remote_public_key);
    let shared_secret = ephemeral_secret
        .diffie_hellman(&remote_public_key)
        .to_bytes();
    ensure!(
        !shared_secret.iter().all(|byte| *byte == 0),
        "invalid X25519 shared secret"
    );
    let cipher = Aes256Gcm::new_from_slice(&shared_secret)
        .map_err(|e| anyhow!("Failed to create cipher: {e}"))?;

    let mut nonce_prefix = [0u8; 8];
    getrandom::fill(&mut nonce_prefix).context("Failed to generate nonce prefix")?;
    let mut header = [0u8; HEADER_LEN];
    header[..STREAM_MAGIC.len()].copy_from_slice(STREAM_MAGIC);
    header[STREAM_MAGIC.len()..STREAM_MAGIC.len() + 32].copy_from_slice(&ephemeral_public_key);
    header[STREAM_MAGIC.len() + 32..STREAM_MAGIC.len() + 40].copy_from_slice(&nonce_prefix);
    header[STREAM_MAGIC.len() + 40..].copy_from_slice(&(chunk_size as u32).to_be_bytes());
    output
        .write_all(&header)
        .context("Failed to write header")?;

    let mut current = vec![0u8; chunk_size];
    let mut next = vec![0u8; chunk_size];
    let mut current_len = read_chunk(&mut input, &mut current)?;
    let mut index = 0u32;
    loop {
        let next_len = read_chunk(&mut input, &mut next)?;
        let final_chunk = next_len == 0;
        let flags = if final_chunk { FINAL_CHUNK } else { 0 };
        let mut frame_header = [0u8; 5];
        frame_header[0] = flags;
        frame_header[1..].copy_from_slice(&(current_len as u32).to_be_bytes());
        let aad = stream_aad(&header, index, &frame_header);
        let nonce = stream_nonce(&nonce_prefix, index);
        let encrypted = cipher
            .encrypt(
                (&nonce).into(),
                Payload {
                    msg: &current[..current_len],
                    aad: &aad,
                },
            )
            .map_err(|e| anyhow!("Failed to encrypt chunk {index}: {e}"))?;
        output
            .write_all(&frame_header)
            .and_then(|_| output.write_all(&encrypted))
            .with_context(|| format!("Failed to write chunk {index}"))?;
        if final_chunk {
            break;
        }
        index = index.checked_add(1).context("Too many chunks")?;
        std::mem::swap(&mut current, &mut next);
        current_len = next_len;
    }
    output.flush().context("Failed to flush encrypted output")?;
    Ok(())
}

fn read_chunk(input: &mut impl Read, buffer: &mut [u8]) -> Result<usize> {
    let mut read = 0;
    while read < buffer.len() {
        match input
            .read(&mut buffer[read..])
            .context("Failed to read input")?
        {
            0 => break,
            n => read += n,
        }
    }
    Ok(read)
}

/// Decrypts a chunked stream after the caller has consumed [`STREAM_MAGIC`].
pub fn dh_decrypt_stream(
    secret: [u8; 32],
    mut input: impl Read,
    mut output: impl Write,
) -> Result<()> {
    let mut header = [0u8; HEADER_LEN];
    header[..STREAM_MAGIC.len()].copy_from_slice(STREAM_MAGIC);
    input
        .read_exact(&mut header[STREAM_MAGIC.len()..])
        .context("Truncated stream header")?;
    let ephemeral_public_key: [u8; 32] = header[STREAM_MAGIC.len()..STREAM_MAGIC.len() + 32]
        .try_into()
        .expect("fixed-size header slice");
    let nonce_prefix: [u8; 8] = header[STREAM_MAGIC.len() + 32..STREAM_MAGIC.len() + 40]
        .try_into()
        .expect("fixed-size header slice");
    let chunk_size = u32::from_be_bytes(
        header[STREAM_MAGIC.len() + 40..]
            .try_into()
            .expect("fixed-size header slice"),
    ) as usize;
    ensure!(
        (1..=MAX_CHUNK_SIZE).contains(&chunk_size),
        "Invalid chunk size: {chunk_size}"
    );

    let shared_secret = dh_agree(secret, ephemeral_public_key);
    ensure!(
        !shared_secret.iter().all(|byte| *byte == 0),
        "invalid X25519 shared secret"
    );
    let cipher = Aes256Gcm::new_from_slice(&shared_secret)
        .map_err(|e| anyhow!("Failed to create cipher: {e}"))?;

    let mut index = 0u32;
    loop {
        let mut frame_header = [0u8; 5];
        input
            .read_exact(&mut frame_header)
            .with_context(|| format!("Missing final chunk at chunk {index}"))?;
        ensure!(frame_header[0] & !FINAL_CHUNK == 0, "Invalid chunk flags");
        let final_chunk = frame_header[0] == FINAL_CHUNK;
        let plaintext_len = u32::from_be_bytes(
            frame_header[1..]
                .try_into()
                .expect("fixed-size frame header"),
        ) as usize;
        ensure!(plaintext_len <= chunk_size, "Chunk {index} is too large");
        ensure!(
            final_chunk || plaintext_len == chunk_size,
            "Non-final chunk {index} has an invalid length"
        );

        let mut encrypted = vec![0u8; plaintext_len + 16];
        input
            .read_exact(&mut encrypted)
            .with_context(|| format!("Truncated chunk {index}"))?;
        let nonce = stream_nonce(&nonce_prefix, index);
        let aad = stream_aad(&header, index, &frame_header);
        let plaintext = cipher
            .decrypt(
                (&nonce).into(),
                Payload {
                    msg: &encrypted,
                    aad: &aad,
                },
            )
            .map_err(|e| anyhow!("Failed to decrypt chunk {index}: {e}"))?;
        output
            .write_all(&plaintext)
            .with_context(|| format!("Failed to write chunk {index}"))?;

        if final_chunk {
            let mut trailing = [0u8; 1];
            ensure!(
                input.read(&mut trailing).context("Failed to read input")? == 0,
                "Trailing data after final chunk"
            );
            output.flush().context("Failed to flush plaintext output")?;
            return Ok(());
        }
        index = index.checked_add(1).context("Too many chunks")?;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dh_agree() {
        use rand::Rng;
        let secret = rand::thread_rng().gen::<[u8; 32]>();
        let pubkey = rand::thread_rng().gen::<[u8; 32]>();
        let shared = dh_agree(secret, pubkey);
        assert_eq!(shared.len(), 32);
        println!("secret: {:?}", hex::encode(secret));
        println!("pubkey: {:?}", hex::encode(pubkey));
        println!("shared: {:?}", hex::encode(shared));
    }

    #[test]
    fn test_dh_decrypt_invalid_input() {
        let secret = [0u8; 32];

        // Test empty input
        assert!(dh_decrypt(secret, &[]).is_err());

        // Test input too short for public key
        assert!(dh_decrypt(secret, &[0u8; 31]).is_err());

        // Test input too short for IV
        assert!(dh_decrypt(secret, &[0u8; 43]).is_err());

        // Test input with no ciphertext
        assert!(dh_decrypt(secret, &[0u8; 44]).is_err());
    }

    #[test]
    fn test_dh_decrypt() {
        let secret: [u8; 32] =
            hex::decode("7c282bf94b35dc47801dc953bfa0896fc2bd313381d3e8eca4e42f6536d2a96f")
                .unwrap()
                .try_into()
                .unwrap();
        let ciphertext = hex::decode("0bd18749612f4c8b9dd583c7d6a646b90abd34e3c731a7708d0caf9039095641e1f0948e775f0b7351788db7f246d51806954626dcccb6a60d64665ca3715c6bef75616cab476d27bba04080361200d6a58cec").unwrap();
        let decrypted = dh_decrypt(secret, &ciphertext).unwrap();
        let decrypted_str = String::from_utf8(decrypted).unwrap();
        assert_eq!(decrypted_str, "[{\"key\":\"\",\"value\":\"\"}]");
    }

    #[test]
    fn test_stream_roundtrip() {
        let secret = StaticSecret::random_from_rng(rand::thread_rng());
        let public_key = PublicKey::from(&secret).to_bytes();
        let plaintext = vec![0x5a; 2500];
        let mut encrypted = Vec::new();
        dh_encrypt_stream(public_key, plaintext.as_slice(), &mut encrypted, 1024).unwrap();
        assert_eq!(&encrypted[..STREAM_MAGIC.len()], STREAM_MAGIC);

        let mut decrypted = Vec::new();
        dh_decrypt_stream(
            secret.to_bytes(),
            &encrypted[STREAM_MAGIC.len()..],
            &mut decrypted,
        )
        .unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_stream_rejects_tampering_and_truncation() {
        let secret = StaticSecret::random_from_rng(rand::thread_rng());
        let public_key = PublicKey::from(&secret).to_bytes();
        let mut encrypted = Vec::new();
        dh_encrypt_stream(public_key, b"hello".as_slice(), &mut encrypted, 4).unwrap();

        let mut tampered = encrypted.clone();
        *tampered.last_mut().unwrap() ^= 1;
        assert!(dh_decrypt_stream(
            secret.to_bytes(),
            &tampered[STREAM_MAGIC.len()..],
            Vec::new(),
        )
        .is_err());

        encrypted.truncate(encrypted.len() - 1);
        assert!(dh_decrypt_stream(
            secret.to_bytes(),
            &encrypted[STREAM_MAGIC.len()..],
            Vec::new(),
        )
        .is_err());
    }
}
