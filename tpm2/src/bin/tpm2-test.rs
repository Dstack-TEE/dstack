// SPDX-FileCopyrightText: © 2025 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

//! TPM 2.0 Test CLI
//!
//! A simple CLI tool to test TPM 2.0 operations on real hardware.
//!
//! Usage:
//!   tpm2-test [command]
//!
//! Commands:
//!   info        - Show TPM device info
//!   random      - Generate random bytes
//!   pcr-read    - Read PCR values
//!   pcr-extend  - Test PCR extend
//!   nv-test     - Test NV read/write operations
//!   nv-full     - Full NV test (define/write/read/undefine)
//!   primary     - Test primary key creation
//!   evict       - Test EvictControl (persistent key)
//!   seal        - Test seal/unseal operations (no PCR policy)
//!   seal-pcr    - Test seal/unseal operations with PCR policy
//!   quote       - Generate a TPM quote with RSA AK (requires GCP vTPM)
//!   quote-ecc   - Generate a TPM quote with ECC AK (requires GCP vTPM)
//!   all         - Run all tests

use std::env;
use tpm2::{tpm_rh, ResponseBuffer, TpmAlgId, TpmContext, TpmlPcrSelection, TpmtPublic, Unmarshal};

fn main() {
    let args: Vec<String> = env::args().collect();
    let command = args.get(1).map(|s| s.as_str()).unwrap_or("all");

    println!("=== TPM 2.0 Pure Rust Test Tool ===\n");

    match command {
        "info" => test_info(),
        "random" => test_random(),
        "pcr-read" => test_pcr_read(),
        "pcr-extend" => test_pcr_extend(),
        "nv-test" => test_nv_operations(),
        "nv-full" => test_nv_full(),
        "primary" => test_primary_key(),
        "evict" => test_evict_control(),
        "seal" => test_seal_unseal(),
        "quote" => test_quote_rsa(),
        "quote-ecc" => test_quote_ecc(),
        "seal-pcr" => test_seal_unseal_with_pcr(),
        "all" => {
            test_info();
            test_random();
            test_pcr_read();
            test_primary_key();
            test_nv_operations();
            test_seal_unseal();
            test_seal_unseal_with_pcr();
            test_quote_rsa();
            test_quote_ecc();
        }
        _ => {
            eprintln!("Unknown command: {}", command);
            eprintln!("Available commands: info, random, pcr-read, pcr-extend, nv-test, nv-full, primary, evict, seal, seal-pcr, seal-nv, quote, quote-ecc, all");
            std::process::exit(1);
        }
    }
}

fn test_info() {
    println!("--- Test: Device Info ---");

    match TpmContext::new(None) {
        Ok(ctx) => {
            println!("✓ TPM device opened: {}", ctx.device_path());
        }
        Err(e) => {
            println!("✗ Failed to open TPM device: {}", e);
        }
    }
    println!();
}

fn test_random() {
    println!("--- Test: Random Number Generation ---");

    let mut ctx = match TpmContext::new(None) {
        Ok(ctx) => ctx,
        Err(e) => {
            println!("✗ Failed to open TPM: {}", e);
            return;
        }
    };

    // Test getting 32 random bytes
    match ctx.get_random(32) {
        Ok(bytes) => {
            println!("✓ Generated 32 random bytes:");
            println!("  {}", hex::encode(&bytes));
        }
        Err(e) => {
            println!("✗ GetRandom failed: {}", e);
        }
    }

    // Test getting 64 random bytes (tests chunking)
    match ctx.get_random(64) {
        Ok(bytes) => {
            println!("✓ Generated 64 random bytes:");
            println!("  {}...", &hex::encode(&bytes)[..64]);
        }
        Err(e) => {
            println!("✗ GetRandom (64 bytes) failed: {}", e);
        }
    }
    println!();
}

fn test_pcr_read() {
    println!("--- Test: PCR Read ---");

    let mut ctx = match TpmContext::new(None) {
        Ok(ctx) => ctx,
        Err(e) => {
            println!("✗ Failed to open TPM: {}", e);
            return;
        }
    };

    // Read PCRs 0, 1, 2, 7
    let pcr_selection = TpmlPcrSelection::single(TpmAlgId::Sha256, &[0, 1, 2, 7]);

    match ctx.pcr_read(&pcr_selection) {
        Ok(values) => {
            println!("✓ Read {} PCR values:", values.len());
            for (idx, value) in values {
                println!("  PCR[{}] = {}", idx, hex::encode(&value));
            }
        }
        Err(e) => {
            println!("✗ PCR_Read failed: {}", e);
        }
    }
    println!();
}

fn test_primary_key() {
    println!("--- Test: Primary Key ---");

    let mut ctx = match TpmContext::new(None) {
        Ok(ctx) => ctx,
        Err(e) => {
            println!("✗ Failed to open TPM: {}", e);
            return;
        }
    };

    // Check if a persistent handle exists
    let test_handle: u32 = 0x81000100;

    match ctx.handle_exists(test_handle) {
        Ok(exists) => {
            println!("  Handle 0x{:08x} exists: {}", test_handle, exists);
        }
        Err(e) => {
            println!("✗ ReadPublic failed: {}", e);
        }
    }

    // Try to create a transient primary key
    println!("  Creating transient primary key under Owner hierarchy...");
    let template = tpm2::TpmtPublic::rsa_storage_key();
    match ctx.create_primary(tpm_rh::OWNER, &template) {
        Ok((handle, public)) => {
            println!("✓ Created primary key:");
            println!("  Handle: 0x{:08x}", handle);
            println!("  Public size: {} bytes", public.len());

            // Flush the transient handle
            if let Err(e) = ctx.flush_context(handle) {
                println!("  Warning: Failed to flush handle: {}", e);
            } else {
                println!("  Flushed transient handle");
            }
        }
        Err(e) => {
            println!("✗ CreatePrimary failed: {}", e);
        }
    }
    println!();
}

fn test_nv_operations() {
    println!("--- Test: NV Operations ---");

    let mut ctx = match TpmContext::new(None) {
        Ok(ctx) => ctx,
        Err(e) => {
            println!("✗ Failed to open TPM: {}", e);
            return;
        }
    };

    // Test NV index (use a test index in the owner range)
    let test_nv_index: u32 = 0x01800100;

    // Check if NV index exists
    match ctx.nv_exists(test_nv_index) {
        Ok(exists) => {
            println!("  NV index 0x{:08x} exists: {}", test_nv_index, exists);

            if exists {
                // Try to read it
                match ctx.nv_read(test_nv_index) {
                    Ok(Some(data)) => {
                        println!("✓ Read {} bytes from NV", data.len());
                        if data.len() <= 64 {
                            println!("  Data: {}", hex::encode(&data));
                        }
                    }
                    Ok(None) => {
                        println!("  NV index exists but couldn't read (auth required?)");
                    }
                    Err(e) => {
                        println!("✗ NV_Read failed: {}", e);
                    }
                }
            }
        }
        Err(e) => {
            println!("✗ NV_ReadPublic failed: {}", e);
        }
    }

    // Try to read GCP AK certificate (if on GCP)
    let gcp_ak_cert_index: u32 = 0x01C10000;
    println!(
        "\n  Checking GCP AK certificate at 0x{:08x}...",
        gcp_ak_cert_index
    );

    match ctx.nv_exists(gcp_ak_cert_index) {
        Ok(true) => {
            println!("  GCP AK certificate NV index exists!");
            match ctx.nv_read(gcp_ak_cert_index) {
                Ok(Some(data)) => {
                    println!("✓ Read GCP AK certificate: {} bytes", data.len());
                }
                Ok(None) => {
                    println!("  Couldn't read certificate data");
                }
                Err(e) => {
                    println!("✗ Failed to read certificate: {}", e);
                }
            }
        }
        Ok(false) => {
            println!("  GCP AK certificate not found (not on GCP vTPM?)");
        }
        Err(e) => {
            println!("✗ NV check failed: {}", e);
        }
    }
    println!();
}

fn test_quote_rsa() {
    println!("--- Test: Quote Generation with RSA AK (GCP vTPM) ---");

    let mut ctx = match TpmContext::new(None) {
        Ok(ctx) => ctx,
        Err(e) => {
            println!("✗ Failed to open TPM: {}", e);
            return;
        }
    };

    // Check if GCP AK template exists
    let gcp_ak_template_index: u32 = 0x01C10001; // RSA AK template

    match ctx.nv_exists(gcp_ak_template_index) {
        Ok(true) => {
            println!("  GCP AK template found, attempting to load AK...");

            // Read template
            match ctx.nv_read(gcp_ak_template_index) {
                Ok(Some(template)) => {
                    println!("  Read AK template: {} bytes", template.len());

                    // Create primary with template
                    match ctx.create_primary_from_template(tpm_rh::ENDORSEMENT, &template) {
                        Ok((handle, _public)) => {
                            println!("✓ Loaded GCP AK: handle 0x{:08x}", handle);

                            // Generate quote
                            let qualifying_data = [0u8; 32]; // Test nonce
                            let pcr_selection =
                                TpmlPcrSelection::single(TpmAlgId::Sha256, &[0, 2, 14]);

                            match ctx.quote(handle, &qualifying_data, &pcr_selection) {
                                Ok((quoted, signature)) => {
                                    println!("✓ Generated quote:");
                                    println!("  Quoted size: {} bytes", quoted.len());
                                    println!("  Signature size: {} bytes", signature.len());

                                    match verify_quote_pcr_digest(&mut ctx, &quoted, &pcr_selection)
                                    {
                                        Ok(()) => println!(
                                            "✓ Quote PCR digest matches current PCR values"
                                        ),
                                        Err(e) => println!(
                                            "✗ Quote PCR digest verification failed: {}",
                                            e
                                        ),
                                    }
                                }
                                Err(e) => {
                                    println!("✗ Quote failed: {}", e);
                                }
                            }

                            // Flush handle
                            let _ = ctx.flush_context(handle);
                        }
                        Err(e) => {
                            println!("✗ Failed to load AK: {}", e);
                        }
                    }
                }
                Ok(None) => {
                    println!("  Couldn't read AK template");
                }
                Err(e) => {
                    println!("✗ Failed to read template: {}", e);
                }
            }
        }
        Ok(false) => {
            println!("  GCP AK template not found (not on GCP vTPM)");
            println!("  Skipping quote test");
        }
        Err(e) => {
            println!("✗ NV check failed: {}", e);
        }
    }
    println!();
}

fn test_quote_ecc() {
    println!("--- Test: Quote Generation with ECC AK (GCP vTPM) ---");

    let mut ctx = match TpmContext::new(None) {
        Ok(ctx) => ctx,
        Err(e) => {
            println!("✗ Failed to open TPM: {}", e);
            return;
        }
    };

    // Check if GCP ECC AK template exists
    let gcp_ak_template_index: u32 = 0x01C10003; // ECC AK template

    match ctx.nv_exists(gcp_ak_template_index) {
        Ok(true) => {
            println!("  GCP ECC AK template found, attempting to load AK...");

            // Read template
            match ctx.nv_read(gcp_ak_template_index) {
                Ok(Some(template)) => {
                    println!("  Read ECC AK template: {} bytes", template.len());

                    // Create primary with template
                    match ctx.create_primary_from_template(tpm_rh::ENDORSEMENT, &template) {
                        Ok((handle, _public)) => {
                            println!("✓ Loaded GCP ECC AK: handle 0x{:08x}", handle);

                            // Generate quote
                            let qualifying_data = [0u8; 32]; // Test nonce
                            let pcr_selection =
                                TpmlPcrSelection::single(TpmAlgId::Sha256, &[0, 2, 14]);

                            match ctx.quote(handle, &qualifying_data, &pcr_selection) {
                                Ok((quoted, signature)) => {
                                    println!("✓ Generated ECC quote:");
                                    println!("  Quoted size: {} bytes", quoted.len());
                                    println!("  Signature size: {} bytes", signature.len());

                                    match verify_quote_pcr_digest(&mut ctx, &quoted, &pcr_selection)
                                    {
                                        Ok(()) => println!(
                                            "✓ Quote PCR digest matches current PCR values"
                                        ),
                                        Err(e) => println!(
                                            "✗ Quote PCR digest verification failed: {}",
                                            e
                                        ),
                                    }
                                }
                                Err(e) => {
                                    println!("✗ Quote failed: {}", e);
                                }
                            }

                            // Flush handle
                            let _ = ctx.flush_context(handle);
                        }
                        Err(e) => {
                            println!("✗ Failed to load ECC AK: {}", e);
                        }
                    }
                }
                Ok(None) => {
                    println!("  Couldn't read ECC AK template");
                }
                Err(e) => {
                    println!("✗ Failed to read template: {}", e);
                }
            }
        }
        Ok(false) => {
            println!("  GCP ECC AK template not found (not on GCP vTPM)");
            println!("  Skipping ECC quote test");
        }
        Err(e) => {
            println!("✗ NV check failed: {}", e);
        }
    }
    println!();
}

fn test_pcr_extend() {
    println!("--- Test: PCR Extend ---");
    println!("  Note: This test extends PCR 23 which is typically resettable");

    let mut ctx = match TpmContext::new(None) {
        Ok(ctx) => ctx,
        Err(e) => {
            println!("✗ Failed to open TPM: {}", e);
            return;
        }
    };

    // Read PCR 23 before extend
    let pcr_selection = TpmlPcrSelection::single(TpmAlgId::Sha256, &[23]);
    let before = match ctx.pcr_read(&pcr_selection) {
        Ok(values) => {
            if let Some((_, value)) = values.first() {
                println!("  PCR[23] before: {}", hex::encode(value));
                value.clone()
            } else {
                println!("✗ No PCR value returned");
                return;
            }
        }
        Err(e) => {
            println!("✗ PCR_Read failed: {}", e);
            return;
        }
    };

    // Extend PCR 23 with test data
    let test_hash = [0x42u8; 32]; // Test hash value
    match ctx.pcr_extend(23, &test_hash, TpmAlgId::Sha256) {
        Ok(()) => {
            println!("✓ PCR_Extend succeeded");
        }
        Err(e) => {
            println!("✗ PCR_Extend failed: {}", e);
            return;
        }
    }

    // Read PCR 23 after extend
    match ctx.pcr_read(&pcr_selection) {
        Ok(values) => {
            if let Some((_, value)) = values.first() {
                println!("  PCR[23] after:  {}", hex::encode(value));
                if value != &before {
                    println!("✓ PCR value changed as expected");
                } else {
                    println!("✗ PCR value did not change!");
                }
            }
        }
        Err(e) => {
            println!("✗ PCR_Read after extend failed: {}", e);
        }
    }
    println!();
}

fn test_nv_full() {
    println!("--- Test: Full NV Operations (Define/Write/Read/Undefine) ---");
    println!("  Warning: This test creates and deletes NV index 0x01800200");

    let mut ctx = match TpmContext::new(None) {
        Ok(ctx) => ctx,
        Err(e) => {
            println!("✗ Failed to open TPM: {}", e);
            return;
        }
    };

    let test_nv_index: u32 = 0x01800200;
    let test_data = b"Hello TPM NV!";

    // Clean up if index exists from previous failed test
    if ctx.nv_exists(test_nv_index).unwrap_or(false) {
        println!("  Cleaning up existing NV index...");
        let _ = ctx.nv_undefine(test_nv_index);
    }

    // Define NV index
    println!(
        "  Defining NV index 0x{:08x} with size {}...",
        test_nv_index,
        test_data.len()
    );
    match ctx.nv_define(test_nv_index, test_data.len(), true) {
        Ok(true) => {
            println!("✓ NV_DefineSpace succeeded");
        }
        Ok(false) => {
            println!("✗ NV_DefineSpace returned false");
            return;
        }
        Err(e) => {
            println!("✗ NV_DefineSpace failed: {}", e);
            return;
        }
    }

    // Write to NV index
    println!("  Writing {} bytes to NV...", test_data.len());
    match ctx.nv_write(test_nv_index, test_data) {
        Ok(true) => {
            println!("✓ NV_Write succeeded");
        }
        Ok(false) => {
            println!("✗ NV_Write returned false");
        }
        Err(e) => {
            println!("✗ NV_Write failed: {}", e);
        }
    }

    // Read from NV index
    println!("  Reading from NV...");
    match ctx.nv_read(test_nv_index) {
        Ok(Some(data)) => {
            println!("✓ NV_Read succeeded: {} bytes", data.len());
            if data == test_data {
                println!("✓ Data matches!");
            } else {
                println!("✗ Data mismatch!");
                println!("  Expected: {:?}", String::from_utf8_lossy(test_data));
                println!("  Got:      {:?}", String::from_utf8_lossy(&data));
            }
        }
        Ok(None) => {
            println!("✗ NV_Read returned None");
        }
        Err(e) => {
            println!("✗ NV_Read failed: {}", e);
        }
    }

    // Undefine NV index
    println!("  Undefining NV index...");
    match ctx.nv_undefine(test_nv_index) {
        Ok(true) => {
            println!("✓ NV_UndefineSpace succeeded");
        }
        Ok(false) => {
            println!("✗ NV_UndefineSpace returned false");
        }
        Err(e) => {
            println!("✗ NV_UndefineSpace failed: {}", e);
        }
    }

    // Verify it's gone
    match ctx.nv_exists(test_nv_index) {
        Ok(false) => {
            println!("✓ NV index successfully removed");
        }
        Ok(true) => {
            println!("✗ NV index still exists after undefine!");
        }
        Err(e) => {
            println!("✗ NV check failed: {}", e);
        }
    }
    println!();
}

fn test_evict_control() {
    println!("--- Test: EvictControl (Persistent Key) ---");
    println!("  Warning: This test creates and removes persistent key at 0x81000200");

    let mut ctx = match TpmContext::new(None) {
        Ok(ctx) => ctx,
        Err(e) => {
            println!("✗ Failed to open TPM: {}", e);
            return;
        }
    };

    let persistent_handle: u32 = 0x81000200;

    // Clean up if handle exists from previous failed test
    if ctx.handle_exists(persistent_handle).unwrap_or(false) {
        println!("  Cleaning up existing persistent handle...");
        // Need to evict it first - create a dummy transient and evict to remove
        let _ = ctx.evict_control(persistent_handle, persistent_handle);
    }

    // Create a transient primary key
    println!("  Creating transient primary key...");
    let template = TpmtPublic::rsa_storage_key();
    let (transient_handle, _public) = match ctx.create_primary(tpm_rh::OWNER, &template) {
        Ok(result) => {
            println!("✓ Created transient key: 0x{:08x}", result.0);
            result
        }
        Err(e) => {
            println!("✗ CreatePrimary failed: {}", e);
            return;
        }
    };

    // Make it persistent
    println!("  Making key persistent at 0x{:08x}...", persistent_handle);
    match ctx.evict_control(transient_handle, persistent_handle) {
        Ok(true) => {
            println!("✓ EvictControl succeeded - key is now persistent");
        }
        Ok(false) => {
            println!("✗ EvictControl returned false");
            let _ = ctx.flush_context(transient_handle);
            return;
        }
        Err(e) => {
            println!("✗ EvictControl failed: {}", e);
            let _ = ctx.flush_context(transient_handle);
            return;
        }
    }

    // Flush the transient handle (no longer needed)
    let _ = ctx.flush_context(transient_handle);

    // Verify persistent handle exists
    match ctx.handle_exists(persistent_handle) {
        Ok(true) => {
            println!("✓ Persistent handle exists");
        }
        Ok(false) => {
            println!("✗ Persistent handle not found!");
            return;
        }
        Err(e) => {
            println!("✗ Handle check failed: {}", e);
            return;
        }
    }

    // Remove the persistent key
    println!("  Removing persistent key...");
    match ctx.evict_control(persistent_handle, persistent_handle) {
        Ok(true) => {
            println!("✓ Persistent key removed");
        }
        Ok(false) => {
            println!("✗ EvictControl (remove) returned false");
        }
        Err(e) => {
            println!("✗ EvictControl (remove) failed: {}", e);
        }
    }

    // Verify it's gone
    match ctx.handle_exists(persistent_handle) {
        Ok(false) => {
            println!("✓ Persistent handle successfully removed");
        }
        Ok(true) => {
            println!("✗ Persistent handle still exists!");
        }
        Err(_) => {
            // Expected - handle doesn't exist
            println!("✓ Persistent handle successfully removed");
        }
    }
    println!();
}

fn test_seal_unseal() {
    println!("--- Test: Seal/Unseal Operations ---");

    let mut ctx = match TpmContext::new(None) {
        Ok(ctx) => ctx,
        Err(e) => {
            println!("✗ Failed to open TPM: {}", e);
            return;
        }
    };

    // First, ensure we have a primary key
    println!("  Creating primary storage key...");
    let template = TpmtPublic::rsa_storage_key();
    let (parent_handle, _) = match ctx.create_primary(tpm_rh::OWNER, &template) {
        Ok(result) => {
            println!("✓ Created parent key: 0x{:08x}", result.0);
            result
        }
        Err(e) => {
            println!("✗ CreatePrimary failed: {}", e);
            return;
        }
    };

    // Data to seal
    let secret_data = b"This is my secret data for TPM sealing test!";
    println!("  Sealing {} bytes of data...", secret_data.len());

    // Seal the data without PCR policy (simpler test)
    let empty_pcr_selection = TpmlPcrSelection::default();
    let (pub_blob, priv_blob) = match ctx.seal(
        secret_data,
        parent_handle,
        &empty_pcr_selection,
        TpmAlgId::Sha256,
    ) {
        Ok(result) => {
            println!("✓ Seal succeeded:");
            println!("  Public blob: {} bytes", result.0.len());
            println!("  Private blob: {} bytes", result.1.len());
            result
        }
        Err(e) => {
            println!("✗ Seal failed: {}", e);
            let _ = ctx.flush_context(parent_handle);
            return;
        }
    };

    // Unseal the data (use same empty PCR selection as seal)
    println!("  Unsealing data...");
    match ctx.unseal(
        &pub_blob,
        &priv_blob,
        parent_handle,
        &empty_pcr_selection,
        TpmAlgId::Sha256,
    ) {
        Ok(unsealed) => {
            println!("✓ Unseal succeeded: {} bytes", unsealed.len());
            if unsealed == secret_data {
                println!("✓ Data matches original!");
                println!("  Content: {:?}", String::from_utf8_lossy(&unsealed));
            } else {
                println!("✗ Data mismatch!");
                println!("  Expected: {:?}", String::from_utf8_lossy(secret_data));
                println!("  Got:      {:?}", String::from_utf8_lossy(&unsealed));
            }
        }
        Err(e) => {
            println!("✗ Unseal failed: {}", e);
        }
    }

    // Clean up
    let _ = ctx.flush_context(parent_handle);
    println!();
}

fn parse_quote_attestation(quoted: &[u8]) -> anyhow::Result<(TpmlPcrSelection, Vec<u8>)> {
    let mut buf = ResponseBuffer::new(quoted);

    let magic = buf.get_u32()?;
    let attest_type = buf.get_u16()?;
    if magic != 0xff544347 {
        anyhow::bail!("unexpected TPMS_ATTEST.magic: 0x{:08x}", magic);
    }
    if attest_type != 0x8018 {
        anyhow::bail!("unexpected TPMS_ATTEST.type: 0x{:04x}", attest_type);
    }
    let _qualified_signer = buf.get_tpm2b()?;
    let _extra_data = buf.get_tpm2b()?;

    let _clock = buf.get_u64()?;
    let _reset_count = buf.get_u32()?;
    let _restart_count = buf.get_u32()?;
    let _safe = buf.get_u8()?;

    let _firmware_version = buf.get_u64()?;

    let pcr_select = TpmlPcrSelection::unmarshal(&mut buf)?;
    let pcr_digest = buf.get_tpm2b()?;

    Ok((pcr_select, pcr_digest))
}

fn verify_quote_pcr_digest(
    ctx: &mut TpmContext,
    quoted: &[u8],
    requested_selection: &TpmlPcrSelection,
) -> anyhow::Result<()> {
    use sha2::{Digest, Sha256, Sha384, Sha512};

    let (attested_selection, attested_digest) = parse_quote_attestation(quoted)?;

    if attested_selection.pcr_selections.len() != requested_selection.pcr_selections.len() {
        anyhow::bail!("quote returned unexpected PCR selection count");
    }
    for (a, r) in attested_selection
        .pcr_selections
        .iter()
        .zip(requested_selection.pcr_selections.iter())
    {
        if a.hash.to_u16() != r.hash.to_u16() || a.pcr_select != r.pcr_select {
            anyhow::bail!("quote returned PCR selection different from request");
        }
    }

    if requested_selection.pcr_selections.len() != 1 {
        anyhow::bail!("quote PCR verification only supports a single PCR bank selection");
    }
    let hash_alg = requested_selection.pcr_selections[0].hash;

    let mut values = ctx.pcr_read(requested_selection)?;
    values.sort_by_key(|(idx, _)| *idx);
    let mut concat = Vec::new();
    for (_, v) in values {
        concat.extend_from_slice(&v);
    }

    let computed = match hash_alg {
        TpmAlgId::Sha256 => Sha256::digest(&concat).to_vec(),
        TpmAlgId::Sha384 => Sha384::digest(&concat).to_vec(),
        TpmAlgId::Sha512 => Sha512::digest(&concat).to_vec(),
        _ => anyhow::bail!("unsupported hash algorithm for quote PCR digest verification"),
    };
    if computed != attested_digest {
        anyhow::bail!("pcrDigest mismatch");
    }

    Ok(())
}

fn test_seal_unseal_with_pcr() {
    println!("--- Test: Seal/Unseal Operations with PCR Policy ---");
    println!("  This seals data bound to PCR[23] (SHA256)");

    let mut ctx = match TpmContext::new(None) {
        Ok(ctx) => ctx,
        Err(e) => {
            println!("✗ Failed to open TPM: {}", e);
            return;
        }
    };

    println!("  Creating primary storage key...");
    let template = TpmtPublic::rsa_storage_key();
    let (parent_handle, _) = match ctx.create_primary(tpm_rh::OWNER, &template) {
        Ok(result) => {
            println!("✓ Created parent key: 0x{:08x}", result.0);
            result
        }
        Err(e) => {
            println!("✗ CreatePrimary failed: {}", e);
            return;
        }
    };

    let secret_data = b"PCR protected secret data!";
    let pcr_selection = TpmlPcrSelection::single(TpmAlgId::Sha256, &[23]);
    println!(
        "  Sealing {} bytes of data with PCR policy...",
        secret_data.len()
    );

    let (pub_blob, priv_blob) =
        match ctx.seal(secret_data, parent_handle, &pcr_selection, TpmAlgId::Sha256) {
            Ok(result) => {
                println!("✓ Seal succeeded with PCR policy");
                result
            }
            Err(e) => {
                println!("✗ Seal failed: {}", e);
                let _ = ctx.flush_context(parent_handle);
                return;
            }
        };

    println!("  Reading PCR values for verification...");
    match ctx.pcr_read(&pcr_selection) {
        Ok(values) => {
            for (idx, value) in values {
                println!("  PCR[{}] = {}", idx, hex::encode(value));
            }
        }
        Err(e) => println!("  Warning: failed to read PCRs: {}", e),
    }

    println!("  Attempting to unseal data (PCRs must match)...");
    let unsealed_ok = match ctx.unseal(
        &pub_blob,
        &priv_blob,
        parent_handle,
        &pcr_selection,
        TpmAlgId::Sha256,
    ) {
        Ok(unsealed) => {
            println!("✓ Unseal succeeded: {} bytes", unsealed.len());
            if unsealed == secret_data {
                println!("✓ Data matches original!");
                println!("  Content: {:?}", String::from_utf8_lossy(&unsealed));
            } else {
                println!("✗ Data mismatch!");
            }
            true
        }
        Err(e) => {
            println!("✗ Unseal failed (PCR mismatch?): {}", e);
            false
        }
    };

    if unsealed_ok {
        println!("  Extending PCR 23 to ensure unseal fails in a different PCR environment...");
        let extend_value = [0xA5u8; 32];
        match ctx.pcr_extend(23, &extend_value, TpmAlgId::Sha256) {
            Ok(()) => println!("✓ PCR_Extend succeeded"),
            Err(e) => println!("✗ PCR_Extend failed: {}", e),
        }

        println!("  Attempting to unseal again (must FAIL after PCR change)...");
        match ctx.unseal(
            &pub_blob,
            &priv_blob,
            parent_handle,
            &pcr_selection,
            TpmAlgId::Sha256,
        ) {
            Ok(_) => println!("✗ Unseal unexpectedly succeeded after PCR change!"),
            Err(_) => println!("✓ Unseal failed after PCR change (expected)"),
        }
    }

    let _ = ctx.flush_context(parent_handle);
    println!();
}
