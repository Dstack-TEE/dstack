// SPDX-FileCopyrightText: © 2025 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

//! Test TDX attestation functions on real TDX hardware.

use dcap_qvl::collateral::get_collateral_and_verify;
use dcap_qvl::quote::Quote;

#[tokio::main]
async fn main() {
    println!("=== TDX Attestation Test ===\n");

    // Test get_report
    println!("1. Testing get_report...");
    let report_data = [0u8; 64];
    match tdx_attest::get_report(&report_data) {
        Ok(report) => {
            println!("   ✓ get_report succeeded");
            println!("   Report size: {} bytes", report.0.len());
            println!("   Report hash: {:02x?}", &report.0[..32]);
        }
        Err(e) => {
            println!("   ✗ get_report failed: {}", e);
        }
    }

    // Test get_quote
    println!("\n2. Testing get_quote...");
    let report_data = [0x42u8; 64];
    let quote = match tdx_attest::get_quote(&report_data) {
        Ok(quote) => {
            println!("   ✓ get_quote succeeded");
            println!("   Quote size: {} bytes", quote.len());
            println!("   Quote header: {:02x?}", &quote[..32.min(quote.len())]);
            Some(quote)
        }
        Err(e) => {
            println!("   ✗ get_quote failed: {}", e);
            None
        }
    };

    // Parse and verify quote with dcap-qvl
    if let Some(ref quote) = quote {
        println!("\n3. Parsing quote...");
        match Quote::parse(quote) {
            Ok(q) => {
                println!("   ✓ Quote parsed");
                println!("   Version: {}", q.header.version);
                if let Some(report) = q.report.as_td10() {
                    println!("   MRTD: {}...", hex::encode(&report.mr_td[..16]));
                    println!("   RTMR3: {}...", hex::encode(&report.rt_mr3[..16]));
                }
            }
            Err(e) => {
                println!("   ✗ Quote parse failed: {:?}", e);
            }
        }

        println!("\n4. Verifying quote with PCCS...");
        let pccs_url = std::env::var("PCCS_URL").ok();
        println!(
            "   PCCS URL: {}",
            pccs_url.as_deref().unwrap_or("(default)")
        );
        match get_collateral_and_verify(quote, pccs_url.as_deref()).await {
            Ok(verified) => {
                println!("   ✓ Quote verified!");
                println!("   QE status: {:?}", verified.qe_status);
                if let Some(report) = verified.report.as_td10() {
                    if report.report_data[..] == report_data[..] {
                        println!("   ✓ Report data matches");
                    } else {
                        println!("   ✗ Report data mismatch!");
                    }
                }
            }
            Err(e) => {
                println!("   ✗ Verification failed: {:?}", e);
            }
        }
    }

    // Test extend_rtmr (RTMR 3 is user-extensible)
    println!("\n5. Testing extend_rtmr (RTMR 3)...");
    let digest = [0xABu8; 48];
    match tdx_attest::extend_rtmr(3, 0, digest) {
        Ok(()) => {
            println!("   ✓ extend_rtmr succeeded");
        }
        Err(e) => {
            println!("   ✗ extend_rtmr failed: {:?}", e);
        }
    }

    println!("\n=== Test Complete ===");
}
