// SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

//! Hardware validation utility. Prints only public TCB metadata or a seed hash.
//! Run inside a disposable SNP guest; never expose it as an application API.

use anyhow::{bail, Context, Result};
use sev_snp_attest::sealing::{derive_sealing_seed, initial_tcb_version};
use sha2::{Digest, Sha256};

fn main() -> Result<()> {
    let mut args = std::env::args().skip(1);
    let argument = args
        .next()
        .context("usage: sealing_probe --initial-tcb | TCB_HEX")?;
    if args.next().is_some() {
        bail!("expected one argument");
    }
    if argument == "--initial-tcb" {
        println!("TCB_VERSION=0x{:016x}", initial_tcb_version()?);
        return Ok(());
    }
    let tcb = u64::from_str_radix(argument.strip_prefix("0x").unwrap_or(&argument), 16)
        .context("invalid TCB hex value")?;
    let seed = derive_sealing_seed(tcb)?;
    println!("KEY_SHA256={}", hex::encode(Sha256::digest(seed.as_ref())));
    Ok(())
}
