// SPDX-FileCopyrightText: © 2025 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

//! Pure Rust TPM 2.0 implementation
//!
//! This crate provides TPM 2.0 commands, communicating directly with the TPM
//! device without C library dependencies.
//!
//! ## Features
//!
//! - **Cross-compilation friendly**: Easy to cross-compile for different targets
//! - **Direct device communication**: Talks directly to `/dev/tpmrm0` or `/dev/tpm0`
//!
//! ## Supported Commands
//!
//! - NV operations: `NV_Read`, `NV_Write`, `NV_DefineSpace`, `NV_UndefineSpace`
//! - PCR operations: `PCR_Read`, `PCR_Extend`
//! - Key operations: `CreatePrimary`, `Create`, `Load`, `EvictControl`
//! - Sealing: `Seal`, `Unseal` with PCR policy
//! - Attestation: `Quote`
//! - Random: `GetRandom`
//! - Sessions: Policy sessions for PCR-based authorization
//!
//! ## Example
//!
//! ```no_run
//! use tpm2::TpmContext;
//!
//! let mut ctx = TpmContext::new(None)?; // Auto-detect TPM device
//! let random_bytes = ctx.get_random(32)?;
//! # Ok::<(), anyhow::Error>(())
//! ```

mod commands;
mod constants;
mod device;
mod marshal;
mod session;
mod types;

pub use commands::TpmContext;
pub use constants::*;
pub use types::*;

// Re-export device for advanced usage
pub use device::{TpmCommand, TpmDevice, TpmResponse};
pub use marshal::{CommandBuffer, Marshal, ResponseBuffer, Unmarshal};
pub use session::AuthSession;
