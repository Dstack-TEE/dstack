// SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

use std::{fs, io, sync::Mutex};

use crate::error::ProviderError;

const SEALING_KEY_PATH: &str = "/dev/attestation/keys/_sgx_mrenclave";
const USER_REPORT_DATA_PATH: &str = "/dev/attestation/user_report_data";
const QUOTE_PATH: &str = "/dev/attestation/quote";
const REPORT_DATA_SIZE: usize = 64;

// Gramine's attestation pseudo-files share mutable state. A quote must be read
// while holding the same lock used to write its report data.
static ATTESTATION_LOCK: Mutex<()> = Mutex::new(());

pub fn sealing_key() -> Result<Vec<u8>, ProviderError> {
    fs::read(SEALING_KEY_PATH).map_err(|error| map_io_error("reading the SGX sealing key", error))
}

pub fn quote(report_data: &[u8]) -> Result<Vec<u8>, ProviderError> {
    if report_data.len() > REPORT_DATA_SIZE {
        return Err(ProviderError::InvalidRequest(format!(
            "SGX report data is {} bytes; maximum is {REPORT_DATA_SIZE}",
            report_data.len()
        )));
    }

    let _guard = ATTESTATION_LOCK
        .lock()
        .map_err(|_| ProviderError::Synchronization("attestation lock is poisoned"))?;

    let mut padded = [0_u8; REPORT_DATA_SIZE];
    padded[..report_data.len()].copy_from_slice(report_data);
    fs::write(USER_REPORT_DATA_PATH, padded)
        .map_err(|error| map_io_error("setting SGX report data", error))?;
    fs::read(QUOTE_PATH).map_err(|error| map_io_error("reading the SGX quote", error))
}

fn map_io_error(operation: &'static str, source: io::Error) -> ProviderError {
    if source.kind() == io::ErrorKind::PermissionDenied {
        ProviderError::RestartRequired { operation, source }
    } else {
        ProviderError::AttestationIo { operation, source }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn permission_denied_requires_restart() {
        let error = map_io_error(
            "testing attestation",
            io::Error::from_raw_os_error(libc_eacces()),
        );
        assert!(error.requires_restart());
    }

    #[test]
    fn other_io_errors_do_not_require_restart() {
        let error = map_io_error(
            "testing attestation",
            io::Error::new(io::ErrorKind::NotFound, "missing"),
        );
        assert!(!error.requires_restart());
    }

    // Avoid adding libc solely for one test.
    const fn libc_eacces() -> i32 {
        13
    }
}
