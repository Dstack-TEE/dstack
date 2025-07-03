use log::debug;
use sha2::{Digest, Sha384};

/// Computes a SHA384 hash of the given data.
pub(crate) fn measure_sha384(data: &[u8]) -> Vec<u8> {
    Sha384::new_with_prefix(data).finalize().to_vec()
}

pub(crate) fn utf16_encode(input: &str) -> Vec<u8> {
    input
        .encode_utf16()
        .flat_map(|c| c.to_le_bytes().into_iter())
        .collect()
}

pub(crate) fn debug_print_log(name: &str, log: &[Vec<u8>]) {
    debug!("{name} event log:");
    for (i, entry) in log.iter().enumerate() {
        debug!("[{i}] digest: {}", hex::encode(entry));
    }
}
/// Computes a measurement of the given RTMR event log.
pub(crate) fn measure_log(log: &[Vec<u8>]) -> Vec<u8> {
    let mut mr = [0u8; 48]; // SHA384 output size
    for entry in log {
        let mut hasher = Sha384::new();
        hasher.update(mr);
        hasher.update(entry);
        mr = hasher.finalize().into();
    }
    mr.to_vec()
}
