// SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

//! pick a vsock CID window that doesn't collide with a VMM already on the host.

use anyhow::{bail, Result};

/// size of a VMM's CID pool (matches `config::VmmRender` default).
const CID_POOL_SIZE: u32 = 1000;
/// default CID pool start when nothing else is using that range.
const DEFAULT_CID_START: u32 = 1000;

/// whether `[start, start+CID_POOL_SIZE)` intersects any occupied range.
fn cid_window_overlaps(start: u32, occupied: &[(u32, u32)]) -> bool {
    let end = start.saturating_add(CID_POOL_SIZE);
    occupied.iter().any(|&(s, e)| start < e && s < end)
}

/// the lowest pool-aligned CID block at or above every occupied range. We jump
/// above the highest reservation rather than packing into a free gap below it —
/// simpler, and the result is always collision-free.
fn next_free_cid_block(occupied: &[(u32, u32)]) -> u32 {
    let max_end = occupied
        .iter()
        .map(|&(_, e)| e)
        .max()
        .unwrap_or(DEFAULT_CID_START);
    (max_end.div_ceil(CID_POOL_SIZE) * CID_POOL_SIZE).max(DEFAULT_CID_START)
}

/// choose a CID window `[start, start+CID_POOL_SIZE)` that won't collide with a
/// VMM already running on this host. With an explicit `--cid-start`, honor it
/// but refuse on overlap; without one, use the default unless it's taken, then
/// move to the next free block.
pub(crate) fn pick_cid_start(explicit: Option<u32>, occupied: &[(u32, u32)]) -> Result<u32> {
    match explicit {
        Some(n) => {
            if cid_window_overlaps(n, occupied) {
                bail!(
                    "--cid-start {n} overlaps a CID range already reserved on this host; \
                     pick a free start, e.g. --cid-start {}",
                    next_free_cid_block(occupied)
                );
            }
            Ok(n)
        }
        None if !cid_window_overlaps(DEFAULT_CID_START, occupied) => Ok(DEFAULT_CID_START),
        None => {
            let start = next_free_cid_block(occupied);
            println!("  [ok] cid-start {start} (avoids CIDs already reserved by another VMM)");
            Ok(start)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cid_default_when_range_free() {
        assert_eq!(pick_cid_start(None, &[]).unwrap(), 1000);
        // a pool entirely above the default window leaves it free.
        assert_eq!(pick_cid_start(None, &[(2000, 3000)]).unwrap(), 1000);
    }

    #[test]
    fn cid_auto_offsets_past_an_existing_vmm() {
        // another VMM reserving [1000,2000) -> jump to 2000.
        assert_eq!(pick_cid_start(None, &[(1000, 2000)]).unwrap(), 2000);
        // its reserved pool plus a stray live CVM at 2500 -> jump past it.
        assert_eq!(
            pick_cid_start(None, &[(1000, 2000), (2500, 2501)]).unwrap(),
            3000
        );
    }

    #[test]
    fn cid_explicit_honored_or_refused() {
        assert_eq!(pick_cid_start(Some(2000), &[(1000, 2000)]).unwrap(), 2000);
        assert!(pick_cid_start(Some(1000), &[(1000, 2000)]).is_err());
    }
}
