// SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

//! pick a vsock CID window that doesn't collide with a VMM already on the host.

use anyhow::{bail, Result};
use rand::Rng;

/// size of a VMM's CID pool (matches `config::VmmRender` default). This is what
/// ends up in `cvm.cid_pool_size`.
const CID_POOL_SIZE: u32 = 1000;

/// spacing between candidate pool starts, and the width we require to be free
/// before taking one.
///
/// This is an installer-side heuristic only: it is never written to vmm.toml and
/// the VMM knows nothing about it. Requiring a whole stride to be free leaves an
/// instance room to raise `cvm.cid_pool_size` later without walking into a
/// neighbour, and striding the candidate space keeps a random pick cheap to
/// verify.
const CID_BLOCK_STRIDE: u32 = 10_000;

/// lowest candidate start. The first stride is skipped because CIDs 0-2 are
/// reserved (hypervisor, local, host).
const CID_MIN: u32 = CID_BLOCK_STRIDE;

/// highest candidate start, chosen so `start + CID_BLOCK_STRIDE` stays in u32.
const CID_MAX: u32 = u32::MAX - CID_BLOCK_STRIDE;

/// how many candidates to try before giving up.
const CID_PICK_ATTEMPTS: usize = 8;

/// whether `[start, start + width)` intersects any occupied range. Both sides
/// are half-open.
fn window_overlaps(start: u32, width: u32, occupied: &[(u32, u32)]) -> bool {
    let end = start.saturating_add(width);
    occupied.iter().any(|&(s, e)| start < e && s < end)
}

/// number of stride-aligned candidate blocks in `[CID_MIN, CID_MAX]`.
fn candidate_blocks() -> u32 {
    (CID_MAX - CID_MIN) / CID_BLOCK_STRIDE + 1
}

/// an endless stream of stride-aligned starts drawn uniformly from the CID space.
///
/// Random rather than "the next free block above everything in use": two installs
/// racing on the same host would compute the same next block from the same
/// observation and collide deterministically, and a single stray high CID from an
/// unrelated QEMU would drag every later install up with it.
fn random_starts() -> impl Iterator<Item = u32> {
    let mut rng = rand::thread_rng();
    let blocks = candidate_blocks();
    std::iter::repeat_with(move || CID_MIN + rng.gen_range(0..blocks) * CID_BLOCK_STRIDE)
}

/// first candidate whose whole stride is free, within the attempt budget.
fn first_free(candidates: impl Iterator<Item = u32>, occupied: &[(u32, u32)]) -> Option<u32> {
    candidates
        .take(CID_PICK_ATTEMPTS)
        .find(|&start| !window_overlaps(start, CID_BLOCK_STRIDE, occupied))
}

/// choose a CID window that won't collide with a VMM already on this host.
///
/// Precedence: an explicit `--cid-start` is honored but refused on overlap; then
/// the start a previous install recorded; then a random free block.
pub(crate) fn pick_cid_start(
    explicit: Option<u32>,
    recorded: Option<u32>,
    occupied: &[(u32, u32)],
) -> Result<u32> {
    pick_cid_start_from(explicit, recorded, occupied, random_starts())
}

fn pick_cid_start_from(
    explicit: Option<u32>,
    recorded: Option<u32>,
    occupied: &[(u32, u32)],
    candidates: impl Iterator<Item = u32>,
) -> Result<u32> {
    if let Some(start) = explicit {
        // An explicit choice is checked against the pool it actually asks for,
        // not the stride: the operator picked the number, so don't demand
        // growth headroom they didn't ask for.
        if window_overlaps(start, CID_POOL_SIZE, occupied) {
            match first_free(candidates, occupied) {
                Some(free) => bail!(
                    "--cid-start {start} overlaps a CID range already reserved on this host; \
                     pick a free start, e.g. --cid-start {free}"
                ),
                None => bail!(
                    "--cid-start {start} overlaps a CID range already reserved on this host; \
                     pick a free start"
                ),
            }
        }
        return Ok(start);
    }

    // A recorded start already belongs to this install, so a re-run reuses it
    // verbatim and never moves a live instance's pool out from under its running
    // CVMs. It is deliberately not re-checked: `occupied` includes this install's
    // own VMM, so the check could only ever fail against itself.
    if let Some(start) = recorded {
        return Ok(start);
    }

    match first_free(candidates, occupied) {
        Some(start) => {
            println!("  [ok] cid-start {start} (avoids CIDs already reserved on this host)");
            Ok(start)
        }
        None => bail!(
            "could not find a free CID window in {CID_PICK_ATTEMPTS} attempts; \
             pass --cid-start <start> explicitly"
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn takes_the_first_candidate_when_the_host_is_empty() {
        let picked = pick_cid_start_from(None, None, &[], [40_000, 50_000].into_iter()).unwrap();
        assert_eq!(picked, 40_000);
    }

    #[test]
    fn skips_candidates_whose_stride_is_taken() {
        let occupied = [(40_000, 41_000), (50_000, 50_001)];
        let picked =
            pick_cid_start_from(None, None, &occupied, [40_000, 50_000, 60_000].into_iter())
                .unwrap();
        assert_eq!(picked, 60_000);
    }

    #[test]
    fn a_candidate_needs_its_whole_stride_free_not_just_its_pool() {
        // 45_000 is clear of [40_000, 41_000) as a 1000-wide pool, but it sits
        // inside that candidate's stride, so the block is rejected.
        let occupied = [(45_000, 45_001)];
        assert!(window_overlaps(40_000, CID_BLOCK_STRIDE, &occupied));
        assert!(!window_overlaps(40_000, CID_POOL_SIZE, &occupied));
        let picked =
            pick_cid_start_from(None, None, &occupied, [40_000, 60_000].into_iter()).unwrap();
        assert_eq!(picked, 60_000);
    }

    #[test]
    fn gives_up_after_the_attempt_budget() {
        let occupied = [(40_000, 50_000)];
        let err = pick_cid_start_from(None, None, &occupied, std::iter::repeat(40_000))
            .unwrap_err()
            .to_string();
        assert!(err.contains("could not find a free CID window"), "{err}");
    }

    #[test]
    fn explicit_is_honored_when_its_pool_is_free() {
        // Overlaps the *stride* of an occupied block but not its pool, which an
        // explicit choice is allowed to do.
        let occupied = [(40_000, 41_000)];
        let picked =
            pick_cid_start_from(Some(45_000), None, &occupied, [60_000].into_iter()).unwrap();
        assert_eq!(picked, 45_000);
    }

    #[test]
    fn explicit_is_refused_on_overlap_and_suggests_a_free_start() {
        let occupied = [(40_000, 41_000)];
        let err = pick_cid_start_from(Some(40_500), None, &occupied, [60_000].into_iter())
            .unwrap_err()
            .to_string();
        assert!(err.contains("--cid-start 40500 overlaps"), "{err}");
        assert!(err.contains("e.g. --cid-start 60000"), "{err}");
    }

    #[test]
    fn explicit_wins_over_a_recorded_start() {
        let picked =
            pick_cid_start_from(Some(45_000), Some(70_000), &[], [60_000].into_iter()).unwrap();
        assert_eq!(picked, 45_000);
    }

    #[test]
    fn a_recorded_start_is_reused_verbatim() {
        // The install's own VMM shows up in `occupied`; reusing must not treat
        // that as a conflict, otherwise every re-run would move the pool.
        let occupied = [(70_000, 71_000)];
        let picked =
            pick_cid_start_from(None, Some(70_000), &occupied, [60_000].into_iter()).unwrap();
        assert_eq!(picked, 70_000);
    }

    #[test]
    fn random_starts_are_aligned_and_leave_room_for_a_stride() {
        for start in random_starts().take(64) {
            assert!((CID_MIN..=CID_MAX).contains(&start), "{start} out of range");
            assert_eq!(start % CID_BLOCK_STRIDE, 0, "{start} is not stride-aligned");
            assert!(start.checked_add(CID_BLOCK_STRIDE).is_some(), "{start}");
        }
    }
}
