// SPDX-FileCopyrightText: © 2025 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

//! Property-test driver for the parsers that consume attacker-controlled bytes.
//!
//! Every parser in the attestation and measurement path is handed bytes an
//! unauthenticated requester chose, and release binaries are built with
//! `panic = "abort"` (`dstack/Cargo.toml`), so a panic in one of them aborts
//! `dstack-verifier` or `dstack-kms` rather than failing one request. The
//! property each suite encodes is therefore the weakest useful one: *for
//! arbitrary input bytes the call returns — `Ok` or `Err` — within a bounded
//! time and never panics*.
//!
//! This crate owns only the mechanics that all of those suites share, so the
//! per-crate modules stay a list of strategies and invariants:
//!
//! - [`check`] drives a strategy from a **fixed seed** with a **bounded case
//!   count**, so a failure reproduces exactly and the suite stays fast enough
//!   to sit in the ordinary `cargo test` gate. `cargo-fuzz` needs nightly and
//!   a separate build; the toolchain here is pinned stable
//!   (`rust-toolchain.toml`), so the search that runs in CI has to be this one.
//! - [`within_deadline`] runs the whole search on a worker thread and fails on
//!   a deadline. A missing termination guard shows up as a hang, and a hang in
//!   `cargo test` stalls CI instead of reporting anything.
//! - [`corpus_files`] loads the checked-in byte patterns that actually broke a
//!   parser, so each one stays a regression test whether or not the random
//!   search rediscovers it.

use std::path::Path;
use std::sync::mpsc::{channel, RecvTimeoutError};
use std::time::Duration;

pub use proptest;

use proptest::strategy::Strategy;
use proptest::test_runner::{Config, FailurePersistence, RngAlgorithm, TestRng, TestRunner};

/// Case count for a parser property.
///
/// Large enough to reach the interesting shapes of a length-prefixed format,
/// small enough that the whole robustness suite stays a few seconds. Raise it
/// locally when hunting, not in the committed test.
pub const CASES: u32 = 256;

/// Wall-clock budget for one property's whole search.
///
/// A parser that terminates does thousands of [`CASES`] a second on bounded
/// input, so anything near this is a termination bug, not a slow machine.
pub const BUDGET: Duration = Duration::from_secs(30);

/// Budget for a single call on one concrete input.
pub const CASE_BUDGET: Duration = Duration::from_secs(5);

/// Run `body` on a worker thread, failing if it does not finish within
/// `budget`.
///
/// The thread is deliberately abandoned on timeout: it is running a parser
/// that has not terminated, and there is nothing to cancel it with. `cargo
/// test` exits the process once the remaining tests finish.
pub fn within_deadline<T, F>(what: &str, budget: Duration, body: F) -> T
where
    T: Send + 'static,
    F: FnOnce() -> T + Send + 'static,
{
    let (tx, rx) = channel();
    std::thread::spawn(move || {
        let _ = tx.send(body());
    });
    match rx.recv_timeout(budget) {
        Ok(value) => value,
        Err(RecvTimeoutError::Timeout) => {
            panic!("{what} did not finish within {budget:?}")
        }
        Err(RecvTimeoutError::Disconnected) => panic!("{what} panicked"),
    }
}

/// Drive `property` over `CASES` values drawn from `strategy`, seeded by
/// `seed`, under a [`BUDGET`] deadline.
///
/// `seed` is the whole reproduction recipe: the same seed, case count and
/// strategy replay the same inputs in the same order on any machine. Failure
/// persistence is off so a red CI run never wants to write a
/// `.proptest-regressions` file — a counterexample worth keeping belongs in
/// the crate's corpus directory instead, where it is reviewable.
pub fn check<S, F>(what: &str, seed: [u8; 32], strategy: S, property: F)
where
    S: Strategy + Send + 'static,
    S::Value: std::fmt::Debug,
    F: Fn(S::Value) -> Result<(), proptest::test_runner::TestCaseError> + Send + 'static,
{
    let label = what.to_string();
    let outcome = within_deadline(what, BUDGET, move || {
        let config = Config {
            cases: CASES,
            failure_persistence: None::<Box<dyn FailurePersistence>>,
            ..Config::default()
        };
        let rng = TestRng::from_seed(RngAlgorithm::ChaCha, &seed);
        TestRunner::new_with_rng(config, rng)
            .run(&strategy, property)
            .map_err(|err| err.to_string())
    });
    if let Err(err) = outcome {
        panic!("{label}: {err}");
    }
}

/// Run `body` on one concrete input under a [`CASE_BUDGET`] deadline.
///
/// This is what the corpus tests use: the interesting property of a checked-in
/// pattern is that it still finishes, and several of them are patterns that
/// once did not.
pub fn case<F>(what: &str, body: F)
where
    F: FnOnce() + Send + 'static,
{
    within_deadline(what, CASE_BUDGET, body)
}

/// Load every corpus file under `dir`, sorted by name.
///
/// Panics if the directory is missing or empty: a corpus that silently stopped
/// being read is worse than no corpus, because the suite still passes.
pub fn corpus_files(dir: impl AsRef<Path>) -> Vec<(String, Vec<u8>)> {
    let dir = dir.as_ref();
    let mut files = vec![];
    let entries = std::fs::read_dir(dir)
        .unwrap_or_else(|err| panic!("failed to read corpus dir {}: {err}", dir.display()));
    for entry in entries {
        let path = match entry {
            Ok(entry) => entry.path(),
            Err(err) => panic!("failed to read corpus entry in {}: {err}", dir.display()),
        };
        if !path.is_file() || path.extension().is_some_and(|ext| ext == "md") {
            continue;
        }
        let Some(name) = path.file_name().map(|n| n.to_string_lossy().into_owned()) else {
            panic!("corpus entry {} has no file name", path.display());
        };
        let bytes = std::fs::read(&path)
            .unwrap_or_else(|err| panic!("failed to read corpus file {}: {err}", path.display()));
        files.push((name, bytes));
    }
    files.sort_by(|a, b| a.0.cmp(&b.0));
    assert!(!files.is_empty(), "corpus dir {} is empty", dir.display());
    files
}
