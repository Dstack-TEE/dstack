<!-- SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network> -->
<!-- SPDX-License-Identifier: Apache-2.0 -->
<a id="tc-vmm-install-007"></a>
# TC-VMM-INSTALL-007: Source installer checkout resolution and failure handling

## Metadata

- Priority: P2
- Type: Functional, Regression
- Minimum environment: UNIT
- Automation: Yes
- Requirements: [req-vmm-install-007](../../../../catalog/feature-audit.md#req-vmm-install-007)
- Risks: [risk-vmm-install-007](../../../../catalog/feature-audit.md#risk-vmm-install-007)
- Source: `dstack/scripts/install.sh`

## Prepared execution knowledge

- Read and obey [`shared/automation/execution-guide.md`](../../../../shared/automation/execution-guide.md) before executing Step 1.
- Read `DSTACK_TEST_RUNTIME_MANIFEST` once and use its `repository` as the only source of the candidate `dstack/scripts/install.sh`.
- The case is hermetic. It needs `sh` and `git` only: a local git origin replaces the GitHub repository, and a stub `cargo` first on `PATH` records its working directory and writes an executable `target/release/dstackup` instead of building. Never let the installer reach the network, `sudo`, or `/usr/local`.
- Feed the script on stdin (`sh -s -- ...`) from a working directory that is not a checkout, the way `curl ... | sh` runs it, so the installer cannot resolve the candidate repository itself as its source.

## Objective

Verify that `dstack/scripts/install.sh` resolves the source checkout it builds `dstackup` from, whether it clones into a new `--src`, updates an existing one, or uses a temporary checkout, and that it refuses an invalid source or prefix before building.

## Preconditions

1. `sh` and `git` are available; no network access is required.
2. A case-scoped temporary directory holds the local origin, stub `cargo`, `TMPDIR`, working directory, and every `--prefix`.

## Test Data

```json
{
  "origin_layout": ["dstack/Cargo.toml", "dstack/crates/dstackup/", "dstack/crates/dstack-cli/", "dstack/vmm/", "dstack/supervisor/"],
  "ref": "dtest-install",
  "common_args": ["--repo", "<case origin>", "--ref", "dtest-install", "--no-sudo"]
}
```

## Steps

<a id="tc-vmm-install-007-step-01"></a>
### Step 1: Clone into a new source directory

Run the installer with `--src <case>/src` (absent) and `--prefix <case>/prefix-clone`.

**Expected results:**

- Exit status is 0; the stub `cargo` ran exactly once with working directory `<case>/src/dstack`; `<case>/prefix-clone/bin/dstackup` exists and is executable.
- `cloning dstack source into` appears on stderr and not on stdout.

<a id="tc-vmm-install-007-step-02"></a>
### Step 2: Update an existing checkout and use a temporary checkout

Run the installer again with the same `--src` and a new prefix, then run it without `--src` and with `TMPDIR` set to the case directory.

**Expected results:**

- The second run exits 0, reports `updating dstack source in` on stderr only, builds in `<case>/src/dstack`, and installs `dstackup`.
- The run without `--src` exits 0, builds exactly once in `<TMPDIR>/dstack-install.*/source/dstack`, installs `dstackup`, and leaves no `dstack-install.*` directory under `TMPDIR`.

<a id="tc-vmm-install-007-step-03"></a>
### Step 3: Refuse invalid inputs before building

Run the installer with an existing `--src` directory that is not a dstack checkout, then with `--prefix relative/prefix`.

**Expected results:**

- The non-checkout source exits non-zero with `exists but is not a dstack git checkout` on stderr, never invokes `cargo`, and installs nothing.
- The relative prefix exits non-zero with `--prefix must be an absolute path` on stderr and never invokes `cargo`.

## Post-baseline regression coverage (PR #1162)

- Before PR #1162 the progress messages and git output of `resolve_source` went to stdout, so `checkout=$(resolve_source)` captured them with the path and the build directory was wrong. Against the pre-fix script, the Step 1 row and both Step 2 rows fail; against the candidate they pass.

## Post-baseline regression coverage (PR #1227)

- `resolve_source` now sets `checkout` in the installer's own shell instead of a `$(resolve_source)` subshell, so the `EXIT` trap sees `tmp_src` and removes the temporary checkout. The temporary-checkout row gates on `temporary_checkout_removed`; against the pre-fix script it fails because `<TMPDIR>/dstack-install.*` is left behind.

## Post-baseline regression coverage (PR #1393)

- The installer builds `dstackup` with `cargo build --release --locked`. The stub `cargo` also records its arguments, and every row that builds (Steps 1 and 2) must pass `--locked`. `dstackup` itself adds `--locked` when it builds the managed binaries (`dstack/crates/dstackup/src/install.rs`); that path needs a real source build and is not exercised here.

## Postconditions

The case-scoped temporary directory, including the local origin, checkouts, prefixes, and its private `TMPDIR`, is removed when the harness exits. Nothing outside it is modified.
