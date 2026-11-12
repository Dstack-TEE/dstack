<!--
SPDX-FileCopyrightText: © 2025 Phala Network <dstack@phala.network>
SPDX-License-Identifier: Apache-2.0
-->

# Formal Verification Plan — `kms/auth-eth`

A layered approach: cheap static analysis → SMTChecker invariants → Halmos
symbolic tests → (optional) Certora. Each layer is independently mergeable.

The **formal specification** these layers verify against lives in
[`specification.md`](./specification.md). The spec is normative — code
and tests track the spec, not the other way around.

Reference: <https://github.com/leonardoalt/ethereum_formal_verification_overview>

## Targets

The two contracts under verification are authorization gates for TEE workloads;
correctness matters more than gas.

- `contracts/DstackApp.sol` (209 LOC) — per-app boot authorization
- `contracts/DstackKms.sol` (276 LOC) — KMS whitelist + factory
- `contracts/IAppAuth.sol`, `contracts/IAppEpochAuth.sol`, `contracts/IAppEpochManagement.sol` — interfaces

## Layer 0 — Slither (static analysis)

Not formal verification but the standard first pass. Catches reentrancy,
shadowing, uninitialized state, unsafe `delegatecall`, etc.

- [ ] Install slither-analyzer (Python via pipx or as a uv tool)
- [ ] Add `slither.config.json` at `kms/auth-eth/` excluding `lib/`, `out/`,
      `cache/`, `node_modules/`, `test/` (focus on production contracts)
- [ ] Run baseline `slither contracts/` and triage findings into:
      - real → fix
      - false-positive / wontfix → suppress with `// slither-disable-next-line`
        and a justifying comment
<!-- CI integration intentionally not added — see "What's intentionally not
in scope" below. Slither runs locally before risky changes. -->
- [x] Slither runs locally; no CI gate (intentional)
- [ ] Update `kms/auth-eth/README.md` with one line on how to run Slither locally

**Effort:** ~1h. **Owner:** _tbd_.

## Layer 1 — SMTChecker (deferred)

**Status: deferred.** Originally planned as the cheap free tier, but the
practical setup cost is high enough that it's not worth doing before Halmos.

What was tried (and why it fails to deliver value here):

1. **CHC engine + `solvers = ["z3"]`:** solc's binary distributions on
   foundry's `svm` (Solidity version manager) are not compiled with z3
   linkage. Result: every analysis emits `Warning (7649): CHC analysis was
   not possible since no Horn solver was found and enabled`.
2. **CHC engine + `solvers = ["smtlib2"]`:** solc emits SMT-LIB2 queries
   but does not auto-spawn an external solver. Without a wrapper, nothing
   actually runs.
3. **BMC engine:** runs, but on our OZ-upgradeable contracts emits only
   `Warning (5724): SMTChecker: N unsupported language feature(s)` —
   delegatecall, complex modifiers, and proxy patterns aren't in scope.
   Net useful findings: zero.

To enable SMTChecker properly we'd need to either:
- build solc from source with `USE_Z3=1`, ship the binary, point forge at it
  (via `solc = "/path/to/our/solc"` in `foundry.toml`);
- or run solc in a container image like `ethereum/solc:0.8.24-z3` and wire
  it into CI.

Either path is significant infra work. Halmos (Layer 2) covers everything
SMTChecker would prove on our contracts (asserts, overflows, owner-gated
mutations) while also handling the symbolic-input cases SMTChecker can't
(TCB string compare, `isAppAllowed` decision table), using a solver that's
already a Foundry-native install.

Revisit Layer 1 only if we want defense-in-depth alongside Halmos.

## Layer 2 — Halmos symbolic tests

[Halmos](https://github.com/a16z/halmos) runs Foundry-style tests with all
function arguments as symbolic variables. Sweet spot for our contracts: we
reuse the existing `.t.sol` scaffolding and OZ-foundry-upgrades plugin.

### Setup

- [x] `pipx install halmos` documented in `README.md`
- [x] Runs in CI (`.github/workflows/halmos.yml`) when `dstack/kms/auth-eth`
      changes, with pinned Halmos and Forge versions

### What we verify

All tests are **single-call symbolic** (each `check_*` proves a property
over symbolic inputs to one call). One test —
`check_UpgradesDisabled_StepPreservation` — is the inductive *step* of a
cross-transaction property (INV-1); see its entry and the note in
"What we deliberately do not verify here" for the precise scope.

We explicitly avoid the "symbolic clothing" failure mode where each
owner-gated function gets its own `_OnlyOwner` test — those degenerate
to a fuzz test of `OwnableUpgradeable.onlyOwner` (upstream-tested),
and Halmos adds no information over bounded fuzzing. Where the spec
says `pre: msg.sender == owner()`, we trust the OZ modifier.

`test/DstackApp.symbolic.t.sol`:
- [x] `check_DisableUpgrades_BlocksNextUpgrade` — after `disableUpgrades()`,
      the *next* upgrade attempt reverts for any caller / impl / init data.
- [x] `check_UpgradesDisabled_StepPreservation` — INV-1 inductive step:
      from the canonical disabled state, no single call to any of the
      enumerated externally-callable mutating functions (symbolic
      selector + symbolic args + symbolic caller), issued against the
      *proxy*, flips `_upgradesDisabled` back to false. Validated by
      mutation testing: a permissionless flag-reset and an owner-callable
      flag-reset are both caught. Scope caveat below.
- [x] `check_Initialize5Arg_DefaultsTcbToFalse` and `_HonorsTcbFlag`
      (6-arg) — initializer storage-layout coverage. Not symbolically
      stronger than bounded fuzz for the assertion they make; they're
      kept because they're cheap and would catch a slot-shift regression
      faster than a unit test would.
- [x] `check_Initialize_OnceOnly` — after setUp's successful 5-arg
      init, both `initialize` overloads revert for any inputs.
      Verifies INV-3.

`test/DstackAppEpoch.symbolic.t.sol` (app epochs; setUp advances to epoch 2
and admits one app per epoch, then one symbolic owner write where noted):
- [x] `check_AppEpoch_StepMonotonic` — no call to any enumerated mutating
      function, by any caller, decreases `currentAppEpoch`; it moves only by
      one, through the owner's `advanceAppEpoch(current)`.
- [x] `check_PolicyWrite_RejectsEpochPastNext` — every `*AtEpoch` setter
      reverts for an epoch above the next one, and every `*AtEpochs` setter
      for a range ending above it, for any caller; the owner may prepare the
      next epoch's row before advancing.
- [x] `check_AuthorizeApp_RejectsInactiveEpochAndForeignOperation` — an
      epoch above the current one or a non-app operation is never authorized.
- [x] `check_IsAppAllowed_RefusesAtNonzeroEpoch` — once the app epoch has
      advanced, the legacy `isAppAllowed` refuses, since its callers derive
      epoch-0 keys.
- [x] `check_IsAppAllowed_EqualsEpochZeroDecisionBeforeAdvance` — at app
      epoch 0, with the next row prepared and any one owner write, the legacy
      `isAppAllowed` returns exactly the `authorizeApp` result at epoch 0.
- [x] `check_PolicyWrite_PreservesOtherEpochDecisions` — a write never
      changes an authorization decision at an epoch outside the rows it names
      (one epoch, or a symbolic range), including epoch 0's legacy fields.
- [x] `check_AuthorizeApp_MatchesPolicy` — for both app operations,
      `authorizeApp` allows exactly when the epoch is active, the TCB
      requirement holds, that epoch admits the compose hash, and the device
      is allowed by `allowAnyDevice` or that epoch's device row.
- [x] `check_PolicyWrite_TakesEffect` — each `*AtEpoch` setter on an epoch
      up to the next one, and each `*AtEpochs` setter on every row of a range
      ending at most there, either sets the value it was given or reverts on
      a zero ID.
- [x] `check_FullRangeRemoval_RevokesAtEveryAppEpoch` — after removing a
      compose hash from rows 0 through the next epoch, or a device from those
      rows and clearing `allowAnyDevice`, no app epoch authorizes it, for
      either app operation.

Mutation-tested: requiring both the any-device flag and a listed device,
dropping a setter's epoch bound or widening it past the next epoch, aliasing epoch 1 onto the
legacy fields, letting `isAppAllowed` decide at a nonzero epoch or read the
prepared next row, a permissionless
`advanceAppEpoch` and dropping its stale-transaction guard each produce a
counterexample. Dropping the inactive-epoch check in `_authorizeApp` does
not: policy for an inactive epoch cannot be written, so that check is
defense in depth.

`test/DstackKmsEpoch.symbolic.t.sol` (root epochs; setUp registers epochs
0-2, activates 1 so that 2 is pending, admits one KMS identity and OS image
per epoch, and deploys an app at app epoch 1):
- [x] `check_RootRegistry_StepInvariant` — after any single call to any
      enumerated mutating function, by any caller with symbolic args: the
      current epoch stays registered and moves only by one, through the
      owner's activation naming its chain hash; the registry changes by at
      most one entry at its end, and only the owner's pop of a pending
      epoch naming its chain hash removes one; existing entries keep their
      keys and hashes; every chain hash commits to its keys and the previous
      hash; `kmsInfo` holds the current keys without legacy evidence.
- [x] `check_RegisterRootEpoch_AcceptsOnlyCanonicalEncodings` — registration
      succeeds exactly for a 91-byte uncompressed P-256 SPKI and a 33-byte
      compressed secp256k1 key.
- [x] `check_Authorize_EnforcesEpochBounds` — a wrong-kind operation, an app
      or `kms_serve` root epoch above the current one, another KMS root epoch
      above the latest registered one, or an app epoch above the app's current one is never
      authorized; every result reports the current root epoch and hash.
- [x] `check_Authorize_OnlyBootstrapBeforeRegistration` — with no root epoch
      registered, only `kms_bootstrap` can be authorized.
- [x] `check_AuthorizeKms_MatchesEpochPolicy` — after any one owner write,
      KMS authorization allows exactly when the selected root epoch is
      registered (current at most for `kms_serve`), the TCB is up to date, and that epoch's row admits the OS
      image, aggregated MR and device.
- [x] `check_AuthorizeApp_MatchesKmsAndAppPolicy` — app authorization allows
      exactly when both epochs are active, the selected root epoch admits
      the OS image, and the app's own `authorizeApp` admits it.
- [x] `check_KmsPolicyWrite_PreservesOtherEpochDecisions` — a KMS policy
      write never changes a KMS decision at a root epoch outside the rows it
      names (one epoch, or a symbolic range).
- [x] `check_FullRangeRemoval_RevokesAtEveryEpoch` — after removing an OS
      image, aggregated MR or KMS device from rows 0 through the latest, no
      request carrying it is authorized at any root or app epoch, for any KMS
      operation, nor for app operations in the OS image case.
- [x] `check_PopThenRegister_StartsWithEmptyRows` — popping the pending
      epoch and registering the number again, with the same keys or others,
      leaves all three of its rows empty.
- [x] `check_EpochZeroRows_AreTheLegacyMappings` — after any one owner
      write, the v0.5.x getters and the epoch 0 getters agree.
- [x] `check_AuthorizeApp_LegacyPolicyOnlyAtAppEpochZero` — an app policy
      without `IAppEpochAuth`, like v0.5.x and v0.6.0 `DstackApp`, is
      authorized exactly when the KMS checks pass at the selected root epoch,
      no nonzero app epoch is requested, and its `isAppAllowed` admits it;
      its app epoch is reported as 0.
- [x] `check_LegacyEntryPoints_RefuseOnceRotated` — once a later root epoch
      is current, `isKmsAllowed` and `isAppAllowed` refuse.
- [x] `check_LegacyKmsCheck_ReadsEpochZeroBeforeRotation` — before any
      rotation, with the next epoch registered and prepared, `isKmsAllowed`
      decides as `kms_serve` at root epoch 0.

Mutation-tested: a chain hash that ignores the previous epoch, activation
that leaves `kmsInfo` stale, a pop that ignores the chain hash, app requests
selecting a pending root epoch, KMS requests limited to the current epoch,
`isKmsAllowed` reading the pending epoch or still deciding after a rotation, accepting an `0x04` k256 tag, an
OS image row aliasing epoch 1 onto the legacy row, an app check skipping the
OS image, and non-bootstrap operations before registration each produce a
counterexample.

The bounds test found that wrong-kind rejections reported root epoch
`(0, 0x0)`, contrary to the KMS README; fixed in #1538.

Single-call (`test/DstackKms.symbolic.t.sol`):
- [x] `check_RegisterApp_AnyCallerCanRegisterNonZeroAddress` + `_RejectsZeroAddress`
      — codifies the permissionless-by-design behavior; see "Findings"
- [x] `check_IsAppAllowed_RejectsUnregisteredApp` / `_RejectsUnknownOsImage`
      — fully symbolic `AppInfo`; the failing gate produces the
      right rejection reason without delegating
- [x] `check_IsAppAllowed_DelegatesFaithfully` — when both KMS gates
      pass, the outer return equals the registered `IAppAuth`'s return.
      Uses `MockConfigurableApp` whose `isAppAllowed` returns a
      symbolic boolean (both branches explored). Caveat: the mock has
      a single observable behavior shape; it does not universally
      quantify over all possible registered contracts.
- [x] `check_IsAppAllowed_PropagatesMockRevert` — a reverting
      `MockRevertingApp` makes the outer `kms.isAppAllowed` revert,
      not return `(false, …)`. Spec §5.1.
- [x] `check_IsKmsAllowed_RejectsUnknownMr` and `_RejectsUnknownDevice`
      — short-circuit gates for the `kmsAllowed*` whitelists
- [x] `check_DeployAndRegisterApp_PostState` — when the 6-arg factory
      returns, all six post-conditions (registered, owner,
      allowAnyDevice, requireTcbUpToDate, and the conditional
      device/compose-hash branches per spec §3.3) hold simultaneously
- [x] `check_DeployAndRegisterApp5Arg_DefaultsTcbToFalse` — same shape
      as above, plus `requireTcbUpToDate == false`
- [x] `check_Owner_NotChangedByKmsFunctions` — INV-2 inductive step:
      no call to any of DstackKms's own mutating functions (symbolic
      selector + args + caller, against the proxy) changes `owner()`;
      the inherited OZ ownership functions are excluded (upstream-
      tested). Mutation-tested: catches owner-seizure in permissionless
      functions (incl. via the indirect `deployAndRegisterApp` →
      `registerApp` path) and owner-writes in owner-only functions.

### What we deliberately do not verify here

- **Owner-gated mutations.** `OwnableUpgradeable.onlyOwner` is upstream-
  tested; the spec records the precondition (§3.7, §3.11) and trusts it.
- **TCB byte-exactness via symbolic strings.** Halmos models `keccak256`
  as an uninterpreted function, so a check of
  `allowed == (keccak(x) == keccak("UpToDate"))` against code that
  computes `allowed = (keccak(x) == keccak("UpToDate"))` is circular.
  The byte-exact-under-collision-resistance argument lives in the spec
  (§3.9) where it can be honest about being an assumption rather than
  a proof.
- **Adversarial mock OOG / malformed-returndata paths.** OOG propagates
  to the outer call by EVM semantics. Misshapen returndata would
  trigger Solidity's strict ABI decoder revert; spec §6.5 calls this
  out as a useful next mock variant.
- **Universal quantification over the registered `IAppAuth` contract.**
  Halmos instantiates one mock at a time; it does not quantify over
  arbitrary contracts. The two mock-driven tests bound the relevant
  shapes (faithful return; revert propagation), and the spec is
  explicit (§3.5) about treating the registered contract's output as
  untrusted downstream.
- **Full cross-transaction monotonicity (INV-1) over arbitrary
  pre-states.** `check_UpgradesDisabled_StepPreservation` proves the
  inductive *step* only from the canonical disabled state, over the
  enumerated mutating surface. A complete proof would symbolically
  quantify the pre-state (Halmos 0.3.3 has no `--symbolic-storage`)
  and enumerate the surface programmatically rather than by hand.
  The residual risk is closed by source inspection — see spec §4 INV-1
  (only two writers to the slot; the initializer path is closed by
  `check_Initialize_OnceOnly`). An earlier attempt to mechanize this
  with Halmos invariant-mode (`--invariant-depth`) was discarded: the
  auto-target fuzzer drove the implementation contract while the
  assertion read the proxy, so it passed vacuously (a flag-reset
  mutant was not caught). The step-test formulation reads and writes
  the same proxy storage and does catch such mutants.
- **Full cross-transaction monotonicity (INV-2) over arbitrary
  pre-states.** Like INV-1, `check_Owner_NotChangedByKmsFunctions`
  proves the inductive step from the canonical post-init state, not
  over arbitrary pre-states. The two-step ownership *behaviour* itself
  (stage / accept / reject / re-target) is covered by unit tests in
  `DstackKms.t.sol` / `DstackApp.t.sol`.
- **INV-6 (`__gap` zeroes).** Gap; would need the same step-test or
  symbolic-storage treatment.

### Findings from the initial run

- **`DstackKms.registerApp` is intentionally permissionless** (confirmed
  by the dstack team). The Halmos counterexample on an earlier
  `_OnlyOwner` test reflected design, not a bug: any non-zero address
  can be registered by anyone. Authorization is gated downstream by the
  owner-controlled `allowedOsImages` whitelist and the registered app's
  own `isAppAllowed`. The natspec on `registerApp` documents this;
  `check_RegisterApp_AnyCallerCanRegisterNonZeroAddress` codifies it.
  Crucially, `check_IsAppAllowed_DelegatesFaithfully` proves that even
  an adversarial registered contract is consulted only after the
  owner-controlled OS-image gate passes — registration alone confers
  no privilege.

- **Two-step ownership transfer adopted.** Both contracts now inherit
  `Ownable2StepUpgradeable` instead of `OwnableUpgradeable`. The new
  storage uses ERC-7201 namespaced slots, so existing UUPS proxies can
  be safely upgraded to the new impl (no slot collision; the pending-
  owner slot is zero-initialized on first upgrade). `transferOwnership`
  no longer immediately transfers — the proposed owner must call
  `acceptOwnership` to complete the transfer, eliminating the typo-bricks-
  contract risk on the single-step variant.

**Effort:** ~1 focused day. **Owner:** _tbd_.

## Layer 3 — Certora (deferred)

Deferred until a security review budget exists. CVL specs are 3-5× the size of
Halmos tests, require team licenses, and overlap with Halmos coverage for
authorization-style properties.

If we revisit, target the same invariants as Layer 2 but add:

- Storage-layout safety across upgrades (especially the
  `@custom:oz-renamed-from tproxyAppId` rename — Certora's storage diff is
  stronger than the OZ Foundry plugin's)
- Cross-contract invariants spanning `DstackKms` ↔ `DstackApp`

## What's intentionally not in scope

- **CI gating of Slither.** It produces non-actionable noise as a PR gate;
  run it locally during development.
- **Echidna** — overlaps with Foundry's built-in fuzzer (already runs 10k
  iterations under `FOUNDRY_PROFILE=ci` in `.github/workflows/foundry-test.yml`).
- **Manticore / Mythril** — bytecode-level tools, slow, awkward with our
  forge artifacts.
- **Scribble** — runtime assertions, redundant with our `assert` + Foundry
  test approach.

## Status

| Layer | Status | PR |
|-------|--------|----|
| 0. Slither | done (0 findings) | this branch |
| 1. SMTChecker | deferred (see above) | — |
| 2. Halmos symbolic (DstackApp) | done (5 properties, incl. INV-1 step) | this branch |
| 2. Halmos symbolic (DstackKms) | done (11 properties, incl. INV-2 step) | this branch |
| 3. Certora | deferred | — |

Update this table as PRs land.
