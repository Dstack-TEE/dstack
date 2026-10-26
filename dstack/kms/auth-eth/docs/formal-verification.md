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
- `contracts/IAppAuth.sol`, `contracts/IAppAuthBasicManagement.sol` — interfaces

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
- [ ] No CI integration (intentional — see "What's intentionally not in
      scope" below)

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

Single-call (`test/DstackKms.symbolic.t.sol`):
- [x] `check_RegisterApp_AnyCallerCanRegisterNonZeroAddress` + `_RejectsZeroAddress`
      — codifies the permissionless-by-design behavior; see "Findings"
- [x] `check_IsAppAllowed_RejectsUnregisteredApp` / `_RejectsUnknownOsImage`
      — fully symbolic `AppBootInfo`; the failing gate produces the
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

- **CI gating of Slither / Halmos.** Symbolic execution is slow, solver-
  version-sensitive, and produces non-actionable noise as a PR gate.
  Run locally during development; treat these as design checks rather
  than blocking lints.
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
