<!--
SPDX-FileCopyrightText: © 2025 Phala Network <dstack@phala.network>
SPDX-License-Identifier: Apache-2.0
-->

# DstackKms + DstackApp — Formal Specification

This document specifies the **intended** behavior of `contracts/DstackKms.sol`
and `contracts/DstackApp.sol` independently of their implementation. It is
the deliverable an external formal-verification engagement (Runtime
Verification, ChainSecurity, Certora) would build against.

Notation:

- `pre`: caller / state / argument constraints that must hold before the call.
  Violating `pre` is allowed to revert with any reason.
- `post`: state and return-value guarantees after a successful call.
- `frame`: storage cells that **must not change** on a successful call.
  Cells not listed in `frame` may or may not change.
- `events`: events that must be emitted on success.
- `reverts`: enumerated revert conditions. Any unlisted revert is a spec
  violation.

Where a property has a corresponding Halmos symbolic proof, the test name
is cited inline as `(verified: TestContract.check_X)`. Properties without
a citation are **specification gaps** awaiting verification.

## 1. Trust model

| Principal | Trusted for | Not trusted for |
|---|---|---|
| `owner` (KMS) | All write operations on KMS; deciding the OS-image whitelist; upgrading the KMS implementation | Liveness (may renounce or be replaced via 2-step transfer) |
| `owner` (App) | All write operations on a specific App; upgrading that App implementation (unless disabled) | Behaving consistently across apps — each app's owner is independent |
| `pendingOwner` | Has the *option* to take ownership; no privilege until they call `acceptOwnership` | Not yet authoritative; current owner can override the pending transfer |
| Any EOA / contract | Calling `registerApp` (permissionless), calling read methods | Any state mutation other than registration |
| Registered `IAppAuth` contract | Returning `(bool, string)` from `isAppAllowed`; honoring the `view` mutability declared at the interface | Adversarial registered apps may return arbitrary values, revert, or consume all gas — the KMS treats their output as untrusted |
| EVM | Standard semantics (gas, calldata, storage, `STATICCALL` propagation) | — |
| ERC1967 / OZ proxy stack | Storage layout via ERC-7201; correct delegatecall to impl | — |
| Off-chain attestation pipeline | Emitting the byte-exact ASCII string `"UpToDate"` as `tcbStatus` when reporting healthy TCB | — |

### Boundary calls

`DstackKms.isAppAllowed(b)` performs an **external view call** into
`IAppAuth(b.appId).isAppAllowed(b)`. Because the outer function is `view`,
the EVM lifts the call into `STATICCALL`, which propagates: the registered
contract cannot mutate KMS state by any path. Out-of-gas, revert, and
return-value spoofing are still possible — see §6.

## 2. State variables

### DstackKms

| Slot | Name | Type | Writable by | Notes |
|---|---|---|---|---|
| 0–3 | `kmsInfo` | `KmsInfo` (struct, 4 fields) | `setKmsInfo`, `setKmsQuote`, `setKmsEventlog` (owner) | |
| 4 | `gatewayAppId` | `string` | `setGatewayAppId` (owner) | Renamed from `tproxyAppId`; carries `@custom:oz-renamed-from` |
| 5 | `registeredApps` | `mapping(address => bool)` | `registerApp` (anyone), `deployAndRegisterApp` (anyone) | Permissionless — see §6.1 |
| 6 | `kmsAllowedAggregatedMrs` | `mapping(bytes32 => bool)` | `addKmsAggregatedMr`, `removeKmsAggregatedMr` (owner) | |
| 7 | `kmsAllowedDeviceIds` | `mapping(bytes32 => bool)` | `addKmsDevice`, `removeKmsDevice` (owner) | |
| 8 | `allowedOsImages` | `mapping(bytes32 => bool)` | `addOsImageHash`, `removeOsImageHash` (owner) | |
| 9 | `appImplementation` | `address` | `setAppImplementation` (owner) | Used by `deployAndRegisterApp` |
| 10 | `__gap[50]` | `uint256[50]` | (none — must always read zero) | Reserved |

Plus inherited storage in ERC-7201 namespaces: `OwnableUpgradeable`,
`Ownable2StepUpgradeable`, `UUPSUpgradeable`, `ERC165Upgradeable`,
`Initializable`.

### DstackApp

| Slot | Name | Type | Writable by |
|---|---|---|---|
| 0 | `allowedComposeHashes` | `mapping(bytes32 => bool)` | `addComposeHash`, `removeComposeHash` (owner); 5/6-arg initializer |
| 1 | `_upgradesDisabled` + `allowAnyDevice` (packed) | `bool` + `bool` | `disableUpgrades` (owner, monotonic); `setAllowAnyDevice` (owner); initializer |
| 2 | `allowedDeviceIds` | `mapping(bytes32 => bool)` | `addDevice`, `removeDevice` (owner); initializer |
| 3 | `requireTcbUpToDate` | `bool` | `setRequireTcbUpToDate` (owner); 6-arg initializer only |
| 4 | `__gap[49]` | `uint256[49]` | (none) |

## 3. Public surface — pre/post/frame

### 3.1 `DstackKms.initialize(address initialOwner, address _appImplementation)`

- **pre**: contract is not yet initialized; `initialOwner != address(0)`;
  `_appImplementation != address(0)`.
- **post**: `owner() == initialOwner`; `appImplementation == _appImplementation`;
  `_getInitializableStorage()._initialized == 1`.
- **frame**: all mappings, `gatewayAppId`, `kmsInfo`.
- **reverts**: already-initialized; either address is zero.

### 3.2 `DstackKms.registerApp(address appId) public` — **permissionless by design**

- **pre**: `appId != address(0)`.
- **post**: `registeredApps[appId] == true`.
- **frame**: every storage cell except `registeredApps[appId]`.
- **events**: `AppRegistered(appId)`.
- **reverts**: `appId == address(0)`.
- **Note**: No caller restriction. Confirmed-intentional. See §6.1 for
  the threat model around this.
- (verified: `DstackKmsSymbolicTest.check_RegisterApp_AnyCallerCanRegisterNonZeroAddress`,
  `check_RegisterApp_RejectsZeroAddress`)

### 3.3 `DstackKms.deployAndRegisterApp(...)` — 6-arg

Signature: `deployAndRegisterApp(address initialOwner, bool disableUpgrades, bool requireTcbUpToDate, bool allowAnyDevice, bytes32 initialDeviceId, bytes32 initialComposeHash) public returns (address appId)`

- **pre**: `appImplementation != address(0)`; `initialOwner != address(0)`.
- **post**:
  - `registeredApps[appId] == true`.
  - `appId` is a freshly-deployed ERC1967 proxy whose implementation is
    `appImplementation`.
  - The proxy is initialized: `DstackApp(appId).owner() == initialOwner`;
    `DstackApp(appId).requireTcbUpToDate() == requireTcbUpToDate`;
    `DstackApp(appId).allowAnyDevice() == allowAnyDevice`;
    `allowedDeviceIds[initialDeviceId] == (initialDeviceId != 0)`;
    `allowedComposeHashes[initialComposeHash] == (initialComposeHash != 0)`.
- **frame**: every KMS storage cell except `registeredApps[appId]`.
- **events**: `AppRegistered(appId)`, `AppDeployedViaFactory(appId, msg.sender)`.
- **reverts**: implementation unset; owner is zero.
- (verified, single-call post-state only:
  `DstackKmsSymbolicTest.check_DeployAndRegisterApp_PostState`)

### 3.4 `DstackKms.deployAndRegisterApp(...)` — 5-arg backward-compatible

Signature: `deployAndRegisterApp(address initialOwner, bool disableUpgrades, bool allowAnyDevice, bytes32 initialDeviceId, bytes32 initialComposeHash) external returns (address appId)`

- Semantics: equivalent to the 6-arg overload with `requireTcbUpToDate = false`.
- (verified: `DstackKmsSymbolicTest.check_DeployAndRegisterApp5Arg_DefaultsTcbToFalse`)

### 3.5 `DstackKms.isAppAllowed(AppBootInfo b) external view returns (bool, string)`

Decision (in order):

1. If `!registeredApps[b.appId]` → return `(false, "App not registered")`.
2. If `!allowedOsImages[b.osImageHash]` → return `(false, "OS image is not allowed")`.
3. If `b.appId.code.length == 0` → return `(false, "App not deployed or invalid address")`.
4. Otherwise return `IAppAuth(b.appId).isAppAllowed(b)` — forwarded verbatim.

- **frame**: entire storage.
- **assumes (§6)**: the delegated call may revert or consume all gas;
  the spec does not bound its behavior.
- (verified, single-call:
  `DstackKmsSymbolicTest.check_IsAppAllowed_RejectsUnregisteredApp`,
  `check_IsAppAllowed_RejectsUnknownOsImage`,
  `check_IsAppAllowed_DelegatesFaithfully`)
- The delegation property uses a `MockConfigurableApp` whose
  `isAppAllowed` returns a symbolic boolean — both `true` and `false`
  branches are explored. The mock does not model reverting / OOG
  behavior of an adversarial registered app; those propagate to the
  outer call by EVM semantics (§5.1).

### 3.6 `DstackKms.isKmsAllowed(AppBootInfo b) external view returns (bool, string)`

Decision (in order):

1. If `keccak256(bytes(b.tcbStatus)) != keccak256(bytes("UpToDate"))` →
   `(false, "TCB status is not up to date")`.
2. If `!allowedOsImages[b.osImageHash]` → `(false, "OS image is not allowed")`.
3. If `!kmsAllowedAggregatedMrs[b.mrAggregated]` → `(false, "Aggregated MR not allowed")`.
4. If `!kmsAllowedDeviceIds[b.deviceId]` → `(false, "KMS is not allowed to boot on this device")`.
5. Otherwise `(true, "")`.

- **frame**: entire storage.
- (verified, single-call, mapping gates only:
  `DstackKmsSymbolicTest.check_IsKmsAllowed_RejectsUnknownMr`,
  `check_IsKmsAllowed_RejectsUnknownDevice`)
- The `tcbStatus` byte-exactness gate is not separately verified —
  same reasoning as §3.9.

### 3.7 Owner-only KMS mutations (uniform pattern)

For each of `setKmsInfo`, `setKmsQuote`, `setKmsEventlog`, `setGatewayAppId`,
`setAppImplementation`, `addKmsAggregatedMr`, `removeKmsAggregatedMr`,
`addKmsDevice`, `removeKmsDevice`, `addOsImageHash`, `removeOsImageHash`:

- **pre**: `msg.sender == owner()`.
- **frame**: every storage cell except the one mapped to the operation.
- **reverts** if `msg.sender != owner()` with `OwnableUnauthorizedAccount`.
- These rely on OpenZeppelin's `onlyOwner` modifier, which is exhaustively
  tested upstream. We do not duplicate that proof in this repo.

### 3.8 `DstackApp.initialize` — both overloads

5-arg `(initialOwner, disableUpgrades, allowAnyDevice, deviceId, composeHash)`:

- **post**: as for 6-arg with `requireTcbUpToDate = false`.

6-arg `(initialOwner, disableUpgrades, requireTcbUpToDate, allowAnyDevice, deviceId, composeHash)`:

- **pre**: not yet initialized; `initialOwner != address(0)`.
- **post**:
  - `owner() == initialOwner`; `_upgradesDisabled == disableUpgrades`;
    `allowAnyDevice == allowAnyDevice`; `requireTcbUpToDate == requireTcbUpToDate`.
  - `deviceId != 0 ⇒ allowedDeviceIds[deviceId] == true`.
  - `composeHash != 0 ⇒ allowedComposeHashes[composeHash] == true`.
- **events**: optionally `DeviceAdded(deviceId)` and `ComposeHashAdded(composeHash)`.
- (verified: `DstackAppSymbolicTest.check_Initialize5Arg_DefaultsTcbToFalse`,
  `check_Initialize6Arg_HonorsTcbFlag`)

### 3.9 `DstackApp.isAppAllowed(AppBootInfo b) external view returns (bool, string)`

Decision (in order, all evaluated under `b.appId == address(this)` by convention):

1. If `requireTcbUpToDate && keccak256(bytes(b.tcbStatus)) != keccak256(bytes("UpToDate"))` →
   `(false, "TCB status is not up to date")`.
2. If `!allowedComposeHashes[b.composeHash]` → `(false, "Compose hash not allowed")`.
3. If `!allowAnyDevice && !allowedDeviceIds[b.deviceId]` → `(false, "Device not allowed")`.
4. Otherwise `(true, "")`.

The TCB compare uses `keccak256` for byte-exact string equality. Under the
keccak collision-resistance assumption, the accept set is exactly `{"UpToDate"}`
(8 bytes, ASCII). The off-chain attestation pipeline **must** emit this exact
byte sequence — no case variations, no trailing nulls, no whitespace.

- **frame**: entire storage.
- The byte-exactness of the TCB compare is a direct consequence of the
  keccak collision-resistance assumption; Halmos can't add new information
  here (its `keccak256` is an uninterpreted function), so this property is
  not symbolically verified — it follows from the spec assumption above.

### 3.10 `DstackApp.disableUpgrades()` — kill-switch

- **pre**: `msg.sender == owner()`.
- **post**: `_upgradesDisabled == true`.
- **frame**: every storage cell except `_upgradesDisabled`.
- **events**: `UpgradesDisabled()`.
- After a successful `disableUpgrades` call, the next attempted upgrade
  reverts for any caller / target impl / init data — (verified, single
  call: `DstackAppSymbolicTest.check_DisableUpgrades_BlocksNextUpgrade`).
- Full monotonicity over arbitrary call sequences — INV-1 below — is a
  cross-transaction property not reachable with our current Halmos setup;
  see §4 and §7.

### 3.11 Owner-only App mutations

For each of `addComposeHash`, `removeComposeHash`, `addDevice`, `removeDevice`,
`setAllowAnyDevice`, `setRequireTcbUpToDate`, `disableUpgrades`:

- **pre**: `msg.sender == owner()`.
- **frame**: every storage cell except the one mapped to the operation.
- These rely on OpenZeppelin's `onlyOwner` modifier, which is exhaustively
  tested upstream. We do not duplicate that proof in this repo.

### 3.12 Ownership transfer (inherited Ownable2Step)

`transferOwnership(address newOwner)`:

- **pre**: `msg.sender == owner()`.
- **post**: `pendingOwner() == newOwner`; `owner()` unchanged.
- **events**: `OwnershipTransferStarted(currentOwner, newOwner)`.

`acceptOwnership()`:

- **pre**: `msg.sender == pendingOwner()`.
- **post**: `owner() == msg.sender`; `pendingOwner() == address(0)`.
- **events**: `OwnershipTransferred(previousOwner, newOwner)`.

- (gap: not symbolically verified; relies on OZ's tested implementation.)

## 4. State invariants

Properties that must hold in **every reachable state**, not just after one call.

| Invariant | Status |
|---|---|
| INV-1: `_upgradesDisabled` is monotonic (once `true`, never `false`). | **Inductive step verified** by `DstackAppSymbolicTest.check_UpgradesDisabled_StepPreservation`: from the canonical disabled state, no single call to any enumerated mutating function (symbolic selector/args/caller, issued against the proxy) flips the flag — validated by mutation testing. **Base + closure by source inspection:** the slot has exactly two writers — `_initializeCommon` (gated by the `initializer` modifier; re-entry closed by `check_Initialize_OnceOnly`) and `disableUpgrades` (assigns only `true`). Together these establish monotonicity. Residual gap: the step is anchored at the canonical pre-state, not symbolically quantified over all disabled pre-states (Halmos 0.3.3 lacks symbolic storage). |
| INV-2: The owner can only be changed via the inherited Ownable2Step flow (`transferOwnership` → `acceptOwnership`) or `renounceOwnership`. | **Inductive step verified** by `DstackKmsSymbolicTest.check_Owner_NotChangedByKmsFunctions`: from the canonical post-init state, no call to any of DstackKms's *own* mutating functions (the inherited OZ ownership functions excluded — they are upstream-tested) changes `owner()`, for any caller / args. Validated by mutation testing (catches owner-seizure in permissionless functions and owner-writes in owner-only functions, including via the indirect `deployAndRegisterApp`→`registerApp` path). Same residual gap as INV-1: anchored at the canonical pre-state, not symbolic-storage-quantified. The two-step *behaviour* itself (stage/accept/reject) is covered by unit tests in `DstackKms.t.sol`. |
| INV-3: `_initialized` reaches `1` exactly once per proxy (either 5-arg or 6-arg, never both, never twice). | Verified by `DstackAppSymbolicTest.check_Initialize_OnceOnly` (after setUp's successful 5-arg init, both overloads revert for any inputs). |
| INV-4: `appImplementation` stays a non-zero contract address once set (so the factory hook can't deploy from a junk impl). | Currently only `setAppImplementation` enforces `_implementation != address(0)`; the initializer sets it from input without re-checking. Inputs are owner-controlled, so the invariant holds modulo owner trust. Gap if we want to verify without trusting the owner. |
| INV-5: For every entry `registeredApps[a] == true`, either `a` was the return of a successful `deployAndRegisterApp` call, **or** an external caller invoked `registerApp(a)` with `a != address(0)`. | Trivially holds by construction; documented for the threat model. |
| INV-6: `__gap` slots read zero in every reachable state. | Standard OZ-upgradeable invariant; relies on never declaring new storage past `__gap`. Gap. |
| INV-7: For all `b`, `kms.isAppAllowed(b)` returns the same value whether or not the registered `IAppAuth(b.appId)` mutates its own storage during the call (because the top-level call is `view`, the EVM enforces `STATICCALL` propagation; no inner mutation can influence the outer return). | Holds by EVM semantics; not separately verified. |

## 5. Cross-contract assumptions

### 5.1 KMS ↔ App (`isAppAllowed` delegation)

KMS calls `IAppAuth(b.appId).isAppAllowed(b)` after confirming
`registeredApps[b.appId]` and `allowedOsImages[b.osImageHash]`. Assumptions:

- The call may revert. KMS does not catch the revert — `isAppAllowed`
  propagates it. **Caller of KMS must be prepared to handle this.**
- The call may consume all gas (1/64th-rule means some gas survives; the
  KMS-level caller sees an out-of-gas-style revert).
- The call's return value is **not authenticated**. A malicious registered
  app can claim "allowed" for any input. The chain of trust requires the
  off-chain consumer of `isAppAllowed`'s `(bool, string)` to also verify
  that the app implementation at `b.appId` is one they expect (e.g., by
  diffing bytecode against `DstackApp`'s known implementation).

### 5.2 KMS ↔ Proxy (factory deploy)

`deployAndRegisterApp` calls `new ERC1967Proxy(appImplementation, initData)`.
The proxy constructor delegatecalls into the implementation's initialize
function. Assumptions:

- The constructor runs `initialize` exactly once on the new proxy.
- `appImplementation` is a contract conforming to `DstackApp`'s storage
  layout. Setting it to anything else is the owner's prerogative; the
  spec does not constrain it beyond non-zero.

### 5.3 App ↔ Proxy (upgrade authorization)

`UUPSUpgradeable._authorizeUpgrade` is overridden in `DstackApp` to
`require(!_upgradesDisabled)` plus the inherited `onlyOwner`. Assumption:

- The OZ Foundry Upgrades plugin's storage-layout check is the primary
  defense against incompatible upgrades; the on-chain `_authorizeUpgrade`
  hook is only the access gate.

## 6. Adversarial scenarios

### 6.1 Malicious `registerApp`

An attacker calls `kms.registerApp(maliciousContract)` where `maliciousContract`
implements `IAppAuth` and returns `(true, "")` for every input. Can they
gain authorization?

**No, conditional on owner integrity.** The downstream gates remain:

1. `allowedOsImages[b.osImageHash]` must be true — owner-controlled.
2. The off-chain consumer of `isAppAllowed` is expected to verify that
   `b.appId`'s deployed bytecode matches the legitimate `DstackApp`
   implementation. The KMS does not (and arguably cannot) do this check
   on-chain because the registered app could be a proxy pointing at the
   correct impl.

**Spec gap**: the on-chain contract does not enforce that the registered
app's bytecode matches `appImplementation`. The trust assumption is
external. Future hardening could require `b.appId.code` to equal a
known proxy template that delegates to `appImplementation`.

### 6.2 Reentrancy via delegated `isAppAllowed`

KMS's `isAppAllowed` is `view`. The EVM lifts the inner call to
`STATICCALL`, which propagates: no path through the registered contract
can mutate KMS state. Reentrancy is structurally impossible at the
KMS level.

### 6.3 Gas-griefing

The registered app's `isAppAllowed` can deliberately consume all gas.
KMS's outer call sees an out-of-gas revert. Mitigation: callers should
budget gas appropriately; do not infer "allowed" from a successful call
without observing the return value.

### 6.4 Front-running `deployAndRegisterApp`

Alice intends to deploy at address `X` (CREATE2-style or similar
prediction). Bob calls `registerApp(X)` first. Outcome:
`registeredApps[X] = true` either way; Alice's later deploy succeeds and
re-sets the bit. No privilege escalation.

### 6.5 Malformed return data from a registered IAppAuth

Solidity's strict ABI decoder reverts on a registered contract that
returns shorter-than-expected data (e.g. a single bool, no string).
That revert propagates out of `kms.isAppAllowed` rather than producing
a `(false, …)` rejection. This matters because an off-chain consumer
that retries on revert may interpret a misshapen-response attack
differently from an explicit reject. Currently not symbolically
verified — `MockConfigurableApp` returns the full tuple shape, and
`MockRevertingApp` exercises only the explicit-revert path
(`check_IsAppAllowed_PropagatesMockRevert`). A short-return mock
remains a useful next addition.

## 7. Known specification gaps

For a future audit-firm engagement to close:

1. **Cross-transaction invariants** — INV-6 (`__gap` zeroes) remains a
   gap. INV-1 and INV-2 each have a verified inductive step
   (`check_UpgradesDisabled_StepPreservation`,
   `check_Owner_NotChangedByKmsFunctions`) plus a source-inspection
   closure, but not a fully symbolic-storage proof over arbitrary
   pre-states. INV-3 is verified by `check_Initialize_OnceOnly`. A
   future engagement would mechanize the pre-state quantification
   (e.g. Certora, or Halmos with symbolic storage once available).
2. **Delegated-call universal quantification** — verify that for any
   registered app contract, `kms.isAppAllowed` either reverts or returns
   the registered contract's verbatim output. Requires modeling adversarial
   external code.
4. **Storage layout verification against deployed bytecode** — see
   `formal-verification.md` Phase 4. The `.openzeppelin/unknown-2035.json`
   manifest diverges from current source on slots 5/8/9/10; the team
   believes the manifest is stale. An audit firm would confirm by
   reading the live proxies.
5. **Bytecode-level verification (KEVM)** — closes the compiler-as-attack-
   surface gap. Phase 5 of the FV plan.
6. **Initializer single-run invariant** — INV-3 needs explicit verification
   that the two `initialize` overloads cannot both succeed on the same
   proxy.

## 8. Open questions for the team

These are spec-level decisions the dstack team should pin down before a
formal audit:

1. **`renounceOwnership` semantics.** Both `DstackKms` and `DstackApp`
   inherit `renounceOwnership` from `OwnableUpgradeable`. Renouncing
   the KMS owner permanently freezes the OS-image whitelist and all
   KMS mutations. Is that acceptable, or should `renounceOwnership` be
   overridden to revert?
2. **App impl drift.** If `appImplementation` is updated after several
   apps have been deployed via the factory, the older proxies stay on
   the older impl. Is that intended (versioning) or should the KMS
   track which impl was current at deploy time?
3. **Removing an OS image.** `removeOsImageHash` does not retroactively
   un-authorize already-running apps that booted under that image. Is
   that intended (revocation requires explicit downstream action) or
   should the spec require it?
4. **`gatewayAppId` semantics.** The string is owner-set with no
   validation. Should the spec require a particular format (address,
   ENS, etc.)?
