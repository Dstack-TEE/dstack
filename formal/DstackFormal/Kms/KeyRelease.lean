-- SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
--
-- SPDX-License-Identifier: Apache-2.0

import DstackFormal.Kms.RootEpoch

/-!
# KMS key release: local gates and the checks behind every release

Models, in `dstack/kms/src/main_service.rs`: `KeyReleasePolicy, ensure_key_release_allowed,
ensure_ticket_presented, RpcHandler::{ensure_self_allowed, ensure_attested, ensure_kms_allowed,
ensure_app_attestation_allowed, ensure_attestation_policy, handover_keys}` and
`KmsRpc::{get_app_key, sign_cert, get_kms_key}`; in `main_service/upgrade_authority.rs`:
`AuthApi::{authorize_kms, authorize_app, check_authorization}` (operation kind and
`ensure_identity_widths`). The epoch checks are `RootEpoch.authorizedEpoch` and
`RootEpoch.ensureRpcCa`.

Proven:
* `keyReleaseAllowed_iff`, `gates_do_not_leak`: a platform with a local opt-in gets keys only
  when its own flag is set; TDX and GCP TDX are never gated (by `decide` over all cases).
* `ticketPresented_ok_of_authorized`, `ticketPresented_only_refines`: the ticket hint never
  blocks an authorized answer and only rewords a denial.
* `ensureSelfAllowed_spec`, `selfAllowed_isolated`, `cached_allow_does_not_transfer`: with
  self-authorization enforced, success means the backend authorized this KMS for exactly the
  requested operation; the cache is keyed by operation, and an allow cached for one operation
  never authorizes another.
* `getAppKey_spec`, `signCert_spec`, `handover_spec`: a key or certificate is released only if
  the caller presented a verified attestation (bound to the CSR key for `sign_cert`), the KMS is
  self-authorized for the operation (when enforced), the identity has checked widths, the auth
  backend authorized the caller for this operation, the root epoch is at most the current one
  and held, the app epoch is active, the RPC CA is the current root CA, the OS image was
  verified (all but SNP, which binds it in its launch measurement), and the platform opt-in
  holds.

Assumptions: the auth backend, attestation verification, boot-info extraction, CSR checks and
the OS image verifier are oracles in `World`; their correctness is out of scope. The RA-TLS
layer is assumed to put only a verified, key-bound attestation in `attestation`. The self cache
is assumed consistent with the backend (`CacheSound`); in the code entries may be up to
`AUTH_API_CACHE_TTL` stale.

Gaps: audit logging, metrics and response assembly are omitted; key derivation is assumed not
to fail; concurrency of the caches is not modeled.
-/

namespace DstackFormal.Kms.KeyRelease

open RootEpoch (Bytes AuthResult Keyring Registry servableEpoch authorizedEpoch ensureRpcCa)

/-! ## Local gates -/

/-- `dstack_types::TeeVariant`. -/
inductive TeeVariant where
  | tdx
  | gcpTdx
  | nitroEnclave
  | amdSevSnp
  | awsNitroTpm
  deriving DecidableEq

/-- `main_service.rs: KeyReleasePolicy`. -/
structure KeyReleasePolicy where
  snp : Bool
  awsNitroTpm : Bool
  nitroEnclave : Bool
  deriving DecidableEq

/-- `main_service.rs: ensure_key_release_allowed`. -/
def ensureKeyReleaseAllowed (variant : TeeVariant) (policy : KeyReleasePolicy) :
    Except String Unit :=
  match variant with
  | .amdSevSnp => if !policy.snp then .error "amd sev-snp key release is not enabled" else .ok ()
  | .awsNitroTpm =>
    if !policy.awsNitroTpm then .error "aws nitro-tpm key release is not enabled" else .ok ()
  | .nitroEnclave =>
    if !policy.nitroEnclave then .error "aws nitro enclave key release is not enabled" else .ok ()
  | _ => .ok ()

def isOk {α : Type} : Except String α → Bool
  | .ok _ => true
  | .error _ => false

/-- The platform opt-in a release needs. -/
def platformOptIn (variant : TeeVariant) (policy : KeyReleasePolicy) : Prop :=
  (variant = .amdSevSnp → policy.snp = true) ∧ (variant = .awsNitroTpm → policy.awsNitroTpm = true) ∧
    (variant = .nitroEnclave → policy.nitroEnclave = true)

theorem keyReleaseAllowed_iff (variant : TeeVariant) (policy : KeyReleasePolicy) :
    isOk (ensureKeyReleaseAllowed variant policy) = true ↔ platformOptIn variant policy := by
  obtain ⟨a, b, c⟩ := policy
  cases variant <;> cases a <;> cases b <;> cases c <;> simp [ensureKeyReleaseAllowed, platformOptIn, isOk]

theorem keyReleaseAllowed_ok {variant : TeeVariant} {policy : KeyReleasePolicy} {u : Unit}
    (h : ensureKeyReleaseAllowed variant policy = .ok u) : platformOptIn variant policy :=
  (keyReleaseAllowed_iff variant policy).1 (by rw [h]; rfl)

/-- `key_release_gates_do_not_leak_across_platforms`: enabling one platform enables no other. -/
theorem gates_do_not_leak :
    isOk (ensureKeyReleaseAllowed .nitroEnclave ⟨true, false, false⟩) = false ∧
    isOk (ensureKeyReleaseAllowed .amdSevSnp ⟨false, false, true⟩) = false ∧
    isOk (ensureKeyReleaseAllowed .amdSevSnp ⟨false, true, false⟩) = false ∧
    isOk (ensureKeyReleaseAllowed .awsNitroTpm ⟨true, false, true⟩) = false ∧
    isOk (ensureKeyReleaseAllowed .tdx ⟨false, false, false⟩) = true ∧
    isOk (ensureKeyReleaseAllowed .gcpTdx ⟨false, false, false⟩) = true := by decide

/-- `ensure_ticket_presented`: `invalidTicketReason` stands for
`rejection_reason.eq_ignore_ascii_case("invalid launch ticket")`. -/
def ensureTicketPresented (authorized ticketEmpty invalidTicketReason : Bool) : Except String Unit :=
  if !authorized && ticketEmpty && invalidTicketReason then
    .error "Authorization denied: no launch ticket was presented"
  else .ok ()

theorem ticketPresented_ok_of_authorized (e r : Bool) :
    ensureTicketPresented true e r = .ok () := by
  cases e <;> cases r <;> rfl

theorem ticketPresented_only_refines (a e r : Bool) :
    isOk (ensureTicketPresented a e r) = false ↔ a = false ∧ e = true ∧ r = true := by
  cases a <;> cases e <;> cases r <;> decide

/-! ## The world the checks consult -/

/-- `dstack_types::authorization::AuthorizationOperation`. -/
inductive Operation where
  | kmsBootstrap
  | kmsServe
  | kmsExportKeys
  | kmsImportKeys
  | appGetKey
  | appGetCert
  deriving DecidableEq

/-- `AuthorizationOperation::is_kms`. -/
def Operation.isKms : Operation → Bool
  | .kmsBootstrap | .kmsServe | .kmsExportKeys | .kmsImportKeys => true
  | _ => false

/-- The fields of `PolicyBootInfo` the KMS checks. -/
structure BootInfo where
  teeVariant : TeeVariant
  appId : Bytes
  composeHash : Bytes
  instanceId : Bytes

/-- `upgrade_authority.rs: AuthorizationResult`. -/
structure Response where
  auth : AuthResult
  invalidTicketReason : Bool
  currentAppEpoch : UInt32

/-- `upgrade_authority.rs: ensure_identity_widths`. -/
def IdentityWidths (b : BootInfo) : Prop :=
  b.appId.length = 20 ∧ b.composeHash.length = 32 ∧ (b.instanceId.length = 0 ∨ b.instanceId.length = 20)

instance (b : BootInfo) : Decidable (IdentityWidths b) := by unfold IdentityWidths; infer_instance

/-- Configuration, state and oracles. `Att` is a verified attestation, `Csr` a decoded CSR. -/
structure World (Att Csr : Type) where
  kec : Bytes → Bytes
  isDev : Bool
  keyring : Keyring
  rpcCaPubkey : Bytes
  enforceSelfAuthorization : Bool
  publicKeyHandover : Bool
  policy : KeyReleasePolicy
  /-- `local_kms_boot_info`, as cached in `self_boot_info`. -/
  selfBootInfo : Except String BootInfo
  /-- `get_info().root_epochs`, as cached in `auth_api_info`. -/
  infoRegistry : Except String Registry
  /-- The dev or webhook backend behind `check_authorization`: `(boot info, operation, requested
  root epoch, requested app epoch, launch ticket)`. -/
  backend : BootInfo → Operation → Option UInt32 → Option UInt32 → String → Except String Response
  /-- `build_boot_info_for_attestation(att, use_boottime_mr, vm_config)`. -/
  bootInfoOf : Att → Bool → String → Except String BootInfo
  /-- `CvmVerifier::verify_os_image_hash(vm_config, att)`. -/
  verifyOsImage : String → Att → Except String Unit
  /-- `CertSigningRequestV{1,2}::decode` and `verify(signature)` for the request. -/
  decodeCsr : Nat → Bytes → Bytes → Except String Csr
  /-- `csr.attestation.verify_with_ra_pubkey(&csr.pubkey, verifier)`. -/
  verifyCsrAttestation : Csr → Except String Att

variable {Att Csr : Type}

def check (c : Prop) [Decidable c] (msg : String) : Except String Unit :=
  if c then .ok () else .error msg

theorem check_eq_ok {c : Prop} [Decidable c] {msg : String} {u : Unit} :
    check c msg = .ok u ↔ c := by
  unfold check; split <;> simp_all

theorem bind_eq_ok {α β : Type} {x : Except String α} {f : α → Except String β} {b : β} :
    x >>= f = .ok b ↔ ∃ a, x = .ok a ∧ f a = .ok b := by
  cases x <;> simp [bind, Except.bind]

/-- `AuthApi::authorize_kms` / `authorize_app` through `check_authorization`. -/
def authorize (w : World Att Csr) (kms : Bool) (bi : BootInfo) (op : Operation)
    (root app : Option UInt32) (ticket : String) : Except String Response := do
  check (op.isKms = kms) "invalid authorization operation"
  check (IdentityWidths bi) "identity widths"
  w.backend bi op root app ticket

/-- `main_service.rs: authorized_epoch`. -/
def epochOf (w : World Att Csr) (r : Response) (requested : Option UInt32) : Except String UInt32 :=
  authorizedEpoch w.kec w.isDev w.keyring r.auth requested

/-! ## The self-authorization cache -/

/-- `self_allowed`: a cache keyed by operation. -/
abbrev SelfCache := Operation → Option Response

def SelfCache.insert (c : SelfCache) (op : Operation) (r : Response) : SelfCache :=
  fun op' => if op' = op then some r else c op'

/-- The cached or freshly fetched self answer of `RpcHandler::ensure_self_allowed`
(`self_allowed.try_get_with(operation, ...)`), with the updated cache. -/
def selfResponse (w : World Att Csr) (bi : BootInfo) (cache : SelfCache) (op : Operation) :
    Except String (Response × SelfCache) :=
  match cache op with
  | some r => .ok (r, cache)
  | none => do
    let r ← authorize w true bi op none none ""
    let epoch ← epochOf w r none
    ensureRpcCa w.keyring w.rpcCaPubkey epoch
    pure (r, cache.insert op r)

/-- `RpcHandler::ensure_self_allowed`: the epoch and the updated cache. -/
def ensureSelfAllowed (w : World Att Csr) (cache : SelfCache) (op : Operation) :
    Except String (UInt32 × SelfCache) :=
  if !w.enforceSelfAuthorization then do
    let reg ← w.infoRegistry
    let epoch ← servableEpoch (w.keyring.hashes w.kec) reg
    ensureRpcCa w.keyring w.rpcCaPubkey epoch
    pure (epoch, cache)
  else do
    let bi ← w.selfBootInfo
    let rc ← selfResponse w bi cache op
    let epoch ← epochOf w rc.1 none
    pure (epoch, rc.2)

/-- Every cached entry is the backend's answer for this KMS and that very operation. -/
def CacheSound (w : World Att Csr) (cache : SelfCache) : Prop :=
  ∀ op r, cache op = some r → ∃ bi, w.selfBootInfo = .ok bi ∧ authorize w true bi op none none "" = .ok r

/-- What a successful self check establishes. -/
def SelfAuthorized (w : World Att Csr) (op : Operation) (epoch : UInt32) : Prop :=
  if w.enforceSelfAuthorization then
    ∃ bi r, w.selfBootInfo = .ok bi ∧ authorize w true bi op none none "" = .ok r ∧
      r.auth.authorized = true ∧ epochOf w r none = .ok epoch
  else
    ∃ reg, w.infoRegistry = .ok reg ∧ servableEpoch (w.keyring.hashes w.kec) reg = .ok epoch ∧
      ensureRpcCa w.keyring w.rpcCaPubkey epoch = .ok ()

theorem ensureSelfAllowed_spec {w : World Att Csr} {cache cache' : SelfCache} {op : Operation}
    {epoch : UInt32} (hc : CacheSound w cache)
    (h : ensureSelfAllowed w cache op = .ok (epoch, cache')) :
    SelfAuthorized w op epoch ∧ CacheSound w cache' := by
  unfold ensureSelfAllowed SelfAuthorized at *
  cases hen : w.enforceSelfAuthorization
  · simp only [hen, Bool.not_false, ↓reduceIte, bind_eq_ok] at h
    obtain ⟨reg, hreg, e, he, u, hu, hret⟩ := h
    cases hret
    exact ⟨⟨reg, hreg, he, hu⟩, hc⟩
  · simp only [hen, Bool.not_true, Bool.false_eq_true, ↓reduceIte, bind_eq_ok] at h
    obtain ⟨bi, hbi, ⟨r, c⟩, hrc, e, he, hret⟩ := h
    cases hret
    have hauth := (RootEpoch.authorizedEpoch_spec he).1
    unfold selfResponse at hrc
    cases hop : cache op with
    | some r' =>
      rw [hop] at hrc
      cases hrc
      obtain ⟨bi', hbi', hr⟩ := hc op r hop
      rw [hbi] at hbi'; cases hbi'
      exact ⟨⟨bi, r, hbi, hr, hauth, he⟩, hc⟩
    | none =>
      rw [hop] at hrc
      simp only [bind_eq_ok] at hrc
      obtain ⟨r', hr', e', he', u, hu, hret⟩ := hrc
      cases hret
      refine ⟨⟨bi, r, hbi, hr', hauth, he⟩, fun op'' r'' h'' => ?_⟩
      simp only [SelfCache.insert] at h''
      split at h''
      · rename_i heq; subst heq; cases h''; exact ⟨bi, hbi, hr'⟩
      · exact hc op'' r'' h''

/-- Whether the check for `op` succeeds, and with which epoch, depends on the cache only
through its `op` entry. -/
theorem selfAllowed_isolated {w : World Att Csr} {c c' c2 : SelfCache} {op : Operation}
    {e : UInt32} (h : c op = c' op) (hok : ensureSelfAllowed w c op = .ok (e, c2)) :
    ∃ c3, ensureSelfAllowed w c' op = .ok (e, c3) := by
  unfold ensureSelfAllowed at *
  cases hen : w.enforceSelfAuthorization
  · simp only [hen, Bool.not_false, ↓reduceIte, bind_eq_ok] at hok ⊢
    obtain ⟨reg, hreg, e', he, u, hu, hret⟩ := hok
    cases hret
    exact ⟨c', reg, hreg, e, he, u, hu, rfl⟩
  · simp only [hen, Bool.not_true, Bool.false_eq_true, ↓reduceIte, bind_eq_ok] at hok ⊢
    obtain ⟨bi, hbi, ⟨r, c4⟩, hrc, e', he, hret⟩ := hok
    cases hret
    unfold selfResponse at hrc ⊢
    rw [← h]
    cases hop : c op with
    | some r' =>
      rw [hop] at hrc
      cases hrc
      exact ⟨c', bi, hbi, (r, c'), rfl, e, he, rfl⟩
    | none =>
      rw [hop] at hrc
      simp only [bind_eq_ok] at hrc ⊢
      obtain ⟨r', hr', e'', he'', u, hu, hret⟩ := hrc
      cases hret
      exact ⟨c'.insert op r, bi, hbi, (r, c'.insert op r), ⟨r, hr', e'', he'', u, hu, rfl⟩, e, he, rfl⟩

/-- `self_authorization_cache_cannot_authorize_a_different_operation`: an allow cached for one
operation does not authorize another the backend denies. -/
theorem cached_allow_does_not_transfer {w : World Att Csr} {cache : SelfCache} {op op' : Operation}
    {r : Response} (hen : w.enforceSelfAuthorization = true) (hne : op' ≠ op)
    (hdeny : ∀ bi r', w.selfBootInfo = .ok bi → authorize w true bi op' none none "" = .ok r' →
      r'.auth.authorized = false)
    (hc : CacheSound w cache) :
    isOk (ensureSelfAllowed w (cache.insert op r) op') = false := by
  cases h1 : ensureSelfAllowed w (cache.insert op r) op' with
  | error => rfl
  | ok v =>
    exfalso
    obtain ⟨e, c2⟩ := v
    obtain ⟨c3, h2⟩ := selfAllowed_isolated (c' := cache) (by simp [SelfCache.insert, hne]) h1
    have hs := (ensureSelfAllowed_spec hc h2).1
    simp only [SelfAuthorized, hen, ↓reduceIte] at hs
    obtain ⟨bi, r', hbi, hr', hauth, -⟩ := hs
    rw [hdeny bi r' hbi hr'] at hauth
    cases hauth

/-! ## Caller checks -/

/-- `RpcHandler::ensure_attestation_policy`. -/
def ensureAttestationPolicy (w : World Att Csr) (att : Att) (vmConfig : String) (bi : BootInfo)
    (r : Response) : Except String Unit := do
  let current := if w.isDev then w.keyring.latest else r.auth.currentRootEpoch
  ensureRpcCa w.keyring w.rpcCaPubkey current
  if bi.teeVariant ≠ .amdSevSnp then w.verifyOsImage vmConfig att else pure ()

/-- `main_service.rs: BootConfig`. -/
structure BootConfig where
  bootInfo : BootInfo
  rootEpoch : UInt32
  appEpoch : UInt32

/-- `RpcHandler::ensure_app_attestation_allowed`. -/
def ensureAppAttestationAllowed (w : World Att Csr) (att : Att) (bi : BootInfo) (vmConfig : String)
    (ticket : String) (op : Operation) (root app : Option UInt32) : Except String BootConfig := do
  let r ← authorize w false bi op root app ticket
  ensureTicketPresented r.auth.authorized ticket.isEmpty r.invalidTicketReason
  let rootEpoch ← epochOf w r root
  let appEpoch := app.getD r.currentAppEpoch
  check (appEpoch ≤ r.currentAppEpoch) "requested app epoch is not active"
  ensureAttestationPolicy w att vmConfig bi r
  return ⟨bi, rootEpoch, appEpoch⟩

/-- `RpcHandler::ensure_kms_allowed`: the source side of a handover. -/
def ensureKmsAllowed (w : World Att Csr) (att : Att) (bi : BootInfo) (vmConfig ticket : String) :
    Except String Unit := do
  let r ← authorize w true bi .kmsImportKeys (some w.keyring.latest) none ticket
  ensureTicketPresented r.auth.authorized ticket.isEmpty r.invalidTicketReason
  let _ ← epochOf w r none
  ensureAttestationPolicy w att vmConfig bi r

/-- `KmsRpc::get_app_key`: the root epoch, app epoch and boot info keys are derived for. -/
def getAppKey (w : World Att Csr) (cache : SelfCache) (attestation : Option Att) (apiVersion : Nat)
    (vmConfig ticket : String) (root app : Option UInt32) : Except String BootConfig := do
  check (apiVersion ≤ 1) "Unsupported API version"
  let some att := attestation | .error "No attestation provided"
  let _ ← ensureSelfAllowed w cache .kmsServe
  let bi ← w.bootInfoOf att false vmConfig
  let config ← ensureAppAttestationAllowed w att bi vmConfig ticket .appGetKey root app
  ensureKeyReleaseAllowed config.bootInfo.teeVariant w.policy
  let _ ← w.keyring.epochRoot config.rootEpoch
  return config

/-- `KmsRpc::sign_cert`: the root and app epochs the app CA is derived for. -/
def signCert (w : World Att Csr) (cache : SelfCache) (apiVersion : Nat) (csr signature : Bytes)
    (vmConfig ticket : String) : Except String BootConfig := do
  let _ ← ensureSelfAllowed w cache .kmsServe
  let decoded ← w.decodeCsr apiVersion csr signature
  let att ← w.verifyCsrAttestation decoded
  let bi ← w.bootInfoOf att true vmConfig
  let config ← ensureAppAttestationAllowed w att bi vmConfig ticket .appGetCert none none
  ensureKeyReleaseAllowed config.bootInfo.teeVariant w.policy
  let _ ← w.keyring.epochRoot config.rootEpoch
  return config

/-- `RpcHandler::handover_keys`: hands out every root `0..=latest`. -/
def handoverKeys (w : World Att Csr) (cache : SelfCache) (attestation : Option Att)
    (vmConfig ticket : String) : Except String (List (Bytes × Bytes)) := do
  let some att := attestation | .error "No attestation provided"
  let _ ← ensureSelfAllowed w cache .kmsExportKeys
  let bi ← w.bootInfoOf att false vmConfig
  ensureKmsAllowed w att bi vmConfig ticket
  ensureKeyReleaseAllowed bi.teeVariant w.policy
  return w.keyring.roots

/-- `KmsRpc::get_kms_key`, the public handover. -/
def getKmsKey (w : World Att Csr) (cache : SelfCache) (attestation : Option Att)
    (vmConfig ticket : String) : Except String (List (Bytes × Bytes)) := do
  check (w.publicKeyHandover = true) "public KMS key handover is disabled"
  handoverKeys w cache attestation vmConfig ticket

/-! ## What a release implies -/

/-- The attestation policy: the RPC CA is the current root CA and, except on SNP, the OS image
was verified. -/
def PolicyHolds (w : World Att Csr) (att : Att) (vmConfig : String) (bi : BootInfo) (r : Response) :
    Prop :=
  ensureRpcCa w.keyring w.rpcCaPubkey (if w.isDev then w.keyring.latest else r.auth.currentRootEpoch)
      = .ok () ∧
    (bi.teeVariant ≠ .amdSevSnp → w.verifyOsImage vmConfig att = .ok ())

theorem ensureAttestationPolicy_spec {w : World Att Csr} {att : Att} {vm : String} {bi : BootInfo}
    {r : Response} {u : Unit} (h : ensureAttestationPolicy w att vm bi r = .ok u) :
    PolicyHolds w att vm bi r := by
  simp only [ensureAttestationPolicy, bind_eq_ok] at h
  obtain ⟨u', hca, hos⟩ := h
  refine ⟨hca, fun hv => ?_⟩
  simp only [hv, ne_eq, not_false_eq_true, ↓reduceIte] at hos
  exact hos

/-- What the auth backend and the epoch checks established for an authorized caller. -/
def CallerAuthorized (w : World Att Csr) (kms : Bool) (att : Att) (bi : BootInfo) (vm : String)
    (op : Operation) (root app : Option UInt32) (ticket : String) (r : Response) : Prop :=
  op.isKms = kms ∧ IdentityWidths bi ∧ w.backend bi op root app ticket = .ok r ∧
    r.auth.authorized = true ∧ PolicyHolds w att vm bi r

theorem authorize_spec {w : World Att Csr} {kms : Bool} {bi : BootInfo} {op : Operation}
    {root app : Option UInt32} {ticket : String} {r : Response}
    (h : authorize w kms bi op root app ticket = .ok r) :
    op.isKms = kms ∧ IdentityWidths bi ∧ w.backend bi op root app ticket = .ok r := by
  simp only [authorize, bind_eq_ok, check_eq_ok] at h
  obtain ⟨_, hk, _, hw, hb⟩ := h
  exact ⟨hk, hw, hb⟩

theorem ensureAppAttestationAllowed_spec {w : World Att Csr} {att : Att} {bi : BootInfo}
    {vm ticket : String} {op : Operation} {root app : Option UInt32} {c : BootConfig}
    (h : ensureAppAttestationAllowed w att bi vm ticket op root app = .ok c) :
    c.bootInfo = bi ∧ ∃ r, CallerAuthorized w false att bi vm op root app ticket r ∧
      epochOf w r root = .ok c.rootEpoch ∧ c.appEpoch ≤ r.currentAppEpoch ∧
      c.appEpoch = app.getD r.currentAppEpoch := by
  simp only [ensureAppAttestationAllowed, bind_eq_ok, check_eq_ok] at h
  obtain ⟨r, hr, _, -, e, he, _, hle, u, hpol, hret⟩ := h
  cases hret
  obtain ⟨hk, hw, hb⟩ := authorize_spec hr
  exact ⟨rfl, r, ⟨hk, hw, hb, (RootEpoch.authorizedEpoch_spec he).1,
    ensureAttestationPolicy_spec hpol⟩, he, hle, rfl⟩

/-- `get_app_key` releases keys only after every check: verified caller attestation,
self-authorization for serving (when enforced), backend authorization of this caller for
`app_get_key` with checked identity widths, an active held root epoch and an active app epoch,
the current RPC CA, a verified OS image (except SNP), and the platform opt-in. -/
theorem getAppKey_spec {w : World Att Csr} {cache : SelfCache} {attestation : Option Att}
    {apiVersion : Nat} {vm ticket : String} {root app : Option UInt32} {c : BootConfig}
    (hc : CacheSound w cache)
    (h : getAppKey w cache attestation apiVersion vm ticket root app = .ok c) :
    ∃ att, attestation = some att ∧ (∃ e, SelfAuthorized w .kmsServe e) ∧
      w.bootInfoOf att false vm = .ok c.bootInfo ∧
      (∃ r, CallerAuthorized w false att c.bootInfo vm .appGetKey root app ticket r ∧
        epochOf w r root = .ok c.rootEpoch ∧ c.appEpoch ≤ r.currentAppEpoch) ∧
      c.rootEpoch.toNat < w.keyring.roots.length ∧
      platformOptIn c.bootInfo.teeVariant w.policy := by
  cases attestation with
  | none => simp [getAppKey, bind_eq_ok, check_eq_ok] at h
  | some att =>
    simp only [getAppKey, bind_eq_ok, check_eq_ok] at h
    obtain ⟨_, -, ⟨e, c'⟩, hself, bi, hbi, cfg, hcfg, u, hrel, root', hroot, hret⟩ := h
    cases hret
    obtain ⟨hbi', r, hauth, hep, hle, -⟩ := ensureAppAttestationAllowed_spec hcfg
    subst hbi'
    refine ⟨att, rfl, ⟨e, (ensureSelfAllowed_spec hc hself).1⟩, hbi, ⟨r, hauth, hep, hle⟩,
      (RootEpoch.authorizedEpoch_spec hep).2.1, keyReleaseAllowed_ok hrel⟩

/-- `sign_cert` issues a certificate only for a CSR whose attestation verified against the CSR's
own public key, with the same checks as `get_app_key` for `app_get_cert` at the current epochs. -/
theorem signCert_spec {w : World Att Csr} {cache : SelfCache} {apiVersion : Nat}
    {csr signature : Bytes} {vm ticket : String} {c : BootConfig} (hc : CacheSound w cache)
    (h : signCert w cache apiVersion csr signature vm ticket = .ok c) :
    (∃ e, SelfAuthorized w .kmsServe e) ∧
      ∃ decoded att, w.decodeCsr apiVersion csr signature = .ok decoded ∧
        w.verifyCsrAttestation decoded = .ok att ∧ w.bootInfoOf att true vm = .ok c.bootInfo ∧
        (∃ r, CallerAuthorized w false att c.bootInfo vm .appGetCert none none ticket r ∧
          epochOf w r none = .ok c.rootEpoch ∧ c.appEpoch = r.currentAppEpoch) ∧
        c.rootEpoch.toNat < w.keyring.roots.length ∧
        platformOptIn c.bootInfo.teeVariant w.policy := by
  simp only [signCert, bind_eq_ok] at h
  obtain ⟨⟨e, c'⟩, hself, decoded, hdec, att, hatt, bi, hbi, cfg, hcfg, u, hrel, root', hroot,
    hret⟩ := h
  cases hret
  obtain ⟨hbi', r, hauth, hep, -, happ⟩ := ensureAppAttestationAllowed_spec hcfg
  subst hbi'
  exact ⟨⟨e, (ensureSelfAllowed_spec hc hself).1⟩, decoded, att, hdec, hatt, hbi,
    ⟨r, hauth, hep, happ⟩, (RootEpoch.authorizedEpoch_spec hep).2.1, keyReleaseAllowed_ok hrel⟩

/-- A handover releases the root keys only to a verified caller the backend authorized to import
keys up to the latest held epoch, after this KMS was authorized to export them (when enforced),
with the attestation policy and platform opt-in. -/
theorem handover_spec {w : World Att Csr} {cache : SelfCache} {attestation : Option Att}
    {vm ticket : String} {keys : List (Bytes × Bytes)} (hc : CacheSound w cache)
    (h : handoverKeys w cache attestation vm ticket = .ok keys) :
    keys = w.keyring.roots ∧ ∃ att bi, attestation = some att ∧
      (∃ e, SelfAuthorized w .kmsExportKeys e) ∧ w.bootInfoOf att false vm = .ok bi ∧
      (∃ r, CallerAuthorized w true att bi vm .kmsImportKeys (some w.keyring.latest) none ticket r) ∧
      platformOptIn bi.teeVariant w.policy := by
  cases attestation with
  | none => simp [handoverKeys] at h
  | some att =>
    simp only [handoverKeys, bind_eq_ok] at h
    obtain ⟨⟨e, c'⟩, hself, bi, hbi, u, hkms, u', hrel, hret⟩ := h
    cases hret
    simp only [ensureKmsAllowed, bind_eq_ok] at hkms
    obtain ⟨r, hr, _, -, ep, hep, hpol⟩ := hkms
    obtain ⟨hk, hw, hb⟩ := authorize_spec hr
    exact ⟨rfl, att, bi, rfl, ⟨e, (ensureSelfAllowed_spec hc hself).1⟩, hbi,
      ⟨r, hk, hw, hb, (RootEpoch.authorizedEpoch_spec hep).1, ensureAttestationPolicy_spec hpol⟩,
      keyReleaseAllowed_ok hrel⟩

theorem getKmsKey_spec {w : World Att Csr} {cache : SelfCache} {attestation : Option Att}
    {vm ticket : String} {keys : List (Bytes × Bytes)}
    (h : getKmsKey w cache attestation vm ticket = .ok keys) :
    w.publicKeyHandover = true ∧ handoverKeys w cache attestation vm ticket = .ok keys := by
  simp only [getKmsKey, bind_eq_ok, check_eq_ok] at h
  obtain ⟨_, hp, hh⟩ := h
  exact ⟨hp, hh⟩

end DstackFormal.Kms.KeyRelease
