-- SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
--
-- SPDX-License-Identifier: Apache-2.0

/-!
# KMS root epochs: chain hashes, the registry contract, and the KMS checks

Models:
* `dstack/dstack-types/src/root_epoch.rs: chain_hashes`
* `dstack/kms/src/main_service.rs: servable_epoch, Keyring::latest, KmsState::authorized_epoch,
  KmsState::ensure_rpc_ca`
* `dstack/kms/src/main_service/upgrade_authority.rs: root_epoch, RootEpochFields::registry,
  ensure_kms_allowed` (the epoch part, after the backend answered)
* `dstack/kms/src/onboard_service.rs: ensure_handover_registered`
* `dstack/kms/auth-eth/contracts/DstackKms.sol: registerRootEpoch, activateRootEpoch,
  popRootEpoch, _useRootEpoch, _latestRootEpoch, _fillRootEpochs`

Proven:
* `chainHashes_binding`: equal chain hashes at epoch `n` imply equal root public keys for
  epochs `0..=n` (collision-extraction form `chainHashes_binding_or_collision` needs no
  idealized hash at all).
* `servableEpoch_current`, `servableEpoch_empty`, `servableEpoch_binds_keys`: a keyring serves
  epoch `e` under a registered current epoch only if its chain hash at `e` is the registered one,
  hence only if it holds exactly the registered keys `0..=e`; an empty registry serves only a
  one-epoch keyring at epoch 0. `servableEpoch_nil_*` and `latest_nil` show what the code does on
  an empty slice: `len as u32 - 1` wraps to `u32::MAX` (release builds have no overflow checks).
* `authorizedEpoch_spec`: an authorized epoch is at most the current one, held, and outside dev
  mode the current epoch is the backend's, with a nonzero hash matching the keyring.
* `handover_binds_held`, `handover_binds_keys`, `handover_rotation`, `handover_empty`: a handover
  is accepted only if every held epoch is bound by a registered chain hash; rotation needs a
  non-empty registry and `held = current = latest`, so the generated epoch `held + 1` is past
  every registered one.
* Contract: `reachable_inv` (current < length, linked chain hashes, fresh registrations, kmsInfo
  follows the current epoch), `step_current_monotone` and `step_active_prefix` (current only
  moves by +1 and entries up to it never change), `pop_spec` (only a pending tail is popped),
  `reachable_chainHashes` (the contract stores exactly the Rust `chain_hashes`),
  `fill_spec`, and `keyring_servable_of_contract` / `servable_of_contract_binds`.

Assumptions: keccak256 is a parameter `kec` returning 32 bytes; binding theorems assume it is
injective (standing in for collision resistance), or exhibit a collision. Bytes are `Nat`.

Gaps: owner checks (`onlyOwner`), events, `setRootEpochEvidenceUrl` and evidence URLs are not
modeled; key validity is checked only on lengths and prefix bytes. Out-of-bounds indexing that
would panic in Rust (`hashes[held as usize]`) is modeled as a failure. Hex/JSON decoding of
backend fields is abstracted to already-decoded `Option` values; uint256 epochs are `Nat` and
the contract-to-KMS link assumes they fit in `u32`.
-/

namespace DstackFormal.Kms.RootEpoch

abbrev Bytes := List Nat

def zero32 : Bytes := List.replicate 32 0

/-- A collision of `kec`. -/
def Collision (kec : Bytes → Bytes) : Prop := ∃ x y, x ≠ y ∧ kec x = kec y

/-- One link of `dstack-types/src/root_epoch.rs: chain_hashes` and of `DstackKms.sol:
registerRootEpoch`: `keccak256(previous || keccak256(ca_pubkey) || keccak256(k256_pubkey))`. -/
def chainStep (kec : Bytes → Bytes) (previous ca k256 : Bytes) : Bytes :=
  kec (previous ++ kec ca ++ kec k256)

/-- `dstack-types/src/root_epoch.rs: chain_hashes`, from a given `previous`. -/
def chainHashesFrom (kec : Bytes → Bytes) : Bytes → List (Bytes × Bytes) → List Bytes
  | _, [] => []
  | previous, (ca, k256) :: rest =>
    chainStep kec previous ca k256 :: chainHashesFrom kec (chainStep kec previous ca k256) rest

/-- `dstack-types/src/root_epoch.rs: chain_hashes`: a zero previous hash for epoch 0. -/
def chainHashes (kec : Bytes → Bytes) (epochs : List (Bytes × Bytes)) : List Bytes :=
  chainHashesFrom kec zero32 epochs

@[simp] theorem length_chainHashesFrom (kec : Bytes → Bytes) (p : Bytes) (l : List (Bytes × Bytes)) :
    (chainHashesFrom kec p l).length = l.length := by
  induction l generalizing p with
  | nil => rfl
  | cons x l ih => obtain ⟨ca, k⟩ := x; simp [chainHashesFrom, ih]

@[simp] theorem length_chainHashes (kec : Bytes → Bytes) (l : List (Bytes × Bytes)) :
    (chainHashes kec l).length = l.length := length_chainHashesFrom kec _ l

theorem chainStep_inj {kec : Bytes → Bytes} (hlen : ∀ x, (kec x).length = 32)
    (hinj : Function.Injective kec) {p ca k p' ca' k' : Bytes}
    (hp : p.length = 32) (hp' : p'.length = 32)
    (h : chainStep kec p ca k = chainStep kec p' ca' k') : p = p' ∧ ca = ca' ∧ k = k' := by
  have h := hinj h
  rw [List.append_assoc, List.append_assoc] at h
  obtain ⟨h1, h2⟩ := List.append_inj h (by rw [hp, hp'])
  obtain ⟨h3, h4⟩ := List.append_inj h2 (by rw [hlen, hlen])
  exact ⟨h1, hinj h3, hinj h4⟩

theorem chainHashesFrom_binding {kec : Bytes → Bytes} (hlen : ∀ x, (kec x).length = 32)
    (hinj : Function.Injective kec) :
    ∀ (a b : List (Bytes × Bytes)) (p q : Bytes) (n : Nat) (h : Bytes),
      p.length = 32 → q.length = 32 →
      (chainHashesFrom kec p a)[n]? = some h → (chainHashesFrom kec q b)[n]? = some h →
      p = q ∧ a.take (n + 1) = b.take (n + 1)
  | [], _, _, _, _, _, _, _, ha, _ => by simp [chainHashesFrom] at ha
  | _ :: _, [], _, _, _, _, _, _, _, hb => by simp [chainHashesFrom] at hb
  | (ca, k) :: as, (ca', k') :: bs, p, q, n, h, hp, hq, ha, hb => by
    cases n with
    | zero =>
      simp only [chainHashesFrom, List.getElem?_cons_zero, Option.some.injEq] at ha hb
      obtain ⟨e1, e2, e3⟩ := chainStep_inj hlen hinj hp hq (ha.trans hb.symm)
      subst e1 e2 e3; simp
    | succ m =>
      simp only [chainHashesFrom, List.getElem?_cons_succ] at ha hb
      obtain ⟨e, et⟩ := chainHashesFrom_binding hlen hinj as bs _ _ m h (hlen _) (hlen _) ha hb
      obtain ⟨e1, e2, e3⟩ := chainStep_inj hlen hinj hp hq e
      subst e1 e2 e3; simp [et]

/-- Chain-hash binding: under an injective 32-byte hash, equal chain hashes at epoch `n` mean
equal root public keys for epochs `0..=n`. -/
theorem chainHashes_binding {kec : Bytes → Bytes} (hlen : ∀ x, (kec x).length = 32)
    (hinj : Function.Injective kec) {a b : List (Bytes × Bytes)} {n : Nat} {h : Bytes}
    (ha : (chainHashes kec a)[n]? = some h) (hb : (chainHashes kec b)[n]? = some h) :
    a.take (n + 1) = b.take (n + 1) :=
  (chainHashesFrom_binding hlen hinj a b _ _ n h (by simp [zero32]) (by simp [zero32]) ha hb).2

/-- The same binding without an idealized hash: either the keys agree or `kec` has a
collision. -/
theorem chainHashes_binding_or_collision {kec : Bytes → Bytes} (hlen : ∀ x, (kec x).length = 32)
    {a b : List (Bytes × Bytes)} {n : Nat} {h : Bytes}
    (ha : (chainHashes kec a)[n]? = some h) (hb : (chainHashes kec b)[n]? = some h) :
    a.take (n + 1) = b.take (n + 1) ∨ Collision kec := by
  refine (Classical.em (Collision kec)).elim Or.inr (fun hc => Or.inl ?_)
  refine chainHashes_binding hlen (fun x y hxy => ?_) ha hb
  exact Classical.byContradiction fun hne => hc ⟨x, y, hne, hxy⟩

/-! ## The KMS side -/

/-- `upgrade_authority.rs: CurrentRootEpoch`. -/
structure CurrentRootEpoch where
  epoch : UInt32
  chainHash : Bytes
  deriving DecidableEq

/-- `upgrade_authority.rs: RootEpochRegistry`. -/
inductive Registry where
  | unchecked
  | empty
  | current (c : CurrentRootEpoch)
  deriving DecidableEq

/-- `main_service.rs: Keyring::latest` on a keyring with `n` epochs: `len as u32 - 1`. -/
def latestOf (n : Nat) : UInt32 := n.toUInt32 - 1

/-- `main_service.rs: servable_epoch`. -/
def servableEpoch (hashes : List Bytes) (registry : Registry) : Except String UInt32 :=
  let latest := latestOf hashes.length
  match registry with
  | .unchecked => .ok latest
  | .empty => if latest = 0 then .ok 0 else .error "no root epoch is registered"
  | .current c =>
    match hashes[c.epoch.toNat]? with
    | some hash => if hash = c.chainHash then .ok c.epoch else .error "not the registered ones"
    | none => .error "the keyring does not hold the current epoch"

theorem latestOf_toNat {n : Nat} (h0 : 0 < n) (h : n < 2 ^ 32) : (latestOf n).toNat = n - 1 := by
  simp only [latestOf]; rw [UInt32.toNat_sub]; simp; omega

theorem servableEpoch_current {hashes : List Bytes} {c : CurrentRootEpoch} {e : UInt32}
    (h : servableEpoch hashes (.current c) = .ok e) :
    e = c.epoch ∧ hashes[c.epoch.toNat]? = some c.chainHash := by
  simp only [servableEpoch] at h
  split at h
  · rename_i hash hget
    split at h
    · cases h; subst_vars; exact ⟨rfl, hget⟩
    · cases h
  · cases h

theorem servableEpoch_empty {hashes : List Bytes} {e : UInt32} (hlen : hashes.length < 2 ^ 32)
    (h : servableEpoch hashes .empty = .ok e) : e = 0 ∧ hashes.length = 1 := by
  simp only [servableEpoch] at h
  split at h
  · rename_i hl
    cases h
    refine ⟨rfl, ?_⟩
    have := congrArg UInt32.toNat hl
    simp only [latestOf] at this
    rw [UInt32.toNat_sub] at this
    simp at this
    omega
  · cases h

/-- On an empty slice `len as u32 - 1` wraps: `Keyring::latest` is `u32::MAX`. -/
theorem latest_nil : latestOf 0 = 4294967295 := by decide

/-- An empty slice under the dev registry "serves" epoch `u32::MAX`. `Keyring::load` and
`Keys::from_key_response` never build an empty keyring, so this is a precondition, not a bug. -/
theorem servableEpoch_nil_unchecked : servableEpoch [] .unchecked = .ok 4294967295 := rfl

theorem servableEpoch_nil_empty : servableEpoch [] .empty = .error "no root epoch is registered" := rfl

theorem servableEpoch_nil_current (c : CurrentRootEpoch) :
    servableEpoch [] (.current c) = .error "the keyring does not hold the current epoch" := by
  simp [servableEpoch]

/-- A keyring serves epoch `e` under a registered current epoch only if it holds exactly the
keys registered for epochs `0..=e`. -/
theorem servableEpoch_binds_keys {kec : Bytes → Bytes} (hlen : ∀ x, (kec x).length = 32)
    (hinj : Function.Injective kec) {held registered : List (Bytes × Bytes)} {c : CurrentRootEpoch}
    {e : UInt32} (hreg : (chainHashes kec registered)[c.epoch.toNat]? = some c.chainHash)
    (h : servableEpoch (chainHashes kec held) (.current c) = .ok e) :
    e = c.epoch ∧ held.take (e.toNat + 1) = registered.take (e.toNat + 1) := by
  obtain ⟨he, hget⟩ := servableEpoch_current h
  subst he
  exact ⟨rfl, chainHashes_binding hlen hinj hget hreg⟩

/-- `upgrade_authority.rs: root_epoch`: the hash is the decoded hex (`none` if it is not hex);
a zero hash means nothing is registered. -/
def rootEpoch (epoch : UInt32) (hash : Option Bytes) : Except String (Option CurrentRootEpoch) :=
  match hash with
  | none => .error "invalid authorization root epoch chain hash"
  | some h =>
    if h.length ≠ 32 then .error "invalid authorization root epoch chain hash"
    else if h = zero32 then .ok none
    else .ok (some ⟨epoch, h⟩)

/-- `upgrade_authority.rs: RootEpochFields::registry`, after hex decoding. -/
def RootEpochFields.registry (epoch : Option UInt32) (hash : Option (Option Bytes)) :
    Except String Registry :=
  match epoch, hash with
  | none, none => .ok .empty
  | some e, some (some h) =>
    if h.length = 32 then .ok (.current ⟨e, h⟩) else .error "invalid root epoch chain hash"
  | some _, some none => .error "invalid root epoch chain hash"
  | _, _ => .error "the auth API reports a root epoch without its chain hash"

/-- The epoch fields of `upgrade_authority.rs: AuthorizationResult`. -/
structure AuthResult where
  authorized : Bool
  currentRootEpoch : UInt32
  currentRootEpochHash : Option Bytes
  latestRootEpoch : UInt32
  latestRootEpochHash : Option Bytes

/-- `main_service.rs: Keyring`, by the public keys of each epoch. -/
structure Keyring where
  roots : List (Bytes × Bytes)

def Keyring.hashes (kec : Bytes → Bytes) (k : Keyring) : List Bytes := chainHashes kec k.roots

/-- `main_service.rs: Keyring::latest`. -/
def Keyring.latest (k : Keyring) : UInt32 := latestOf k.roots.length

/-- `main_service.rs: KmsState::epoch_root`. -/
def Keyring.epochRoot (k : Keyring) (epoch : UInt32) : Except String (Bytes × Bytes) :=
  match k.roots[epoch.toNat]? with
  | some r => .ok r
  | none => .error "root epoch is not held by this KMS"

/-- The current epoch of `main_service.rs: KmsState::authorized_epoch`. -/
def currentEpoch (kec : Bytes → Bytes) (isDev : Bool) (kr : Keyring) (res : AuthResult) :
    Except String UInt32 :=
  if isDev then .ok kr.latest
  else
    match rootEpoch res.currentRootEpoch res.currentRootEpochHash with
    | .error err => .error err
    | .ok none => .error "Root epoch not registered"
    | .ok (some c) => servableEpoch (kr.hashes kec) (.current c)

/-- `main_service.rs: KmsState::authorized_epoch`. -/
def authorizedEpoch (kec : Bytes → Bytes) (isDev : Bool) (kr : Keyring) (res : AuthResult)
    (requested : Option UInt32) : Except String UInt32 :=
  if !res.authorized then .error "Authorization denied"
  else
    match currentEpoch kec isDev kr res with
    | .error err => .error err
    | .ok current =>
      let epoch := requested.getD current
      if epoch > current then .error "root epoch is not active"
      else
        match kr.epochRoot epoch with
        | .error err => .error err
        | .ok _ => .ok epoch

theorem currentEpoch_spec {kec : Bytes → Bytes} {kr : Keyring} {res : AuthResult} {c : UInt32}
    (h : currentEpoch kec false kr res = .ok c) :
    c = res.currentRootEpoch ∧ ∃ hash, res.currentRootEpochHash = some hash ∧ hash ≠ zero32 ∧
      (kr.hashes kec)[c.toNat]? = some hash := by
  simp only [currentEpoch, Bool.false_eq_true, ite_false] at h
  split at h
  · cases h
  · cases h
  · rename_i cur hroot
    obtain ⟨he, hget⟩ := servableEpoch_current h
    simp only [rootEpoch] at hroot
    split at hroot
    · cases hroot
    · rename_i hash hh
      split at hroot
      · cases hroot
      · split at hroot
        · cases hroot
        · rename_i hz
          cases hroot
          subst he
          exact ⟨rfl, hash, hh, hz, hget⟩

/-- `authorized_epoch` returns only an authorized, held epoch at most the current one; outside
dev mode the current epoch is the backend's, whose nonzero chain hash the keyring matches. -/
theorem authorizedEpoch_spec {kec : Bytes → Bytes} {isDev : Bool} {kr : Keyring} {res : AuthResult}
    {requested : Option UInt32} {e : UInt32}
    (h : authorizedEpoch kec isDev kr res requested = .ok e) :
    res.authorized = true ∧ e.toNat < kr.roots.length ∧
      (∀ r, requested = some r → e = r) ∧
      ∃ current, currentEpoch kec isDev kr res = .ok current ∧ e ≤ current ∧
        (isDev = false → current = res.currentRootEpoch ∧
          ∃ hash, res.currentRootEpochHash = some hash ∧ hash ≠ zero32 ∧
            (kr.hashes kec)[current.toNat]? = some hash) := by
  simp only [authorizedEpoch] at h
  split at h
  · cases h
  · rename_i hauth
    split at h
    · cases h
    · rename_i current hcur
      split at h
      · cases h
      · rename_i hle
        split at h
        · cases h
        · rename_i r hroot
          cases h
          simp only [Keyring.epochRoot] at hroot
          split at hroot
          · rename_i hget
            refine ⟨by simpa using hauth, ?_, ?_, current, hcur, ?_, ?_⟩
            · exact (List.getElem?_eq_some_iff.1 hget).1
            · intro r hr; simp [hr]
            · exact UInt32.not_lt.1 hle
            · intro hdev; subst hdev; exact currentEpoch_spec hcur
          · cases hroot

/-- `main_service.rs: KmsState::ensure_rpc_ca`: the running TLS issuer must be the CA of the
current epoch. -/
def ensureRpcCa (kr : Keyring) (rpcCaPubkey : Bytes) (current : UInt32) : Except String Unit :=
  match kr.epochRoot current with
  | .error err => .error err
  | .ok (ca, _) => if ca ≠ rpcCaPubkey then .error "the RPC root CA changed" else .ok ()

/-- `upgrade_authority.rs: RootEpochRegistration`. -/
structure Registration where
  registry : Registry
  latest : Option CurrentRootEpoch

/-- The epoch part of `upgrade_authority.rs: ensure_kms_allowed`, after `authorize_kms` returned
`res`. -/
def registrationOf (isDev : Bool) (res : AuthResult) : Except String Registration :=
  if !res.authorized then .error "boot denied"
  else if isDev then .ok ⟨.unchecked, none⟩
  else
    match rootEpoch res.currentRootEpoch res.currentRootEpochHash with
    | .error err => .error err
    | .ok none => .error "root epoch not registered"
    | .ok (some current) =>
      match rootEpoch res.latestRootEpoch res.latestRootEpochHash with
      | .error err => .error err
      | .ok (some latest) =>
        if latest.epoch ≥ current.epoch then .ok ⟨.current current, some latest⟩
        else .error "no latest root epoch at or after the current one"
      | .ok none => .error "no latest root epoch at or after the current one"

theorem registrationOf_spec {isDev : Bool} {res : AuthResult} {r : Registration}
    (h : registrationOf isDev res = .ok r) :
    res.authorized = true ∧ (isDev = false →
      ∃ c l, r.registry = .current c ∧ r.latest = some l ∧ c.epoch ≤ l.epoch) := by
  simp only [registrationOf] at h
  split at h
  · cases h
  · rename_i hauth
    refine ⟨by simpa using hauth, fun hdev => ?_⟩
    subst hdev
    simp only [Bool.false_eq_true, ite_false] at h
    split at h
    · cases h
    · cases h
    · rename_i c _
      split at h
      · cases h
      · rename_i l _
        split at h
        · rename_i hle; cases h; exact ⟨c, l, rfl, rfl, hle⟩
        · cases h
      · cases h

/-- `onboard_service.rs: ensure_handover_registered`. A panic on `hashes[held as usize]` is a
failure. -/
def ensureHandoverRegistered (kec : Bytes → Bytes) (roots : List (Bytes × Bytes))
    (registration : Registration) (rotate : Bool) : Except String Unit :=
  if rotate = true ∧ registration.registry = .empty then .error "register root epoch 0 before rotating"
  else
    let hashes := chainHashes kec roots
    match servableEpoch hashes registration.registry with
    | .error err => .error err
    | .ok current =>
      let held := latestOf roots.length
      let latestCheck : Except String Unit :=
        match registration.latest with
        | none => .ok ()
        | some latest =>
          if held > latest.epoch then .error "source KMS holds unregistered root epochs"
          else if held > current ∧ held < latest.epoch then .error "only the latest can be checked"
          else if held = latest.epoch ∧ hashes[held.toNat]? ≠ some latest.chainHash then
            .error "the source root keys are not the registered ones"
          else if rotate = true ∧ latest.epoch ≠ current then .error "activate it before rotating"
          else .ok ()
      match latestCheck with
      | .error err => .error err
      | .ok () =>
        if rotate = true ∧ current ≠ held then .error "rotate from a source at the current epoch"
        else .ok ()

theorem handover_unfold {kec : Bytes → Bytes} {roots : List (Bytes × Bytes)} {reg : Registration}
    {rotate : Bool} (h : ensureHandoverRegistered kec roots reg rotate = .ok ()) :
    ¬(rotate = true ∧ reg.registry = .empty) ∧
    ∃ current, servableEpoch (chainHashes kec roots) reg.registry = .ok current ∧
      (rotate = true → current = latestOf roots.length) ∧
      ∀ l, reg.latest = some l →
        ¬(latestOf roots.length > l.epoch) ∧
        ¬(latestOf roots.length > current ∧ latestOf roots.length < l.epoch) ∧
        (latestOf roots.length = l.epoch →
          (chainHashes kec roots)[(latestOf roots.length).toNat]? = some l.chainHash) ∧
        (rotate = true → l.epoch = current) := by
  simp only [ensureHandoverRegistered] at h
  split at h
  · cases h
  · rename_i hrot
    split at h
    · cases h
    · rename_i current hserv
      split at h
      · cases h
      · rename_i hlat
        split at h
        · cases h
        · rename_i hfin
          refine ⟨hrot, current, hserv, ?_, ?_⟩
          · intro hr; subst hr; exact Classical.byContradiction fun hne => hfin ⟨rfl, hne⟩
          · intro l hl
            rw [hl] at hlat
            simp only at hlat
            split at hlat
            · cases hlat
            · split at hlat
              · cases hlat
              · split at hlat
                · cases hlat
                · split at hlat
                  · cases hlat
                  · rename_i h1 h2 h3 h4
                    refine ⟨h1, h2, fun he => ?_, fun hr => ?_⟩
                    · exact Classical.byContradiction fun hne => h3 ⟨he, hne⟩
                    · exact (Classical.byContradiction fun hne => h4 ⟨hr, hne⟩)

/-- A handover is accepted against a registered current and latest epoch only if the held
epochs run from the current one to at most the latest, and the highest held epoch is bound by
the current or the latest registered chain hash. -/
theorem handover_binds_held {kec : Bytes → Bytes} {roots : List (Bytes × Bytes)} {c l : CurrentRootEpoch}
    {rotate : Bool} (hne : roots ≠ []) (hlen : roots.length < 2 ^ 32)
    (h : ensureHandoverRegistered kec roots ⟨.current c, some l⟩ rotate = .ok ()) :
    c.epoch ≤ latestOf roots.length ∧ latestOf roots.length ≤ l.epoch ∧
      ((latestOf roots.length = c.epoch ∧
          (chainHashes kec roots)[c.epoch.toNat]? = some c.chainHash) ∨
       (latestOf roots.length = l.epoch ∧
          (chainHashes kec roots)[l.epoch.toNat]? = some l.chainHash)) := by
  obtain ⟨-, current, hserv, -, hl⟩ := handover_unfold h
  obtain ⟨rfl, hget⟩ := servableEpoch_current hserv
  obtain ⟨h1, h2, h3, -⟩ := hl l rfl
  have hpos : 0 < roots.length := List.length_pos_iff.2 hne
  have hheld := latestOf_toNat hpos hlen
  have hc : c.epoch.toNat < roots.length := by
    have := (List.getElem?_eq_some_iff.1 hget).1; simpa using this
  have hcle : c.epoch ≤ latestOf roots.length := by
    rw [UInt32.le_iff_toNat_le]; omega
  refine ⟨hcle, UInt32.not_lt.1 h1, ?_⟩
  by_cases hceq : latestOf roots.length = c.epoch
  · exact Or.inl ⟨hceq, hget⟩
  · have hgt : c.epoch < latestOf roots.length := by
      have : (latestOf roots.length).toNat ≠ c.epoch.toNat := fun e => hceq (UInt32.toNat_inj.1 e)
      rw [UInt32.le_iff_toNat_le] at hcle
      exact UInt32.lt_iff_toNat_lt.2 (by omega)
    have hnlt : ¬ latestOf roots.length < l.epoch := fun hlt => h2 ⟨hgt, hlt⟩
    have heq : latestOf roots.length = l.epoch := by
      have := UInt32.not_lt.1 h1; have := UInt32.not_lt.1 hnlt
      rw [UInt32.le_iff_toNat_le] at *; exact UInt32.toNat_inj.1 (by omega)
    exact Or.inr ⟨heq, heq ▸ h3 heq⟩

/-- In key terms: if governance registered the key list `registered` (its chain hashes at the
current and latest epochs are the reported ones), an accepted handover holds exactly a prefix of
it. -/
theorem handover_binds_keys {kec : Bytes → Bytes} (hk : ∀ x, (kec x).length = 32)
    (hinj : Function.Injective kec) {roots registered : List (Bytes × Bytes)} {c l : CurrentRootEpoch}
    {rotate : Bool} (hne : roots ≠ []) (hlen : roots.length < 2 ^ 32)
    (hc : (chainHashes kec registered)[c.epoch.toNat]? = some c.chainHash)
    (hl : (chainHashes kec registered)[l.epoch.toNat]? = some l.chainHash)
    (h : ensureHandoverRegistered kec roots ⟨.current c, some l⟩ rotate = .ok ()) :
    roots = registered.take roots.length := by
  have hpos : 0 < roots.length := List.length_pos_iff.2 hne
  have hheld := latestOf_toNat hpos hlen
  have key : ∀ e : UInt32, latestOf roots.length = e → ∀ hash,
      (chainHashes kec roots)[e.toNat]? = some hash →
      (chainHashes kec registered)[e.toNat]? = some hash → roots = registered.take roots.length := by
    intro e he hash h1 h2
    have := chainHashes_binding hk hinj h1 h2
    subst he
    rw [hheld, Nat.sub_add_cancel hpos, List.take_length] at this
    exact this
  obtain ⟨-, -, hor⟩ := handover_binds_held hne hlen h
  rcases hor with ⟨he, hg⟩ | ⟨he, hg⟩
  · exact key _ he _ hg hc
  · exact key _ he _ hg hl

/-- Rotation is accepted only with a non-empty registry, from a source holding exactly the
current epoch, with the latest registered epoch being the current one: the generated epoch
`held + 1` cannot collide with an epoch pending activation. -/
theorem handover_rotation {kec : Bytes → Bytes} {roots : List (Bytes × Bytes)} {reg : Registration}
    (h : ensureHandoverRegistered kec roots reg true = .ok ()) :
    reg.registry ≠ .empty ∧ ∃ current, servableEpoch (chainHashes kec roots) reg.registry = .ok current ∧
      current = latestOf roots.length ∧ ∀ l, reg.latest = some l → l.epoch = latestOf roots.length := by
  obtain ⟨hne, current, hserv, hheld, hl⟩ := handover_unfold h
  refine ⟨fun he => hne ⟨rfl, he⟩, current, hserv, hheld rfl, fun l hl' => ?_⟩
  rw [(hl l hl').2.2.2 rfl, hheld rfl]

/-- With nothing registered only a one-epoch keyring joins, and nobody rotates. -/
theorem handover_empty {kec : Bytes → Bytes} {roots : List (Bytes × Bytes)} {rotate : Bool}
    (hlen : roots.length < 2 ^ 32) (h : ensureHandoverRegistered kec roots ⟨.empty, none⟩ rotate = .ok ()) :
    roots.length = 1 ∧ rotate = false := by
  obtain ⟨hrot, current, hserv, -, -⟩ := handover_unfold h
  refine ⟨by simpa using (servableEpoch_empty (by simpa using hlen) hserv).2, ?_⟩
  cases rotate
  · rfl
  · exact absurd ⟨rfl, rfl⟩ hrot

/-! ## The DstackKms contract -/

/-- `DstackKms.sol: RootEpoch`, without `evidenceUrl`. -/
structure Entry where
  ca : Bytes
  k256 : Bytes
  chainHash : Bytes
  registration : Nat

def Entry.keys (e : Entry) : Bytes × Bytes := (e.ca, e.k256)

/-- The root epoch storage of `DstackKms.sol`: `_rootEpochs`, `_currentRootEpoch`,
`_rootEpochRegistrations`, and the keys of `kmsInfo`. -/
structure Kms where
  epochs : List Entry
  current : Nat
  registrations : Nat
  kmsInfo : Bytes × Bytes

/-- `DstackKms.sol: P256_SPKI_PREFIX`. -/
def p256SpkiPrefix : Bytes :=
  [0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08,
   0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00, 0x04]

/-- `epoch == 0 ? bytes32(0) : _rootEpochs[epoch - 1].chainHash` in `registerRootEpoch`. -/
def previousHash (epochs : List Entry) : Bytes :=
  if epochs.length = 0 then zero32
  else
    match epochs[epochs.length - 1]? with
    | some e => e.chainHash
    | none => zero32

/-- `DstackKms.sol: registerRootEpoch` (with `_useRootEpoch(0)` for epoch 0), as the owner. -/
def registerRootEpoch (kec : Bytes → Bytes) (st : Kms) (ca k256 evidenceUrl : Bytes) :
    Except String (Kms × Nat) :=
  if ca.length ≠ 91 ∨ ca.take 27 ≠ p256SpkiPrefix then .error "InvalidEpochCaPubkey"
  else if k256.length ≠ 33 ∨ (k256.head? ≠ some 0x02 ∧ k256.head? ≠ some 0x03) then
    .error "InvalidEpochK256Pubkey"
  else if evidenceUrl = [] then .error "EmptyEpochEvidenceUrl"
  else
    let epoch := st.epochs.length
    if epoch = 0 ∧ st.kmsInfo.2 ≠ [] ∧
        (kec ca ≠ kec st.kmsInfo.1 ∨ kec k256 ≠ kec st.kmsInfo.2) then
      .error "Epoch0KeysDifferFromKmsInfo"
    else
      let chainHash := chainStep kec (previousHash st.epochs) ca k256
      let pushed : Kms := { st with
        epochs := st.epochs ++ [⟨ca, k256, chainHash, st.registrations⟩]
        registrations := st.registrations + 1 }
      .ok (if epoch = 0 then { pushed with kmsInfo := (ca, k256) } else pushed, epoch)

/-- `DstackKms.sol: activateRootEpoch` (with `_useRootEpoch`), as the owner. -/
def activateRootEpoch (st : Kms) (epoch : Nat) (chainHash : Bytes) : Except String Kms :=
  if epoch ≠ st.current + 1 ∨ epoch ≥ st.epochs.length then .error "InvalidRootEpochActivation"
  else
    match st.epochs[epoch]? with
    | none => .error "InvalidRootEpochActivation"
    | some e =>
      if e.chainHash ≠ chainHash then .error "RootEpochChainHashMismatch"
      else .ok { st with current := epoch, kmsInfo := e.keys }

/-- `DstackKms.sol: popRootEpoch`, as the owner. -/
def popRootEpoch (st : Kms) (epoch : Nat) (chainHash : Bytes) : Except String Kms :=
  if epoch + 1 ≠ st.epochs.length ∨ epoch ≤ st.current then .error "NotPendingRootEpoch"
  else
    match st.epochs[epoch]? with
    | none => .error "NotPendingRootEpoch"
    | some e =>
      if e.chainHash ≠ chainHash then .error "RootEpochChainHashMismatch"
      else .ok { st with epochs := st.epochs.dropLast }

inductive Step (kec : Bytes → Bytes) : Kms → Kms → Prop
  | register {st st' : Kms} {n : Nat} (ca k256 url : Bytes) :
      registerRootEpoch kec st ca k256 url = .ok (st', n) → Step kec st st'
  | activate {st st' : Kms} (epoch : Nat) (hash : Bytes) :
      activateRootEpoch st epoch hash = .ok st' → Step kec st st'
  | pop {st st' : Kms} (epoch : Nat) (hash : Bytes) :
      popRootEpoch st epoch hash = .ok st' → Step kec st st'

/-- States reachable from deployment or from an upgrade of a legacy contract, whose `kmsInfo`
may already be set but which has no root epoch storage yet. -/
inductive Reachable (kec : Bytes → Bytes) : Kms → Prop
  | init (kmsInfo : Bytes × Bytes) : Reachable kec ⟨[], 0, 0, kmsInfo⟩
  | step {st st' : Kms} : Reachable kec st → Step kec st st' → Reachable kec st'

/-- Each stored chain hash links its keys to the previous stored chain hash. -/
def Linked (kec : Bytes → Bytes) : Bytes → List Entry → Prop
  | _, [] => True
  | p, e :: es => e.chainHash = chainStep kec p e.ca e.k256 ∧ Linked kec e.chainHash es

def lastHash : Bytes → List Entry → Bytes
  | p, [] => p
  | _, e :: es => lastHash e.chainHash es

theorem linked_iff_map (kec : Bytes → Bytes) :
    ∀ (p : Bytes) (es : List Entry),
      Linked kec p es ↔ es.map Entry.chainHash = chainHashesFrom kec p (es.map Entry.keys)
  | p, [] => by simp [Linked, chainHashesFrom]
  | p, e :: es => by
    have ih := linked_iff_map kec e.chainHash es
    simp only [Linked, List.map_cons, Entry.keys, chainHashesFrom, List.cons.injEq]
    constructor
    · rintro ⟨h1, h2⟩; rw [← h1]; exact ⟨rfl, ih.1 h2⟩
    · rintro ⟨h1, h2⟩; rw [← h1] at h2; exact ⟨h1, ih.2 h2⟩

theorem linked_append (kec : Bytes → Bytes) (x : Entry) :
    ∀ (p : Bytes) (es : List Entry),
      Linked kec p (es ++ [x]) ↔
        Linked kec p es ∧ x.chainHash = chainStep kec (lastHash p es) x.ca x.k256
  | p, [] => by simp [Linked, lastHash]
  | p, e :: es => by
    simp only [List.cons_append, Linked, lastHash, linked_append kec x e.chainHash es, and_assoc]

theorem linked_take (kec : Bytes → Bytes) :
    ∀ (p : Bytes) (es : List Entry) (n : Nat), Linked kec p es → Linked kec p (es.take n)
  | _, [], _, _ => by simp [Linked]
  | _, _ :: _, 0, _ => by simp [Linked]
  | p, e :: es, n + 1, ⟨h1, h2⟩ => ⟨h1, linked_take kec e.chainHash es n h2⟩

theorem previousHash_eq (es : List Entry) : previousHash es = lastHash zero32 es := by
  have key : ∀ (p : Bytes) (es : List Entry), es ≠ [] →
      (es[es.length - 1]?).map Entry.chainHash = some (lastHash p es) := by
    intro p es
    induction es generalizing p with
    | nil => intro h; exact absurd rfl h
    | cons e es ih =>
      intro _
      cases es with
      | nil => simp [lastHash]
      | cons f rest =>
        have := ih e.chainHash (List.cons_ne_nil f rest)
        simpa [lastHash] using this
  unfold previousHash
  split
  · rename_i h; rw [List.length_eq_zero_iff.1 h]; rfl
  · rename_i h
    have := key zero32 es (fun he => h (by simp [he]))
    split
    · rename_i e he; rw [he] at this; simpa using this
    · rename_i he; rw [he] at this; cases this

/-- The invariant of reachable contract states. -/
structure Inv (kec : Bytes → Bytes) (st : Kms) : Prop where
  current_lt : st.epochs ≠ [] → st.current < st.epochs.length
  current_zero : st.epochs = [] → st.current = 0
  linked : Linked kec zero32 st.epochs
  fresh : ∀ e ∈ st.epochs, e.registration < st.registrations
  ordered : st.epochs.Pairwise (fun a b => a.registration < b.registration)
  kmsInfo : ∀ e, st.epochs[st.current]? = some e → st.kmsInfo = e.keys

theorem register_spec {kec : Bytes → Bytes} {st st' : Kms} {ca k256 url : Bytes} {n : Nat}
    (h : registerRootEpoch kec st ca k256 url = .ok (st', n)) :
    n = st.epochs.length ∧ st'.current = st.current ∧ st'.registrations = st.registrations + 1 ∧
      st'.epochs = st.epochs ++ [⟨ca, k256, chainStep kec (previousHash st.epochs) ca k256,
        st.registrations⟩] ∧
      st'.kmsInfo = (if st.epochs.length = 0 then (ca, k256) else st.kmsInfo) := by
  unfold registerRootEpoch at h
  split at h; · cases h
  split at h; · cases h
  split at h; · cases h
  dsimp only at h
  split at h; · cases h
  simp only [Except.ok.injEq, Prod.mk.injEq] at h
  obtain ⟨rfl, rfl⟩ := h
  split <;> simp_all

theorem activate_spec {st st' : Kms} {epoch : Nat} {hash : Bytes}
    (h : activateRootEpoch st epoch hash = .ok st') :
    epoch = st.current + 1 ∧ epoch < st.epochs.length ∧ st'.current = epoch ∧
      st'.epochs = st.epochs ∧ st'.registrations = st.registrations ∧
      ∃ e, st.epochs[epoch]? = some e ∧ e.chainHash = hash ∧ st'.kmsInfo = e.keys := by
  unfold activateRootEpoch at h
  split at h; · cases h
  rename_i hc
  split at h; · cases h
  rename_i e he
  split at h; · cases h
  rename_i hh
  cases h
  have hc' := not_or.1 hc
  exact ⟨Classical.byContradiction hc'.1, Nat.lt_of_not_ge hc'.2, rfl, rfl, rfl, e, he,
    Classical.byContradiction hh, rfl⟩

/-- Only a pending tail is popped: the last epoch, strictly past the current one. -/
theorem pop_spec {st st' : Kms} {epoch : Nat} {hash : Bytes}
    (h : popRootEpoch st epoch hash = .ok st') :
    st.current < epoch ∧ epoch + 1 = st.epochs.length ∧ st'.epochs = st.epochs.dropLast ∧
      st'.current = st.current ∧ st'.registrations = st.registrations ∧
      st'.kmsInfo = st.kmsInfo ∧ ∃ e, st.epochs[epoch]? = some e ∧ e.chainHash = hash := by
  unfold popRootEpoch at h
  split at h; · cases h
  rename_i hc
  split at h; · cases h
  rename_i e he
  split at h; · cases h
  rename_i hh
  cases h
  have hc' := not_or.1 hc
  exact ⟨Nat.lt_of_not_ge hc'.2, Classical.byContradiction hc'.1, rfl, rfl, rfl, rfl, e, he,
    Classical.byContradiction hh⟩

theorem inv_init (kec : Bytes → Bytes) (kmsInfo : Bytes × Bytes) : Inv kec ⟨[], 0, 0, kmsInfo⟩ where
  current_lt h := absurd rfl h
  current_zero _ := rfl
  linked := trivial
  fresh _ h := by cases h
  ordered := List.Pairwise.nil
  kmsInfo _ h := by cases h

theorem inv_step {kec : Bytes → Bytes} {st st' : Kms} (hi : Inv kec st) (hs : Step kec st st') :
    Inv kec st' := by
  cases hs with
  | register ca k256 url h =>
    obtain ⟨-, hcur, hreg, heps, hinfo⟩ := register_spec h
    refine ⟨fun _ => ?_, fun he => by simp [heps] at he, ?_, ?_, ?_, ?_⟩
    · rw [hcur, heps, List.length_append]
      by_cases he : st.epochs = []
      · rw [hi.current_zero he]; simp
      · have := hi.current_lt he; simp; omega
    · rw [heps, linked_append]; exact ⟨hi.linked, by rw [previousHash_eq]⟩
    · intro e he
      rw [heps, List.mem_append] at he
      rw [hreg]
      rcases he with he | he
      · have := hi.fresh e he; omega
      · simp at he; rw [he]; simp
    · rw [heps, List.pairwise_append]
      refine ⟨hi.ordered, List.pairwise_singleton _ _, fun a ha b hb => ?_⟩
      simp at hb; rw [hb]; exact hi.fresh a ha
    · intro e he
      rw [hcur, heps] at he
      rw [hinfo]
      by_cases h0 : st.epochs.length = 0
      · rw [List.length_eq_zero_iff.1 h0] at he ⊢
        rw [hi.current_zero (List.length_eq_zero_iff.1 h0)] at he
        simp at he; rw [← he]; rfl
      · have hlt := hi.current_lt (fun he' => h0 (by simp [he']))
        rw [List.getElem?_append_left hlt] at he
        simp only [h0, ↓reduceIte]
        exact hi.kmsInfo e he
  | activate epoch hash h =>
    obtain ⟨-, hlt, hcur, heps, hreg, e, he, -, hinfo⟩ := activate_spec h
    refine ⟨fun _ => by rw [hcur, heps]; exact hlt, fun h0 => by rw [heps] at h0; rw [h0] at hlt; simp at hlt, ?_, ?_, ?_, ?_⟩
    · rw [heps]; exact hi.linked
    · rw [heps, hreg]; exact hi.fresh
    · rw [heps]; exact hi.ordered
    · intro e' he'
      rw [hcur, heps, he] at he'
      cases he'; exact hinfo
  | pop epoch hash h =>
    obtain ⟨hlt, hlen, heps, hcur, hreg, hinfo, -⟩ := pop_spec h
    refine ⟨fun _ => ?_, fun h0 => ?_, ?_, ?_, ?_, ?_⟩
    · rw [hcur, heps, List.length_dropLast]; omega
    · rw [heps] at h0
      have := congrArg List.length h0
      simp [List.length_dropLast] at this; omega
    · rw [heps, List.dropLast_eq_take]; exact linked_take kec _ _ _ hi.linked
    · intro e he
      rw [heps] at he
      rw [hreg]; exact hi.fresh e ((List.dropLast_sublist _).subset he)
    · rw [heps]; exact hi.ordered.sublist (List.dropLast_sublist _)
    · intro e he
      rw [hcur, heps, List.getElem?_dropLast] at he
      simp only [show st.current < st.epochs.length - 1 by omega, ↓reduceIte] at he
      rw [hinfo]; exact hi.kmsInfo e he

theorem reachable_inv {kec : Bytes → Bytes} {st : Kms} (h : Reachable kec st) : Inv kec st := by
  induction h with
  | init kmsInfo => exact inv_init kec kmsInfo
  | step _ hs ih => exact inv_step ih hs

/-- Contract and KMS agree on the chain hash: the contract stores, for every epoch, exactly the
`chain_hashes` the KMS computes from the registered keys. -/
theorem reachable_chainHashes {kec : Bytes → Bytes} {st : Kms} (h : Reachable kec st) :
    st.epochs.map Entry.chainHash = chainHashes kec (st.epochs.map Entry.keys) :=
  (linked_iff_map kec zero32 st.epochs).1 (reachable_inv h).linked

/-- The current epoch only stays or moves by one. -/
theorem step_current_monotone {kec : Bytes → Bytes} {st st' : Kms} (hs : Step kec st st') :
    st'.current = st.current ∨ st'.current = st.current + 1 := by
  cases hs with
  | register _ _ _ h => exact Or.inl (register_spec h).2.1
  | activate _ _ h =>
    obtain ⟨he, -, hc, -⟩ := activate_spec h
    exact Or.inr (hc.trans he)
  | pop _ _ h => exact Or.inl (pop_spec h).2.2.2.1

/-- Entries up to the current epoch never change: once active, an epoch's keys and chain hash
are fixed. -/
theorem step_active_prefix {kec : Bytes → Bytes} {st st' : Kms} (hi : Inv kec st)
    (hne : st.epochs ≠ []) (hs : Step kec st st') :
    st'.epochs.take (st.current + 1) = st.epochs.take (st.current + 1) := by
  have hlt := hi.current_lt hne
  cases hs with
  | register _ _ _ h =>
    rw [(register_spec h).2.2.2.1, List.take_append_of_le_length (by omega)]
  | activate _ _ h => rw [(activate_spec h).2.2.2.1]
  | pop _ _ h =>
    obtain ⟨hlt', hlen, heps, -⟩ := pop_spec h
    rw [heps, List.dropLast_eq_take, List.take_take, Nat.min_eq_left (by omega)]

/-- A popped epoch number registered again gets a registration nobody used, so its policy rows
start empty. -/
theorem pop_then_register_fresh {kec : Bytes → Bytes} {st st1 st2 : Kms} {epoch n : Nat}
    {hash ca k256 url : Bytes} {old : Entry} (hi : Inv kec st)
    (hpop : popRootEpoch st epoch hash = .ok st1)
    (hreg : registerRootEpoch kec st1 ca k256 url = .ok (st2, n))
    (hold : st.epochs[epoch]? = some old) :
    n = epoch ∧ ∃ e, st2.epochs[n]? = some e ∧ old.registration < e.registration := by
  obtain ⟨-, hlen, heps1, -, hreg1, -⟩ := pop_spec hpop
  obtain ⟨hn, -, -, heps2, -⟩ := register_spec hreg
  have hn' : n = epoch := by rw [hn, heps1, List.length_dropLast]; omega
  refine ⟨hn', ⟨ca, k256, chainStep kec (previousHash st1.epochs) ca k256, st1.registrations⟩, ?_, ?_⟩
  · rw [heps2, List.getElem?_append_right (by rw [hn]; exact Nat.le_refl _), hn]; simp
  · rw [hreg1]
    exact hi.fresh old (List.mem_of_getElem? hold)

/-- The root epoch fields of `DstackKms.sol: _fillRootEpochs` (zero when nothing is
registered). -/
structure Fill where
  currentRootEpoch : Nat
  currentRootEpochHash : Bytes
  latestRootEpoch : Nat
  latestRootEpochHash : Bytes

/-- `DstackKms.sol: _latestRootEpoch`. -/
def latestRootEpoch (st : Kms) : Nat := if st.epochs.length = 0 then 0 else st.epochs.length - 1

/-- `DstackKms.sol: _fillRootEpochs`. -/
def fillRootEpochs (st : Kms) : Fill :=
  if st.epochs.length = 0 then ⟨0, zero32, 0, zero32⟩
  else
    ⟨st.current, ((st.epochs[st.current]?).map Entry.chainHash).getD zero32,
     latestRootEpoch st, ((st.epochs[latestRootEpoch st]?).map Entry.chainHash).getD zero32⟩

/-- What a reachable contract reports: current ≤ latest = count - 1, each with its chain hash
over the registered keys. This is why `ensure_kms_allowed`'s `latest.epoch >= current.epoch`
filter never rejects a contract answer. -/
theorem fill_spec {kec : Bytes → Bytes} {st : Kms} (h : Reachable kec st) (hne : st.epochs ≠ []) :
    let f := fillRootEpochs st
    f.currentRootEpoch ≤ f.latestRootEpoch ∧ f.latestRootEpoch + 1 = st.epochs.length ∧
      (chainHashes kec (st.epochs.map Entry.keys))[f.currentRootEpoch]? = some f.currentRootEpochHash ∧
      (chainHashes kec (st.epochs.map Entry.keys))[f.latestRootEpoch]? = some f.latestRootEpochHash := by
  have hi := reachable_inv h
  have hlt := hi.current_lt hne
  have h0 : st.epochs.length ≠ 0 := fun h0 => hne (List.length_eq_zero_iff.1 h0)
  have hmap := reachable_chainHashes h
  have get : ∀ i, i < st.epochs.length →
      (chainHashes kec (st.epochs.map Entry.keys))[i]? =
        some (((st.epochs[i]?).map Entry.chainHash).getD zero32) := by
    intro i hi'
    rw [← hmap, List.getElem?_map, List.getElem?_eq_getElem hi']
    rfl
  simp only [fillRootEpochs, latestRootEpoch, h0, ↓reduceIte]
  refine ⟨by omega, by omega, get _ hlt, get _ (by omega)⟩

/-- A keyring holding the registered keys up to the current epoch serves it. -/
theorem keyring_servable_of_contract {kec : Bytes → Bytes} {st : Kms} {roots : List (Bytes × Bytes)}
    (h : Reachable kec st) (hne : st.epochs ≠ []) (hsmall : st.current < 2 ^ 32)
    (hkeys : roots.take (st.current + 1) = (st.epochs.map Entry.keys).take (st.current + 1)) :
    servableEpoch (chainHashes kec roots)
        (.current ⟨st.current.toUInt32, (fillRootEpochs st).currentRootEpochHash⟩) =
      .ok st.current.toUInt32 := by
  obtain ⟨-, -, hcur, -⟩ := fill_spec h hne
  have h0 : st.epochs.length ≠ 0 := fun h0 => hne (List.length_eq_zero_iff.1 h0)
  have hc : (fillRootEpochs st).currentRootEpoch = st.current := by
    simp [fillRootEpochs, h0]
  rw [hc] at hcur
  have htake : ∀ (p : Bytes) (l : List (Bytes × Bytes)) (n : Nat),
      (chainHashesFrom kec p l).take n = chainHashesFrom kec p (l.take n) := by
    intro p l n
    induction l generalizing p n with
    | nil => simp [chainHashesFrom]
    | cons x l ih => cases n <;> simp [chainHashesFrom, ih]
  have hget : (chainHashes kec roots)[st.current]? =
      (chainHashes kec (st.epochs.map Entry.keys))[st.current]? := by
    have e1 := congrArg (fun l => l[st.current]?) (htake zero32 roots (st.current + 1))
    have e2 := congrArg (fun l => l[st.current]?)
      (htake zero32 (st.epochs.map Entry.keys) (st.current + 1))
    simp only [List.getElem?_take, Nat.lt_succ_self, ↓reduceIte] at e1 e2
    simp only [chainHashes]
    rw [e1, e2, hkeys]
  have hn : st.current.toUInt32.toNat = st.current := by simp; omega
  simp only [servableEpoch, hn, hget, hcur, ↓reduceIte]

/-- Conversely, a keyring serving the contract's current epoch holds exactly its registered keys
up to that epoch. -/
theorem servable_of_contract_binds {kec : Bytes → Bytes} (hk : ∀ x, (kec x).length = 32)
    (hinj : Function.Injective kec) {st : Kms} {roots : List (Bytes × Bytes)} {e : UInt32}
    (h : Reachable kec st) (hne : st.epochs ≠ []) (hsmall : st.current < 2 ^ 32)
    (hs : servableEpoch (chainHashes kec roots)
        (.current ⟨st.current.toUInt32, (fillRootEpochs st).currentRootEpochHash⟩) = .ok e) :
    e.toNat = st.current ∧
      roots.take (st.current + 1) = (st.epochs.map Entry.keys).take (st.current + 1) := by
  obtain ⟨-, -, hcur, -⟩ := fill_spec h hne
  have h0 : st.epochs.length ≠ 0 := fun h0 => hne (List.length_eq_zero_iff.1 h0)
  have hc : (fillRootEpochs st).currentRootEpoch = st.current := by
    simp [fillRootEpochs, h0]
  rw [hc] at hcur
  have hn : st.current.toUInt32.toNat = st.current := by simp; omega
  obtain ⟨he, hb⟩ := servableEpoch_binds_keys (c := ⟨st.current.toUInt32, _⟩) hk hinj
    (by simpa only [hn] using hcur) hs
  subst he
  simp only [hn] at hb
  exact ⟨hn, hb⟩

/-! ### Mirrors of `onboard_service.rs` tests, on a toy hash -/

/-- A toy 32-byte hash for evaluating examples; no property of it is assumed. -/
def toyKec (x : Bytes) : Bytes :=
  List.replicate 31 0 ++ [x.foldl (fun a b => (a * 257 + b + 1) % 1000003) 7]

/-- `handover(n)` of the tests: distinct keys per epoch. -/
def toyKeys (n : Nat) (seed : Nat := 0) : List (Bytes × Bytes) :=
  (List.range n).map fun i => ([seed, i, 1], [seed, i, 2])

def toyEpoch (keys : List (Bytes × Bytes)) (e : Nat) : CurrentRootEpoch :=
  ⟨e.toUInt32, ((chainHashes toyKec keys)[e]?).getD []⟩

def toyRegistered (keys : List (Bytes × Bytes)) (current latest : Nat) : Registration :=
  ⟨.current (toyEpoch keys current), some (toyEpoch keys latest)⟩

def isOk {α : Type} : Except String α → Bool
  | .ok _ => true
  | .error _ => false

-- rotation_imports_the_keyring_and_generates_the_next_epoch
example : isOk (ensureHandoverRegistered toyKec (toyKeys 2) (toyRegistered (toyKeys 2) 1 1) true) = true := by
  decide +kernel
-- onboarding_checks_the_handover_against_the_current_epoch
example : isOk (ensureHandoverRegistered toyKec (toyKeys 2) (toyRegistered (toyKeys 2) 0 1) false) = true := by
  decide +kernel
example : isOk (ensureHandoverRegistered toyKec (toyKeys 2) (toyRegistered (toyKeys 2) 0 1) true) = false := by
  decide +kernel
example : isOk (ensureHandoverRegistered toyKec (toyKeys 2) (toyRegistered (toyKeys 2 1) 1 1) false) = false := by
  decide +kernel
example : isOk (ensureHandoverRegistered toyKec (toyKeys 1) (toyRegistered (toyKeys 2) 1 1) false) = false := by
  decide +kernel
example : isOk (ensureHandoverRegistered toyKec ((toyKeys 2).drop 1) (toyRegistered (toyKeys 2) 0 1) false) = false := by
  decide +kernel
-- rotation_refuses_a_registered_epoch_pending_activation
example : isOk (ensureHandoverRegistered toyKec (toyKeys 2) (toyRegistered (toyKeys 3) 1 2) true) = false := by
  decide +kernel
-- onboarding_binds_the_pending_tail_to_the_latest_registered_epoch
example : isOk (ensureHandoverRegistered toyKec (toyKeys 3) (toyRegistered (toyKeys 3) 1 1) false) = false := by
  decide +kernel
example : isOk (ensureHandoverRegistered toyKec (toyKeys 2) (toyRegistered (toyKeys 3) 1 2) false) = true := by
  decide +kernel
example : isOk (ensureHandoverRegistered toyKec (toyKeys 3) (toyRegistered (toyKeys 4) 1 3) false) = false := by
  decide +kernel
-- an_unregistered_deployment_can_only_join_at_epoch_0
example : isOk (ensureHandoverRegistered toyKec (toyKeys 1) ⟨.empty, none⟩ false) = true := by decide +kernel
example : isOk (ensureHandoverRegistered toyKec (toyKeys 2) ⟨.empty, none⟩ false) = false := by decide +kernel
example : isOk (ensureHandoverRegistered toyKec (toyKeys 1) ⟨.empty, none⟩ true) = false := by decide +kernel
-- a_keyring_serves_the_current_epoch_it_holds
example : (servableEpoch (chainHashes toyKec (toyKeys 3)) (.current (toyEpoch (toyKeys 3) 1))).toOption = some 1 := by
  decide +kernel
example : (servableEpoch (chainHashes toyKec (toyKeys 3)) .unchecked).toOption = some 2 := by
  decide +kernel
example : isOk (servableEpoch (chainHashes toyKec (toyKeys 3)) .empty) = false := by decide +kernel
example : isOk (servableEpoch (chainHashes toyKec (toyKeys 3)) (.current (toyEpoch (toyKeys 4) 3))) = false := by
  decide +kernel

end DstackFormal.Kms.RootEpoch
