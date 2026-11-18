-- SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
--
-- SPDX-License-Identifier: Apache-2.0

/-!
# Guest boot: measure before use

A control-flow model of `dstack/dstack-util/src/system_setup.rs`:
`do_sys_setup`, `Stage0::measure_app_info`, `Stage0::measure_gpu` (only the
`gpu-policy-hash` emission and the gate outcome), `Stage0::request_app_keys`,
`Stage0::request_app_keys_from_kms` (`os-image-hash`), `Stage0::get_snp_seed`
(`system_setup/snp.rs`, its pre-key config check), `Stage0::setup_fs`,
`Stage0::verify_app`, `verify_key_provider_id`, `parse_dstack_options`, and
`Stage1::setup` / `unseal_env_vars` / `close_env_window`.

The boot is a list of `Step`s: an observable `Action`, a `check` that aborts
on `false` (a Rust `?`/`bail!`), or `fail`. `run` executes until the first
failure; the application starts iff `dstack-util setup` returns `Ok`
(`appStarted`), since the app units are ordered after it.

Covered branches: compose parse failure (`Stage0::load`), the app-compose
policy gate, `app_id` defaulting to the truncated compose hash and its
20-byte check, instance-id seed regeneration, `no_instance_id`, platform
binding on/off and SNP, any number of init scripts, GPU gate fail/pass with or
without a `gpu-attestation` payload, every key-provider kind (KMS with
`os-image-hash`; SEV-SNP with its early `verify_app_config` and encrypted-storage
requirement), key-provider failure, empty disk key, config-id and key-provider
pin checks, cmdline parse failure, mount, env decryption, env-window closing.

Proven:
* `emitNames_run_prefix`, `appStarted_spec`: the runtime events of
  any run are a prefix of `system-preparing, app-id, compose-hash,
  init-script-hash*, gpu-policy-hash, instance-id, boot-mr-done,
  [os-image-hash], [gpu-attestation], key-provider, storage-fs,
  storage-encrypted, system-ready`, and exactly that on success.
* Ordering: keys are requested only after `boot-mr-done`
  (`requestKeys_after_bootMrDone`); the config-id check, the `key-provider`
  measurement and both storage events precede the mount
  (`mount_after_measurements`); keys are written only after the config-id
  check (`writeKeys_after_checkConfig`); env decryption follows
  `system-ready` (`decryptEnv_after_systemReady`).
* `program_ok`, `appStarted_spec`: the app starts only if every check passed;
  its trace then contains `system-ready` and the env-window close, and every
  config-id check in it was accepted.
* `run_dataflow`: every config-derived argument of a key request, config-PCR
  extend, config-id check, mount and env decryption equals the payload of an
  event measured earlier in the same trace, or is a field of the compose file
  whose hash was measured (assuming `sha256` injective).

Modeling gaps: hashing, parsing, the GPU gate, key providers, the config-id
verifier, mount and decryption are opaque parameters (`Fns`, `Platform`); the
key provider is modeled as answering from the measurement log it is shown.
`emit_runtime_event` failures, `platform_instance_binding` errors, secure-time
sync, swap, gateway registration (non-fatal in Rust) and file linking are
omitted. `keys.key_provider.kind()` is modeled as the requested kind, which
holds for every branch of `request_app_keys` / `gen_app_keys_from_seed`. The
host-supplied env ciphertext and disk contents are not modeled; they are
authenticated by keys, not measured.
-/

namespace DstackFormal.Guest.BootTrace

abbrev Bytes := List UInt8

/-- `dstack_types::KeyProviderKind`. -/
inductive KeyProviderKind where
  | none
  | «local»
  | kms
  | tpm
  | sevSnp
  deriving DecidableEq, Repr

/-- `FsType`. -/
inductive FsType where
  | zfs
  | ext4
  deriving DecidableEq, Repr

/-- Runtime event names emitted by `dstack-util setup`. -/
inductive Ev where
  | systemPreparing
  | appId
  | composeHash
  | initScriptHash
  | gpuPolicyHash
  | instanceId
  | bootMrDone
  | osImageHash
  | gpuAttestation
  | keyProvider
  | storageFs
  | storageEncrypted
  | systemReady
  deriving DecidableEq, Repr

/-- The string passed to `emit_runtime_event`. -/
def Ev.name : Ev → String
  | .systemPreparing => "system-preparing"
  | .appId => "app-id"
  | .composeHash => "compose-hash"
  | .initScriptHash => "init-script-hash"
  | .gpuPolicyHash => "gpu-policy-hash"
  | .instanceId => "instance-id"
  | .bootMrDone => "boot-mr-done"
  | .osImageHash => "os-image-hash"
  | .gpuAttestation => "gpu-attestation"
  | .keyProvider => "key-provider"
  | .storageFs => "storage-fs"
  | .storageEncrypted => "storage-encrypted"
  | .systemReady => "system-ready"

/-- Every boot event name passes `RuntimeEvent::validate` as a V1 event. -/
theorem Ev.name_colon_free (e : Ev) : ':' ∉ e.name.toList := by cases e <;> decide

/-- The `AppCompose` fields the boot path consumes. -/
structure AppCompose where
  keyProvider : KeyProviderKind
  keyProviderId : Bytes
  initScripts : List Bytes
  noInstanceId : Bool
  storageFs : Option FsType
  storageDiscard : Bool
  allowedEnvs : List Bytes

/-- Host-supplied inputs (`HostShared`, `/proc/cmdline`). `cmdline` is the
result of `parse_dstack_options` on the kernel command line (`none` = error). -/
structure Host where
  composeFile : Bytes
  appId : Bytes
  instanceIdSeed : Bytes
  cmdline : Option (Bool × FsType)

/-- The `AppKeys` fields the boot path consumes. -/
structure Keys where
  diskKey : Bytes
  providerId : Bytes
  osImageHash : Bytes

/-- `LocalMrConfigValues` passed to `verify_mr_config_id`. -/
structure LocalValues where
  composeHash : Bytes
  gpuPolicyHash : Bytes
  initScriptHashes : List Bytes
  appId : Bytes
  instanceId : Bytes
  keyProvider : KeyProviderKind
  keyProviderId : Bytes

/-- Inputs of the AWS `MrConfig::V2` extended into PCR8. -/
structure ConfigPcrInput where
  composeHash : Bytes
  appId : Bytes
  keyProvider : KeyProviderKind
  keyProviderId : Bytes

inductive Action where
  | emit (e : Ev) (payload : Bytes)
  /-- `measure_aws_config_pcr` (a no-op off AWS). -/
  | extendConfigPcr (v : ConfigPcrInput)
  /-- `verify_app_config`. -/
  | checkConfig (l : LocalValues)
  /-- `request_app_keys`; `log` is the measurement log at that point. -/
  | requestKeys (kind : KeyProviderKind) (log : List (Ev × Bytes))
  | writeKeys
  /-- `mount_data_disk(keys, opts)`. -/
  | mount (encrypted : Bool) (fs : FsType) (discard : Bool) (diskKey : Bytes)
  /-- `decrypt_env` + `parse_env(.., allowed_envs)`. -/
  | decryptEnv (allowed : List Bytes)
  | closeEnvWindow

inductive Step where
  | act (a : Action)
  | check (ok : Bool)
  | fail

/-- Pure functions of the guest code. -/
structure Fns where
  sha256 : Bytes → Bytes
  parseCompose : Bytes → Option AppCompose
  /-- `gpu_policy_hash` of the raw compose file. -/
  gpuPolicyHash : Bytes → Bytes
  /-- `serde_json::to_vec(&KeyProviderInfo)`. -/
  keyProviderInfo : KeyProviderKind → Bytes → Bytes
  /-- `FsType::to_string`. -/
  fsName : FsType → Bytes

/-- Platform state and outcomes of opaque operations. -/
structure Platform where
  isSnp : Bool
  binding : Option Bytes
  random : Bytes
  /-- `verify_app_compose_policy`. -/
  policyOk : AppCompose → Bool
  /-- `measure_gpu` after the policy hash: `none` = gate failed. -/
  gpu : AppCompose → Option (Option Bytes)
  keys : KeyProviderKind → List (Ev × Bytes) → Option Keys
  /-- `verify_mr_config_id` against the attested config register. -/
  configOk : LocalValues → Bool
  mountOk : Bool
  envOk : Bool
  windowClosed : Bool

def emitAll (l : List (Ev × Bytes)) : List Step := l.map fun x => .act (.emit x.1 x.2)

/-- Payload of `storage-encrypted`: `b"1"` or `b"0"`. -/
def encFlag (enc : Bool) : Bytes := if enc then [0x31] else [0x30]

/-- `Stage0::setup_fs` after `request_app_keys`, then `Stage1::setup`. -/
def afterKeys (F : Fns) (h : Host) (p : Platform) (c : AppCompose)
    (loc : KeyProviderKind → Bytes → LocalValues) (gpuEv : Option Bytes)
    (kind : KeyProviderKind) (k : Keys) : List Step :=
  [.check !k.diskKey.isEmpty] ++
  (match gpuEv with
   | some ev => [.act (.emit .gpuAttestation ev)]
   | none => []) ++
  [.act (.checkConfig (loc kind k.providerId)), .check (p.configOk (loc kind k.providerId)),
   .check (c.keyProviderId.isEmpty || c.keyProviderId == k.providerId),
   .act (.emit .keyProvider (F.keyProviderInfo kind k.providerId)), .act .writeKeys] ++
  match h.cmdline with
  | none => [.fail]
  | some (enc, fs0) =>
    let fs := c.storageFs.getD fs0
    [.act (.emit .storageFs (F.fsName fs)),
     .act (.emit .storageEncrypted (encFlag enc)),
     .act (.mount enc fs c.storageDiscard k.diskKey), .check p.mountOk,
     .act (.emit .systemReady []),
     .act (.decryptEnv c.allowedEnvs), .check p.envOk,
     .act .closeEnvWindow, .check p.windowClosed]

/-- `request_app_keys` (with the SEV-SNP pre-checks of `get_snp_seed` and the
`os-image-hash` emission of `request_app_keys_from_kms`), then `afterKeys`. -/
def keyPhase (F : Fns) (h : Host) (p : Platform) (c : AppCompose) (log : List (Ev × Bytes))
    (loc : KeyProviderKind → Bytes → LocalValues) (gpuEv : Option Bytes) : List Step :=
  let kind := c.keyProvider
  (if kind = .sevSnp then
    [.check p.isSnp, .act (.checkConfig (loc .sevSnp [])), .check (p.configOk (loc .sevSnp []))] ++
      (match h.cmdline with
       | none => [.fail]
       | some (enc, _) => [.check enc])
   else []) ++
  [.act (.requestKeys kind log)] ++
  match p.keys kind log with
  | none => [.fail]
  | some k =>
    (if kind = .kms then [.act (.emit .osImageHash k.osImageHash)] else []) ++
      afterKeys F h p c loc gpuEv kind k

/-- `instance_info.app_id`, defaulting to the truncated compose hash. -/
def effectiveAppId (F : Fns) (h : Host) : Bytes :=
  if h.appId.isEmpty then (F.sha256 h.composeFile).take 20 else h.appId

/-- `instance_id = sha256(seed || app_id || binding)[..20]` (empty with `no_instance_id`). -/
def instanceIdOf (F : Fns) (h : Host) (p : Platform) (c : AppCompose) : Bytes :=
  let seed :=
    if (c.keyProvider == .none && !p.isSnp) || h.instanceIdSeed.isEmpty then p.random
    else h.instanceIdSeed
  let binding := if p.isSnp then [] else p.binding.getD []
  if c.noInstanceId then [] else (F.sha256 (seed ++ effectiveAppId F h ++ binding)).take 20

/-- Events of `measure_app_info` emitted before the GPU gate can fail. -/
def premeasured (F : Fns) (h : Host) (c : AppCompose) : List (Ev × Bytes) :=
  [(.systemPreparing, []), (.appId, effectiveAppId F h), (.composeHash, F.sha256 h.composeFile)] ++
    (c.initScripts.map F.sha256).map (fun x => (.initScriptHash, x)) ++
    [(.gpuPolicyHash, F.gpuPolicyHash h.composeFile)]

/-- The measurement log when `boot-mr-done` has been emitted. -/
def measuredLog (F : Fns) (h : Host) (p : Platform) (c : AppCompose) : List (Ev × Bytes) :=
  premeasured F h c ++ [(.instanceId, instanceIdOf F h p c), (.bootMrDone, [])]

/-- The `AppInfo` values handed to `verify_app_config`. -/
def localValues (F : Fns) (h : Host) (p : Platform) (c : AppCompose)
    (kind : KeyProviderKind) (id : Bytes) : LocalValues :=
  ⟨F.sha256 h.composeFile, F.gpuPolicyHash h.composeFile, c.initScripts.map F.sha256,
    effectiveAppId F h, instanceIdOf F h p c, kind, id⟩

/-- `measure_app_info` from the first event on, then the rest of `setup_fs`. -/
def body (F : Fns) (h : Host) (p : Platform) (c : AppCompose) : List Step :=
  emitAll (premeasured F h c) ++
  match p.gpu c with
  | none => [.fail]
  | some g =>
    emitAll [(.instanceId, instanceIdOf F h p c), (.bootMrDone, [])] ++
      [.act (.extendConfigPcr
        ⟨F.sha256 h.composeFile, effectiveAppId F h, c.keyProvider, c.keyProviderId⟩)] ++
      keyPhase F h p c (measuredLog F h p c) (localValues F h p c) g

/-- `do_sys_setup` (after `Stage0::load` parsed the compose file). -/
def program (F : Fns) (h : Host) (p : Platform) : List Step :=
  match F.parseCompose h.composeFile with
  | none => [.fail]
  | some c =>
    if !p.policyOk c then [.fail]
    else if (effectiveAppId F h).length ≠ 20 then [.fail]
    else body F h p c

/-! ## Execution -/

/-- Execute until the first failing step; the flag is `Ok`. -/
def exec : List Step → List Action × Bool
  | [] => ([], true)
  | .act a :: s => ((a :: (exec s).1), (exec s).2)
  | .check b :: s => if b then exec s else ([], false)
  | .fail :: _ => ([], false)

def Step.ok : Step → Bool
  | .act _ => true
  | .check b => b
  | .fail => false

def actions (s : List Step) : List Action := s.filterMap fun | .act a => some a | _ => none

def run (F : Fns) (h : Host) (p : Platform) : List Action := (exec (program F h p)).1

/-- `dstack-util setup` returned `Ok`, so the application units start. -/
def appStarted (F : Fns) (h : Host) (p : Platform) : Prop := (exec (program F h p)).2 = true

theorem exec_prefix : ∀ s : List Step, (exec s).1 <+: actions s
  | [] => List.prefix_refl _
  | .act a :: s => by simpa [exec, actions] using exec_prefix s
  | .check b :: s => by
      cases b
      · simp [exec]
      · simpa [exec, actions] using exec_prefix s
  | .fail :: _ => by simp [exec]

theorem exec_ok : ∀ s : List Step, (exec s).2 = true → (∀ st ∈ s, st.ok = true) ∧ (exec s).1 = actions s
  | [] => fun _ => by simp [exec, actions]
  | .act a :: s => fun h => by
      have := exec_ok s h
      refine ⟨?_, ?_⟩
      · simpa [Step.ok] using this.1
      · simp only [exec, actions, List.filterMap_cons] at this ⊢; rw [this.2]
  | .check b :: s => fun h => by
      cases b
      · simp [exec] at h
      · have := exec_ok s h
        refine ⟨?_, ?_⟩
        · simpa [Step.ok] using this.1
        · simpa [exec, actions] using this.2
  | .fail :: _ => fun h => by simp [exec] at h

theorem actions_append (a b : List Step) : actions (a ++ b) = actions a ++ actions b := by
  simp [actions, List.filterMap_append]

theorem actions_emitAll (l : List (Ev × Bytes)) :
    actions (emitAll l) = l.map fun x => .emit x.1 x.2 := by
  induction l with
  | nil => rfl
  | cons x xs ih => simp only [emitAll, actions, List.map_cons, List.filterMap_cons] at ih ⊢; rw [ih]

/-! ## Flattened action lists -/

def emits (l : List (Ev × Bytes)) : List Action := l.map fun x => .emit x.1 x.2

theorem actions_afterKeys (F : Fns) (h : Host) (p : Platform) (c : AppCompose) loc g kind k :
    actions (afterKeys F h p c loc g kind k) =
      (match g with | some ev => [.emit .gpuAttestation ev] | none => []) ++
      [.checkConfig (loc kind k.providerId),
       .emit .keyProvider (F.keyProviderInfo kind k.providerId), .writeKeys] ++
      match h.cmdline with
      | none => []
      | some (enc, fs0) =>
        [.emit .storageFs (F.fsName (c.storageFs.getD fs0)),
         .emit .storageEncrypted (encFlag enc),
         .mount enc (c.storageFs.getD fs0) c.storageDiscard k.diskKey,
         .emit .systemReady [], .decryptEnv c.allowedEnvs, .closeEnvWindow] := by
  unfold afterKeys
  cases g <;> cases h.cmdline <;> rfl

theorem actions_keyPhase (F : Fns) (h : Host) (p : Platform) (c : AppCompose) log loc g :
    actions (keyPhase F h p c log loc g) =
      (if c.keyProvider = .sevSnp then [.checkConfig (loc .sevSnp [])] else []) ++
      [.requestKeys c.keyProvider log] ++
      match p.keys c.keyProvider log with
      | none => []
      | some k =>
        (if c.keyProvider = .kms then [.emit .osImageHash k.osImageHash] else []) ++
          actions (afterKeys F h p c loc g c.keyProvider k) := by
  unfold keyPhase
  simp only [actions_append]
  congr 1
  · congr 1
    split
    · cases h.cmdline <;> rfl
    · rfl
  · split
    · rfl
    · rw [actions_append]; congr 1; split <;> rfl

theorem actions_body (F : Fns) (h : Host) (p : Platform) (c : AppCompose) :
    actions (body F h p c) =
      emits (premeasured F h c) ++
      match p.gpu c with
      | none => []
      | some g =>
        emits [(.instanceId, instanceIdOf F h p c), (.bootMrDone, [])] ++
          [.extendConfigPcr ⟨F.sha256 h.composeFile, effectiveAppId F h, c.keyProvider, c.keyProviderId⟩] ++
          actions (keyPhase F h p c (measuredLog F h p c) (localValues F h p c) g) := by
  unfold body
  rw [actions_append, actions_emitAll]
  congr 1
  split
  · rfl
  · rw [actions_append, actions_append, actions_emitAll]; rfl

theorem actions_program (F : Fns) (h : Host) (p : Platform) :
    actions (program F h p) = [] ∨
      ∃ c, F.parseCompose h.composeFile = some c ∧ actions (program F h p) = actions (body F h p c) := by
  unfold program
  split
  · exact Or.inl rfl
  · rename_i c hc
    split
    · exact Or.inl rfl
    · split
      · exact Or.inl rfl
      · exact Or.inr ⟨c, hc, rfl⟩

/-! ## Ordering -/

/-- The first `Q`-action is preceded by a `P`-action. -/
def precedes (P Q : Action → Bool) : List Action → Bool
  | [] => true
  | x :: xs => P x || (!Q x && precedes P Q xs)

theorem precedes_append (P Q : Action → Bool) (A B : List Action) :
    precedes P Q (A ++ B) = (precedes P Q A && (A.any P || precedes P Q B)) := by
  induction A with
  | nil => simp [precedes]
  | cons x xs ih => cases hP : P x <;> cases hQ : Q x <;> simp [precedes, ih, hP, hQ]

theorem precedes_of_prefix {P Q : Action → Bool} {A B : List Action} (h : A <+: B)
    (hB : precedes P Q B = true) : precedes P Q A = true := by
  obtain ⟨t, rfl⟩ := h
  rw [precedes_append] at hB
  simp only [Bool.and_eq_true] at hB
  exact hB.1

theorem precedes_emits_append (P Q : Action → Bool) (hQ : ∀ e x, Q (.emit e x) = false)
    (l : List (Ev × Bytes)) (B : List Action) (hB : precedes P Q B = true) :
    precedes P Q (emits l ++ B) = true := by
  induction l with
  | nil => exact hB
  | cons x xs ih => simp [emits, precedes, hQ] at ih ⊢; exact Or.inr ih

def isEmit (e : Ev) : Action → Bool
  | .emit e' _ => e' == e
  | _ => false

def isRequestKeys : Action → Bool
  | .requestKeys .. => true
  | _ => false

def isCheckConfig : Action → Bool
  | .checkConfig .. => true
  | _ => false

def isMount : Action → Bool
  | .mount .. => true
  | _ => false

def isDecryptEnv : Action → Bool
  | .decryptEnv .. => true
  | _ => false

def isWriteKeys : Action → Bool
  | .writeKeys => true
  | _ => false

set_option linter.unusedSimpArgs false in
/-- Lift an ordering fact about `afterKeys` to every run. -/
theorem precedes_run_of_afterKeys (P Q : Action → Bool) (F : Fns) (h : Host) (p : Platform)
    (hQe : ∀ e x, Q (.emit e x) = false) (hQc : ∀ l, Q (.checkConfig l) = false)
    (hQr : ∀ k l, Q (.requestKeys k l) = false) (hQp : ∀ v, Q (.extendConfigPcr v) = false)
    (htail : ∀ c loc g kind k, precedes P Q (actions (afterKeys F h p c loc g kind k)) = true) :
    precedes P Q (run F h p) = true := by
  refine precedes_of_prefix (exec_prefix _) ?_
  rcases actions_program F h p with h0 | ⟨c, _, h1⟩
  · rw [h0]; rfl
  rw [h1, actions_body]
  apply precedes_emits_append P Q hQe
  split
  · rfl
  next g _ =>
    rw [List.append_assoc]
    apply precedes_emits_append P Q hQe
    rw [actions_keyPhase]
    by_cases hs : c.keyProvider = .sevSnp <;>
      cases hk : p.keys c.keyProvider (measuredLog F h p c) <;>
      by_cases hm : c.keyProvider = .kms <;>
      simp [hs, hk, hm, precedes, precedes_append, hQe, hQc, hQr, hQp, htail]

/-- The disk/app keys are requested only after `boot-mr-done`. -/
theorem requestKeys_after_bootMrDone (F : Fns) (h : Host) (p : Platform) :
    precedes (isEmit .bootMrDone) isRequestKeys (run F h p) = true := by
  refine precedes_of_prefix (exec_prefix _) ?_
  rcases actions_program F h p with h0 | ⟨c, _, h1⟩
  · rw [h0]; rfl
  rw [h1, actions_body]
  apply precedes_emits_append _ _ (fun _ _ => rfl)
  split
  · rfl
  · simp [emits, precedes, isEmit, isRequestKeys]

/-- Mounting the data disk is preceded by the config-id check, the
`key-provider` measurement and both storage-option measurements. -/
theorem mount_after_measurements (F : Fns) (h : Host) (p : Platform) :
    precedes isCheckConfig isMount (run F h p) = true ∧
    precedes (isEmit .keyProvider) isMount (run F h p) = true ∧
    precedes (isEmit .storageFs) isMount (run F h p) = true ∧
    precedes (isEmit .storageEncrypted) isMount (run F h p) = true := by
  refine ⟨?_, ?_, ?_, ?_⟩ <;>
  refine precedes_run_of_afterKeys _ _ F h p (fun _ _ => rfl) (fun _ => rfl) (fun _ _ => rfl)
    (fun _ => rfl) ?_ <;>
  · intro c loc g kind k
    rw [actions_afterKeys]
    cases g <;> cases h.cmdline <;> simp [precedes, isMount, isEmit, isCheckConfig]

/-- App keys are written to disk only after the config-id check. -/
theorem writeKeys_after_checkConfig (F : Fns) (h : Host) (p : Platform) :
    precedes isCheckConfig isWriteKeys (run F h p) = true := by
  refine precedes_run_of_afterKeys _ _ F h p (fun _ _ => rfl) (fun _ => rfl) (fun _ _ => rfl)
    (fun _ => rfl) ?_
  intro c loc g kind k
  rw [actions_afterKeys]
  cases g <;> cases h.cmdline <;> simp [precedes, isWriteKeys, isCheckConfig]

/-- The env is decrypted only after `system-ready`. -/
theorem decryptEnv_after_systemReady (F : Fns) (h : Host) (p : Platform) :
    precedes (isEmit .systemReady) isDecryptEnv (run F h p) = true := by
  refine precedes_run_of_afterKeys _ _ F h p (fun _ _ => rfl) (fun _ => rfl) (fun _ _ => rfl)
    (fun _ => rfl) ?_
  intro c loc g kind k
  rw [actions_afterKeys]
  cases g <;> cases h.cmdline <;> simp [precedes, isDecryptEnv, isEmit]

/-! ## Event order -/

def emitNames (t : List Action) : List Ev := t.filterMap fun | .emit e _ => some e | _ => none

/-- The full runtime-event sequence of a successful boot. -/
def expectedNames (kind : KeyProviderKind) (nInit : Nat) (gpuAttested : Bool) : List Ev :=
  [.systemPreparing, .appId, .composeHash] ++ List.replicate nInit .initScriptHash ++
    [.gpuPolicyHash, .instanceId, .bootMrDone] ++
    (if kind = .kms then [.osImageHash] else []) ++
    (if gpuAttested then [.gpuAttestation] else []) ++
    [.keyProvider, .storageFs, .storageEncrypted, .systemReady]

#guard (expectedNames .kms 1 false).map Ev.name =
  ["system-preparing", "app-id", "compose-hash", "init-script-hash", "gpu-policy-hash",
   "instance-id", "boot-mr-done", "os-image-hash", "key-provider", "storage-fs",
   "storage-encrypted", "system-ready"]

theorem emitNames_append (a b : List Action) : emitNames (a ++ b) = emitNames a ++ emitNames b := by
  simp [emitNames, List.filterMap_append]

theorem emitNames_emits (l : List (Ev × Bytes)) : emitNames (emits l) = l.map Prod.fst := by
  induction l with
  | nil => rfl
  | cons x xs ih => simp only [emits, emitNames, List.map_cons, List.filterMap_cons] at ih ⊢; rw [ih]

theorem map_fst_const (e : Ev) (l : List Bytes) :
    (l.map fun x => (e, x)).map Prod.fst = List.replicate l.length e := by
  induction l with
  | nil => rfl
  | cons x xs ih => simp [ih, List.replicate_succ]

theorem emitNames_premeasured (F : Fns) (h : Host) (c : AppCompose) :
    emitNames (emits (premeasured F h c)) =
      [.systemPreparing, .appId, .composeHash] ++ List.replicate c.initScripts.length .initScriptHash ++
        [.gpuPolicyHash] := by
  rw [emitNames_emits]
  simp only [premeasured, List.map_append, map_fst_const, List.length_map]
  rfl

theorem emitNames_afterKeys (F : Fns) (h : Host) (p : Platform) (c : AppCompose) loc g kind k :
    emitNames (actions (afterKeys F h p c loc g kind k)) =
      (if g.isSome then [.gpuAttestation] else []) ++ [.keyProvider] ++
        match h.cmdline with
        | none => []
        | some _ => [.storageFs, .storageEncrypted, .systemReady] := by
  rw [actions_afterKeys]
  cases g <;> cases h.cmdline <;> rfl

set_option linter.unusedSimpArgs false in
theorem emitNames_body (F : Fns) (h : Host) (p : Platform) (c : AppCompose) :
    emitNames (actions (body F h p c)) =
      [.systemPreparing, .appId, .composeHash] ++ List.replicate c.initScripts.length .initScriptHash ++
        [.gpuPolicyHash] ++
      match p.gpu c with
      | none => []
      | some g =>
        [.instanceId, .bootMrDone] ++
        match p.keys c.keyProvider (measuredLog F h p c) with
        | none => []
        | some _ =>
          (if c.keyProvider = .kms then [.osImageHash] else []) ++
          (if g.isSome then [.gpuAttestation] else []) ++ [.keyProvider] ++
          match h.cmdline with
          | none => []
          | some _ => [.storageFs, .storageEncrypted, .systemReady] := by
  rw [actions_body, emitNames_append, emitNames_premeasured]
  congr 1
  split
  · rfl
  next g _ =>
    rw [actions_keyPhase]
    cases hk : p.keys c.keyProvider (measuredLog F h p c) with
    | none => by_cases hs : c.keyProvider = .sevSnp <;> simp [emitNames, emits, hs]
    | some k =>
      simp only [emitNames_append, emitNames_afterKeys]
      by_cases hs : c.keyProvider = .sevSnp <;> by_cases hm : c.keyProvider = .kms <;>
        simp [emitNames, emits, hs, hm]

/-- Any run (failed or not) emits a prefix of the expected event sequence. -/
theorem emitNames_run_prefix (F : Fns) (h : Host) (p : Platform) (c : AppCompose) (g : Option Bytes)
    (hc : F.parseCompose h.composeFile = some c) (hg : p.gpu c = some g) :
    emitNames (run F h p) <+: expectedNames c.keyProvider c.initScripts.length g.isSome := by
  refine List.IsPrefix.trans ((exec_prefix _).filterMap _) ?_
  rcases actions_program F h p with h0 | ⟨c', hc', h1⟩
  · rw [h0]; exact List.nil_prefix
  rw [hc] at hc'
  cases hc'
  change emitNames (actions (program F h p)) <+: _
  rw [h1, emitNames_body, hg]
  cases p.keys c.keyProvider (measuredLog F h p c) <;> cases h.cmdline <;>
    simp [expectedNames, List.prefix_append_right_inj]

/-! ## Successful boot -/

set_option linter.unusedSimpArgs false in
/-- Every check of a successful boot, in the branch it takes. -/
theorem program_ok (F : Fns) (h : Host) (p : Platform)
    (hok : ∀ st ∈ program F h p, st.ok = true) :
    ∃ c g k enc fs0,
      F.parseCompose h.composeFile = some c ∧ p.policyOk c = true ∧
      (effectiveAppId F h).length = 20 ∧ p.gpu c = some g ∧
      p.keys c.keyProvider (measuredLog F h p c) = some k ∧ h.cmdline = some (enc, fs0) ∧
      (c.keyProvider = .sevSnp →
        p.isSnp = true ∧ p.configOk (localValues F h p c .sevSnp []) = true ∧ enc = true) ∧
      k.diskKey ≠ [] ∧ p.configOk (localValues F h p c c.keyProvider k.providerId) = true ∧
      (c.keyProviderId = [] ∨ c.keyProviderId = k.providerId) ∧
      p.mountOk = true ∧ p.envOk = true ∧ p.windowClosed = true := by
  have chk : ∀ b, Step.check b ∈ program F h p → b = true := fun b hb => hok _ hb
  unfold program at hok
  split at hok
  · simp [Step.ok] at hok
  next c hc =>
  by_cases hpol : p.policyOk c = true
  case neg => simp [hpol, Step.ok] at hok
  by_cases hlen : (effectiveAppId F h).length = 20
  case neg => simp [hpol, hlen, Step.ok] at hok
  simp only [hpol, hlen, Bool.not_true, Bool.false_eq_true, ite_false, ne_eq, not_true_eq_false] at hok
  unfold body at hok
  cases hg : p.gpu c with
  | none => exact absurd (hok .fail (by simp [hg])) (by simp [Step.ok])
  | some g =>
  unfold keyPhase at hok
  cases hk : p.keys c.keyProvider (measuredLog F h p c) with
  | none => exact absurd (hok .fail (by simp [hg, hk])) (by simp [Step.ok])
  | some k =>
  cases hcl : h.cmdline with
  | none =>
    unfold afterKeys at hok
    exact absurd (hok .fail (by simp [hg, hk, hcl])) (by simp [Step.ok])
  | some o =>
  obtain ⟨enc, fs0⟩ := o
  unfold afterKeys at hok
  have m : ∀ st, st ∈ body F h p c → st ∈ program F h p := by
    intro st hst; unfold program; simpa [hc, hpol, hlen] using hst
  have cb : ∀ b, Step.check b ∈ body F h p c → b = true := fun b hb => chk b (m _ hb)
  have mem : ∀ st, st ∈ afterKeys F h p c (localValues F h p c) g c.keyProvider k →
      st ∈ body F h p c := by
    intro st hst
    unfold body keyPhase
    simp only [hg, hk, List.mem_append]
    exact Or.inr (Or.inr (Or.inr (Or.inr hst)))
  have ca : ∀ b, Step.check b ∈ afterKeys F h p c (localValues F h p c) g c.keyProvider k → b = true :=
    fun b hb => cb b (mem _ hb)
  refine ⟨c, g, k, enc, fs0, hc, hpol, hlen, hg, hk, (by simp [hcl]), ?_, ?_, ?_, ?_, ?_, ?_, ?_⟩
  · intro hs
    refine ⟨cb _ ?_, cb _ ?_, cb _ ?_⟩ <;> (unfold body keyPhase; simp [hg, hk, hs, hcl])
  · have := ca (!k.diskKey.isEmpty) (by unfold afterKeys; simp)
    simpa [List.isEmpty_iff] using this
  · exact ca (p.configOk (localValues F h p c c.keyProvider k.providerId)) (by unfold afterKeys; simp)
  · have := ca (c.keyProviderId.isEmpty || c.keyProviderId == k.providerId) (by unfold afterKeys; simp)
    simpa [List.isEmpty_iff] using this
  · exact ca p.mountOk (by unfold afterKeys; simp [hcl])
  · exact ca p.envOk (by unfold afterKeys; simp [hcl])
  · exact ca p.windowClosed (by unfold afterKeys; simp [hcl])

/-- The app starts only if every check passed; its trace then contains the
full event sequence, `system-ready` and the closing of the env window, and
every config-id check it performed was accepted. -/
theorem appStarted_spec (F : Fns) (h : Host) (p : Platform) (hs : appStarted F h p) :
    (∃ c g, F.parseCompose h.composeFile = some c ∧ p.gpu c = some g ∧
      emitNames (run F h p) = expectedNames c.keyProvider c.initScripts.length g.isSome) ∧
    Action.emit .systemReady [] ∈ run F h p ∧ Action.closeEnvWindow ∈ run F h p ∧
    (∀ l, Action.checkConfig l ∈ run F h p → p.configOk l = true) := by
  obtain ⟨hok, hrun⟩ := exec_ok _ hs
  obtain ⟨c, g, k, enc, fs0, hc, hpol, hlen, hg, hk, hcl, hsnp, -, hcfg, -⟩ := program_ok F h p hok
  have hprog : program F h p = body F h p c := by unfold program; simp [hc, hpol, hlen]
  have hrun' : run F h p = actions (body F h p c) := by rw [run, hrun, hprog]
  refine ⟨⟨c, g, hc, hg, ?_⟩, ?_, ?_, ?_⟩
  · rw [hrun', emitNames_body, hg, hk, hcl]
    simp [expectedNames]
  · simp [hrun', actions_body, hg, actions_keyPhase, hk, actions_afterKeys, hcl]
  · simp [hrun', actions_body, hg, actions_keyPhase, hk, actions_afterKeys, hcl]
  · intro l hl
    simp only [hrun', actions_body, hg, actions_keyPhase, hk, actions_afterKeys, hcl] at hl
    by_cases hs : c.keyProvider = .sevSnp <;> cases g <;> simp [emits, hs] at hl <;>
      first
      | (rw [hl]; exact hcfg)
      | (rcases hl with hl | hl <;> rw [hl] <;>
          first | exact hcfg | exact (hsnp hs).2.1 | (rw [hs] at hcfg; exact hcfg))

/-! ## Data flow from measured values -/

def Action.payloadFor (e : Ev) : Action → Option Bytes
  | .emit e' x => if e' = e then some x else none
  | _ => none

/-- Payload of the first `e` event in a trace. -/
def pay (e : Ev) (t : List Action) : Option Bytes := t.findSome? (Action.payloadFor e)

/-- Payloads of all `e` events in a trace. -/
def pays (e : Ev) (t : List Action) : List Bytes := t.filterMap (Action.payloadFor e)

/-- The measurement log of a trace. -/
def emitLog (t : List Action) : List (Ev × Bytes) :=
  t.filterMap fun | .emit e x => some (e, x) | _ => none

/-- `Φ` holds of the compose file whose hash was measured as `compose-hash`. -/
def FromCompose (F : Fns) (pre : List Action) (Φ : AppCompose → Prop) : Prop :=
  ∀ file c, pay .composeHash pre = some (F.sha256 file) → F.parseCompose file = some c → Φ c

/-- What each security-relevant action may depend on, given the trace `pre`
before it: only measured payloads and the measured compose file. -/
def measuredFlow (F : Fns) (pre : List Action) : Action → Prop
  | .extendConfigPcr v =>
    pay .composeHash pre = some v.composeHash ∧ pay .appId pre = some v.appId ∧
      FromCompose F pre (fun c => v.keyProvider = c.keyProvider ∧ v.keyProviderId = c.keyProviderId)
  | .requestKeys kind log => log = emitLog pre ∧ FromCompose F pre (fun c => kind = c.keyProvider)
  | .checkConfig l =>
    pay .composeHash pre = some l.composeHash ∧ pay .appId pre = some l.appId ∧
      pay .gpuPolicyHash pre = some l.gpuPolicyHash ∧ pay .instanceId pre = some l.instanceId ∧
      pays .initScriptHash pre = l.initScriptHashes ∧ FromCompose F pre (fun c => l.keyProvider = c.keyProvider)
  | .mount enc fs discard _ =>
    pay .storageEncrypted pre = some (encFlag enc) ∧ pay .storageFs pre = some (F.fsName fs) ∧
      FromCompose F pre (fun c => discard = c.storageDiscard)
  | .decryptEnv allowed => FromCompose F pre (fun c => allowed = c.allowedEnvs)
  | _ => True

/-- `R pre a` for every action `a` with preceding trace `pre`. -/
def flowsFrom (R : List Action → Action → Prop) : List Action → List Action → Prop
  | _, [] => True
  | pre, a :: t => R pre a ∧ flowsFrom R (pre ++ [a]) t

theorem flowsFrom_append (R : List Action → Action → Prop) (pre A B : List Action) :
    flowsFrom R pre (A ++ B) ↔ flowsFrom R pre A ∧ flowsFrom R (pre ++ A) B := by
  induction A generalizing pre with
  | nil => simp [flowsFrom]
  | cons x xs ih => simp [flowsFrom, ih, and_assoc]

theorem flowsFrom_iff (R : List Action → Action → Prop) (pre t : List Action) :
    flowsFrom R pre t ↔ ∀ q a post, t = q ++ a :: post → R (pre ++ q) a := by
  induction t generalizing pre with
  | nil => simp [flowsFrom]
  | cons x xs ih =>
    simp only [flowsFrom, ih]
    constructor
    · rintro ⟨hx, hxs⟩ q a post heq
      cases q with
      | nil => simp at heq; obtain ⟨rfl, rfl⟩ := heq; simpa using hx
      | cons y ys =>
        simp at heq; obtain ⟨rfl, rfl⟩ := heq
        simpa using hxs ys a post rfl
    · intro H
      exact ⟨by simpa using H [] x xs rfl, fun q a post heq => by simpa using H (x :: q) a post (by simp [heq])⟩

theorem flowsFrom_emits (F : Fns) (pre : List Action) (l : List (Ev × Bytes)) :
    flowsFrom (measuredFlow F) pre (emits l) := by
  induction l generalizing pre with
  | nil => trivial
  | cons x xs ih => exact ⟨trivial, ih _⟩

theorem pay_append (e : Ev) (A B : List Action) : pay e (A ++ B) = (pay e A).or (pay e B) := by
  simp [pay, List.findSome?_append]

theorem pays_append (e : Ev) (A B : List Action) : pays e (A ++ B) = pays e A ++ pays e B := by
  simp [pays, List.filterMap_append]

theorem emitLog_append (A B : List Action) : emitLog (A ++ B) = emitLog A ++ emitLog B := by
  simp [emitLog, List.filterMap_append]

theorem emitLog_emits (l : List (Ev × Bytes)) : emitLog (emits l) = l := by
  induction l with
  | nil => rfl
  | cons x xs ih => simp only [emits, emitLog, List.map_cons, List.filterMap_cons] at ih ⊢; rw [ih]

theorem pays_emits_init (l : List Bytes) :
    pays .initScriptHash (emits (l.map fun x => (.initScriptHash, x))) = l := by
  induction l with
  | nil => rfl
  | cons x xs ih =>
    simp only [emits, pays, List.map_map, List.map_cons, List.filterMap_cons] at ih ⊢
    simp [Action.payloadFor, ih]

theorem pay_emits_init (e : Ev) (he : e ≠ .initScriptHash) (l : List Bytes) :
    pay e (emits (l.map fun x => (.initScriptHash, x))) = none := by
  induction l with
  | nil => rfl
  | cons x xs ih =>
    simp only [emits, pay, List.map_map, List.map_cons, List.findSome?_cons] at ih ⊢
    simp [Action.payloadFor, Ne.symm he, ih]

/-- The measured payloads of `premeasured`, read back from the trace. -/
theorem pay_premeasured (F : Fns) (h : Host) (c : AppCompose) (B : List Action) :
    pay .appId (emits (premeasured F h c) ++ B) = some (effectiveAppId F h) ∧
    pay .composeHash (emits (premeasured F h c) ++ B) = some (F.sha256 h.composeFile) ∧
    pay .gpuPolicyHash (emits (premeasured F h c) ++ B) = some (F.gpuPolicyHash h.composeFile) ∧
    (∀ e, e ≠ .systemPreparing → e ≠ .appId → e ≠ .composeHash → e ≠ .initScriptHash →
      e ≠ .gpuPolicyHash → pay e (emits (premeasured F h c) ++ B) = pay e B) ∧
    pays .initScriptHash (emits (premeasured F h c) ++ B) =
      c.initScripts.map F.sha256 ++ pays .initScriptHash B := by
  have split : emits (premeasured F h c) =
      [.emit .systemPreparing [], .emit .appId (effectiveAppId F h),
        .emit .composeHash (F.sha256 h.composeFile)] ++
      emits ((c.initScripts.map F.sha256).map fun x => (.initScriptHash, x)) ++
      [.emit .gpuPolicyHash (F.gpuPolicyHash h.composeFile)] := by
    simp [premeasured, emits]
  rw [split]
  refine ⟨?_, ?_, ?_, ?_, ?_⟩
  · simp [pay, Action.payloadFor]
  · simp [pay, Action.payloadFor]
  · simp only [pay_append, pay_emits_init .gpuPolicyHash (by decide)]
    simp [pay, Action.payloadFor]
  · intro e h1 h2 h3 h4 h5
    simp only [pay_append, pay_emits_init _ h4]
    simp [pay, Action.payloadFor, Ne.symm h1, Ne.symm h2, Ne.symm h3, Ne.symm h5]
  · simp only [pays_append, pays_emits_init]
    simp [pays, Action.payloadFor]

theorem fromCompose_iff (F : Fns) (h : Host) (c : AppCompose) (pre : List Action) (Φ : AppCompose → Prop)
    (hsha : ∀ a b, F.sha256 a = F.sha256 b → a = b) (hc : F.parseCompose h.composeFile = some c)
    (hp : pay .composeHash pre = some (F.sha256 h.composeFile)) :
    FromCompose F pre Φ ↔ Φ c := by
  constructor
  · intro H; exact H _ _ hp hc
  · intro H file c' h1 h2
    rw [hp] at h1
    have := hsha _ _ (Option.some.inj h1)
    subst this
    rw [hc] at h2
    cases h2
    exact H

theorem pay_premeasured_appId (F : Fns) (h : Host) (c : AppCompose) (B : List Action) :
    pay .appId (emits (premeasured F h c) ++ B) = some (effectiveAppId F h) :=
  (pay_premeasured F h c B).1

theorem pay_premeasured_composeHash (F : Fns) (h : Host) (c : AppCompose) (B : List Action) :
    pay .composeHash (emits (premeasured F h c) ++ B) = some (F.sha256 h.composeFile) :=
  (pay_premeasured F h c B).2.1

theorem pay_premeasured_gpuPolicyHash (F : Fns) (h : Host) (c : AppCompose) (B : List Action) :
    pay .gpuPolicyHash (emits (premeasured F h c) ++ B) = some (F.gpuPolicyHash h.composeFile) :=
  (pay_premeasured F h c B).2.2.1

theorem pay_premeasured_other (F : Fns) (h : Host) (c : AppCompose) (B : List Action) (e : Ev)
    (h1 : e ≠ .systemPreparing) (h2 : e ≠ .appId) (h3 : e ≠ .composeHash) (h4 : e ≠ .initScriptHash)
    (h5 : e ≠ .gpuPolicyHash) : pay e (emits (premeasured F h c) ++ B) = pay e B :=
  (pay_premeasured F h c B).2.2.2.1 e h1 h2 h3 h4 h5

theorem findSome_premeasured_other (F : Fns) (h : Host) (c : AppCompose) (e : Ev)
    (h1 : e ≠ .systemPreparing) (h2 : e ≠ .appId) (h3 : e ≠ .composeHash) (h4 : e ≠ .initScriptHash)
    (h5 : e ≠ .gpuPolicyHash) : (emits (premeasured F h c)).findSome? (Action.payloadFor e) = none := by
  have := pay_premeasured_other F h c [] e h1 h2 h3 h4 h5
  simpa [pay] using this

theorem pays_premeasured (F : Fns) (h : Host) (c : AppCompose) (B : List Action) :
    pays .initScriptHash (emits (premeasured F h c) ++ B) =
      c.initScripts.map F.sha256 ++ pays .initScriptHash B :=
  (pay_premeasured F h c B).2.2.2.2

theorem fromCompose_premeasured (F : Fns) (h : Host) (c : AppCompose)
    (hsha : ∀ a b, F.sha256 a = F.sha256 b → a = b) (hc : F.parseCompose h.composeFile = some c)
    (B : List Action) (Φ : AppCompose → Prop) :
    FromCompose F (emits (premeasured F h c) ++ B) Φ ↔ Φ c :=
  fromCompose_iff F h c _ Φ hsha hc (pay_premeasured_composeHash F h c B)

set_option linter.unusedSimpArgs false in
/-- Every config-derived argument reaching the key provider, the config PCR,
the config-id check, the mount and the env decryption is a payload measured
earlier in the same trace or a field of the compose file whose hash was
measured (for an injective `sha256`). -/
theorem run_dataflow (F : Fns) (h : Host) (p : Platform)
    (hsha : ∀ a b, F.sha256 a = F.sha256 b → a = b) :
    ∀ pre a post, run F h p = pre ++ a :: post → measuredFlow F pre a := by
  have key : flowsFrom (measuredFlow F) [] (actions (program F h p)) := by
    rcases actions_program F h p with h0 | ⟨c, hc, h1⟩
    · rw [h0]; trivial
    rw [h1, actions_body, flowsFrom_append]
    refine ⟨flowsFrom_emits _ _ _, ?_⟩
    split
    · trivial
    next g _ =>
    have he : emits [(Ev.instanceId, instanceIdOf F h p c), (Ev.bootMrDone, [])] =
        [.emit .instanceId (instanceIdOf F h p c), .emit .bootMrDone []] := rfl
    rw [he, actions_keyPhase]
    by_cases hs : c.keyProvider = .sevSnp <;>
    cases hk : p.keys c.keyProvider (measuredLog F h p c) <;>
    by_cases hm : c.keyProvider = .kms <;>
    (try cases g) <;> (try cases hcl : h.cmdline) <;>
    simp only [hs, hm, hk, hcl, actions_afterKeys, flowsFrom_append, flowsFrom, measuredFlow, List.append_assoc,
      List.cons_append, List.nil_append, List.singleton_append, ite_true, ite_false,
      reduceCtorEq] <;>
    simp only [pay_premeasured_appId, pay_premeasured_composeHash, pay_premeasured_gpuPolicyHash,
      pays_premeasured, fromCompose_premeasured F h c hsha hc, emitLog_append, emitLog_emits,
      pay_premeasured_other F h c] <;>
    simp_all [pay, pays, emitLog, Action.payloadFor, localValues, measuredLog,
      findSome_premeasured_other F h c, List.findSome?_cons]
  have hrun : flowsFrom (measuredFlow F) [] (run F h p) := by
    obtain ⟨t, ht⟩ := exec_prefix (program F h p)
    rw [← ht] at key
    exact ((flowsFrom_append _ _ _ _).mp key).1
  intro pre a post heq
  simpa using (flowsFrom_iff _ _ _).mp hrun pre a post heq

end DstackFormal.Guest.BootTrace
