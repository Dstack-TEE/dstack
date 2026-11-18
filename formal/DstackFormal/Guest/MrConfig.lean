-- SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
--
-- SPDX-License-Identifier: Apache-2.0

/-!
# MR_CONFIG_ID encodings and the guest-side verifier

Models `dstack/dstack-types/src/mr_config.rs`: `MrConfig::to_mr_config_id`
(V1, V2), `key_provider_kind_byte`, `MrConfigV3::tdx_mr_config_id_from_document`,
`snp_host_data_from_document`, `hash_document`; and the decision logic of
`dstack/dstack-util/src/system_setup/config_id_verifier.rs`:
`verify_mr_config_id_for_mode`, `verify_tdx_mr_config_id_value`,
`verify_snp_mr_config`, `verify_mr_config_v3_document`.

Proven:
* All three encodings are 48 bytes, carry distinct version tags and are never
  the all-zero id (`configId_tag_ne`, `configId_ne_zero`).
* V1 is injective in the compose hash; V2 is injective in
  `(compose_hash, app_id, key_provider, key_provider_id)` given an injective
  Keccak and the fixed 32/20-byte widths (`v2_injective`); V3 is injective in
  the document bytes given an injective SHA-256 (`v3_injective`).
* `verifyTdxValue_iff`: the TDX verifier accepts iff the attested id is zero,
  or equals the V1/V2 encoding of the locally measured values, or is the V3
  encoding of a host-supplied document that parses and agrees with them.
  `verifySnp_iff` is the SNP analogue.
* `v3_document_bound`: under an injective SHA-256 the attested register fixes
  the accepted document. `v3_optional_fields_unchecked`: fields omitted from a
  V3 document are not compared (`app_id`, `gpu_policy_hash`, `init_script_hashes`,
  `key_provider_id`), while an omitted `instance_id` means empty.

Assumptions: hashes are parameters; injectivity is an explicit hypothesis.
Modeling gaps: `serde_json` document parsing is a parameter `parseDoc`; reading
the quote and `sys-config` is outside the model (their outputs are inputs).
`hex_bytes` decoding of document fields is folded into `parseDoc`.
-/

namespace DstackFormal.Guest.MrConfig

abbrev Bytes := List UInt8

/-- `dstack_types::KeyProviderKind`. -/
inductive KeyProviderKind where
  | none
  | «local»
  | kms
  | tpm
  | sevSnp
  deriving DecidableEq, Repr

/-- `key_provider_kind_byte`. -/
def kindByte : KeyProviderKind → UInt8
  | .none => 0
  | .local => 1
  | .kms => 2
  | .tpm => 3
  | .sevSnp => 4

theorem kindByte_injective {a b : KeyProviderKind} (h : kindByte a = kindByte b) : a = b := by
  cases a <;> cases b <;> first | rfl | (simp [kindByte] at h)

/-- `config_id = [tag] || d[0..32] || 0^15` (Rust copies a 32-byte digest into `[1..33]`). -/
def configId (tag : UInt8) (d : Bytes) : Bytes := tag :: d ++ List.replicate 15 0

def zeroId : Bytes := List.replicate 48 0

/-- `MrConfig::V1::to_mr_config_id`. -/
def v1 (composeHash : Bytes) : Bytes := configId 1 composeHash

/-- The Keccak-256 preimage of `MrConfig::V2`. -/
def v2Preimage (composeHash appId : Bytes) (kp : KeyProviderKind) (kpId : Bytes) : Bytes :=
  composeHash ++ appId ++ [kindByte kp] ++ kpId

/-- `MrConfig::V2::to_mr_config_id`. -/
def v2 (keccak : Bytes → Bytes) (composeHash appId : Bytes) (kp : KeyProviderKind) (kpId : Bytes) : Bytes :=
  configId 2 (keccak (v2Preimage composeHash appId kp kpId))

/-- `MR_CONFIG_V3_DOCUMENT_HASH_DOMAIN`. -/
def v3Domain : Bytes := "dstack-mr-config-v3:".toList.map Char.toUInt8

/-- `MrConfigV3::hash_document` = `snp_host_data_from_document`. -/
def hashDocument (sha256 : Bytes → Bytes) (doc : Bytes) : Bytes := sha256 (v3Domain ++ [0] ++ doc)

/-- `MrConfigV3::tdx_mr_config_id_from_document`. -/
def v3 (sha256 : Bytes → Bytes) (doc : Bytes) : Bytes := configId 3 (hashDocument sha256 doc)

theorem configId_length {d : Bytes} (h : d.length = 32) (t : UInt8) : (configId t d).length = 48 := by
  simp [configId, h]

theorem configId_inj {t t' : UInt8} {d d' : Bytes} (h : configId t d = configId t' d') :
    t = t' ∧ d = d' := by
  simp only [configId, List.cons_append, List.cons.injEq] at h
  exact ⟨h.1, List.append_cancel_right h.2⟩

theorem configId_tag_ne {t t' : UInt8} (d d' : Bytes) (h : t ≠ t') : configId t d ≠ configId t' d' :=
  fun e => h (configId_inj e).1

theorem configId_ne_zero {t : UInt8} (d : Bytes) (h : t ≠ 0) : configId t d ≠ zeroId := by
  intro e
  simp only [configId, zeroId, List.cons_append] at e
  exact h (List.cons.inj e).1

theorem v1_injective {c c' : Bytes} (h : v1 c = v1 c') : c = c' := (configId_inj h).2

theorem v2Preimage_injective {c c' a a' i i' : Bytes} {k k' : KeyProviderKind}
    (hc : c.length = 32) (hc' : c'.length = 32) (ha : a.length = 20) (ha' : a'.length = 20)
    (h : v2Preimage c a k i = v2Preimage c' a' k' i') : c = c' ∧ a = a' ∧ k = k' ∧ i = i' := by
  simp only [v2Preimage, List.append_assoc] at h
  obtain ⟨e1, h⟩ := List.append_inj h (by rw [hc, hc'])
  obtain ⟨e2, h⟩ := List.append_inj h (by rw [ha, ha'])
  simp only [List.singleton_append, List.cons.injEq] at h
  exact ⟨e1, e2, kindByte_injective h.1, h.2⟩

/-- V2 binds every field, given an injective Keccak and the Rust array widths. -/
theorem v2_injective (keccak : Bytes → Bytes) (hk : ∀ x y, keccak x = keccak y → x = y)
    {c c' a a' i i' : Bytes} {k k' : KeyProviderKind}
    (hc : c.length = 32) (hc' : c'.length = 32) (ha : a.length = 20) (ha' : a'.length = 20)
    (h : v2 keccak c a k i = v2 keccak c' a' k' i') : c = c' ∧ a = a' ∧ k = k' ∧ i = i' :=
  v2Preimage_injective hc hc' ha ha' (hk _ _ (configId_inj h).2)

theorem v3_injective (sha256 : Bytes → Bytes) (hs : ∀ x y, sha256 x = sha256 y → x = y)
    {d d' : Bytes} (h : v3 sha256 d = v3 sha256 d') : d = d' := by
  have := hs _ _ (configId_inj h).2
  simpa [List.append_assoc] using this

theorem versions_disjoint (keccak sha256 : Bytes → Bytes) (c c' a i d : Bytes) (k : KeyProviderKind) :
    v1 c ≠ v2 keccak c' a k i ∧ v1 c ≠ v3 sha256 d ∧ v2 keccak c' a k i ≠ v3 sha256 d ∧
    v1 c ≠ zeroId ∧ v2 keccak c' a k i ≠ zeroId ∧ v3 sha256 d ≠ zeroId :=
  ⟨configId_tag_ne _ _ (by decide), configId_tag_ne _ _ (by decide), configId_tag_ne _ _ (by decide),
    configId_ne_zero _ (by decide), configId_ne_zero _ (by decide), configId_ne_zero _ (by decide)⟩

#guard (v1 (List.replicate 32 0x11)).length = 48
#guard (v1 (List.replicate 32 0x11)).head? = some 1
#guard (kindByte <$> [.none, .local, .kms, .tpm, .sevSnp]) = [0, 1, 2, 3, 4]

/-! ## Verifier -/

/-- `LocalMrConfigValues`: the values the guest measured. -/
structure Local where
  composeHash : Bytes
  gpuPolicyHash : Bytes
  initScriptHashes : List Bytes
  appId : Bytes
  instanceId : Bytes
  keyProvider : KeyProviderKind
  keyProviderId : Bytes

/-- `MrConfigV3` after deserialization. -/
structure MrConfigV3 where
  version : Nat
  appId : Option Bytes
  composeHash : Bytes
  gpuPolicyHash : Option Bytes
  keyProvider : KeyProviderKind
  keyProviderId : Option Bytes
  instanceId : Option Bytes
  initScriptHashes : Option (List Bytes)

/-- The comparisons of `verify_mr_config_v3_document`, in order. -/
def docOk (m : MrConfigV3) (l : Local) : Bool :=
  m.version == 3 && m.composeHash == l.composeHash &&
  m.gpuPolicyHash.all (· == l.gpuPolicyHash) &&
  m.initScriptHashes.all (· == l.initScriptHashes) &&
  m.appId.all (· == l.appId) &&
  m.instanceId.getD [] == l.instanceId &&
  m.keyProvider == l.keyProvider &&
  m.keyProviderId.all (· == l.keyProviderId)

/-- `verify_mr_config_v3_document`: `parseDoc` is `MrConfigV3::from_document`. -/
def verifyV3Document (parseDoc : Bytes → Option MrConfigV3) (doc : Bytes) (l : Local) : Bool :=
  match parseDoc doc with
  | none => false
  | some m => docOk m l

section
variable (keccak sha256 : Bytes → Bytes) (parseDoc : Bytes → Option MrConfigV3)

/-- `verify_tdx_mr_config_id_value`: `read` is the quoted `mr_config_id`,
`doc` the host-supplied `sys-config` document (read only for version 3). -/
def verifyTdxValue (read : Bytes) (doc : Option Bytes) (l : Local) : Bool :=
  if read = zeroId then true
  else
    match read.head? with
    | some 1 => read == v1 l.composeHash
    | some 2 => read == v2 keccak l.composeHash l.appId l.keyProvider l.keyProviderId
    | some 3 =>
      match doc with
      | none => false
      | some d => verifyV3Document parseDoc d l && read == v3 sha256 d
    | _ => false

/-- `verify_snp_mr_config`: `hostData` is the attested SNP `HOST_DATA`. -/
def verifySnp (doc : Bytes) (hostData : Bytes) (l : Local) : Bool :=
  verifyV3Document parseDoc doc l && hashDocument sha256 doc == hostData

/-- `TeeVariant`, as far as the verifier distinguishes it. -/
inductive Mode where
  | tdx
  | sevSnp
  | awsNitroTpm
  | nitroEnclave
  | other
  deriving DecidableEq

/-- `verify_mr_config_id_for_mode`; `tdxRead`/`snpHostData` are what the
hardware reports, `doc` what the host supplied. -/
def verifyForMode (mode : Mode) (tdxRead snpHostData : Bytes) (doc : Option Bytes) (l : Local) : Bool :=
  match mode with
  | .sevSnp =>
    match doc with
    | none => false
    | some d => verifySnp sha256 parseDoc d snpHostData l
  | .awsNitroTpm => true
  | .nitroEnclave => true
  | _ => verifyTdxValue keccak sha256 parseDoc tdxRead doc l

theorem docOk_iff (m : MrConfigV3) (l : Local) :
    docOk m l = true ↔
      m.version = 3 ∧ m.composeHash = l.composeHash ∧
      (∀ x ∈ m.gpuPolicyHash, x = l.gpuPolicyHash) ∧
      (∀ x ∈ m.initScriptHashes, x = l.initScriptHashes) ∧
      (∀ x ∈ m.appId, x = l.appId) ∧
      m.instanceId.getD [] = l.instanceId ∧ m.keyProvider = l.keyProvider ∧
      (∀ x ∈ m.keyProviderId, x = l.keyProviderId) := by
  simp [docOk, Option.all_eq_true, and_assoc]

/-- The TDX verifier accepts exactly a zero id, the V1/V2 encoding of the
measured values, or the V3 encoding of a document agreeing with them. -/
theorem verifyTdxValue_iff (read : Bytes) (doc : Option Bytes) (l : Local) :
    verifyTdxValue keccak sha256 parseDoc read doc l = true ↔
      read = zeroId ∨ read = v1 l.composeHash ∨
      read = v2 keccak l.composeHash l.appId l.keyProvider l.keyProviderId ∨
      ∃ d m, doc = some d ∧ parseDoc d = some m ∧ docOk m l = true ∧ read = v3 sha256 d := by
  unfold verifyTdxValue
  by_cases hz : read = zeroId
  · simp [hz]
  simp only [hz, ite_false, false_or]
  have h1 : read = v1 l.composeHash → read.head? = some 1 := by rintro rfl; rfl
  have h2 : read = v2 keccak l.composeHash l.appId l.keyProvider l.keyProviderId →
      read.head? = some 2 := by rintro rfl; rfl
  have h3 : ∀ d, read = v3 sha256 d → read.head? = some 3 := by rintro d rfl; rfl
  split
  · next hh =>
    simp only [beq_iff_eq]
    constructor
    · exact Or.inl
    · rintro (h | h | ⟨d, _, _, _, _, h⟩)
      · exact h
      · exact absurd (hh.symm.trans (h2 h)) (by decide)
      · exact absurd (hh.symm.trans (h3 d h)) (by decide)
  · next hh =>
    simp only [beq_iff_eq]
    constructor
    · exact fun h => Or.inr (Or.inl h)
    · rintro (h | h | ⟨d, _, _, _, _, h⟩)
      · exact absurd (hh.symm.trans (h1 h)) (by decide)
      · exact h
      · exact absurd (hh.symm.trans (h3 d h)) (by decide)
  · next hh =>
    constructor
    · intro h
      split at h
      · simp at h
      · next d =>
        unfold verifyV3Document at h
        split at h
        · simp at h
        · next m hm =>
          simp only [Bool.and_eq_true, beq_iff_eq] at h
          exact Or.inr (Or.inr ⟨d, m, rfl, hm, h.1, h.2⟩)
    · rintro (h | h | ⟨d, m, rfl, hm, hok, h⟩)
      · exact absurd (hh.symm.trans (h1 h)) (by decide)
      · exact absurd (hh.symm.trans (h2 h)) (by decide)
      · simp [verifyV3Document, hm, hok, h]
  · next h1' h2' h3' =>
    simp only [Bool.false_eq_true, false_iff]
    rintro (h | h | ⟨d, _, _, _, _, h⟩)
    · exact h1' (h1 h)
    · exact h2' (h2 h)
    · exact h3' (h3 d h)

theorem verifySnp_iff (doc hostData : Bytes) (l : Local) :
    verifySnp sha256 parseDoc doc hostData l = true ↔
      ∃ m, parseDoc doc = some m ∧ docOk m l = true ∧ hashDocument sha256 doc = hostData := by
  unfold verifySnp verifyV3Document
  split
  · next hm => simp [hm]
  · next m hm => simp [hm]

/-- Under an injective SHA-256, the attested V3 register determines the
accepted document: two accepted documents for one register are equal. -/
theorem v3_document_bound (hs : ∀ x y, sha256 x = sha256 y → x = y) (read : Bytes) (d d' : Bytes)
    (l l' : Local) (hr : read.head? = some 3)
    (h : verifyTdxValue keccak sha256 parseDoc read (some d) l = true)
    (h' : verifyTdxValue keccak sha256 parseDoc read (some d') l' = true) : d = d' := by
  have nz : read ≠ zeroId := by rintro rfl; exact absurd hr (by decide)
  have ex : ∀ {dd : Bytes} {ll : Local}, verifyTdxValue keccak sha256 parseDoc read (some dd) ll = true →
      read = v3 sha256 dd := by
    intro dd ll hv
    rcases (verifyTdxValue_iff keccak sha256 parseDoc read _ ll).mp hv with h0 | h1 | h2 | ⟨d0, _, hd, _, _, h3⟩
    · exact absurd h0 nz
    · rw [h1] at hr; simp [v1, configId] at hr
    · rw [h2] at hr; simp [v2, configId] at hr
    · cases hd; exact h3
  exact v3_injective sha256 hs ((ex h).symm.trans (ex h'))

/-- Without an attested id there is no host claim to check: any measured
values are accepted. -/
theorem verifyTdxValue_zero (doc : Option Bytes) (l : Local) :
    verifyTdxValue keccak sha256 parseDoc zeroId doc l = true := by
  simp [verifyTdxValue]

end

/-- Omitted optional V3 fields are not compared: a document without `app_id`,
`gpu_policy_hash`, `init_script_hashes` and `key_provider_id` accepts any
values for them. An omitted `instance_id`, in contrast, only matches an empty
measured instance id. -/
theorem v3_optional_fields_unchecked (m : MrConfigV3) (l : Local)
    (hm : m.appId = none ∧ m.gpuPolicyHash = none ∧ m.initScriptHashes = none ∧ m.keyProviderId = none)
    (a g : Bytes) (s : List Bytes) (k : Bytes) :
    docOk m l = docOk m { l with appId := a, gpuPolicyHash := g, initScriptHashes := s, keyProviderId := k } ∧
    (m.instanceId = none → docOk m l = true → l.instanceId = []) := by
  obtain ⟨h1, h2, h3, h4⟩ := hm
  refine ⟨by simp [docOk, h1, h2, h3, h4], fun hi hok => ?_⟩
  have := ((docOk_iff m l).mp hok).2.2.2.2.2.1
  rw [hi] at this
  exact this.symm

/-! ## Mirrors of Rust unit tests -/

def sampleDoc (instanceId : Option Bytes) (appId : Option Bytes) : MrConfigV3 :=
  ⟨3, appId, List.replicate 32 0x22, none, .kms, none, instanceId, none⟩

def sampleLocal (instanceId appId : Bytes) : Local :=
  ⟨List.replicate 32 0x22, List.replicate 32 0x55, [], appId, instanceId, .kms, []⟩

/-- `mr_config_v3_treats_missing_instance_id_as_empty`. -/
example : docOk (sampleDoc none (some (List.replicate 20 0x11)))
    (sampleLocal (List.replicate 20 0x44) (List.replicate 20 0x11)) = false := by decide
example : docOk (sampleDoc none (some (List.replicate 20 0x11)))
    (sampleLocal [] (List.replicate 20 0x11)) = true := by decide

/-- `mr_config_v3_document_must_match_expected_app_info` /
`mr_config_v3_skips_app_id_check_when_field_is_missing`. -/
example : docOk (sampleDoc (some (List.replicate 20 0x44)) (some (List.replicate 20 0x11)))
    (sampleLocal (List.replicate 20 0x44) (List.replicate 20 0x12)) = false := by decide
example : docOk (sampleDoc (some (List.replicate 20 0x44)) none)
    (sampleLocal (List.replicate 20 0x44) (List.replicate 20 0x12)) = true := by decide

end DstackFormal.Guest.MrConfig
