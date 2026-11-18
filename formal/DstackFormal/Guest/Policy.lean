-- SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
--
-- SPDX-License-Identifier: Apache-2.0

/-!
# App-compose requirement checks

Models the decisions of `dstack/dstack-util/src/system_setup.rs`:
`verify_app_compose_policy`, `verify_platform_requirements`,
`parse_requirement_platform`, `verify_tdx_measure_acpi_tables_requirement`,
`verify_launch_token_requirement` and `launch_token_from_user_config`.

Proven (`*_iff` characterize acceptance exactly):
* platforms: an explicit empty list, an unparsable entry, or a current
  platform not in the list rejects; an omitted list accepts.
* ACPI tables: on TDX the requirement holds iff the host-declared attestation
  variant matches it, and an unparsable `vm_config` rejects; other platforms
  ignore it.
* launch token: acceptance needs a 32-byte hex hash, a token of at least 32
  bytes, and a matching hash; for an injective hash at most one token is
  accepted (`launch_token_unique`).
* `appComposePolicy_sound`: an accepted policy satisfies every requirement it
  states.

Observation: the ACPI-table decision compares against `vm_config`, which is
host-supplied (`sys_config`). It only constrains the platform if the verifier
of the quote binds the same attestation variant (e.g. through the measured
firmware/ACPI events); the guest check alone does not.

Modeling gaps: JSON parsing, `detect_tee_variant`, file reads and `hex::decode`
are parameters or inputs; `verify_manifest_feature_requirements` is an opaque
Boolean.
-/

namespace DstackFormal.Guest.Policy

abbrev Bytes := List UInt8

variable {Tee : Type} [DecidableEq Tee]

/-- `verify_platform_requirements` with `platforms = Some list`; `parse` is
`parse_requirement_platform` (`none` = error). -/
def platformsOk (parse : String → Option Tee) (current : Tee) (list : List String) : Bool :=
  match list.mapM parse with
  | none => false
  | some modes => modes.contains current

/-- The `platforms` branch of `verify_app_compose_policy` (including its
explicit empty-list rejection). -/
def platformRequirement (parse : String → Option Tee) (current : Tee) : Option (List String) → Bool
  | none => true
  | some [] => false
  | some list => platformsOk parse current list

theorem platformRequirement_iff (parse : String → Option Tee) (current : Tee) (req : Option (List String)) :
    platformRequirement parse current req = true ↔
      req = none ∨ ∃ list modes, req = some list ∧ list.mapM parse = some modes ∧ current ∈ modes := by
  unfold platformRequirement
  split
  · simp
  · simp
  · next list hne =>
    unfold platformsOk
    constructor
    · intro h
      split at h
      · simp at h
      · next modes hm => exact Or.inr ⟨list, modes, rfl, hm, by simpa using h⟩
    · rintro (h | ⟨l, modes, hl, hm, hc⟩)
      · simp at h
      · cases hl; rw [hm]; simpa using hc

theorem platformRequirement_empty (parse : String → Option Tee) (current : Tee) :
    platformRequirement parse current (some []) = false := rfl

/-- `verify_tdx_measure_acpi_tables_requirement`; `usesLite` is
`vm_config.tdx_attestation_variant.is_lite()` (`none` = parse error). -/
def acpiRequirement (isTdx : Bool) (usesLite : Option Bool) : Option Bool → Bool
  | none => true
  | some measure =>
    if !isTdx then true
    else
      match usesLite with
      | none => false
      | some lite => measure == !lite

theorem acpiRequirement_iff (isTdx : Bool) (usesLite req : Option Bool) :
    acpiRequirement isTdx usesLite req = true ↔
      req = none ∨ isTdx = false ∨ ∃ m lite, req = some m ∧ usesLite = some lite ∧ m = !lite := by
  unfold acpiRequirement
  cases req with
  | none => simp
  | some m =>
    cases isTdx with
    | false => simp
    | true => cases usesLite with
      | none => simp
      | some lite => simp

/-- `verify_launch_token_requirement`; `expected` is `hex::decode` of the
hash (`none` = error), `launchTokenHash` is `dstack_types::launch_token_hash`. -/
def launchTokenOk (launchTokenHash : Bytes → Bytes) (expected : Option Bytes) (token : Bytes) : Bool :=
  match expected with
  | none => false
  | some e => e.length == 32 && decide (32 ≤ token.length) && launchTokenHash token == e

theorem launchTokenOk_iff (H : Bytes → Bytes) (expected : Option Bytes) (token : Bytes) :
    launchTokenOk H expected token = true ↔
      ∃ e, expected = some e ∧ e.length = 32 ∧ 32 ≤ token.length ∧ H token = e := by
  unfold launchTokenOk
  cases expected <;> simp [and_assoc]

/-- For an injective token hash at most one token passes. -/
theorem launch_token_unique (H : Bytes → Bytes) (hH : ∀ a b, H a = H b → a = b)
    (expected : Option Bytes) (t t' : Bytes)
    (h : launchTokenOk H expected t = true) (h' : launchTokenOk H expected t' = true) : t = t' := by
  obtain ⟨e, he, -, -, h1⟩ := (launchTokenOk_iff H _ _).mp h
  obtain ⟨e', he', -, -, h2⟩ := (launchTokenOk_iff H _ _).mp h'
  rw [he] at he'
  cases he'
  exact hH _ _ (h1.trans h2.symm)

/-- `requirements` fields consulted by `verify_app_compose_policy`. -/
structure Requirements where
  platforms : Option (List String)
  tdxMeasureAcpiTables : Option Bool
  launchTokenHash : Option (Option Bytes)

/-- `verify_app_compose_policy`; `token` is `launch_token_from_user_config`
(`none` = missing or not a string). -/
def appComposePolicy (parse : String → Option Tee) (current : Tee) (isTdx : Bool)
    (usesLite : Option Bool) (H : Bytes → Bytes) (featuresOk : Bool) (token : Option Bytes) :
    Option Requirements → Bool
  | none => featuresOk
  | some r =>
    featuresOk && platformRequirement parse current r.platforms &&
      acpiRequirement isTdx usesLite r.tdxMeasureAcpiTables &&
      match r.launchTokenHash with
      | none => true
      | some expected =>
        match token with
        | none => false
        | some t => launchTokenOk H expected t

theorem appComposePolicy_sound (parse : String → Option Tee) (current : Tee) (isTdx : Bool)
    (usesLite : Option Bool) (H : Bytes → Bytes) (featuresOk : Bool) (token : Option Bytes)
    (r : Requirements)
    (h : appComposePolicy parse current isTdx usesLite H featuresOk token (some r) = true) :
    featuresOk = true ∧ platformRequirement parse current r.platforms = true ∧
      acpiRequirement isTdx usesLite r.tdxMeasureAcpiTables = true ∧
      ∀ expected, r.launchTokenHash = some expected →
        ∃ t, token = some t ∧ launchTokenOk H expected t = true := by
  unfold appComposePolicy at h
  simp only [Bool.and_eq_true] at h
  obtain ⟨⟨⟨hf, hp⟩, ha⟩, hl⟩ := h
  refine ⟨hf, hp, ha, fun expected he => ?_⟩
  rw [he] at hl
  cases ht : token with
  | none => rw [ht] at hl; simp at hl
  | some t => rw [ht] at hl; exact ⟨t, rfl, hl⟩

/-! ## Mirrors of Rust unit tests -/

/-- `test_platform_requirements_explicit_empty_rejects_all_platforms`. -/
example : platformRequirement (fun _ => some 0) (0 : Nat) (some []) = false := rfl

/-- `test_platform_requirements_reject_invalid_platform_value`. -/
example : platformRequirement (fun s => if s = "dstack-tdx" then some 0 else none) (0 : Nat)
    (some ["dstack-tdx", "bogus"]) = false := by decide

/-- `test_tdx_measure_acpi_tables_requirement_ignored_on_non_tdx`. -/
example : acpiRequirement false none (some true) = true := rfl

/-- `test_launch_token_requirement_rejects_short_token`. -/
example (H : Bytes → Bytes) : launchTokenOk H (some (List.replicate 32 0)) (List.replicate 31 0x61) = false := by
  simp [launchTokenOk]

end DstackFormal.Guest.Policy
