-- SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
--
-- SPDX-License-Identifier: Apache-2.0

/-!
# Instance-id derivation

Models the instance-id computation in
`dstack/dstack-util/src/system_setup.rs: Stage0::measure_app_info`:
`instance_id = sha256(instance_id_seed || app_id || binding)[..20]`, where the
seed is host-supplied unless it is empty (or the key provider is `none` off
SEV-SNP), in which case 20 random bytes are used; `app_id` must be 20 bytes;
`binding` is `platform_instance_binding()` (a 32-byte SHA-256 on GCP/AWS,
absent elsewhere and always absent on SEV-SNP); `no_instance_id` yields an
empty id.

Proven:
* `idPreimage_injective`: with equal seed lengths and 20-byte app ids, the
  preimage determines `(seed, app_id, binding)`.
* `seed_determined`: for a fixed app id and binding width, the preimage
  determines the seed even when its length is unconstrained.
* `instanceId_injective`: the same for the id itself, assuming the 20-byte
  truncated SHA-256 is injective.
* `idPreimage_collision`: without a seed-length constraint, a VM without a
  platform binding and a host-chosen seed reproduces the preimage (hence the
  instance id) of a VM with a binding and a different app id.

The counterexample does not give a collision for a fixed app id: since app-id
is measured separately, a pair `(app_id, instance_id)` stays unambiguous
unless the 32-byte binding hash ends in the app id. It does show that the
instance id alone is not a unique identifier across apps and platforms, and
that the derivation is not a prefix-free encoding of its inputs.

Modeling gaps: SHA-256 is a parameter; `getrandom` is an input; errors from
`platform_instance_binding` are not modeled.
-/

namespace DstackFormal.Guest.InstanceId

abbrev Bytes := List UInt8

/-- `instance_id_seed || app_id || binding`. -/
def idPreimage (seed appId binding : Bytes) : Bytes := seed ++ appId ++ binding

/-- The seed selection of `measure_app_info`. -/
def effectiveSeed (hostSeed random : Bytes) (keyProviderNone isSnp : Bool) : Bytes :=
  if (keyProviderNone && !isSnp) || hostSeed.isEmpty then random else hostSeed

/-- The binding mixed in by `measure_app_info` (skipped on SEV-SNP). -/
def effectiveBinding (binding : Option Bytes) (isSnp : Bool) : Bytes :=
  if isSnp then [] else binding.getD []

/-- The instance-id computation of `measure_app_info`. -/
def instanceId (sha256 : Bytes → Bytes) (noInstanceId : Bool) (seed appId binding : Bytes) : Bytes :=
  if noInstanceId then [] else (sha256 (idPreimage seed appId binding)).take 20

theorem idPreimage_injective {s s' a a' b b' : Bytes} (hs : s.length = s'.length)
    (ha : a.length = 20) (ha' : a'.length = 20)
    (h : idPreimage s a b = idPreimage s' a' b') : s = s' ∧ a = a' ∧ b = b' := by
  simp only [idPreimage, List.append_assoc] at h
  obtain ⟨e1, h⟩ := List.append_inj h hs
  obtain ⟨e2, e3⟩ := List.append_inj h (by rw [ha, ha'])
  exact ⟨e1, e2, e3⟩

theorem seed_determined {s s' a b b' : Bytes} (hb : b.length = b'.length)
    (h : idPreimage s a b = idPreimage s' a b') : s = s' ∧ b = b' := by
  simp only [idPreimage, List.append_assoc] at h
  have hl := congrArg List.length h
  simp only [List.length_append, hb] at hl
  have hs : s.length = s'.length := by omega
  obtain ⟨e1, h⟩ := List.append_inj h hs
  exact ⟨e1, List.append_cancel_left h⟩

theorem instanceId_injective (sha256 : Bytes → Bytes)
    (ht : ∀ x y, (sha256 x).take 20 = (sha256 y).take 20 → x = y)
    {s s' a a' b b' : Bytes} (hs : s.length = s'.length) (ha : a.length = 20) (ha' : a'.length = 20)
    (h : instanceId sha256 false s a b = instanceId sha256 false s' a' b') :
    s = s' ∧ a = a' ∧ b = b' :=
  idPreimage_injective hs ha ha' (ht _ _ h)

/-- A host-chosen seed on a platform without a binding reproduces the
preimage of a VM with a 32-byte binding and a different app id. -/
theorem idPreimage_collision :
    let seedA : Bytes := [7]
    let appA : Bytes := List.replicate 20 1
    let bindA : Bytes := List.replicate 32 2
    let seedB : Bytes := [7] ++ List.replicate 20 1 ++ List.replicate 12 2
    let appB : Bytes := List.replicate 20 2
    idPreimage seedA appA bindA = idPreimage seedB appB [] ∧ appA ≠ appB ∧
      appA.length = 20 ∧ appB.length = 20 := by
  decide

/-- With `no_instance_id` every instance has the empty id. -/
theorem instanceId_disabled (sha256 : Bytes → Bytes) (s a b : Bytes) :
    instanceId sha256 true s a b = [] := rfl

/-- A random seed is used whenever the host seed is empty. -/
theorem effectiveSeed_empty (random : Bytes) (kpNone isSnp : Bool) :
    effectiveSeed [] random kpNone isSnp = random := by
  simp [effectiveSeed]

end DstackFormal.Guest.InstanceId
