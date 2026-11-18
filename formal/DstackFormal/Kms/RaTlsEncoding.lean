-- SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
--
-- SPDX-License-Identifier: Apache-2.0

/-!
# Length-prefixed encodings of the v1 application-key API

Models `dstack/ra-tls/src/api_v1.rs: push_length_prefixed, key_derivation_info, key_claim,
KeyAlgorithm::name`, the constants `KDF_SALT, KEY_CONTEXT_TAG, CLAIM_CONTEXT_TAG`, and the v0
claim `format!("{}:{}", purpose, pubkey_hex)` of
`dstack/guest-agent/src/rpc_service.rs: get_key`.

Proven:
* `lp_prefix_code`, `encode_injective`: `LP(x) = be32(len x) || x` is a prefix code, so a
  concatenation of LP fields determines the fields (given every field is shorter than 2^32,
  which `push_length_prefixed` checks).
* `keyDerivationInfo_injective`, `keyClaim_injective`: equal outputs mean equal inputs.
* `info_not_prefix_of_claim`, `claim_not_prefix_of_info`, `info_ne_claim`: whatever the domain,
  algorithm and public key, no derivation info is a prefix of (or equal to) a claim, and back.
* `v0_claim_ne_v1_claim`: a v0 claim `purpose || ":" || hex(pubkey)` is never a v1 claim, for any
  caller-chosen `purpose`, since the v1 claim's tail holds a `0x00` length byte.
* `kdfSalt_ne_legacySalt`: v1 and v0 derivations use different HKDF salts.

Assumptions: none; these are statements about byte strings. Domains are arbitrary bytes (UTF-8
strings are a subset). Bytes are `Nat`.

Gaps: HKDF and the signing envelope are not modeled; their separation follows from these
injectivity results under HKDF/keccak injectivity.
-/

namespace DstackFormal.Kms.RaTlsEncoding

abbrev Bytes := List Nat

def ascii (s : String) : Bytes := s.toList.map Char.toNat

/-- `u32::to_be_bytes` of a length already checked to fit `u32`. -/
def be32 (n : Nat) : Bytes := [n / 2 ^ 24 % 256, n / 2 ^ 16 % 256, n / 2 ^ 8 % 256, n % 256]

@[simp] theorem length_be32 (n : Nat) : (be32 n).length = 4 := rfl

theorem be32_inj {a b : Nat} (ha : a < 2 ^ 32) (hb : b < 2 ^ 32) (h : be32 a = be32 b) : a = b := by
  simp only [be32, List.cons.injEq, and_true] at h
  omega

/-- `LP(x)`. -/
def lp (field : Bytes) : Bytes := be32 field.length ++ field

/-- `api_v1.rs: push_length_prefixed`. -/
def pushLengthPrefixed (out field : Bytes) : Except String Bytes :=
  if field.length < 2 ^ 32 then .ok (out ++ lp field) else .error "field is too long to encode"

/-- `api_v1.rs: KDF_SALT`. -/
def kdfSalt : Bytes := ascii "dstack-guest-v1"
/-- `kdf.rs: LEGACY_SALT`. -/
def legacySalt : Bytes := ascii "RATLS"
/-- `api_v1.rs: KEY_CONTEXT_TAG`. -/
def keyContextTag : Bytes := ascii "dstack-guest-v1-key"
/-- `api_v1.rs: CLAIM_CONTEXT_TAG`. -/
def claimContextTag : Bytes := ascii "dstack-guest-v1-key-claim"

theorem kdfSalt_ne_legacySalt : kdfSalt ≠ legacySalt := by decide

/-- `api_v1.rs: KeyAlgorithm`. -/
inductive KeyAlgorithm where
  | secp256k1
  | ed25519
  deriving DecidableEq

/-- `api_v1.rs: KeyAlgorithm::name`. -/
def KeyAlgorithm.name : KeyAlgorithm → Bytes
  | .secp256k1 => ascii "secp256k1"
  | .ed25519 => ascii "ed25519"

theorem KeyAlgorithm.name_inj {a b : KeyAlgorithm} (h : a.name = b.name) : a = b := by
  cases a <;> cases b <;> first | rfl | exact absurd h (by decide)

theorem KeyAlgorithm.name_length (a : KeyAlgorithm) : a.name.length < 2 ^ 32 := by
  cases a <;> decide

/-- `api_v1.rs: key_derivation_info`: `LP(tag) || LP(algorithm) || LP(domain)`. -/
def keyDerivationInfo (domain : Bytes) (algorithm : KeyAlgorithm) : Except String Bytes :=
  match pushLengthPrefixed [] keyContextTag with
  | .error e => .error e
  | .ok info =>
    match pushLengthPrefixed info algorithm.name with
    | .error e => .error e
    | .ok info => pushLengthPrefixed info domain

/-- `api_v1.rs: key_claim`: `LP(tag) || LP(algorithm) || LP(domain) || LP(public_key)`. -/
def keyClaim (algorithm : KeyAlgorithm) (domain publicKey : Bytes) : Except String Bytes :=
  match pushLengthPrefixed [] claimContextTag with
  | .error e => .error e
  | .ok claim =>
    match pushLengthPrefixed claim algorithm.name with
    | .error e => .error e
    | .ok claim =>
      match pushLengthPrefixed claim domain with
      | .error e => .error e
      | .ok claim => pushLengthPrefixed claim publicKey

/-- Concatenated LP fields. -/
def encode (fields : List Bytes) : Bytes := (fields.map lp).flatten

theorem keyDerivationInfo_eq {domain : Bytes} {algorithm : KeyAlgorithm} {info : Bytes}
    (h : keyDerivationInfo domain algorithm = .ok info) :
    domain.length < 2 ^ 32 ∧ info = encode [keyContextTag, algorithm.name, domain] := by
  have ht : keyContextTag.length < 2 ^ 32 := by decide
  by_cases hd : domain.length < 2 ^ 32 <;>
    simp [keyDerivationInfo, pushLengthPrefixed, ht, algorithm.name_length, hd] at h
  exact ⟨hd, by simp [encode, h]⟩

theorem keyClaim_eq {algorithm : KeyAlgorithm} {domain publicKey claim : Bytes}
    (h : keyClaim algorithm domain publicKey = .ok claim) :
    domain.length < 2 ^ 32 ∧ publicKey.length < 2 ^ 32 ∧
      claim = encode [claimContextTag, algorithm.name, domain, publicKey] := by
  have ht : claimContextTag.length < 2 ^ 32 := by decide
  by_cases hd : domain.length < 2 ^ 32 <;> by_cases hp : publicKey.length < 2 ^ 32 <;>
    simp [keyClaim, pushLengthPrefixed, ht, algorithm.name_length, hd, hp] at h
  exact ⟨hd, hp, by simp [encode, h]⟩

/-- `LP` is a prefix code. -/
theorem lp_prefix_code {f g x y : Bytes} (hf : f.length < 2 ^ 32) (hg : g.length < 2 ^ 32)
    (h : lp f ++ x = lp g ++ y) : f = g ∧ x = y := by
  simp only [lp, List.append_assoc] at h
  obtain ⟨hl, h⟩ := List.append_inj h (by simp)
  have hlen := be32_inj hf hg hl
  exact List.append_inj h hlen

theorem encode_injective : ∀ {fs gs : List Bytes} {x y : Bytes},
    fs.length = gs.length → (∀ f ∈ fs, f.length < 2 ^ 32) → (∀ g ∈ gs, g.length < 2 ^ 32) →
    encode fs ++ x = encode gs ++ y → fs = gs ∧ x = y
  | [], [], _, _, _, _, _, h => ⟨rfl, by simpa [encode] using h⟩
  | f :: fs, g :: gs, x, y, hl, hf, hg, h => by
    simp only [encode, List.map_cons, List.flatten_cons, List.append_assoc] at h
    obtain ⟨rfl, h2⟩ := lp_prefix_code (hf f (by simp)) (hg g (by simp)) h
    obtain ⟨rfl, rfl⟩ := encode_injective (fs := fs) (gs := gs) (x := x) (y := y)
      (by simpa using hl) (fun f h => hf f (by simp [h])) (fun g h => hg g (by simp [h])) h2
    exact ⟨rfl, rfl⟩

theorem keyDerivationInfo_injective {d d' : Bytes} {a a' : KeyAlgorithm} {info : Bytes}
    (h : keyDerivationInfo d a = .ok info) (h' : keyDerivationInfo d' a' = .ok info) :
    d = d' ∧ a = a' := by
  obtain ⟨hd, rfl⟩ := keyDerivationInfo_eq h
  obtain ⟨hd', he⟩ := keyDerivationInfo_eq h'
  have ht : keyContextTag.length < 2 ^ 32 := by decide
  have := encode_injective (fs := [keyContextTag, a.name, d]) (gs := [keyContextTag, a'.name, d'])
    (x := []) (y := []) rfl
    (by simp [ht, a.name_length, hd]) (by simp [ht, a'.name_length, hd']) (by simpa using he)
  simp only [List.cons.injEq, true_and, and_true] at this
  exact ⟨this.2, KeyAlgorithm.name_inj this.1⟩

theorem keyClaim_injective {a a' : KeyAlgorithm} {d d' pk pk' claim : Bytes}
    (h : keyClaim a d pk = .ok claim) (h' : keyClaim a' d' pk' = .ok claim) :
    a = a' ∧ d = d' ∧ pk = pk' := by
  obtain ⟨hd, hp, rfl⟩ := keyClaim_eq h
  obtain ⟨hd', hp', he⟩ := keyClaim_eq h'
  have ht : claimContextTag.length < 2 ^ 32 := by decide
  have := encode_injective (fs := [claimContextTag, a.name, d, pk])
    (gs := [claimContextTag, a'.name, d', pk']) (x := []) (y := []) rfl
    (by simp [ht, a.name_length, hd, hp]) (by simp [ht, a'.name_length, hd', hp'])
    (by simpa using he)
  simp only [List.cons.injEq, true_and, and_true] at this
  exact ⟨KeyAlgorithm.name_inj this.1, this.2.1, this.2.2⟩

theorem tags_lp_distinct (x y : Bytes) : lp keyContextTag ++ x ≠ lp claimContextTag ++ y := by
  intro h
  have := (lp_prefix_code (by decide) (by decide) h).1
  exact absurd this (by decide)

/-- No derivation info is a prefix of any claim. -/
theorem info_not_prefix_of_claim {d d' pk info claim : Bytes} {a a' : KeyAlgorithm}
    (h : keyDerivationInfo d a = .ok info) (h' : keyClaim a' d' pk = .ok claim) :
    ¬ info <+: claim := by
  rintro ⟨z, hz⟩
  obtain ⟨-, rfl⟩ := keyDerivationInfo_eq h
  obtain ⟨-, -, rfl⟩ := keyClaim_eq h'
  simp only [encode, List.map_cons, List.flatten_cons, List.append_assoc] at hz
  exact tags_lp_distinct _ _ hz

/-- No claim is a prefix of any derivation info. -/
theorem claim_not_prefix_of_info {d d' pk info claim : Bytes} {a a' : KeyAlgorithm}
    (h : keyDerivationInfo d a = .ok info) (h' : keyClaim a' d' pk = .ok claim) :
    ¬ claim <+: info := by
  rintro ⟨z, hz⟩
  obtain ⟨-, rfl⟩ := keyDerivationInfo_eq h
  obtain ⟨-, -, rfl⟩ := keyClaim_eq h'
  simp only [encode, List.map_cons, List.flatten_cons, List.append_assoc] at hz
  exact tags_lp_distinct _ _ hz.symm

theorem info_ne_claim {d d' pk info claim : Bytes} {a a' : KeyAlgorithm}
    (h : keyDerivationInfo d a = .ok info) (h' : keyClaim a' d' pk = .ok claim) : info ≠ claim :=
  fun he => info_not_prefix_of_claim h h' ⟨[], by simp [he]⟩

/-- Lowercase hex digits, the output alphabet of `hex::encode`. -/
def isHexDigit (b : Nat) : Bool := (48 ≤ b && b ≤ 57) || (97 ≤ b && b ≤ 102)

/-- The v0 chain-link message `format!("{}:{}", purpose, pubkey_hex)`. -/
def v0Claim (purpose pubkeyHex : Bytes) : Bytes := purpose ++ ascii ":" ++ pubkeyHex

theorem suffix_of_append_eq {x h y t : Bytes} (heq : x ++ h = y ++ t) (hl : t.length ≤ h.length) :
    ∃ u, h = u ++ t := by
  rcases List.append_eq_append_iff.1 heq with ⟨a, -, ha⟩ | ⟨b, -, hb⟩
  · exact ⟨a, ha⟩
  · have := congrArg List.length hb
    simp only [List.length_append] at this
    have hb0 : b = [] := List.length_eq_zero_iff.1 (by omega)
    subst hb0
    exact ⟨[], by simpa using hb.symm⟩

/-- Whatever `purpose` a caller picks, a v0 claim is never a v1 claim: the v1 claim ends in
`LP(public_key)` whose first length byte is `0x00`, which `hex::encode` never emits. The v0 public
key hex is at least four bytes longer than the v1 public key (66 or 64 hex digits against 33 or
32 bytes in the code). -/
theorem v0_claim_ne_v1_claim {purpose pubkeyHex d pk claim : Bytes} {a : KeyAlgorithm}
    (hhex : ∀ b ∈ pubkeyHex, isHexDigit b = true) (hsmall : pk.length < 2 ^ 24)
    (hlen : pk.length + 4 ≤ pubkeyHex.length) (h : keyClaim a d pk = .ok claim) :
    v0Claim purpose pubkeyHex ≠ claim := by
  intro heq
  obtain ⟨-, -, rfl⟩ := keyClaim_eq h
  have : encode [claimContextTag, a.name, d, pk] = encode [claimContextTag, a.name, d] ++ lp pk := by
    simp [encode]
  rw [this, v0Claim] at heq
  obtain ⟨u, hu⟩ := suffix_of_append_eq heq (by simp [lp]; omega)
  have hz : 0 ∈ pubkeyHex := by
    rw [hu]
    have : (be32 pk.length).head? = some 0 := by
      simp only [be32, List.head?_cons, Option.some.injEq]
      have : pk.length / 2 ^ 24 = 0 := Nat.div_eq_of_lt hsmall
      rw [this]
    simp only [lp, List.mem_append]
    right; left
    cases hb : be32 pk.length with
    | nil => simp [hb] at this
    | cons b bs => simp only [hb, List.head?_cons, Option.some.injEq] at this; simp [this]
  exact absurd (hhex 0 hz) (by decide)

/-! ### Mirrors of `api_v1.rs` tests -/

-- encodes_derivation_info_with_length_prefixes
example : (keyDerivationInfo (ascii "storage-encryption") .secp256k1).toOption =
    some ([0, 0, 0, 19] ++ ascii "dstack-guest-v1-key" ++ [0, 0, 0, 9] ++ ascii "secp256k1" ++
      [0, 0, 0, 18] ++ ascii "storage-encryption") := by decide
-- no_two_domains_encode_the_same_way
example : (keyDerivationInfo [97, 0, 98] .ed25519).toOption ≠ (keyDerivationInfo [97] .ed25519).toOption := by
  decide
example : (keyDerivationInfo [97, 98] .ed25519).toOption ≠ (keyDerivationInfo [97, 0, 98] .ed25519).toOption := by
  decide
-- the_two_context_tags_are_not_prefixes_of_one_another_once_encoded
example : ((keyDerivationInfo (ascii "p") .ed25519).toOption.getD []).isPrefixOf
    ((keyClaim .ed25519 (ascii "p") (List.replicate 32 0)).toOption.getD []) = false := by decide

end DstackFormal.Kms.RaTlsEncoding
