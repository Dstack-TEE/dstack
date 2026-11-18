-- SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
--
-- SPDX-License-Identifier: Apache-2.0

/-!
# KMS key derivation: domain separation of KDF inputs and signature preimages

Models:
* `dstack/kms/src/crypto.rs: app_epoch_context, derive_k256_key, sign_message,
  sign_message_with_timestamp`
* `dstack/kms/src/main_service.rs: derive_app_keys` (disk and env keys), `derive_sealed_env_key`,
  `RpcHandler::derive_app_ca`, `get_app_env_encrypt_pub_key` (legacy env key and both
  signatures), `get_sealed_env_pub_key` (sealed-env message)
* `dstack/ra-tls/src/kdf.rs: derive_key, derive_key_with_salt, derive_p256_key_pair,
  derive_dh_secret`: ring's HKDF-SHA256 concatenates the `info` slices, so a derivation is
  determined by `(salt, root secret, concatenated info)`.

Proven:
* `kdf_input_injective`: two well-formed derivations (any purpose, app, instance, app epoch)
  with the same salt and concatenated info are the same derivation, even ignoring which root
  secret they use. Distinct derivations therefore never feed HKDF the same input.
* `kdf_input_injective_any_instance`: the same holds with no constraint on the instance id
  width; only the 20-byte app id is load-bearing.
* `disk_collision_without_app_width`: without the app id width, `(app, instance)` and
  `(app ++ instance, [])` share a disk key.
* `legacy_env_is_epoch0`: the legacy env key RPC derives exactly the app-epoch-0 env key.
* `domains_prefix_free` and `preimage_injective`: the signature preimages of the root k256 key
  (`dstack-kms-issued`, `-v2`, env pubkey with and without timestamp, sealed env pubkey) are
  pairwise distinct for distinct well-formed messages.

Width preconditions and where the code enforces them: app id 20 bytes
(`build_boot_info_for_attestation` and the env pubkey RPCs call `ensure_app_id_len`);
instance id 0 or 20 bytes (`ensure_identity_widths` in `AuthApi::check_authorization`, which
`get_app_key` runs via `ensure_app_attestation_allowed` before `derive_app_keys`); public keys
33 bytes (SEC1 compressed k256) or 32 bytes (X25519).

Assumptions: none on HKDF or keccak here; these are statements about the byte strings fed to
them, so separation of outputs follows under HKDF/keccak injectivity (collision resistance).

Gaps: the KDF post-processing (P-256 scalar decoding, `sha256` of PKCS#8 in `derive_dh_secret`,
X25519 clamping) is not modeled; it is applied to already separated HKDF outputs. Bytes are
`Nat`.
-/

namespace DstackFormal.Kms.KeyDerivation

abbrev Bytes := List Nat

def ascii (s : String) : Bytes := s.toList.map Char.toNat

/-- `u32::to_be_bytes`. -/
def be32 (n : UInt32) : Bytes :=
  [n.toNat / 2 ^ 24 % 256, n.toNat / 2 ^ 16 % 256, n.toNat / 2 ^ 8 % 256, n.toNat % 256]

/-- `u64::to_be_bytes`. -/
def be64 (n : UInt64) : Bytes :=
  [n.toNat / 2 ^ 56 % 256, n.toNat / 2 ^ 48 % 256, n.toNat / 2 ^ 40 % 256, n.toNat / 2 ^ 32 % 256,
   n.toNat / 2 ^ 24 % 256, n.toNat / 2 ^ 16 % 256, n.toNat / 2 ^ 8 % 256, n.toNat % 256]

@[simp] theorem length_be32 (n : UInt32) : (be32 n).length = 4 := rfl
@[simp] theorem length_be64 (n : UInt64) : (be64 n).length = 8 := rfl

theorem be32_inj {a b : UInt32} (h : be32 a = be32 b) : a = b := by
  have ha := UInt32.toNat_lt a
  have hb := UInt32.toNat_lt b
  simp only [be32, List.cons.injEq, and_true] at h
  exact UInt32.toNat_inj.1 (by omega)

theorem be64_inj {a b : UInt64} (h : be64 a = be64 b) : a = b := by
  have ha := UInt64.toNat_lt a
  have hb := UInt64.toNat_lt b
  simp only [be64, List.cons.injEq, and_true] at h
  exact UInt64.toNat_inj.1 (by omega)

def epochTag : Bytes := ascii "app-epoch-v1:"

/-- `crypto.rs: app_epoch_context`: empty for epoch 0, so epoch-0 keys are the pre-epoch ones. -/
def appEpochContext (epoch : UInt32) : Bytes :=
  if epoch = 0 then [] else epochTag ++ be32 epoch

theorem appEpochContext_length (e : UInt32) :
    (appEpochContext e).length = if e = 0 then 0 else 17 := by
  unfold appEpochContext; split <;> rfl

theorem appEpochContext_inj {e e' : UInt32} (h : appEpochContext e = appEpochContext e') :
    e = e' := by
  have hl := congrArg List.length h
  rw [appEpochContext_length, appEpochContext_length] at hl
  unfold appEpochContext at h
  by_cases h0 : e = 0 <;> by_cases h0' : e' = 0 <;> simp only [h0, h0', ↓reduceIte] at h hl
  all_goals first
    | rw [h0, h0']
    | exact absurd hl (by decide)
    | exact be32_inj (List.append_cancel_left h)

/-- `kdf.rs: LEGACY_SALT`. -/
def legacySalt : Bytes := ascii "RATLS"
/-- The salt of `main_service.rs: derive_sealed_env_key`. -/
def sealedEnvSalt : Bytes := ascii "dstack-sealed-env-v1"

def diskTag : Bytes := ascii "app-disk-crypt-key"
def envTag : Bytes := ascii "env-encrypt-key"
def appCaTag : Bytes := ascii "app-ca"
def appKeyTag : Bytes := ascii "app-key"

@[simp] theorem length_diskTag : diskTag.length = 18 := by decide
@[simp] theorem length_envTag : envTag.length = 15 := by decide
@[simp] theorem length_appCaTag : appCaTag.length = 6 := by decide
@[simp] theorem length_appKeyTag : appKeyTag.length = 7 := by decide

/-- The root secret a derivation expands: the root CA P-256 scalar or the root k256 scalar. -/
inductive Root where
  | ca
  | k256
  deriving DecidableEq

/-- Every HKDF derivation the KMS makes from its root keys. -/
inductive Derivation where
  /-- `main_service.rs: derive_app_keys`, `disk_crypt_key`. -/
  | diskCrypt (app inst : Bytes) (appEpoch : UInt32)
  /-- `main_service.rs: derive_app_keys`, `env_crypt_key`. -/
  | envCrypt (app : Bytes) (appEpoch : UInt32)
  /-- `main_service.rs: RpcHandler::derive_app_ca`. -/
  | appCa (app : Bytes) (appEpoch : UInt32)
  /-- `crypto.rs: derive_k256_key`. -/
  | appK256 (app : Bytes) (appEpoch : UInt32)
  /-- `main_service.rs: derive_sealed_env_key`. -/
  | sealedEnv (app : Bytes) (appEpoch : UInt32)
  deriving DecidableEq

/-- What HKDF sees: salt, root secret, and the concatenated info slices. -/
structure KdfInput where
  salt : Bytes
  root : Root
  info : Bytes

/-- The salt, root and `info` slices each derivation passes to `kdf.rs`. -/
def Derivation.input : Derivation → KdfInput
  | .diskCrypt app inst e => ⟨legacySalt, .ca, [app, inst, diskTag, appEpochContext e].flatten⟩
  | .envCrypt app e => ⟨legacySalt, .ca, [app, envTag, appEpochContext e].flatten⟩
  | .appCa app e => ⟨legacySalt, .ca, [app, appCaTag, appEpochContext e].flatten⟩
  | .appK256 app e => ⟨legacySalt, .k256, [app, appKeyTag, appEpochContext e].flatten⟩
  | .sealedEnv app e => ⟨sealedEnvSalt, .ca, [app, appEpochContext e].flatten⟩

/-- `main_service.rs: get_app_env_encrypt_pub_key`: `[app_id, b"env-encrypt-key"]`. -/
def legacyEnvInput (app : Bytes) : KdfInput := ⟨legacySalt, .ca, [app, envTag].flatten⟩

theorem legacy_env_is_epoch0 (app : Bytes) : legacyEnvInput app = (Derivation.envCrypt app 0).input := by
  simp [legacyEnvInput, Derivation.input, appEpochContext]

def Derivation.app : Derivation → Bytes
  | .diskCrypt app _ _ | .envCrypt app _ | .appCa app _ | .appK256 app _ | .sealedEnv app _ => app

def Derivation.epoch : Derivation → UInt32
  | .diskCrypt _ _ e | .envCrypt _ e | .appCa _ e | .appK256 _ e | .sealedEnv _ e => e

/-- The info after the app id. -/
def Derivation.rest : Derivation → Bytes
  | .diskCrypt _ inst e => inst ++ diskTag ++ appEpochContext e
  | .envCrypt _ e => envTag ++ appEpochContext e
  | .appCa _ e => appCaTag ++ appEpochContext e
  | .appK256 _ e => appKeyTag ++ appEpochContext e
  | .sealedEnv _ e => appEpochContext e

theorem info_eq (d : Derivation) : d.input.info = d.app ++ d.rest := by
  cases d <;> simp [Derivation.input, Derivation.app, Derivation.rest]

/-- The instance id width `ensure_identity_widths` enforces: 0 or 20 bytes. -/
def Derivation.instanceWidthOk : Derivation → Prop
  | .diskCrypt _ inst _ => inst.length = 0 ∨ inst.length = 20
  | _ => True

/-- The widths the KMS enforces before deriving. -/
def Derivation.WellFormed (d : Derivation) : Prop := d.app.length = 20 ∧ d.instanceWidthOk

theorem strip_app {a a' x y : Bytes} (ha : a.length = 20) (ha' : a'.length = 20)
    (h : a ++ x = a' ++ y) : a = a' ∧ x = y :=
  List.append_inj h (by rw [ha, ha'])

theorem legacySalt_ne_sealedEnvSalt : legacySalt ≠ sealedEnvSalt := by decide

theorem ctx_cases (e : UInt32) : (appEpochContext e).length = 0 ∨ (appEpochContext e).length = 17 := by
  rw [appEpochContext_length]; split <;> simp

/-- Same salt and same info length force the same purpose (and, for disk keys, the same
instance id width). -/
theorem same_purpose {d d' : Derivation} (hw : d.instanceWidthOk) (hw' : d'.instanceWidthOk)
    (hs : d.input.salt = d'.input.salt) (hl : d.rest.length = d'.rest.length) :
    match d, d' with
    | .diskCrypt _ i _, .diskCrypt _ i' _ => i.length = i'.length
    | .envCrypt .., .envCrypt .. | .appCa .., .appCa .. | .appK256 .., .appK256 ..
    | .sealedEnv .., .sealedEnv .. => True
    | _, _ => False := by
  have c1 := ctx_cases d.epoch
  have c2 := ctx_cases d'.epoch
  cases d <;> cases d' <;>
    simp only [Derivation.input, Derivation.rest, Derivation.epoch, Derivation.instanceWidthOk,
      List.length_append, length_diskTag, length_envTag, length_appCaTag, length_appKeyTag]
      at hs hl hw hw' c1 c2 ⊢ <;>
    first
    | exact absurd hs legacySalt_ne_sealedEnvSalt
    | exact absurd hs.symm legacySalt_ne_sealedEnvSalt
    | trivial
    | omega

/-- Distinct well-formed derivations never give HKDF the same salt and info. The root secret is
not used: the separation holds even if the CA and k256 root scalars were equal. -/
theorem kdf_input_injective {d d' : Derivation} (hw : d.WellFormed) (hw' : d'.WellFormed)
    (hs : d.input.salt = d'.input.salt) (hi : d.input.info = d'.input.info) : d = d' := by
  rw [info_eq, info_eq] at hi
  obtain ⟨happ, hrest⟩ := strip_app hw.1 hw'.1 hi
  have hp := same_purpose hw.2 hw'.2 hs (congrArg List.length hrest)
  cases d <;> cases d' <;> simp only [Derivation.app, Derivation.rest] at hp happ hrest ⊢ <;>
    try exact hp.elim
  · obtain ⟨hinst, hctx⟩ := List.append_inj (by simpa only [List.append_assoc] using hrest) hp
    rw [happ, hinst, appEpochContext_inj (List.append_cancel_left hctx)]
  all_goals first
    | rw [happ, appEpochContext_inj (List.append_cancel_left hrest)]
    | rw [happ, appEpochContext_inj hrest]

/-! ### Mirrors of `main_service.rs` tests -/

-- app_epoch_derivation_is_separate_and_epoch_zero_is_unchanged
example : (Derivation.diskCrypt (List.replicate 20 1) (List.replicate 20 2) 0).input.info =
    [List.replicate 20 1, List.replicate 20 2, ascii "app-disk-crypt-key"].flatten := by decide
example : appEpochContext 4294967295 = ascii "app-epoch-v1:" ++ [255, 255, 255, 255] := by decide
example : appEpochContext 1 ≠ appEpochContext 2 := by decide
-- sealed_env_derivation_is_separate_and_shared_with_app_keys
example : (Derivation.sealedEnv (List.replicate 20 1) 0).input.info = List.replicate 20 1 := by decide

/-! ### Without the instance id width -/

def diskHead : Bytes := diskTag.take 14
def diskTail : Bytes := diskTag.drop 14

theorem diskTag_split : diskTag = diskHead ++ diskTail := (List.take_append_drop _ _).symm

@[simp] theorem length_diskTail : diskTail.length = 4 := by decide

theorem ctx_zero {e : UInt32} (h : (appEpochContext e).length = 0) : appEpochContext e = [] :=
  List.length_eq_zero_iff.1 h

theorem ctx_ne_zero {e : UInt32} (h : (appEpochContext e).length = 17) :
    appEpochContext e = epochTag ++ be32 e := by
  unfold appEpochContext at h ⊢
  split
  · rename_i h0; simp [h0] at h
  · rfl

/-- A disk-key info never equals another purpose's info, whatever the instance id. -/
theorem disk_ne_tagged {inst t : Bytes} {e e' : UInt32} (ht : t.length < 18)
    (hbad : diskHead ≠ (t ++ epochTag).drop (t.length - 1))
    (h : inst ++ diskTag ++ appEpochContext e = t ++ appEpochContext e') : False := by
  have hl := congrArg List.length h
  simp only [List.length_append, length_diskTag] at hl
  rcases ctx_cases e with c1 | c1 <;> rcases ctx_cases e' with c2 | c2
  all_goals try omega
  rw [ctx_zero c1, ctx_ne_zero c2, diskTag_split] at h
  have h' : (inst ++ diskHead) ++ diskTail = (t ++ epochTag) ++ be32 e' := by
    simpa only [List.append_assoc, List.append_nil] using h
  have h2 := List.append_inj_left' h' (by rw [length_diskTail, length_be32])
  have h3 := congrArg (List.drop inst.length) h2
  rw [List.drop_left, show inst.length = t.length - 1 by omega] at h3
  exact hbad h3

/-- Two disk-key infos with the same app id are equal only for the same instance id and app
epoch, whatever the instance id widths. -/
theorem disk_inj {inst inst' : Bytes} {e e' : UInt32}
    (h : inst ++ diskTag ++ appEpochContext e = inst' ++ diskTag ++ appEpochContext e') :
    inst = inst' ∧ e = e' := by
  have hl := congrArg List.length h
  simp only [List.length_append, length_diskTag] at hl
  have bad : ∀ {i i' : Bytes} {e' : UInt32},
      i ++ diskTag = i' ++ diskTag ++ epochTag ++ be32 e' → False := by
    intro i i' e' h
    rw [diskTag_split] at h
    have h' : (i ++ diskHead) ++ diskTail = (i' ++ (diskHead ++ diskTail) ++ epochTag) ++ be32 e' := by
      simpa only [List.append_assoc] using h
    have h2 := List.append_inj_left' h' (by rw [length_diskTail, length_be32])
    have hl2 := congrArg List.length h2
    simp only [List.length_append] at hl2
    have h3 := congrArg (List.drop i.length) h2
    rw [List.drop_left, List.append_assoc, List.drop_append, List.drop_eq_nil_of_le (by omega),
      List.nil_append, show i.length - i'.length = 17 by
        have : diskHead.length = 14 := by decide
        have : diskTail.length = 4 := by decide
        have : epochTag.length = 13 := by decide
        omega] at h3
    exact absurd h3 (by decide)
  rcases ctx_cases e with c1 | c1 <;> rcases ctx_cases e' with c2 | c2
  · obtain ⟨h1, h2⟩ := List.append_inj h (by simp only [List.length_append]; omega)
    exact ⟨List.append_cancel_right h1, appEpochContext_inj h2⟩
  · rw [ctx_zero c1, ctx_ne_zero c2, List.append_nil] at h
    exact (bad (by simpa only [List.append_assoc] using h)).elim
  · rw [ctx_ne_zero c1, ctx_zero c2, List.append_nil] at h
    exact (bad (by simpa only [List.append_assoc] using h.symm)).elim
  · obtain ⟨h1, h2⟩ := List.append_inj h (by simp only [List.length_append]; omega)
    exact ⟨List.append_cancel_right h1, appEpochContext_inj h2⟩

/-- Domain separation needs only the 20-byte app id: the instance id width enforced by
`ensure_identity_widths` is not load-bearing for the KDF (it guards the policy backends'
left-padding instead). -/
theorem kdf_input_injective_any_instance {d d' : Derivation} (hw : d.app.length = 20)
    (hw' : d'.app.length = 20) (hs : d.input.salt = d'.input.salt)
    (hi : d.input.info = d'.input.info) : d = d' := by
  have hi0 := hi
  have hs0 := hs
  rw [info_eq, info_eq] at hi
  obtain ⟨happ, hrest⟩ := strip_app hw hw' hi
  cases d <;> cases d' <;> simp only [Derivation.app, Derivation.rest, Derivation.input] at happ hrest hs ⊢
  all_goals first
    | exact absurd hs legacySalt_ne_sealedEnvSalt
    | exact absurd hs.symm legacySalt_ne_sealedEnvSalt
    | exact (disk_ne_tagged (by decide) (by decide) hrest).elim
    | exact (disk_ne_tagged (by decide) (by decide) hrest.symm).elim
    | (obtain ⟨h1, h2⟩ := disk_inj hrest; rw [happ, h1, h2])
    | exact kdf_input_injective ⟨hw, trivial⟩ ⟨hw', trivial⟩ hs0 hi0

/-- Without the app id width the disk key of `(app, instance)` is that of `(app ++ instance, [])`:
`build_boot_info_for_attestation`'s `ensure_app_id_len` is load-bearing. -/
theorem disk_collision_without_app_width (app inst : Bytes) (e : UInt32) :
    (Derivation.diskCrypt app inst e).input = (Derivation.diskCrypt (app ++ inst) [] e).input := by
  simp [Derivation.input]

/-! ## Signature preimages of the root k256 key -/

def issuedDomain : Bytes := ascii "dstack-kms-issued"
def issuedV2Domain : Bytes := ascii "dstack-kms-issued-v2"
def envPubkeyDomain : Bytes := ascii "dstack-env-encrypt-pubkey"
def sealedEnvPubkeyDomain : Bytes := ascii "dstack-sealed-env-pubkey-v1"

/-- The keccak256 preimage of `crypto.rs: sign_message`. -/
def signMessagePreimage (pre appid message : Bytes) : Bytes := pre ++ ascii ":" ++ appid ++ message

/-- The keccak256 preimage of `crypto.rs: sign_message_with_timestamp`. -/
def signMessageWithTimestampPreimage (pre appid : Bytes) (timestamp : UInt64) (message : Bytes) :
    Bytes :=
  pre ++ ascii ":" ++ appid ++ be64 timestamp ++ message

/-- Everything the KMS signs with a root k256 key. -/
inductive Signed where
  /-- `crypto.rs: derive_k256_key`, app epoch 0. -/
  | issued (app pubkey : Bytes)
  /-- `crypto.rs: derive_k256_key`, app epoch `appEpoch ≠ 0`. -/
  | issuedV2 (app : Bytes) (appEpoch : UInt32) (pubkey : Bytes)
  /-- `main_service.rs: get_app_env_encrypt_pub_key`, `signature`. -/
  | envPubkey (app pubkey : Bytes)
  /-- `main_service.rs: get_app_env_encrypt_pub_key`, `signature_v1`. -/
  | envPubkeyV1 (app : Bytes) (timestamp : UInt64) (pubkey : Bytes)
  /-- `main_service.rs: get_sealed_env_pub_key`. -/
  | sealedEnvPubkey (app : Bytes) (rootEpoch appEpoch : UInt32) (pubkey : Bytes) (timestamp : UInt64)
  deriving DecidableEq

def Signed.preimage : Signed → Bytes
  | .issued app pk => signMessagePreimage issuedDomain app pk
  | .issuedV2 app e pk => signMessagePreimage issuedV2Domain app (be32 e ++ pk)
  | .envPubkey app pk => signMessagePreimage envPubkeyDomain app pk
  | .envPubkeyV1 app ts pk => signMessageWithTimestampPreimage envPubkeyDomain app ts pk
  | .sealedEnvPubkey app r a pk ts =>
    signMessagePreimage sealedEnvPubkeyDomain app (be32 r ++ be32 a ++ pk ++ be64 ts)

def Signed.domain : Signed → Bytes
  | .issued .. => issuedDomain
  | .issuedV2 .. => issuedV2Domain
  | .envPubkey .. | .envPubkeyV1 .. => envPubkeyDomain
  | .sealedEnvPubkey .. => sealedEnvPubkeyDomain

def Signed.app : Signed → Bytes
  | .issued app _ | .issuedV2 app _ _ | .envPubkey app _ | .envPubkeyV1 app _ _
  | .sealedEnvPubkey app _ _ _ _ => app

def Signed.body : Signed → Bytes
  | .issued _ pk => pk
  | .issuedV2 _ e pk => be32 e ++ pk
  | .envPubkey _ pk => pk
  | .envPubkeyV1 _ ts pk => be64 ts ++ pk
  | .sealedEnvPubkey _ r a pk ts => be32 r ++ be32 a ++ pk ++ be64 ts

/-- App ids are 20 bytes; signed public keys are SEC1-compressed k256 (33 bytes) or X25519
(32 bytes). -/
def Signed.WellFormed : Signed → Prop
  | .issued app pk | .issuedV2 app _ pk => app.length = 20 ∧ pk.length = 33
  | .envPubkey app pk | .envPubkeyV1 app _ pk | .sealedEnvPubkey app _ _ pk _ =>
    app.length = 20 ∧ pk.length = 32

theorem preimage_eq (s : Signed) : s.preimage = (s.domain ++ ascii ":") ++ (s.app ++ s.body) := by
  cases s <;> simp [Signed.preimage, Signed.domain, Signed.app, Signed.body, signMessagePreimage,
    signMessageWithTimestampPreimage]

def taggedDomains : List Bytes :=
  [issuedDomain, issuedV2Domain, envPubkeyDomain, sealedEnvPubkeyDomain].map (· ++ ascii ":")

/-- With the `:` separator the signing domains are prefix-free, although `dstack-kms-issued` is
a prefix of `dstack-kms-issued-v2`. -/
theorem domains_prefix_free : ∀ a ∈ taggedDomains, ∀ b ∈ taggedDomains, a <+: b → a = b := by
  decide

theorem issued_prefix_of_v2 : issuedDomain <+: issuedV2Domain := by decide

theorem domain_mem (s : Signed) : s.domain ++ ascii ":" ∈ taggedDomains := by
  cases s <;> simp [Signed.domain, taggedDomains]

theorem eq_of_prefix_free {a b x y : Bytes} (ha : a ∈ taggedDomains) (hb : b ∈ taggedDomains)
    (h : a ++ x = b ++ y) : a = b := by
  rcases List.append_eq_append_iff.1 h with ⟨c, hc, -⟩ | ⟨c, hc, -⟩
  · exact domains_prefix_free a ha b hb ⟨c, hc.symm⟩
  · exact (domains_prefix_free b hb a ha ⟨c, hc.symm⟩).symm

/-- Distinct well-formed signed messages have distinct keccak256 preimages: no signature the
KMS issues for one purpose, app, epoch, key or timestamp verifies for another. -/
theorem preimage_injective {s s' : Signed} (hw : s.WellFormed) (hw' : s'.WellFormed)
    (h : s.preimage = s'.preimage) : s = s' := by
  rw [preimage_eq, preimage_eq] at h
  have hd := eq_of_prefix_free (domain_mem s) (domain_mem s') h
  have hr := List.append_cancel_left (hd ▸ h)
  have hdom := List.append_cancel_right hd
  cases s <;> cases s' <;>
    simp only [Signed.WellFormed, Signed.domain, Signed.app, Signed.body, Signed.issued.injEq,
      Signed.issuedV2.injEq, Signed.envPubkey.injEq, Signed.envPubkeyV1.injEq,
      Signed.sealedEnvPubkey.injEq] at hw hw' hdom hr ⊢ <;>
    first
    | exact absurd hdom (by decide)
    | skip
  all_goals
    obtain ⟨ha, hp⟩ := hw
    obtain ⟨ha', hp'⟩ := hw'
    obtain ⟨rfl, hb⟩ := strip_app ha ha' hr
    have hl := congrArg List.length hb
    try simp only [List.length_append, length_be32, length_be64] at hl
  · exact ⟨rfl, hb⟩
  · obtain ⟨he, hpk⟩ := List.append_inj hb (by simp)
    exact ⟨rfl, be32_inj he, hpk⟩
  · exact ⟨rfl, hb⟩
  · omega
  · omega
  · obtain ⟨ht, hpk⟩ := List.append_inj hb (by simp)
    exact ⟨rfl, be64_inj ht, hpk⟩
  · obtain ⟨h1, ht⟩ := List.append_inj hb (by simp only [List.length_append, length_be32]; omega)
    obtain ⟨h2, hpk⟩ := List.append_inj h1 (by simp only [List.length_append, length_be32])
    obtain ⟨hr1, ha1⟩ := List.append_inj h2 (by simp)
    exact ⟨rfl, be32_inj hr1, be32_inj ha1, hpk, be64_inj ht⟩

end DstackFormal.Kms.KeyDerivation
