-- SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
--
-- SPDX-License-Identifier: Apache-2.0

/-!
# Iterative MessagePack skipping (`dstack/gateway/src/kv/compat.rs`)

Models `skip_value` and `read_uint`. The marker table of `skip_value` (payload length and child
count per `rmp::Marker`) is `kind` / `info`, regrouped by shape but entry-for-entry the same.

The format is given by `Seq k bytes`: `bytes` is exactly `k` consecutive encoded values in
prefix order. A value is a marker, its payload (whose length `info` reads from the bytes after
the marker), then the encodings of its children; so `k + 1` values are one header followed by
`k + children` values. This is the grammar the iterative `pending` counter walks.

Proven:
* `skip_in_bounds`: a result lies strictly after `pos` and never past the end of the buffer.
* `skip_exact`: if `buf = pre ++ v ++ rest` with `v` one encoded value, `skip_value buf pre.length`
  returns `pre.length + v.length`, whatever follows (the `pending > len - pos` guard never refuses
  a well-formed value).
* `skip_sound`: conversely, whenever `skip_value buf pos = some q`, the bytes `pos..q` are exactly
  one encoded value.
* `skipLoop_fuel`: the fuel given to the loop is never what stops it.

Assumption / modeling gap: bytes are `Nat` (callers pass values below 256); `usize` overflow in
`checked_add` / `checked_mul` is not modeled (lengths read are below 2^32); the loop is run with
fuel `len - pos + 1`, each iteration consuming at least the marker byte.
-/

namespace DstackFormal.Gateway.MsgpackSkip

abbrev Bytes := List Nat

/-- `read_uint`, on the bytes after the marker. -/
def readUint (l : Bytes) (size : Nat) : Option Nat :=
  if size ≤ l.length then some ((l.take size).foldl (fun a b => a * 256 + b) 0) else none

/-- Shapes of `skip_value`'s match arms. -/
inductive Kind where
  /-- Fixed payload length and child count. -/
  | fixed (payload children : Nat)
  /-- `Str*`, `Bin*` (`extra = 0`) and `Ext*` (`extra = 1`): a `size`-byte length, then data. -/
  | sized (size extra : Nat)
  /-- `Array*` (`mul = 1`) and `Map*` (`mul = 2`): a `size`-byte element count. -/
  | coll (size mul : Nat)
deriving DecidableEq, Repr

/-- `Marker::from_u8` composed with the match in `skip_value`; `none` is `Marker::Reserved`. -/
def kind (m : Nat) : Option Kind :=
  if m ≤ 0x7f then some (.fixed 0 0)
  else if m ≤ 0x8f then some (.fixed 0 (2 * (m - 0x80)))
  else if m ≤ 0x9f then some (.fixed 0 (m - 0x90))
  else if m ≤ 0xbf then some (.fixed (m - 0xa0) 0)
  else if m = 0xc0 then some (.fixed 0 0)
  else if m = 0xc1 then none
  else if m = 0xc2 ∨ m = 0xc3 then some (.fixed 0 0)
  else if m = 0xc4 then some (.sized 1 0)
  else if m = 0xc5 then some (.sized 2 0)
  else if m = 0xc6 then some (.sized 4 0)
  else if m = 0xc7 then some (.sized 1 1)
  else if m = 0xc8 then some (.sized 2 1)
  else if m = 0xc9 then some (.sized 4 1)
  else if m = 0xca then some (.fixed 4 0)
  else if m = 0xcb then some (.fixed 8 0)
  else if m = 0xcc ∨ m = 0xd0 then some (.fixed 1 0)
  else if m = 0xcd ∨ m = 0xd1 then some (.fixed 2 0)
  else if m = 0xce ∨ m = 0xd2 then some (.fixed 4 0)
  else if m = 0xcf ∨ m = 0xd3 then some (.fixed 8 0)
  else if m = 0xd4 then some (.fixed 2 0)
  else if m = 0xd5 then some (.fixed 3 0)
  else if m = 0xd6 then some (.fixed 5 0)
  else if m = 0xd7 then some (.fixed 9 0)
  else if m = 0xd8 then some (.fixed 17 0)
  else if m = 0xd9 then some (.sized 1 0)
  else if m = 0xda then some (.sized 2 0)
  else if m = 0xdb then some (.sized 4 0)
  else if m = 0xdc then some (.coll 2 1)
  else if m = 0xdd then some (.coll 4 1)
  else if m = 0xde then some (.coll 2 2)
  else if m = 0xdf then some (.coll 4 2)
  else some (.fixed 0 0)

/-- `(payload, children)` for marker `m`, reading length fields from `after`. -/
def info (m : Nat) (after : Bytes) : Option (Nat × Nat) :=
  match kind m with
  | none => none
  | some (.fixed p c) => some (p, c)
  | some (.sized s e) => (readUint after s).map fun n => (s + e + n, 0)
  | some (.coll s mul) => (readUint after s).map fun n => (s, mul * n)

/-- The `while pending > 0` loop, with explicit fuel. -/
def skipLoop (buf : Bytes) : Nat → Nat → Nat → Option Nat
  | _, 0, pos => some pos
  | 0, _ + 1, _ => none
  | f + 1, k + 1, pos =>
    match buf[pos]? with
    | none => none
    | some m =>
      match info m (buf.drop (pos + 1)) with
      | none => none
      | some (payload, children) =>
        let pos' := pos + 1 + payload
        if buf.length < pos' then none
        else if buf.length - pos' < k + children then none
        else skipLoop buf f (k + children) pos'

/-- `skip_value`. -/
def skipValue (buf : Bytes) (pos : Nat) : Option Nat := skipLoop buf (buf.length - pos + 1) 1 pos

/-- `bytes` is exactly `k` encoded values. -/
inductive Seq : Nat → Bytes → Prop
  | nil : Seq 0 []
  | cons {k c : Nat} (m : Nat) (payload tail : Bytes) :
      info m (payload ++ tail) = some (payload.length, c) → Seq (k + c) tail →
      Seq (k + 1) (m :: (payload ++ tail))

/-! ## `info` only depends on the payload -/

theorem readUint_size {l : Bytes} {s n : Nat} (h : readUint l s = some n) : s ≤ l.length := by
  unfold readUint at h; split at h
  · assumption
  · simp at h

theorem readUint_prefix {l r : Bytes} {s : Nat} (hs : s ≤ l.length) :
    readUint (l ++ r) s = readUint l s := by
  have h2 : s ≤ (l ++ r).length := by rw [List.length_append]; omega
  unfold readUint
  simp only [h2, hs, ↓reduceIte, List.take_append_of_le_length hs]

theorem info_prefix {m : Nat} {l r : Bytes} {p c : Nat} (hp : p ≤ l.length) :
    info m (l ++ r) = some (p, c) → info m l = some (p, c) := by
  unfold info
  cases hk : kind m with
  | none => simp
  | some k =>
    cases k with
    | fixed p' c' => simp
    | sized s e =>
      simp only
      intro h
      obtain ⟨n, hn, he⟩ := Option.map_eq_some_iff.mp h
      simp only [Prod.mk.injEq] at he
      have hs : s ≤ l.length := by omega
      rw [readUint_prefix hs] at hn
      rw [hn]; simp [he.1, he.2]
    | coll s mul =>
      simp only
      intro h
      obtain ⟨n, hn, he⟩ := Option.map_eq_some_iff.mp h
      simp only [Prod.mk.injEq] at he
      have hs : s ≤ l.length := by omega
      rw [readUint_prefix hs] at hn
      rw [hn]; simp [he.1, he.2]

theorem info_extend {m : Nat} {l r : Bytes} {p c : Nat}
    (h : info m l = some (p, c)) : info m (l ++ r) = some (p, c) := by
  unfold info at h ⊢
  cases hk : kind m with
  | none => simp [hk] at h
  | some k =>
    rw [hk] at h
    cases k with
    | fixed p' c' => exact h
    | sized s e =>
      simp only at h ⊢
      obtain ⟨n, hn, he⟩ := Option.map_eq_some_iff.mp h
      rw [readUint_prefix (readUint_size hn), hn]
      simp [he]
    | coll s mul =>
      simp only at h ⊢
      obtain ⟨n, hn, he⟩ := Option.map_eq_some_iff.mp h
      rw [readUint_prefix (readUint_size hn), hn]
      simp [he]

theorem Seq.length_ge {k : Nat} {v : Bytes} (h : Seq k v) : k ≤ v.length := by
  induction h with
  | nil => simp
  | cons m payload tail _ _ ih => simp; omega

/-! ## Bounds -/

theorem skipLoop_ge (buf : Bytes) : ∀ f k pos q, skipLoop buf f k pos = some q → pos ≤ q
  | _, 0, pos, q, h => by simp [skipLoop] at h; omega
  | 0, _ + 1, _, _, h => by simp [skipLoop] at h
  | f + 1, k + 1, pos, q, h => by
    unfold skipLoop at h
    split at h
    · simp at h
    · split at h
      · simp at h
      · simp only at h
        split at h
        · simp at h
        · split at h
          · simp at h
          · have := skipLoop_ge buf f _ _ q h; omega

theorem skipLoop_bounds (buf : Bytes) :
    ∀ f k pos q, skipLoop buf f (k + 1) pos = some q → pos < q ∧ q ≤ buf.length
  | 0, _, _, _, h => by simp [skipLoop] at h
  | f + 1, k, pos, q, h => by
    unfold skipLoop at h
    split at h
    · simp at h
    · split at h
      · simp at h
      · rename_i payload children _
        simp only at h
        split at h
        · simp at h
        · rename_i hle
          split at h
          · simp at h
          · cases hk : k + children with
            | zero =>
              rw [hk] at h
              simp [skipLoop] at h
              omega
            | succ k' =>
              rw [hk] at h
              have := skipLoop_bounds buf f k' _ q h
              omega

theorem skip_in_bounds {buf : Bytes} {pos q : Nat} (h : skipValue buf pos = some q) :
    pos < q ∧ q ≤ buf.length :=
  skipLoop_bounds buf _ 0 pos q h

/-! ## Exactness -/

theorem skipLoop_exact {k : Nat} {v : Bytes} (hv : Seq k v) :
    ∀ (pre rest : Bytes) (f : Nat), v.length ≤ f →
      skipLoop (pre ++ v ++ rest) f k pre.length = some (pre.length + v.length) := by
  induction hv with
  | nil => intro pre rest f _; cases f <;> simp [skipLoop]
  | @cons k c m payload tail hinfo htail ih =>
    intro pre rest f hf
    obtain ⟨f, rfl⟩ : ∃ f', f = f' + 1 := ⟨f - 1, by simp at hf; omega⟩
    unfold skipLoop
    have hget : (pre ++ m :: (payload ++ tail) ++ rest)[pre.length]? = some m := by simp
    rw [hget]
    simp only
    have hdrop : (pre ++ m :: (payload ++ tail) ++ rest).drop (pre.length + 1) =
        payload ++ tail ++ rest := by simp
    rw [hdrop, info_extend (by simpa using hinfo)]
    simp only
    have hlen := htail.length_ge
    have e1 : ¬ (pre ++ m :: (payload ++ tail) ++ rest).length < pre.length + 1 + payload.length := by
      simp; omega
    have e2 : ¬ (pre ++ m :: (payload ++ tail) ++ rest).length - (pre.length + 1 + payload.length) <
        k + c := by simp; omega
    simp only [e1, e2, ↓reduceIte]
    have := ih (pre ++ m :: payload) rest f (by simp at hf; omega)
    simp only [List.append_assoc, List.cons_append, List.length_append, List.length_cons] at this ⊢
    rw [show pre.length + 1 + payload.length = pre.length + (payload.length + 1) by omega, this]
    congr 1; omega

theorem skip_exact {v : Bytes} (hv : Seq 1 v) (pre rest : Bytes) :
    skipValue (pre ++ v ++ rest) pre.length = some (pre.length + v.length) := by
  unfold skipValue
  exact skipLoop_exact hv pre rest _ (by simp; omega)

/-! ## Soundness -/

def window (buf : Bytes) (pos q : Nat) : Bytes := (buf.drop pos).take (q - pos)

theorem skipLoop_sound (buf : Bytes) :
    ∀ f k pos q, skipLoop buf f k pos = some q → Seq k (window buf pos q)
  | _, 0, pos, q, h => by
    simp [skipLoop] at h; subst h; simp [window]; exact Seq.nil
  | 0, _ + 1, _, _, h => by simp [skipLoop] at h
  | f + 1, k + 1, pos, q, h => by
    have hb := skipLoop_bounds buf (f + 1) k pos q h
    unfold skipLoop at h
    split at h
    · simp at h
    · rename_i m hm
      split at h
      · simp at h
      · rename_i payload children hinfo
        simp only at h
        split at h
        · simp at h
        · rename_i hle
          split at h
          · simp at h
          · have ih := skipLoop_sound buf f (k + children) _ q h
            have hq := skipLoop_ge buf f _ _ q h
            have hpos : pos < buf.length := by
              rcases Nat.lt_or_ge pos buf.length with h' | h'
              · exact h'
              · simp [List.getElem?_eq_none h'] at hm
            have hdrop : buf.drop pos = m :: buf.drop (pos + 1) := by
              rw [List.drop_eq_getElem_cons hpos]
              simp only [List.getElem?_eq_getElem hpos, Option.some.injEq] at hm
              rw [hm]
            obtain ⟨pl, hpl⟩ : ∃ pl, pl = (buf.drop (pos + 1)).take payload := ⟨_, rfl⟩
            have hwin : window buf pos q =
                m :: (pl ++ window buf (pos + 1 + payload) q) := by
              unfold window
              rw [hdrop]
              obtain ⟨d, hd⟩ : ∃ d, q - pos = d + 1 := ⟨q - pos - 1, by omega⟩
              rw [hd, List.take_succ_cons]
              congr 1
              have hsplit : buf.drop (pos + 1) =
                  (buf.drop (pos + 1)).take payload ++ buf.drop (pos + 1 + payload) := by
                conv => lhs; rw [← List.take_append_drop payload (buf.drop (pos + 1))]
                simp [List.drop_drop, Nat.add_comm]
              rw [hsplit, List.take_append]
              have hplen : ((buf.drop (pos + 1)).take payload).length = payload := by
                simp; omega
              rw [hplen, List.take_of_length_le (by omega), hpl]
              congr 2; omega
            rw [hwin]
            have hplen : pl.length = payload := by simp [hpl]; omega
            refine Seq.cons m pl _ ?_ ih
            rw [hplen]
            apply info_prefix (r := (buf.drop (pos + 1 + payload)).drop (q - (pos + 1 + payload)))
              (by simp; omega)
            rw [← hinfo]
            congr 1
            unfold window
            rw [List.append_assoc, List.take_append_drop]
            conv => rhs; rw [← List.take_append_drop payload (buf.drop (pos + 1))]
            simp [hpl, List.drop_drop, Nat.add_comm]

theorem skip_sound {buf : Bytes} {pos q : Nat} (h : skipValue buf pos = some q) :
    Seq 1 (window buf pos q) :=
  skipLoop_sound buf _ 1 pos q h

/-! ## Fuel adequacy -/

theorem skipLoop_fuel (buf : Bytes) :
    ∀ f k pos, buf.length - pos < f → skipLoop buf f k pos = skipLoop buf (f + 1) k pos
  | _, 0, _, _ => by simp [skipLoop]
  | 0, _ + 1, _, h => absurd h (Nat.not_lt_zero _)
  | f + 1, k + 1, pos, h => by
    conv => lhs; unfold skipLoop
    conv => rhs; unfold skipLoop
    cases hm : buf[pos]? with
    | none => rfl
    | some m =>
      simp only
      cases hi : info m (buf.drop (pos + 1)) with
      | none => rfl
      | some pc =>
        obtain ⟨payload, children⟩ := pc
        simp only
        split
        · rfl
        · split
          · rfl
          · rename_i hle _
            have hpos : pos < buf.length := by
              rcases Nat.lt_or_ge pos buf.length with h' | h'
              · exact h'
              · simp [List.getElem?_eq_none h'] at hm
            exact skipLoop_fuel buf f _ _ (by omega)

/-! ## Mirrors of Rust unit tests -/

-- deep_nesting_does_not_exhaust_the_stack (scaled down)
#guard skipValue (List.replicate 2000 0x91 ++ [0xc0]) 0 == some 2001
-- a_header_claiming_more_than_the_buffer_holds_is_refused
#guard skipValue [0xdf, 0xff, 0xff, 0xff, 0xff] 0 == none
#guard skipValue [0xdd, 0xff, 0xff, 0xff, 0xff] 0 == none
#guard skipValue [0xdb, 0xff, 0xff, 0xff, 0xff] 0 == none
#guard skipValue [0xc1] 0 == none
-- {"a": [1, "xy"]} followed by a trailing byte
#guard skipValue [0x81, 0xa1, 0x61, 0x92, 0x01, 0xa2, 0x78, 0x79, 0xc0] 0 == some 8

end DstackFormal.Gateway.MsgpackSkip
