-- SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
--
-- SPDX-License-Identifier: Apache-2.0

/-!
# ClientHello SNI sniffing (`dstack/gateway/src/proxy/sni.rs`)

Models `extract_sni` / `extract_sni_inner` and `take_record_u8_len`, with the `parcelona`
primitives it uses (`take_len_be_u8`, `take_len_be_u16`, `take_len_be_u24`, `take_record`,
`take_record_be_u16`) as bounds-checked operations on a byte list.

Proven:
* `extract_infix`: a returned name is a contiguous sub-slice of the input.
* `extract_client_hello`: on the ClientHello built by the Rust test helper `client_hello` (one
  `host_name` entry), the extractor returns exactly the name, for any name up to 65000 bytes.
* `extract_short_none`, `extract_not_handshake_none`: inputs under 10 bytes, or whose first byte
  is not `0x16`, yield nothing.
* Totality is by construction: every read is bounds checked and returns `none` past the end.
  `take_record_u8_len` is `take_len_be_u8` followed by `take_record`, so a length byte that
  covers itself cannot over-read (the bug its doc comment describes).

Observation: the record length, handshake length, extensions length and `ServerNameList` length
are read and ignored; both loops keep reading until the buffer ends. A name can therefore be
taken from bytes past the declared extensions block (`extract_ignores_declared_lengths`), where a
full TLS parser would not look.

Modeling gap: bytes are `Nat` (callers pass values below 256); the two unbounded `loop`s are given
fuel `length + 1`, which is never exhausted first because every iteration consumes at least three
bytes (`nameLoop_fuel`, `extLoop_fuel`); `trace!` is dropped.
-/

namespace DstackFormal.Gateway.Sni

abbrev Bytes := List Nat

/-- `take_len_be_u8`. -/
def u8 : Bytes → Option (Bytes × Nat)
  | [] => none
  | x :: r => some (r, x)

/-- `take_len_be_u16`. -/
def u16 : Bytes → Option (Bytes × Nat)
  | x :: y :: r => some (r, x * 256 + y)
  | _ => none

/-- `take_len_be_u24`. -/
def u24 : Bytes → Option (Bytes × Nat)
  | x :: y :: z :: r => some (r, (x * 256 + y) * 256 + z)
  | _ => none

/-- `take_record(b, n)`: `(rest, record)`. -/
def record (b : Bytes) (n : Nat) : Option (Bytes × Bytes) :=
  if n ≤ b.length then some (b.drop n, b.take n) else none

/-- `take_record_u8_len`. -/
def recordU8 (b : Bytes) : Option (Bytes × Bytes) :=
  match u8 b with
  | some (b, n) => record b n
  | none => none

/-- `take_record_be_u16`. -/
def recordU16 (b : Bytes) : Option (Bytes × Bytes) :=
  match u16 b with
  | some (b, n) => record b n
  | none => none

/-- The inner `ServerNameList` loop. -/
def nameLoop : Nat → Bytes → Option Bytes
  | 0, _ => none
  | f + 1, b =>
    match u8 b with
    | none => none
    | some (b, ty) =>
      match u16 b with
      | none => none
      | some (b, len) =>
        match record b len with
        | none => none
        | some (b, sni) => if ty ≠ 0 then nameLoop f b else some sni

/-- The extension loop. -/
def extLoop : Nat → Bytes → Option Bytes
  | 0, _ => none
  | f + 1, b =>
    match u16 b with
    | none => none
    | some (b, ty) =>
      match u16 b with
      | none => none
      | some (b, len) =>
        if ty ≠ 0 then
          if 0 < len then
            match record b len with
            | none => none
            | some (b, _) => extLoop f b
          else extLoop f b
        else
          match u16 b with
          | none => none
          | some (b, _) => nameLoop (b.length + 1) b

/-- `extract_sni`. -/
def extractSni (b : Bytes) : Option Bytes :=
  if b.length < 10 then none
  else if b.head? ≠ some 0x16 then none
  else
    match u8 (b.drop 5) with
    | none => none
    | some (b, c) =>
      if c ≠ 1 then none
      else match u24 b with
        | none => none
        | some (b, _) =>
          match record b 34 with
          | none => none
          | some (b, _) =>
            match recordU8 b with
            | none => none
            | some (b, _) =>
              match recordU16 b with
              | none => none
              | some (b, _) =>
                match recordU8 b with
                | none => none
                | some (b, _) =>
                  match u16 b with
                  | none => none
                  | some (b, _) => extLoop (b.length + 1) b

/-! ## Sub-slice -/

def Suffix (r b : Bytes) : Prop := ∃ p, b = p ++ r

def Infix (s b : Bytes) : Prop := ∃ pre post, b = pre ++ s ++ post

theorem Suffix.trans {a b c : Bytes} (h₁ : Suffix a b) (h₂ : Suffix b c) : Suffix a c := by
  obtain ⟨p, rfl⟩ := h₁; obtain ⟨q, rfl⟩ := h₂; exact ⟨q ++ p, by simp⟩

theorem Infix.of_suffix {s r b : Bytes} (h₁ : Infix s r) (h₂ : Suffix r b) : Infix s b := by
  obtain ⟨pre, post, rfl⟩ := h₁; obtain ⟨q, rfl⟩ := h₂; exact ⟨q ++ pre, post, by simp⟩

theorem u8_suffix {b r : Bytes} {x : Nat} (h : u8 b = some (r, x)) : Suffix r b := by
  match b, h with
  | y :: r', h => simp [u8] at h; obtain ⟨rfl, -⟩ := h; exact ⟨[y], rfl⟩

theorem u16_suffix {b r : Bytes} {x : Nat} (h : u16 b = some (r, x)) : Suffix r b := by
  match b, h with
  | y :: z :: r', h => simp [u16] at h; obtain ⟨rfl, -⟩ := h; exact ⟨[y, z], rfl⟩

theorem u24_suffix {b r : Bytes} {x : Nat} (h : u24 b = some (r, x)) : Suffix r b := by
  match b, h with
  | y :: z :: w :: r', h => simp [u24] at h; obtain ⟨rfl, -⟩ := h; exact ⟨[y, z, w], rfl⟩

theorem record_split {b r t : Bytes} {n : Nat} (h : record b n = some (r, t)) :
    b = t ++ r ∧ t.length = n := by
  unfold record at h
  split at h
  · simp only [Option.some.injEq, Prod.mk.injEq] at h
    obtain ⟨rfl, rfl⟩ := h
    exact ⟨(List.take_append_drop n b).symm, by simp; omega⟩
  · simp at h

theorem record_suffix {b r t : Bytes} {n : Nat} (h : record b n = some (r, t)) : Suffix r b :=
  ⟨t, (record_split h).1⟩

theorem record_infix {b r t : Bytes} {n : Nat} (h : record b n = some (r, t)) : Infix t b :=
  ⟨[], r, by simp [(record_split h).1]⟩

theorem recordU8_suffix {b r t : Bytes} (h : recordU8 b = some (r, t)) : Suffix r b := by
  unfold recordU8 at h
  split at h
  · rename_i b' n h1; exact (record_suffix h).trans (u8_suffix h1)
  · simp at h

theorem recordU16_suffix {b r t : Bytes} (h : recordU16 b = some (r, t)) : Suffix r b := by
  unfold recordU16 at h
  split at h
  · rename_i b' n h1; exact (record_suffix h).trans (u16_suffix h1)
  · simp at h

theorem nameLoop_infix : ∀ (f : Nat) (b s : Bytes), nameLoop f b = some s → Infix s b
  | 0, _, _, h => by simp [nameLoop] at h
  | f + 1, b, s, h => by
    unfold nameLoop at h
    split at h
    · simp at h
    · rename_i b₁ ty h₁
      split at h
      · simp at h
      · rename_i b₂ len h₂
        split at h
        · simp at h
        · rename_i b₃ sni h₃
          have hs : Suffix b₂ b := (u16_suffix h₂).trans (u8_suffix h₁)
          split at h
          · exact (nameLoop_infix f b₃ s h).of_suffix ((record_suffix h₃).trans hs)
          · simp only [Option.some.injEq] at h
            subst h
            exact (record_infix h₃).of_suffix hs

theorem extLoop_infix : ∀ (f : Nat) (b s : Bytes), extLoop f b = some s → Infix s b
  | 0, _, _, h => by simp [extLoop] at h
  | f + 1, b, s, h => by
    unfold extLoop at h
    split at h
    · simp at h
    · rename_i b₁ ty h₁
      split at h
      · simp at h
      · rename_i b₂ len h₂
        have hs : Suffix b₂ b := (u16_suffix h₂).trans (u16_suffix h₁)
        split at h
        · split at h
          · split at h
            · simp at h
            · rename_i b₃ _ h₃
              exact (extLoop_infix f b₃ s h).of_suffix ((record_suffix h₃).trans hs)
          · exact (extLoop_infix f b₂ s h).of_suffix hs
        · split at h
          · simp at h
          · rename_i b₃ _ h₃
            exact (nameLoop_infix _ b₃ s h).of_suffix ((u16_suffix h₃).trans hs)

theorem drop_suffix (b : Bytes) (n : Nat) : Suffix (b.drop n) b :=
  ⟨b.take n, (List.take_append_drop n b).symm⟩

/-- A returned name is a contiguous sub-slice of the input. -/
theorem extract_infix {b s : Bytes} (h : extractSni b = some s) : Infix s b := by
  unfold extractSni at h
  split at h
  · simp at h
  split at h
  · simp at h
  split at h
  · simp at h
  rename_i b₁ c h₁
  have s₁ := (u8_suffix h₁).trans (drop_suffix b 5)
  split at h
  · simp at h
  split at h
  · simp at h
  rename_i b₂ _ h₂
  have s₂ := (u24_suffix h₂).trans s₁
  split at h
  · simp at h
  rename_i b₃ _ h₃
  have s₃ := (record_suffix h₃).trans s₂
  split at h
  · simp at h
  rename_i b₄ _ h₄
  have s₄ := (recordU8_suffix h₄).trans s₃
  split at h
  · simp at h
  rename_i b₅ _ h₅
  have s₅ := (recordU16_suffix h₅).trans s₄
  split at h
  · simp at h
  rename_i b₆ _ h₆
  have s₆ := (recordU8_suffix h₆).trans s₅
  split at h
  · simp at h
  rename_i b₇ _ h₇
  exact (extLoop_infix _ b₇ s h).of_suffix ((u16_suffix h₇).trans s₆)

theorem extract_short_none {b : Bytes} (h : b.length < 10) : extractSni b = none := by
  simp [extractSni, h]

theorem extract_not_handshake_none {b : Bytes} (h : b.head? ≠ some 0x16) : extractSni b = none := by
  unfold extractSni
  split <;> rfl

/-! ## Fuel adequacy -/

theorem u8_length {b r : Bytes} {x : Nat} (h : u8 b = some (r, x)) : r.length + 1 = b.length := by
  match b, h with
  | _ :: _, h => simp [u8] at h; obtain ⟨rfl, -⟩ := h; simp

theorem u16_length {b r : Bytes} {x : Nat} (h : u16 b = some (r, x)) : r.length + 2 = b.length := by
  match b, h with
  | _ :: _ :: _, h => simp [u16] at h; obtain ⟨rfl, -⟩ := h; simp

theorem record_length {b r t : Bytes} {n : Nat} (h : record b n = some (r, t)) :
    r.length ≤ b.length := by
  have := congrArg List.length (record_split h).1; simp at this; omega

theorem nameLoop_fuel : ∀ (f : Nat) (b : Bytes), b.length < f → nameLoop f b = nameLoop (f + 1) b
  | 0, _, h => absurd h (Nat.not_lt_zero _)
  | f + 1, b, h => by
    conv => rhs; unfold nameLoop
    conv => lhs; unfold nameLoop
    cases h₁ : u8 b with
    | none => rfl
    | some p₁ =>
      obtain ⟨b₁, ty⟩ := p₁
      simp only
      cases h₂ : u16 b₁ with
      | none => rfl
      | some p₂ =>
        obtain ⟨b₂, len⟩ := p₂
        simp only
        cases h₃ : record b₂ len with
        | none => rfl
        | some p₃ =>
          obtain ⟨b₃, sni⟩ := p₃
          simp only
          have := u8_length h₁; have := u16_length h₂; have := record_length h₃
          rw [nameLoop_fuel f b₃ (by omega)]

theorem nameLoop_fuel_le (b : Bytes) :
    ∀ k f, b.length < f → nameLoop f b = nameLoop (f + k) b
  | 0, _, _ => rfl
  | k + 1, f, h => by
    rw [nameLoop_fuel_le b k f h, nameLoop_fuel (f + k) b (by omega)]; rfl

theorem extLoop_fuel : ∀ (f : Nat) (b : Bytes), b.length < f → extLoop f b = extLoop (f + 1) b
  | 0, _, h => absurd h (Nat.not_lt_zero _)
  | f + 1, b, h => by
    conv => rhs; unfold extLoop
    conv => lhs; unfold extLoop
    cases h₁ : u16 b with
    | none => rfl
    | some p₁ =>
      obtain ⟨b₁, ty⟩ := p₁
      simp only
      cases h₂ : u16 b₁ with
      | none => rfl
      | some p₂ =>
        obtain ⟨b₂, len⟩ := p₂
        simp only
        have := u16_length h₁; have := u16_length h₂
        split
        · split
          · cases h₃ : record b₂ len with
            | none => rfl
            | some p₃ =>
              obtain ⟨b₃, _⟩ := p₃
              simp only
              have := record_length h₃
              rw [extLoop_fuel f b₃ (by omega)]
          · rw [extLoop_fuel f b₂ (by omega)]
        · rfl

/-! ## Round trip on the test helper's ClientHello -/

def be16 (n : Nat) : Bytes := [n / 256 % 256, n % 256]
def be24 (n : Nat) : Bytes := [n / 65536 % 256, n / 256 % 256, n % 256]

/-- The Rust test helper `client_hello(server_name)`. -/
def clientHello (name : Bytes) : Bytes :=
  let sniExt := 0 :: (be16 name.length ++ name)
  let list := be16 sniExt.length ++ sniExt
  let exts := [0, 0] ++ be16 list.length ++ list
  let body := [3, 3] ++ List.replicate 32 0x41 ++ [0] ++ [0, 2, 0x13, 1] ++ [1, 0] ++
    be16 exts.length ++ exts
  let hs := [1] ++ be24 body.length ++ body
  [0x16, 3, 1] ++ be16 hs.length ++ hs

theorem be16_val {n : Nat} (h : n < 65536) : n / 256 % 256 * 256 + n % 256 = n := by omega

theorem extract_client_hello (name : Bytes) (h : name.length ≤ 65000) :
    extractSni (clientHello name) = some name := by
  have e1 := be16_val (n := name.length) (by omega)
  simp only [clientHello, be16, be24, List.cons_append, List.nil_append, List.append_assoc]
  unfold extractSni
  simp only [List.length_cons, List.length_append, List.length_replicate, List.head?_cons,
    List.drop_succ_cons, List.drop_zero, u8, u24, record, recordU8, recordU16, u16,
    List.replicate_succ, List.cons_append]
  simp [extLoop, nameLoop, u8, u16, record, e1]

-- extracts_the_server_name_from_a_client_hello
#guard extractSni (clientHello ("app.example.com".toList.map Char.toNat)) ==
  some ("app.example.com".toList.map Char.toNat)
-- a_record_that_is_not_a_handshake_has_no_sni
#guard extractSni (0x17 :: (clientHello [97]).drop 1) == none
-- a_truncated_client_hello_yields_no_name_rather_than_a_wrong_one
#guard (List.range (clientHello [97, 98, 99]).length).all fun n =>
  extractSni ((clientHello [97, 98, 99]).take n) == none

/-- Record length 0, handshake length 0, and an extensions block declared empty: the bytes after
it are still parsed as extensions and the name is returned. -/
theorem extract_ignores_declared_lengths :
    extractSni ([0x16, 3, 1, 0, 0] ++ [1, 0, 0, 0] ++ List.replicate 34 0 ++
      [0] ++ [0, 0] ++ [0] ++ [0, 0] ++ [0, 0, 0, 6, 0, 4, 0, 0, 1, 97]) = some [97] := by
  decide

end DstackFormal.Gateway.Sni
