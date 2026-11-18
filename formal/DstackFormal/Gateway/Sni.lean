-- SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
--
-- SPDX-License-Identifier: Apache-2.0

/-!
# ClientHello SNI sniffing (`dstack/gateway/src/proxy/sni.rs`)

Models `extract_sni` / `extract_sni_inner` and `take_record_u8_len`, with the `parcelona`
primitives it uses (`take_len_be_u8`, `take_len_be_u16`, `take_len_be_u24`, `take_record`,
`take_record_be_u16`) as bounds-checked operations on a byte list, plus the `take_declared` and
`room` helpers.

Tracks commit 50f0d34df4 (PR #1602, "honour declared lengths when sniffing sni"): the record,
the handshake message, the extensions block and each extension are cut to their declared length
(or to what has arrived); the extensions length must equal the room left in the handshake, each
extension must fit the room left in the block, and the `ServerNameList` length must equal the
room left in the extension.

Proven:
* `extract_within`: a returned name lies inside the extension declared by the length field
  preceding it, which lies inside the declared extensions block, which lies inside the declared
  handshake message, which lies inside the declared record (`DeclU16` / `DeclU24`: the block is
  what a length field in the enclosing block declares, cut to what has arrived).
* `extract_infix`: consequently, a returned name is a contiguous sub-slice of the input.
* `extract_client_hello`: on the ClientHello built by the Rust test helper `client_hello` (one
  `host_name` entry), the extractor returns exactly the name, for any name up to 65000 bytes.
* `extract_short_none`, `extract_not_handshake_none`: inputs under 10 bytes, or whose first byte
  is not `0x16`, yield nothing.
* Totality is by construction: every read is bounds checked and returns `none` past the end.
  `take_record_u8_len` is `take_len_be_u8` followed by `take_record`, so a length byte that
  covers itself cannot over-read (the bug its doc comment describes).
* The three Rust tests about names outside a declared block are mirrored as `#guard`s, and
  the input that the previous code accepted past an empty extensions block is now refused
  (`name_past_empty_extensions_refused`).

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

/-- `take_declared(b, len)`: `(rest, block)`, the block cut to what has arrived. -/
def takeDeclared (b : Bytes) (len : Nat) : Bytes × Bytes := (b.drop len, b.take len)

/-- `room(len, block, rest)`. -/
def room (len : Nat) (block rest : Bytes) : Nat := len - (block.length - rest.length)

/-- The extension loop over the declared extensions block `exts` of length `extsLen`. -/
def extLoop (extsLen : Nat) (exts : Bytes) : Nat → Bytes → Option Bytes
  | 0, _ => none
  | f + 1, b =>
    match u16 b with
    | none => none
    | some (b, ty) =>
      match u16 b with
      | none => none
      | some (b, len) =>
        if room extsLen exts b < len then none
        else
          let (b, ext) := takeDeclared b len
          if ty ≠ 0 then extLoop extsLen exts f b
          else
            match u16 ext with
            | none => none
            | some (eb, c) => if c ≠ room len ext eb then none else nameLoop (eb.length + 1) eb

/-- `extract_sni`. -/
def extractSni (b : Bytes) : Option Bytes :=
  if b.length < 10 then none
  else if b.head? ≠ some 0x16 then none
  else
    match u16 (b.drop 3) with
    | none => none
    | some (r, recLen) =>
      let (_, rec) := takeDeclared r recLen
      match u8 rec with
      | none => none
      | some (b, c) =>
        if c ≠ 1 then none
        else match u24 b with
          | none => none
          | some (b, helloLen) =>
            let (_, hello) := takeDeclared b helloLen
            match record hello 34 with
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
                    | some (b, extsLen) =>
                      if extsLen ≠ room helloLen hello b then none
                      else
                        let (_, exts) := takeDeclared b extsLen
                        extLoop extsLen exts (exts.length + 1) exts

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

theorem drop_suffix (b : Bytes) (n : Nat) : Suffix (b.drop n) b :=
  ⟨b.take n, (List.take_append_drop n b).symm⟩

/-- `blk` is the block declared by a 16-bit length field in `outer`, cut to what has arrived. -/
def DeclU16 (blk outer : Bytes) : Prop :=
  ∃ pre hi lo rest, outer = pre ++ hi :: lo :: rest ∧ blk = rest.take (hi * 256 + lo)

/-- The same for a 24-bit length field. -/
def DeclU24 (blk outer : Bytes) : Prop :=
  ∃ pre x y z rest, outer = pre ++ x :: y :: z :: rest ∧ blk = rest.take ((x * 256 + y) * 256 + z)

theorem take_infix (b : Bytes) (n : Nat) : Infix (b.take n) b :=
  ⟨[], b.drop n, by simp⟩

theorem DeclU16.infix {blk outer : Bytes} (h : DeclU16 blk outer) : Infix blk outer := by
  obtain ⟨pre, hi, lo, rest, rfl, rfl⟩ := h
  exact (take_infix rest _).of_suffix ⟨pre ++ [hi, lo], by simp⟩

theorem DeclU24.infix {blk outer : Bytes} (h : DeclU24 blk outer) : Infix blk outer := by
  obtain ⟨pre, x, y, z, rest, rfl, rfl⟩ := h
  exact (take_infix rest _).of_suffix ⟨pre ++ [x, y, z], by simp⟩

theorem Infix.trans {a b c : Bytes} (h₁ : Infix a b) (h₂ : Infix b c) : Infix a c := by
  obtain ⟨p, q, rfl⟩ := h₁; obtain ⟨p', q', rfl⟩ := h₂
  exact ⟨p' ++ p, q ++ q', by simp⟩

theorem decl_u16 {b outer r : Bytes} {n : Nat} (hs : Suffix b outer) (h : u16 b = some (r, n)) :
    DeclU16 (r.take n) outer := by
  obtain ⟨pre, rfl⟩ := hs
  match b, h with
  | hi :: lo :: r', h =>
    simp only [u16, Option.some.injEq, Prod.mk.injEq] at h
    refine ⟨pre, hi, lo, r', rfl, ?_⟩
    rw [← h.1, ← h.2]

theorem decl_u24 {b outer r : Bytes} {n : Nat} (hs : Suffix b outer) (h : u24 b = some (r, n)) :
    DeclU24 (r.take n) outer := by
  obtain ⟨pre, rfl⟩ := hs
  match b, h with
  | x :: y :: z :: r', h =>
    simp only [u24, Option.some.injEq, Prod.mk.injEq] at h
    refine ⟨pre, x, y, z, r', rfl, ?_⟩
    rw [← h.1, ← h.2]

theorem extLoop_within {extsLen : Nat} {exts : Bytes} :
    ∀ (f : Nat) (b s : Bytes), Suffix b exts → extLoop extsLen exts f b = some s →
      ∃ ext, DeclU16 ext exts ∧ Infix s ext
  | 0, _, _, _, h => by simp [extLoop] at h
  | f + 1, b, s, hb, h => by
    unfold extLoop at h
    split at h
    · simp at h
    · rename_i b₁ ty h₁
      split at h
      · simp at h
      · rename_i b₂ len h₂
        have hs₁ : Suffix b₁ exts := (u16_suffix h₁).trans hb
        split at h
        · simp at h
        · simp only [takeDeclared] at h
          split at h
          · exact extLoop_within f _ s ((drop_suffix b₂ len).trans ((u16_suffix h₂).trans hs₁)) h
          · split at h
            · simp at h
            · rename_i eb c h₃
              by_cases hc : c ≠ room len (b₂.take len) eb
              · simp [hc] at h
              · simp only [hc, ↓reduceIte] at h
                exact ⟨b₂.take len, decl_u16 hs₁ h₂,
                  (nameLoop_infix _ eb s h).of_suffix (u16_suffix h₃)⟩

/-- The returned name lies within every declared enclosing block. -/
theorem extract_within {b s : Bytes} (h : extractSni b = some s) :
    ∃ rec hello exts ext, DeclU16 rec b ∧ DeclU24 hello rec ∧ DeclU16 exts hello ∧
      DeclU16 ext exts ∧ Infix s ext := by
  unfold extractSni at h
  split at h
  · simp at h
  split at h
  · simp at h
  split at h
  · simp at h
  rename_i r recLen h₀
  simp only [takeDeclared] at h
  have dRec := decl_u16 (drop_suffix b 3) h₀
  split at h
  · simp at h
  rename_i b₁ c h₁
  have s₁ := u8_suffix h₁
  split at h
  · simp at h
  split at h
  · simp at h
  rename_i b₂ helloLen h₂
  have dHello := decl_u24 s₁ h₂
  split at h
  · simp at h
  rename_i b₃ _ h₃
  have s₃ := record_suffix h₃
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
  rename_i b₇ extsLen h₇
  have dExts := decl_u16 s₆ h₇
  by_cases hc : extsLen ≠ room helloLen (b₂.take helloLen) b₇
  · simp [hc] at h
  simp only [hc, ↓reduceIte] at h
  obtain ⟨ext, dExt, hs⟩ := extLoop_within _ _ s ⟨[], rfl⟩ h
  exact ⟨_, _, _, ext, dRec, dHello, dExts, dExt, hs⟩

/-- A returned name is a contiguous sub-slice of the input. -/
theorem extract_infix {b s : Bytes} (h : extractSni b = some s) : Infix s b := by
  obtain ⟨rec, hello, exts, ext, d₁, d₂, d₃, d₄, hs⟩ := extract_within h
  exact hs.trans (d₄.infix.trans (d₃.infix.trans (d₂.infix.trans d₁.infix)))

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

theorem extLoop_fuel {extsLen : Nat} {exts : Bytes} :
    ∀ (f : Nat) (b : Bytes), b.length < f →
      extLoop extsLen exts f b = extLoop extsLen exts (f + 1) b
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
        simp only [takeDeclared]
        have := u16_length h₁; have := u16_length h₂
        split
        · rfl
        · split
          · rw [extLoop_fuel f (b₂.drop len) (by simp; omega)]
          · rfl

/-! ## Round trip on the test helper's ClientHello -/

def be16 (n : Nat) : Bytes := [n / 256 % 256, n % 256]
def be24 (n : Nat) : Bytes := [n / 65536 % 256, n / 256 % 256, n % 256]

/-- The pieces of the Rust test helper `client_hello(server_name)`, innermost first. -/
def chSniExt (name : Bytes) : Bytes := 0 :: (be16 name.length ++ name)
def chList (name : Bytes) : Bytes := be16 (chSniExt name).length ++ chSniExt name
def chExts (name : Bytes) : Bytes := [0, 0] ++ be16 (chList name).length ++ chList name
def chBody (name : Bytes) : Bytes :=
  [3, 3] ++ List.replicate 32 0x41 ++ [0] ++ [0, 2, 0x13, 1] ++ [1, 0] ++
    be16 (chExts name).length ++ chExts name
def chHs (name : Bytes) : Bytes := [1] ++ be24 (chBody name).length ++ chBody name

/-- The Rust test helper `client_hello(server_name)`. -/
def clientHello (name : Bytes) : Bytes := [0x16, 3, 1] ++ be16 (chHs name).length ++ chHs name

theorem u16_be16 {n : Nat} (h : n < 65536) (t : Bytes) : u16 (be16 n ++ t) = some (t, n) := by
  simp only [be16, List.cons_append, List.nil_append, u16, Option.some.injEq, Prod.mk.injEq,
    true_and]
  omega

theorem u24_be24 {n : Nat} (h : n < 16777216) (t : Bytes) : u24 (be24 n ++ t) = some (t, n) := by
  simp only [be24, List.cons_append, List.nil_append, u24, Option.some.injEq, Prod.mk.injEq,
    true_and]
  omega

theorem extract_client_hello (name : Bytes) (h : name.length ≤ 65000) :
    extractSni (clientHello name) = some name := by
  have lS : (chSniExt name).length = name.length + 3 := by simp [chSniExt, be16]; try omega
  have lL : (chList name).length = name.length + 5 := by simp [chList, be16, lS]
  have lE : (chExts name).length = name.length + 9 := by simp [chExts, be16, lL]; try omega
  have lB : (chBody name).length = name.length + 52 := by simp [chBody, be16, lE]; try omega
  have lH : (chHs name).length = name.length + 56 := by simp [chHs, be24, lB]; try omega
  unfold extractSni
  have hlen : ¬ (clientHello name).length < 10 := by simp [clientHello, be16, lH]
  have hhead : (clientHello name).head? = some 0x16 := by simp [clientHello]
  have hdrop : (clientHello name).drop 3 = be16 (chHs name).length ++ chHs name := by
    simp [clientHello]
  simp only [hlen, hhead, ↓reduceIte, ne_eq, not_true_eq_false, hdrop,
    u16_be16 (show (chHs name).length < 65536 by omega), takeDeclared, List.take_length]
  have hhs : chHs name = 1 :: (be24 (chBody name).length ++ chBody name) := rfl
  rw [hhs]
  simp only [u8, not_true_eq_false, ↓reduceIte,
    u24_be24 (show (chBody name).length < 16777216 by omega), List.take_length]
  have hbody : chBody name = [3, 3] ++ List.replicate 32 0x41 ++ [0] ++ [0, 2, 0x13, 1] ++
      [1, 0] ++ be16 (chExts name).length ++ chExts name := rfl
  have hrec : record (chBody name) 34 =
      some ([0] ++ [0, 2, 0x13, 1] ++ [1, 0] ++ be16 (chExts name).length ++ chExts name,
        [3, 3] ++ List.replicate 32 0x41) := by
    rw [hbody]; unfold record
    simp [List.replicate_succ, be16]; try omega
  have r1 : ∀ T : Bytes, recordU8 ([0] ++ T) = some (T, []) := by
    intro T; simp [recordU8, u8, record]
  have r2 : ∀ T : Bytes, recordU16 ([0, 2, 0x13, 1] ++ T) = some (T, [0x13, 1]) := by
    intro T; simp [recordU16, u16, record]
  have r3 : ∀ T : Bytes, recordU8 ([1, 0] ++ T) = some (T, [0]) := by
    intro T; simp [recordU8, u8, record]
  rw [hrec]
  simp only [List.append_assoc]
  rw [r1]; simp only
  rw [r2]; simp only
  rw [r3]; simp only
  rw [u16_be16 (show (chExts name).length < 65536 by omega)]; simp only
  have hroom : room (chBody name).length (chBody name) (chExts name) = (chExts name).length := by
    unfold room; try omega
  simp only [hroom, not_true_eq_false, ↓reduceIte, List.take_length]
  have uE : u16 (chExts name) = some (be16 (chList name).length ++ chList name, 0) := rfl
  have uL : u16 (be16 (chList name).length ++ chList name) =
      some (chList name, (chList name).length) := u16_be16 (by omega) _
  have uS : u16 (chList name) = some (chSniExt name, (chSniExt name).length) :=
    u16_be16 (by omega) _
  have hroom2 : room (chExts name).length (chExts name) (chList name) = (chList name).length := by
    unfold room; omega
  have hroom3 : room (chList name).length (chList name) (chSniExt name) =
      (chSniExt name).length := by
    unfold room; omega
  unfold extLoop
  rw [uE]; simp only
  rw [uL]; simp only
  rw [hroom2]
  simp only [Nat.lt_irrefl, ↓reduceIte, takeDeclared, List.take_length, ne_eq,
    not_true_eq_false]
  rw [uS]; simp only
  rw [hroom3]
  simp only [not_true_eq_false, ↓reduceIte]
  have hs : chSniExt name = 0 :: (be16 name.length ++ name) := rfl
  rw [hs]
  unfold nameLoop
  simp only [u8]
  rw [u16_be16 (show name.length < 65536 by omega)]
  simp [record]

-- extracts_the_server_name_from_a_client_hello
#guard extractSni (clientHello ("app.example.com".toList.map Char.toNat)) ==
  some ("app.example.com".toList.map Char.toNat)
-- a_record_that_is_not_a_handshake_has_no_sni
#guard extractSni (0x17 :: (clientHello [97]).drop 1) == none
-- a_truncated_client_hello_yields_no_name_rather_than_a_wrong_one
#guard (List.range (clientHello [97, 98, 99]).length).all fun n =>
  extractSni ((clientHello [97, 98, 99]).take n) == none

-- The test helper's layout: the extensions length sits after 5 + 4 + 34 + 1 + 4 + 2 bytes.
def extsLenOffset : Nat := 50

def setAt (b : Bytes) (i v : Nat) : Bytes := b.set i v

def appHello : Bytes := clientHello ("app.example.com".toList.map Char.toNat)

-- a_name_outside_the_declared_extensions_block_is_not_returned
#guard extractSni (setAt (setAt appHello extsLenOffset 0) (extsLenOffset + 1) 0) == none
-- a_name_past_the_declared_record_is_not_returned
def recordEndsBeforeExtensions : Bytes :=
  let trailing := appHello.length - extsLenOffset - 2
  let recLen := appHello[3]! * 256 + appHello[4]! - trailing
  let b := setAt (setAt appHello 3 (recLen / 256)) 4 (recLen % 256)
  let hl := recLen - 4
  let b := setAt (setAt (setAt b 6 (hl / 65536 % 256)) 7 (hl / 256 % 256)) 8 (hl % 256)
  setAt (setAt b extsLenOffset 0) (extsLenOffset + 1) 0
#guard extractSni recordEndsBeforeExtensions == none
-- a_name_outside_the_declared_server_name_list_is_not_returned
#guard extractSni (setAt (setAt appHello (extsLenOffset + 6) 0) (extsLenOffset + 7) 0) == none

/-- The input the previous code accepted (record, handshake and extensions declared empty, a
name after them) is refused. -/
theorem name_past_empty_extensions_refused :
    extractSni ([0x16, 3, 1, 0, 0] ++ [1, 0, 0, 0] ++ List.replicate 34 0 ++
      [0] ++ [0, 0] ++ [0] ++ [0, 0] ++ [0, 0, 0, 6, 0, 4, 0, 0, 1, 97]) = none := by
  decide

end DstackFormal.Gateway.Sni
