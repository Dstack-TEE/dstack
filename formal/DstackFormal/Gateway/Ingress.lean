-- SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
--
-- SPDX-License-Identifier: Apache-2.0

/-!
# Ingress subdomain parsing (`dstack/gateway/src/proxy.rs`)

Models `parse_canonical_port` and `parse_dst_info`, which turn the first SNI label
`<app_id>[-[<port>][s|g]]` into a destination. Strings are `List Char`.

Proven:
* `port_canonical_unique`: an accepted port string is exactly the canonical decimal spelling of
  its value, and the value is in `1..=65535` (no port 0, no leading zero, no sign).
* `port_roundtrip`: every port in `1..=65535` is accepted in its canonical spelling.
* `parse_print`: printing a well-formed destination with an explicit port and parsing it back is
  the identity.
* `parse_ok_wf`: every accepted destination is well formed: non-empty app id without `-`,
  port in `1..=65535`, never both TLS passthrough (`s`) and HTTP/2 (`g`).
* `default_port_spellings`: the port spelling is canonical but the destination spelling is not:
  `myapp`, `myapp-` and `myapp-80` all name the same destination (likewise `myapp-s` and
  `myapp-443s`). The comment "one decimal spelling for each destination port" holds for the
  port field only.
* `sg_rejected`, `gs_rejected`: both suffix orders are refused, but by different checks:
  `…sg` by the explicit `gs` check (whose message names the other order), `…gs` because
  `g` is left in the port string.

Modeling gap: `Result` errors carry no message; Rust's `split('-')` and `strip_suffix` are
reimplemented on `List Char`; `str::parse::<u16>` is modeled on all-digit inputs only, which is
all `parse_canonical_port` passes it.
-/

namespace DstackFormal.Gateway.Ingress

deriving instance DecidableEq for Except

abbrev Str := List Char

def digitChar (d : Nat) : Char := Char.ofNat (48 + d)

def digitVal (c : Char) : Nat := c.toNat - 48

/-- `u16::from_str` on an all-digit string, before the range check. -/
def value (s : Str) : Nat := s.foldl (fun n c => n * 10 + digitVal c) 0

/-- Canonical decimal spelling (`u16::to_string`). -/
def digits (n : Nat) : Str :=
  if n < 10 then [digitChar n] else digits (n / 10) ++ [digitChar (n % 10)]
termination_by n
decreasing_by omega

/-- `parse_canonical_port`. -/
def parseCanonicalPort (s : Str) : Except Unit Nat :=
  if s.head? = some '0' || !s.all Char.isDigit then .error ()
  else if s = [] then .error ()
  else if 65535 < value s then .error ()
  else .ok (value s)

/-- `str::split('-')`. -/
def splitDash : Str → List Str
  | [] => [[]]
  | c :: cs =>
    if c = '-' then [] :: splitDash cs
    else match splitDash cs with
      | [] => [[c]]
      | p :: ps => (c :: p) :: ps

/-- `str::strip_suffix(c)`. -/
def stripSuffix (c : Char) (s : Str) : Option Str :=
  if s.getLast? = some c then some s.dropLast else none

/-- `DstInfo`. -/
structure DstInfo where
  appId : Str
  port : Nat
  isTls : Bool
  isH2 : Bool
deriving DecidableEq, Repr

/-- `match last_part.strip_suffix(c) { Some(w) => (w, true), None => (last_part, false) }`. -/
def stripFlag (c : Char) (s : Str) : Str × Bool :=
  match stripSuffix c s with
  | some w => (w, true)
  | none => (s, false)

/-- The `Some(last_part)` arm: `(is_tls, is_h2, port)`. -/
def parseLast (last : Str) : Except Unit (Bool × Bool × Option Nat) :=
  let (p₁, hasG) := stripFlag 'g' last
  let (p₂, hasS) := stripFlag 's' p₁
  if hasG && hasS then .error ()
  else if p₂.isEmpty then .ok (hasS, hasG, none)
  else match parseCanonicalPort p₂ with
    | .ok n => .ok (hasS, hasG, some n)
    | .error e => .error e

/-- `parse_dst_info`. -/
def parseDstInfo (sub : Str) : Except Unit DstInfo :=
  match splitDash sub with
  | [] => .error ()
  | appId :: rest =>
    if appId.isEmpty then .error ()
    else
      let r : Except Unit (Bool × Bool × Option Nat) := match rest.head? with
        | none => .ok (false, false, none)
        | some last => parseLast last
      match r with
      | .error e => .error e
      | .ok (tls, h2, port) =>
        let port := port.getD (if tls then 443 else 80)
        if 2 ≤ rest.length then .error () else .ok ⟨appId, port, tls, h2⟩

/-- The suffix a destination is printed with. -/
def modeSuffix (tls h2 : Bool) : Str := if tls then ['s'] else if h2 then ['g'] else []

/-- Printer with an explicit port. -/
def print (d : DstInfo) : Str := d.appId ++ '-' :: (digits d.port ++ modeSuffix d.isTls d.isH2)

def DstInfo.WF (d : DstInfo) : Prop :=
  d.appId ≠ [] ∧ '-' ∉ d.appId ∧ 1 ≤ d.port ∧ d.port ≤ 65535 ∧ ¬ (d.isTls = true ∧ d.isH2 = true)

/-! ## Decimal digits -/

theorem digitChar_toNat : ∀ d, d < 10 → (digitChar d).toNat = 48 + d := by decide

theorem digitChar_isDigit (d : Nat) (h : d < 10) : (digitChar d).isDigit = true := by
  have := digitChar_toNat d h
  have h0 : '0'.toNat = 48 := rfl
  have h9 : '9'.toNat = 57 := rfl
  exact Char.isDigit_iff_toNat.mpr (by omega)

theorem digitChar_digitVal {c : Char} (h : c.isDigit = true) : digitChar (digitVal c) = c := by
  have hb := Char.isDigit_iff_toNat.mp h
  have h0 : '0'.toNat = 48 := rfl
  have h9 : '9'.toNat = 57 := rfl
  apply Char.toNat_inj.mp
  rw [digitChar_toNat _ (by unfold digitVal; omega)]
  unfold digitVal; omega

theorem digitVal_digitChar (d : Nat) (h : d < 10) : digitVal (digitChar d) = d := by
  unfold digitVal; rw [digitChar_toNat d h]; omega

theorem digitVal_lt {c : Char} (h : c.isDigit = true) : digitVal c < 10 := by
  have hb := Char.isDigit_iff_toNat.mp h
  have h0 : '0'.toNat = 48 := rfl
  have h9 : '9'.toNat = 57 := rfl
  unfold digitVal; omega

theorem digitChar_ne (d : Nat) (h : d < 10) (c : Char) (hc : c.isDigit = false) :
    digitChar d ≠ c := by
  intro he; rw [← he, digitChar_isDigit d h] at hc; exact absurd hc (by decide)

theorem value_append (s : Str) (c : Char) : value (s ++ [c]) = value s * 10 + digitVal c := by
  simp [value, List.foldl_append]

theorem digits_value : ∀ n, value (digits n) = n := by
  intro n
  induction n using Nat.strongRecOn with
  | ind n ih =>
    rw [digits]
    by_cases h : n < 10
    · simp [h, value, digitVal_digitChar n h]
    · simp only [h, ↓reduceIte, value_append, ih (n / 10) (by omega),
        digitVal_digitChar _ (Nat.mod_lt _ (by omega))]
      omega

theorem digits_isDigit : ∀ n, ∀ c ∈ digits n, c.isDigit = true := by
  intro n
  induction n using Nat.strongRecOn with
  | ind n ih =>
    rw [digits]
    by_cases h : n < 10
    · simp only [h, ↓reduceIte, List.mem_singleton]
      rintro c rfl; exact digitChar_isDigit n h
    · simp only [h, ↓reduceIte, List.mem_append, List.mem_singleton]
      rintro c (hc | rfl)
      · exact ih (n / 10) (by omega) c hc
      · exact digitChar_isDigit _ (Nat.mod_lt _ (by omega))

theorem digits_head : ∀ n, 0 < n → ∃ d, 0 < d ∧ d < 10 ∧ (digits n).head? = some (digitChar d) := by
  intro n
  induction n using Nat.strongRecOn with
  | ind n ih =>
    intro hn
    rw [digits]
    by_cases h : n < 10
    · exact ⟨n, hn, h, by simp [h]⟩
    · obtain ⟨d, h1, h2, h3⟩ := ih (n / 10) (by omega) (by omega)
      refine ⟨d, h1, h2, ?_⟩
      simp only [h, ↓reduceIte]
      cases hd : digits (n / 10) with
      | nil => rw [hd] at h3; simp at h3
      | cons x xs => rw [hd] at h3; simpa using h3

theorem digits_ne_nil (n : Nat) : digits n ≠ [] := by
  rw [digits]; split <;> simp

theorem digits_not_zero_head {n : Nat} (hn : 0 < n) : (digits n).head? ≠ some '0' := by
  obtain ⟨d, h1, h2, h3⟩ := digits_head n hn
  rw [h3]
  intro he
  have := congrArg Char.toNat (Option.some.inj he)
  rw [digitChar_toNat d h2] at this
  have h0 : '0'.toNat = 48 := rfl
  omega

theorem le_foldl (l : Str) : ∀ a, a ≤ l.foldl (fun n c => n * 10 + digitVal c) a := by
  induction l with
  | nil => intro a; simp
  | cons c l ih => intro a; simp only [List.foldl_cons]; exact Nat.le_trans (by omega) (ih _)

theorem value_pos {c : Char} {rest : Str} (hc : c.isDigit = true) (h0 : c ≠ '0') :
    0 < value (c :: rest) := by
  have hb := Char.isDigit_iff_toNat.mp hc
  have h48 : '0'.toNat = 48 := rfl
  have h57 : '9'.toNat = 57 := rfl
  have hne : c.toNat ≠ 48 := fun he => h0 (Char.toNat_inj.mp (by rw [he]; rfl))
  have := le_foldl rest (0 * 10 + digitVal c)
  simp only [value, List.foldl_cons]
  unfold digitVal at this ⊢; omega

theorem value_digits : ∀ (k : Nat) (s : Str), s.length = k → s ≠ [] →
    (∀ c ∈ s, c.isDigit = true) → s.head? ≠ some '0' → digits (value s) = s := by
  intro k
  induction k using Nat.strongRecOn with
  | ind k ih =>
    intro s hk hne hd hz
    rcases List.eq_nil_or_concat s with rfl | ⟨t, c, rfl⟩
    · exact absurd rfl hne
    · simp only [List.concat_eq_append] at hk hne hd hz ⊢
      have hc : c.isDigit = true := hd c (by simp)
      have hcv := digitVal_lt hc
      cases t with
      | nil =>
        simp only [List.nil_append]
        rw [digits]
        simp [value, hcv, digitChar_digitVal hc]
      | cons x xs =>
        have hx : x.isDigit = true := hd x (by simp)
        have hx0 : x ≠ '0' := fun he => hz (by simp [he])
        have hpos := value_pos (rest := xs) hx hx0
        rw [value_append, digits]
        have hge : ¬ value (x :: xs) * 10 + digitVal c < 10 := by omega
        simp only [hge, ↓reduceIte]
        have e1 : (value (x :: xs) * 10 + digitVal c) / 10 = value (x :: xs) := by omega
        have e2 : (value (x :: xs) * 10 + digitVal c) % 10 = digitVal c := by omega
        rw [e1, e2, digitChar_digitVal hc]
        rw [ih (x :: xs).length (by simp at hk ⊢; omega) (x :: xs) rfl (by simp)
          (fun c' hc' => hd c' (List.mem_append_left _ hc')) (by simpa using hx0)]

/-! ## Ports -/

theorem port_canonical_unique {s : Str} {n : Nat} (h : parseCanonicalPort s = .ok n) :
    s = digits n ∧ 1 ≤ n ∧ n ≤ 65535 := by
  unfold parseCanonicalPort at h
  by_cases h1 : (s.head? = some '0' || !s.all Char.isDigit) = true
  · simp [h1] at h
  · simp only [h1, Bool.false_eq_true, ↓reduceIte] at h
    by_cases h2 : s = []
    · simp [h2] at h
    · simp only [h2, ↓reduceIte] at h
      by_cases h3 : 65535 < value s
      · simp [h3] at h
      · simp only [h3, ↓reduceIte, Except.ok.injEq] at h
        subst h
        simp only [Bool.or_eq_true, decide_eq_true_eq, Bool.not_eq_true', List.all_eq_false,
          not_or, not_exists, not_and] at h1
        have hd : ∀ c ∈ s, c.isDigit = true := fun c hc => by simpa using h1.2 c hc
        obtain ⟨x, xs, rfl⟩ := List.exists_cons_of_ne_nil h2
        have hx0 : x ≠ '0' := fun he => h1.1 (by simp [he])
        refine ⟨(value_digits _ _ rfl h2 hd h1.1).symm, value_pos (hd x (by simp)) hx0, by omega⟩

theorem port_roundtrip {n : Nat} (h1 : 1 ≤ n) (h2 : n ≤ 65535) :
    parseCanonicalPort (digits n) = .ok n := by
  unfold parseCanonicalPort
  have hz := digits_not_zero_head (n := n) (by omega)
  have hd : (digits n).all Char.isDigit = true := List.all_eq_true.mpr (digits_isDigit n)
  simp [hz, hd, digits_ne_nil, digits_value]; omega

/-! ## Destinations -/

theorem splitDash_of_no_dash : ∀ {s : Str}, '-' ∉ s → splitDash s = [s]
  | [], _ => rfl
  | c :: cs, h => by
    simp only [List.mem_cons, not_or] at h
    have hc : c ≠ '-' := fun he => h.1 he.symm
    simp [splitDash, hc, splitDash_of_no_dash h.2]

theorem splitDash_dash : ∀ {a : Str} (b : Str), '-' ∉ a →
    splitDash (a ++ '-' :: b) = a :: splitDash b
  | [], b, _ => by simp [splitDash]
  | c :: cs, b, h => by
    simp only [List.mem_cons, not_or] at h
    have hc : c ≠ '-' := fun he => h.1 he.symm
    simp [splitDash, hc, splitDash_dash b h.2]

theorem getLast_digits (n : Nat) : ∃ d, d < 10 ∧ (digits n).getLast? = some (digitChar d) := by
  rw [digits]
  split
  · rename_i h; exact ⟨n, h, rfl⟩
  · exact ⟨n % 10, Nat.mod_lt _ (by omega), by simp⟩

theorem strip_digits (c : Char) (hc : c.isDigit = false) (n : Nat) :
    stripSuffix c (digits n) = none := by
  obtain ⟨d, hd, hl⟩ := getLast_digits n
  simp [stripSuffix, hl, digitChar_ne d hd c hc]

theorem flag_append_self (c : Char) (s : Str) : stripFlag c (s ++ [c]) = (s, true) := by
  simp [stripFlag, stripSuffix]

theorem flag_append_ne {c c' : Char} (h : c' ≠ c) (s : Str) :
    stripFlag c (s ++ [c']) = (s ++ [c'], false) := by
  simp [stripFlag, stripSuffix, h]

theorem flag_digits (c : Char) (hc : c.isDigit = false) (n : Nat) :
    stripFlag c (digits n) = (digits n, false) := by
  simp [stripFlag, strip_digits c hc n]

theorem parse_print {d : DstInfo} (h : d.WF) : parseDstInfo (print d) = .ok d := by
  obtain ⟨hne, hdash, hp1, hp2, hmode⟩ := h
  have hport := port_roundtrip hp1 hp2
  have hnd : '-' ∉ digits d.port ++ modeSuffix d.isTls d.isH2 := by
    intro hm
    rcases List.mem_append.mp hm with hm | hm
    · have := digits_isDigit d.port _ hm; exact absurd this (by decide)
    · unfold modeSuffix at hm; split at hm <;> (try split at hm) <;> simp at hm
  have hsplit : splitDash (print d) = [d.appId, digits d.port ++ modeSuffix d.isTls d.isH2] := by
    unfold print; rw [splitDash_dash _ hdash, splitDash_of_no_dash hnd]
  have hsg : 's'.isDigit = false := by decide
  have hgg : 'g'.isDigit = false := by decide
  have hlast : parseLast (digits d.port ++ modeSuffix d.isTls d.isH2) =
      .ok (d.isTls, d.isH2, some d.port) := by
    unfold parseLast
    cases ht : d.isTls <;> cases hh : d.isH2
    · simp [modeSuffix, flag_digits 'g' hgg, flag_digits 's' hsg, digits_ne_nil, hport]
    · simp [modeSuffix, flag_append_self, flag_digits 's' hsg, digits_ne_nil, hport]
    · simp [modeSuffix, flag_append_ne (show 's' ≠ 'g' by decide), flag_append_self,
        digits_ne_nil, hport]
    · simp [ht, hh] at hmode
  unfold parseDstInfo
  rw [hsplit]
  have : d.appId.isEmpty = false := by simpa using hne
  simp [this, hlast]

theorem parseLast_spec {last : Str} {tls h2 : Bool} {port : Option Nat}
    (h : parseLast last = .ok (tls, h2, port)) :
    ¬ (tls = true ∧ h2 = true) ∧ ∀ n, port = some n → 1 ≤ n ∧ n ≤ 65535 := by
  rcases hA : stripFlag 'g' last with ⟨p₁, hasG⟩
  rcases hB : stripFlag 's' p₁ with ⟨p₂, hasS⟩
  simp only [parseLast, hA, hB] at h
  by_cases hgs : (hasG && hasS) = true
  · simp [hgs] at h
  · simp only [hgs, Bool.false_eq_true, ↓reduceIte] at h
    have hns : ¬ (hasS = true ∧ hasG = true) := fun ⟨a, b⟩ => hgs (by simp [a, b])
    by_cases he : p₂.isEmpty = true
    · simp only [he, ↓reduceIte, Except.ok.injEq, Prod.mk.injEq] at h
      obtain ⟨rfl, rfl, rfl⟩ := h
      exact ⟨hns, by simp⟩
    · simp only [he, Bool.false_eq_true, ↓reduceIte] at h
      cases hp : parseCanonicalPort p₂ with
      | error e => simp [hp] at h
      | ok n =>
        simp only [hp, Except.ok.injEq, Prod.mk.injEq] at h
        obtain ⟨rfl, rfl, rfl⟩ := h
        have := port_canonical_unique hp
        exact ⟨hns, fun m hm => by simp at hm; subst hm; exact this.2⟩

theorem splitDash_head_no_dash : ∀ (s : Str), ∃ a rest, splitDash s = a :: rest ∧ '-' ∉ a
  | [] => ⟨[], [], rfl, by simp⟩
  | c :: cs => by
    obtain ⟨a, rest, he, ha⟩ := splitDash_head_no_dash cs
    by_cases hc : c = '-'
    · exact ⟨[], splitDash cs, by simp [splitDash, hc], by simp⟩
    · refine ⟨c :: a, rest, by simp [splitDash, hc, he], ?_⟩
      simp only [List.mem_cons, not_or]
      exact ⟨fun h => hc h.symm, ha⟩

theorem parse_ok_wf {s : Str} {d : DstInfo} (h : parseDstInfo s = .ok d) : d.WF := by
  obtain ⟨a, rest, hs, ha⟩ := splitDash_head_no_dash s
  unfold parseDstInfo at h
  rw [hs] at h
  simp only at h
  by_cases he : a.isEmpty = true
  · simp [he] at h
  · simp only [he, Bool.false_eq_true, ↓reduceIte] at h
    have hne : a ≠ [] := by simpa using he
    cases hr : rest.head? with
    | none =>
      simp only [hr] at h
      split at h
      · simp at h
      · simp only [Except.ok.injEq] at h
        subst h
        exact ⟨hne, ha, by simp, by simp, by simp⟩
    | some last =>
      simp only [hr] at h
      cases hl : parseLast last with
      | error e => simp [hl] at h
      | ok v =>
        obtain ⟨tls, h2, port⟩ := v
        have hspec := parseLast_spec hl
        simp only [hl] at h
        split at h
        · simp at h
        · simp only [Except.ok.injEq] at h
          subst h
          refine ⟨hne, ha, ?_, ?_, hspec.1⟩ <;>
          · cases port with
            | none => cases tls <;> simp
            | some n => have := hspec.2 n rfl; simp; omega

/-! ## Spellings -/

theorem default_port_spellings :
    parseDstInfo "myapp".toList = parseDstInfo "myapp-".toList ∧
    parseDstInfo "myapp-".toList = parseDstInfo "myapp-80".toList ∧
    parseDstInfo "myapp-s".toList = parseDstInfo "myapp-443s".toList ∧
    parseDstInfo "myapp-80".toList = .ok ⟨"myapp".toList, 80, false, false⟩ := by
  decide

theorem sg_rejected : parseLast "443sg".toList = .error () := by decide
theorem gs_rejected : parseLast "443gs".toList = .error () := by decide
theorem bare_sg_rejected : parseLast "sg".toList = .error () := by decide

-- test_parse_canonical_port
example : parseCanonicalPort "1".toList = .ok 1 := by decide
example : parseCanonicalPort "80".toList = .ok 80 := by decide
example : parseCanonicalPort "65535".toList = .ok 65535 := by decide
example : ∀ p ∈ ["", "0", "08090", "+8090", "65536", "８０", "80s"],
    parseCanonicalPort p.toList = .error () := by decide
-- test_parse_destination
example : parseDstInfo "myapp".toList = .ok ⟨"myapp".toList, 80, false, false⟩ := by decide
example : parseDstInfo "myapp-8080".toList = .ok ⟨"myapp".toList, 8080, false, false⟩ := by decide
example : parseDstInfo "myapp-443s".toList = .ok ⟨"myapp".toList, 443, true, false⟩ := by decide
example : parseDstInfo "myapp-8443s".toList = .ok ⟨"myapp".toList, 8443, true, false⟩ := by decide
example : parseDstInfo "myapps".toList = .ok ⟨"myapps".toList, 80, false, false⟩ := by decide
example : parseDstInfo "myapp-s".toList = .ok ⟨"myapp".toList, 443, true, false⟩ := by decide
example : parseDstInfo "myapp-8090g".toList = .ok ⟨"myapp".toList, 8090, false, true⟩ := by decide
example : parseDstInfo "myapp-08090s".toList = .error () := by decide

end DstackFormal.Gateway.Ingress
