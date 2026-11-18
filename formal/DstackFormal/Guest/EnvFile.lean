-- SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
--
-- SPDX-License-Identifier: Apache-2.0

/-!
# Decrypted env file: key filter and systemd escaping

Models `dstack/dstack-util/src/parse_env_file.rs`: `parse_env` (after JSON
decoding), the `KEY_REGEX` check, `escape_value` and the line format of
`convert_env_to_str`. The reader is systemd's `EnvironmentFile=` parser; its
value states (`PRE_VALUE`, `VALUE`, `VALUE_ESCAPE`, `SINGLE_QUOTE_VALUE`,
`DOUBLE_QUOTE_VALUE`, `DOUBLE_QUOTE_VALUE_ESCAPE` of
`parse_env_file_internal` in systemd's `src/basic/env-file.c`) are modeled as
`parseValue`.

Proven:
* `envFile_roundtrip`: systemd reads back `escape_value(v)` as `v` with each
  newline replaced by the two characters `\n`; hence values without a newline
  round-trip exactly (`envFile_roundtrip_of_no_newline`), and the newline
  encoding is lossy (`newline_collision`), as the Rust doc comment states.
* `validKey_safe`: keys passing `KEY_REGEX` are nonempty and contain no `=`,
  whitespace, `#` or quote, so `KEY=value` lines split at the first `=`.
* `parseEnv_spec`: every accepted entry is allowed, has a valid key and
  respects the length limits; unauthorized keys are dropped, not rejected.

Assumptions: Rust's `char::is_whitespace` is a parameter `rustWs` required to
hold for systemd's `WHITESPACE` (` `, `\t`, `\n`, `\r`).
Modeling gaps: the systemd parser model is limited to one value line, is
written from the upstream state machine rather than extracted from it, and
the Rust `systemd_round_trip` test is its only executable cross-check; JSON
decoding, `MAX_ITEMS`, and the `BTreeMap` (later duplicates override) are not
modeled; lengths are counted in chars, not UTF-8 bytes.
-/

namespace DstackFormal.Guest.EnvFile

/-! ## `escape_value` -/

/-- Characters that force quoting besides whitespace. -/
def quoteSpecials : List Char := "|&;<>()$`\\\"'".toList

def needsQuotes (rustWs : Char → Bool) (v : List Char) : Bool :=
  v.any fun c => rustWs c || quoteSpecials.contains c

/-- The per-character escape of `escape_value`. -/
def escChar (c : Char) : List Char :=
  if c = '\n' then ['\\', 'n']
  else if c = '\\' ∨ c = '"' ∨ c = '$' ∨ c = '`' then ['\\', c]
  else [c]

/-- `escape_value`. -/
def escapeValue (rustWs : Char → Bool) (v : List Char) : List Char :=
  let e := v.flatMap escChar
  if needsQuotes rustWs v then '"' :: e ++ ['"'] else e

/-! ## systemd's value parser -/

/-- systemd `WHITESPACE`. -/
def isWs (c : Char) : Bool := c = ' ' || c = '\t' || c = '\n' || c = '\r'

/-- systemd `NEWLINE`. -/
def isNl (c : Char) : Bool := c = '\n' || c = '\r'

/-- systemd `SHELL_NEED_ESCAPE`. -/
def needEsc (c : Char) : Bool := c = '"' || c = '\\' || c = '`' || c = '$'

inductive St where
  | pre
  | value
  | valueEsc
  | sq
  | dq
  | dqEsc

/-- Value states of `parse_env_file_internal`; `w` is `last_value_whitespace`.
Returns the value when a newline ends it. -/
def parseValue : St → List Char → Option Nat → List Char → Option (List Char)
  | _, _, _, [] => none
  | .pre, acc, w, c :: cs =>
    if isNl c then some acc
    else if c = '\'' then parseValue .sq acc w cs
    else if c = '"' then parseValue .dq acc w cs
    else if c = '\\' then parseValue .valueEsc acc w cs
    else if isWs c then parseValue .pre acc w cs
    else parseValue .value (acc ++ [c]) w cs
  | .value, acc, w, c :: cs =>
    if isNl c then some (match w with | some i => acc.take i | none => acc)
    else if c = '\\' then parseValue .valueEsc acc none cs
    else if !isWs c then parseValue .value (acc ++ [c]) none cs
    else parseValue .value (acc ++ [c]) (some (w.getD acc.length)) cs
  | .valueEsc, acc, w, c :: cs =>
    if isNl c then parseValue .value acc w cs else parseValue .value (acc ++ [c]) w cs
  | .sq, acc, w, c :: cs =>
    if c = '\'' then parseValue .value acc w cs else parseValue .sq (acc ++ [c]) w cs
  | .dq, acc, w, c :: cs =>
    if c = '"' then parseValue .value acc w cs
    else if c = '\\' then parseValue .dqEsc acc w cs
    else parseValue .dq (acc ++ [c]) w cs
  | .dqEsc, acc, w, c :: cs =>
    if needEsc c then parseValue .dq (acc ++ [c]) w cs
    else if c = '\n' then parseValue .dq acc w cs
    else parseValue .dq (acc ++ ['\\', c]) w cs

theorem isNl_false (c : Char) (h : isWs c = false) : isNl c = false := by
  simp only [isWs, isNl, Bool.or_eq_false_iff] at h ⊢
  exact ⟨h.1.2, h.2⟩

/-- What systemd delivers for a value line `escape_value(v) "\n"`. -/
def readBack (rustWs : Char → Bool) (v : List Char) : Option (List Char) :=
  parseValue .pre [] none (escapeValue rustWs v ++ ['\n'])

/-- A newline becomes the two characters `\n`. -/
def nlLiteral (c : Char) : List Char := if c = '\n' then ['\\', 'n'] else [c]

theorem dq_run (acc : List Char) (w : Option Nat) (v rest : List Char) :
    parseValue .dq acc w (v.flatMap escChar ++ '"' :: rest) =
      parseValue .value (acc ++ v.flatMap nlLiteral) w rest := by
  induction v generalizing acc with
  | nil => simp [parseValue]
  | cons c cs ih =>
    simp only [List.flatMap_cons, List.append_assoc]
    by_cases h1 : c = '\n'
    · subst h1; simp [escChar, nlLiteral, parseValue, needEsc, ih]
    by_cases h2 : c = '\\' ∨ c = '"' ∨ c = '$' ∨ c = '`'
    · have hn : needEsc c = true := by
        rcases h2 with rfl | rfl | rfl | rfl <;> rfl
      simp only [escChar, h1, h2, ite_false, ite_true, nlLiteral]
      simp [parseValue, hn, ih]
    · simp only [not_or] at h2
      simp [escChar, nlLiteral, h1, h2, parseValue, ih]

theorem value_run (rustWs : Char → Bool) (hws : ∀ c, isWs c = true → rustWs c = true)
    (acc v : List Char) (hv : needsQuotes rustWs v = false) :
    parseValue .value acc none (v ++ ['\n']) = some (acc ++ v) := by
  induction v generalizing acc with
  | nil => simp [parseValue, isNl]
  | cons c cs ih =>
    simp only [needsQuotes, List.any_cons, Bool.or_eq_false_iff] at hv
    have hw : isWs c = false := by
      cases h : isWs c
      · rfl
      · exact absurd (hws c h) (by simp [hv.1.1])
    have hn : isNl c = false := isNl_false c hw
    have hb : c ≠ '\\' := by rintro rfl; simp [quoteSpecials] at hv
    have := ih (acc ++ [c]) hv.2
    simp [parseValue, hn, hb, hw, this]

theorem escChar_plain (rustWs : Char → Bool) (hws : ∀ c, isWs c = true → rustWs c = true)
    (v : List Char) (hv : needsQuotes rustWs v = false) : v.flatMap escChar = v ∧ v.flatMap nlLiteral = v := by
  induction v with
  | nil => simp
  | cons c cs ih =>
    simp only [needsQuotes, List.any_cons, Bool.or_eq_false_iff] at hv
    have h1 : c ≠ '\n' := by rintro rfl; simp [hws '\n' rfl] at hv
    have h2 : ¬ (c = '\\' ∨ c = '"' ∨ c = '$' ∨ c = '`') := by
      rintro (rfl | rfl | rfl | rfl) <;> simp [quoteSpecials] at hv
    have := ih hv.2
    simp [escChar, nlLiteral, h1, h2, this]

/-- systemd reads back `escape_value(v)` as `v` with newlines written as `\n`. -/
theorem envFile_roundtrip (rustWs : Char → Bool) (hws : ∀ c, isWs c = true → rustWs c = true)
    (v : List Char) : readBack rustWs v = some (v.flatMap nlLiteral) := by
  unfold readBack escapeValue
  cases hq : needsQuotes rustWs v
  · simp only [Bool.false_eq_true, ite_false]
    obtain ⟨he, hn⟩ := escChar_plain rustWs hws v hq
    rw [he, hn]
    cases v with
    | nil => simp [parseValue, isNl]
    | cons c cs =>
      simp only [needsQuotes, List.any_cons, Bool.or_eq_false_iff] at hq
      have hw : isWs c = false := by
        cases h : isWs c
        · rfl
        · exact absurd (hws c h) (by simp [hq.1.1])
      have hn' : isNl c = false := isNl_false c hw
      have h1 : c ≠ '\'' := by rintro rfl; simp [quoteSpecials] at hq
      have h2 : c ≠ '"' := by rintro rfl; simp [quoteSpecials] at hq
      have h3 : c ≠ '\\' := by rintro rfl; simp [quoteSpecials] at hq
      have := value_run rustWs hws [c] cs hq.2
      simp [parseValue, hn', h1, h2, h3, hw, this]
  · simp only [ite_true, List.cons_append, List.append_assoc]
    simp only [parseValue, isNl, Bool.or_eq_true, decide_eq_true_eq]
    simp only [show ¬('"' = '\n' ∨ '"' = '\r') by decide, show ('"' : Char) ≠ '\'' by decide, ite_false,
      ite_true]
    rw [dq_run]
    simp [parseValue, isNl]

theorem envFile_roundtrip_of_no_newline (rustWs : Char → Bool)
    (hws : ∀ c, isWs c = true → rustWs c = true) (v : List Char) (hv : '\n' ∉ v) :
    readBack rustWs v = some v := by
  rw [envFile_roundtrip rustWs hws]
  congr 1
  induction v with
  | nil => rfl
  | cons c cs ih =>
    simp only [List.mem_cons, not_or] at hv
    simp [nlLiteral, Ne.symm hv.1, ih hv.2]

/-- A newline and the two characters `\n` are delivered identically. -/
theorem newline_collision (rustWs : Char → Bool) (hws : ∀ c, isWs c = true → rustWs c = true) :
    readBack rustWs ['a', '\n'] = readBack rustWs ['a', '\\', 'n'] := by
  rw [envFile_roundtrip rustWs hws, envFile_roundtrip rustWs hws]
  decide

/-- Mirrors `test_escape_value` (with ASCII whitespace for `char::is_whitespace`). -/
def ws (c : Char) : Bool := c.isWhitespace

#guard escapeValue ws "simple".toList = "simple".toList
#guard escapeValue ws "hello world".toList = "\"hello world\"".toList
#guard escapeValue ws "say \"hello\"".toList = "\"say \\\"hello\\\"\"".toList
#guard escapeValue ws "line1\nline2".toList = "\"line1\\nline2\"".toList
#guard escapeValue ws "price=$100".toList = "\"price=\\$100\"".toList
#guard escapeValue ws "command=`date`".toList = "\"command=\\`date\\`\"".toList
#guard escapeValue ws "trail\\".toList = "\"trail\\\\\"".toList
#guard escapeValue ws "cr\r".toList = "\"cr\r\"".toList
#guard readBack ws "a\\$b".toList = some "a\\$b".toList
#guard readBack ws "it's".toList = some "it's".toList

/-! ## Keys and `parse_env` -/

def isKeyHead (c : Char) : Bool := c.isAlpha || c = '_'
def isKeyTail (c : Char) : Bool := c.isAlphanum || c = '_'

/-- `KEY_REGEX = ^[a-zA-Z_][a-zA-Z0-9_]*$`. -/
def validKey : List Char → Bool
  | [] => false
  | c :: cs => isKeyHead c && cs.all isKeyTail

theorem isKeyTail_safe (c : Char) (h : isKeyTail c = true) :
    c ≠ '=' ∧ isWs c = false ∧ c ≠ '#' ∧ c ≠ '"' ∧ c ≠ '\'' := by
  have : c.isAlphanum = true ∨ c = '_' := by simpa [isKeyTail] using h
  rcases this with h | rfl
  · refine ⟨?_, ?_, ?_, ?_, ?_⟩ <;> first
      | (rintro rfl; revert h; decide)
      | (cases hw : isWs c
         · rfl
         · simp only [isWs, Bool.or_eq_true, decide_eq_true_eq] at hw
           rcases hw with ((rfl | rfl) | rfl) | rfl <;> revert h <;> decide)
  · decide

/-- Valid keys are nonempty and free of `=`, whitespace, `#` and quotes. -/
theorem validKey_safe (k : List Char) (h : validKey k = true) :
    k ≠ [] ∧ ∀ c ∈ k, c ≠ '=' ∧ isWs c = false ∧ c ≠ '#' ∧ c ≠ '"' ∧ c ≠ '\'' := by
  cases k with
  | nil => simp [validKey] at h
  | cons c cs =>
    simp only [validKey, Bool.and_eq_true, List.all_eq_true] at h
    refine ⟨List.cons_ne_nil _ _, fun x hx => ?_⟩
    rcases List.mem_cons.mp hx with rfl | hx
    · apply isKeyTail_safe
      simp only [isKeyHead, Bool.or_eq_true] at h
      simp only [isKeyTail, Char.isAlphanum, Bool.or_eq_true]
      rcases h.1 with h' | h'
      · exact Or.inl (Or.inl h')
      · exact Or.inr h'
    · exact isKeyTail_safe x (h.2 x hx)

#guard validKey "DSTACK_ENV_CASE_0".toList
#guard !validKey "1A".toList
#guard !validKey "A-B".toList
#guard !validKey []

/-- The loop of `parse_env` over decoded pairs; `none` is an error. -/
def parseEnvGo (allowed : List Char → Bool) :
    Nat → List (List Char × List Char) → Option (List (List Char × List Char))
  | _, [] => some []
  | total, (k, v) :: rest =>
    if !allowed k then parseEnvGo allowed total rest
    else if k.length > 255 then none
    else if v.length > 128 * 1024 then none
    else if !validKey k then none
    else if total + k.length + v.length > 1024 * 1024 then none
    else ((k, v) :: ·) <$> parseEnvGo allowed (total + k.length + v.length) rest

def parseEnv (allowed : List Char → Bool) (pairs : List (List Char × List Char)) :
    Option (List (List Char × List Char)) := parseEnvGo allowed 0 pairs

theorem parseEnvGo_spec (allowed : List Char → Bool) :
    ∀ (total : Nat) (pairs out : List (List Char × List Char)), parseEnvGo allowed total pairs = some out →
      out.Sublist pairs ∧ ∀ kv ∈ out, allowed kv.1 = true ∧ validKey kv.1 = true ∧
        kv.1.length ≤ 255 ∧ kv.2.length ≤ 128 * 1024
  | _, [], out, h => by simp [parseEnvGo] at h; subst h; simp
  | total, (k, v) :: rest, out, h => by
    unfold parseEnvGo at h
    by_cases ha : allowed k = true
    · simp only [ha, Bool.not_true, Bool.false_eq_true, ite_false] at h
      by_cases h1 : k.length > 255
      · simp [h1] at h
      by_cases h2 : v.length > 128 * 1024
      · simp [h1, h2] at h
      by_cases h3 : validKey k = true
      · by_cases h4 : total + k.length + v.length > 1024 * 1024
        · simp [h1, h2, h3, h4] at h
        simp only [h1, h2, h3, h4, ite_false, Bool.not_true, Bool.false_eq_true] at h
        cases hr : parseEnvGo allowed (total + k.length + v.length) rest with
        | none => simp [hr] at h
        | some out' =>
          simp only [hr, Option.some.injEq, Functor.map, Option.map] at h
          subst h
          obtain ⟨hs, hp⟩ := parseEnvGo_spec allowed _ rest out' hr
          refine ⟨hs.cons_cons _, ?_⟩
          intro kv hkv
          rcases List.mem_cons.mp hkv with rfl | hkv
          · exact ⟨ha, h3, by dsimp only; omega, by dsimp only; omega⟩
          · exact hp kv hkv
      · simp [h1, h2, h3] at h
    · simp only [Bool.not_eq_true] at ha
      simp only [ha, Bool.not_false, ite_true] at h
      obtain ⟨hs, hp⟩ := parseEnvGo_spec allowed total rest out h
      exact ⟨hs.cons _, hp⟩

/-- Every accepted entry is allowed, has a valid key and respects the limits. -/
theorem parseEnv_spec (allowed : List Char → Bool) (pairs out : List (List Char × List Char))
    (h : parseEnv allowed pairs = some out) :
    out.Sublist pairs ∧ ∀ kv ∈ out, allowed kv.1 = true ∧ validKey kv.1 = true ∧
      kv.1.length ≤ 255 ∧ kv.2.length ≤ 128 * 1024 :=
  parseEnvGo_spec allowed 0 pairs out h

/-- Unauthorized keys are skipped, not rejected. -/
example : parseEnv (fun k => k == "A".toList) [("B".toList, []), ("A".toList, "1".toList)] =
    some [("A".toList, "1".toList)] := by decide

end DstackFormal.Guest.EnvFile
