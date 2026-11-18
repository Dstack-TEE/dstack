-- SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
--
-- SPDX-License-Identifier: Apache-2.0

/-!
# Runtime event log: digest preimages and RTMR replay

Models `dstack/cc-eventlog/src/runtime_events.rs`:
`RuntimeEvent::preimage`, `RuntimeEvent::digest`, `canonical_event_json_v2`,
`replay_events`, and `RuntimeEvent::validate` (added by Dstack-TEE/dstack#1596),
plus `dstack/cc-eventlog/src/tdx.rs: validate_v2_preimages`.

Proven:
* V1: `event_type_le || ":" || name || ":" || payload` is injective in
  `(name, payload)` for names without `0x3a` (`preimageV1_injective`); without
  that precondition `("app-id:x", "y")` and `("app-id", "x:y")` collide
  (`preimageV1_collision`), and `validate` rejects the forged event.
* V2: the JCS bytes of `{"name":…,"payload":"<hex>","type":134217729}` are
  injective in `(name, payload)` (`canonicalEventJsonV2_injective`), via a
  proven decoding lemma for the serde_json/serde_jcs string escaper
  (`escapeStr_quote_cancel`).
* V1 and V2 preimages are disjoint; together: `preimage_injective` on events
  that pass `validate`.
* Replay is a left fold from zeros, extends under append, the `to_event` cut is
  inclusive of the first match, and equal replay results bind the digest list
  (`replay_binds_digests`) and, for validated events, the whole log
  (`replay_binds_log`).
* `validate_v2_preimages` accepts iff every runtime V2 event carries a preimage
  that hex-decodes to the canonical preimage whose hash is the advertised digest.

Assumptions (explicit hypotheses only): the byte hash `hash` is injective; the
RTMR extend `extend mr d` (Rust `H::hash((mr, d))`) is injective as a pair
function; for binding logs of different length, no `extend` output equals the
zero register.

Modeling gaps: names are modeled as their UTF-8 byte strings. Rust's
`str::contains(':')` is char-wise; for valid UTF-8 it is equivalent to the byte
check used here because byte `0x3a` occurs only as the one-byte char `:`.
`Hasher` output types are abstracted to a type `D`. The escaper is serde_json's
`ESCAPE` table with serde_jcs's `write_char_escape` (lowercase `\u00xx`, no `/`
escape), applied bytewise to the UTF-8 encoding as in
`format_escaped_str_contents`. The JSON number `134217729` and key order are
fixed constants, as in the Rust unit test.
-/

namespace DstackFormal.Guest.EventLog

abbrev Bytes := List UInt8

/-- ASCII bytes of a string literal (used for the fixed JSON fragments). -/
def ascii (s : String) : Bytes := s.toList.map Char.toUInt8

/-- `dstack_types::EventLogVersion`. -/
inductive Version where
  | v1
  | v2
  deriving DecidableEq, Repr

/-- `cc_eventlog::RuntimeEvent` with the name as its UTF-8 bytes. -/
structure RuntimeEvent where
  event : Bytes
  payload : Bytes
  version : Version
  deriving DecidableEq, Repr

/-- `DSTACK_RUNTIME_EVENT_TYPE`. -/
def runtimeEventType : Nat := 0x08000001

/-- `u32::to_le_bytes`. -/
def u32le (n : Nat) : Bytes :=
  [n % 256, n / 256 % 256, n / 65536 % 256, n / 16777216 % 256].map UInt8.ofNat

def colon : UInt8 := 0x3a

/-- The fixed 4-byte prefix `DSTACK_RUNTIME_EVENT_TYPE.to_le_bytes()`. -/
def eventTypeLE : Bytes := u32le runtimeEventType

theorem eventTypeLE_eq : eventTypeLE = [0x01, 0x00, 0x00, 0x08] := by decide

theorem colon_not_mem_eventTypeLE : colon ∉ eventTypeLE := by decide

/-- V1 arm of `RuntimeEvent::preimage`. -/
def preimageV1 (name payload : Bytes) : Bytes :=
  eventTypeLE ++ [colon] ++ name ++ [colon] ++ payload

/-! ## JSON string escaping (serde_json `format_escaped_str_contents` + serde_jcs) -/

def quote : UInt8 := 0x22
def backslash : UInt8 := 0x5c

/-- `HEX = b"0123456789abcdef"` (serde_jcs `serialize`, `hex::encode`). -/
def hexTable : Bytes := ascii "0123456789abcdef"

def hexDigit (n : UInt8) : UInt8 := hexTable.getD n.toNat 0

/-- One byte through serde_json's `ESCAPE` table and serde_jcs's
`write_char_escape`; unlisted bytes (including `/` and all bytes `≥ 0x20`
other than `"` and `\`) are copied. -/
def escapeByte (b : UInt8) : Bytes :=
  if b = 0x22 then [backslash, 0x22]
  else if b = 0x5c then [backslash, 0x5c]
  else if b = 0x08 then [backslash, 0x62]
  else if b = 0x0c then [backslash, 0x66]
  else if b = 0x0a then [backslash, 0x6e]
  else if b = 0x0d then [backslash, 0x72]
  else if b = 0x09 then [backslash, 0x74]
  else if b < 0x20 then [backslash, 0x75, 0x30, 0x30, hexDigit (b >>> 4), hexDigit (b &&& 0xf)]
  else [b]

def escapeStr (s : Bytes) : Bytes := s.flatMap escapeByte

/-- A serialized JSON string: `"` escaped-contents `"`. -/
def jsonString (s : Bytes) : Bytes := [quote] ++ escapeStr s ++ [quote]

/-- `hex::encode` (lowercase). -/
def hexEncode (p : Bytes) : Bytes := p.flatMap fun (b : UInt8) => [hexDigit (b >>> 4), hexDigit (b &&& 0xf)]

/-- `canonical_event_json_v2`: JCS sorts keys to `name`, `payload`, `type`. -/
def canonicalEventJsonV2 (name payload : Bytes) : Bytes :=
  ascii "{\"name\":" ++ jsonString name ++ ascii ",\"payload\":" ++
    jsonString (hexEncode payload) ++ ascii ",\"type\":134217729}"

/-- `RuntimeEvent::preimage`. -/
def preimage (e : RuntimeEvent) : Bytes :=
  match e.version with
  | .v1 => preimageV1 e.event e.payload
  | .v2 => canonicalEventJsonV2 e.event e.payload

/-- `RuntimeEvent::digest`, for a byte hash `hash`. -/
def digest {D : Type} (hash : Bytes → D) (e : RuntimeEvent) : D := hash (preimage e)

/-- `RuntimeEvent::validate` (Dstack-TEE/dstack#1596): a V1 name must not contain `:`. -/
def validate (e : RuntimeEvent) : Bool :=
  match e.version with
  | .v1 => !(e.event.contains colon)
  | .v2 => true

/-! ## Mirrors of Rust unit tests -/

#guard preimageV1 (ascii "app-id") [0xde, 0xad, 0xbe, 0xef] =
  [0x01, 0x00, 0x00, 0x08] ++ ascii ":app-id:" ++ [0xde, 0xad, 0xbe, 0xef]
#guard canonicalEventJsonV2 (ascii "compose-hash") [0xab, 0xcd] =
  ascii "{\"name\":\"compose-hash\",\"payload\":\"abcd\",\"type\":134217729}"
#guard canonicalEventJsonV2 (ascii "event\"with\\special\nchars") [0xff] =
  ascii "{\"name\":\"event\\\"with\\\\special\\nchars\",\"payload\":\"ff\",\"type\":134217729}"
#guard canonicalEventJsonV2 [] [] = ascii "{\"name\":\"\",\"payload\":\"\",\"type\":134217729}"
#guard jsonString (ascii "\x08\x0c\n\r\t\x01") = ascii "\"\\b\\f\\n\\r\\t\\u0001\""
#guard hexEncode [0xAB, 0xCD, 0xEF] = ascii "abcdef"
#guard escapeStr (ascii "a/b") = ascii "a/b"
#guard validate ⟨ascii "app-id:x", ascii "y", .v1⟩ = false
#guard validate ⟨ascii "app-id", ascii "x:y", .v1⟩ = true
#guard validate ⟨ascii "a:b", [], .v2⟩ = true

/-! ## V1 -/

theorem append_colon_cancel :
    ∀ (n n' p p' : Bytes), colon ∉ n → colon ∉ n' →
      n ++ colon :: p = n' ++ colon :: p' → n = n' ∧ p = p'
  | [], [], _, _, _, _, h => ⟨rfl, by simpa using h⟩
  | [], x :: _, _, _, _, h', h => by
      simp only [List.nil_append, List.cons_append, List.cons.injEq] at h
      exact absurd (h.1 ▸ List.mem_cons_self) h'
  | x :: _, [], _, _, h, _, h' => by
      simp only [List.nil_append, List.cons_append, List.cons.injEq] at h'
      exact absurd (h'.1 ▸ List.mem_cons_self) h
  | x :: xs, y :: ys, p, p', h, h', heq => by
      simp only [List.cons_append, List.cons.injEq] at heq
      have := append_colon_cancel xs ys p p' (fun m => h (List.mem_cons_of_mem _ m))
        (fun m => h' (List.mem_cons_of_mem _ m)) heq.2
      exact ⟨by rw [heq.1, this.1], this.2⟩

/-- V1 preimages are injective in `(name, payload)` for colon-free names. -/
theorem preimageV1_injective {n n' p p' : Bytes} (hn : colon ∉ n) (hn' : colon ∉ n')
    (h : preimageV1 n p = preimageV1 n' p') : n = n' ∧ p = p' := by
  simp only [preimageV1, List.append_assoc, List.singleton_append] at h
  exact append_colon_cancel n n' p p' hn hn' (List.cons.inj (List.append_cancel_left h)).2

/-- Without the precondition the V1 preimage is ambiguous. -/
theorem preimageV1_collision :
    preimageV1 (ascii "app-id:x") (ascii "y") = preimageV1 (ascii "app-id") (ascii "x:y") ∧
      (ascii "app-id:x", ascii "y") ≠ (ascii "app-id", ascii "x:y") := by decide

/-- The forged event of `preimageV1_collision` is the one `validate` rejects. -/
theorem validate_rejects_collision :
    validate ⟨ascii "app-id:x", ascii "y", .v1⟩ = false ∧
      validate ⟨ascii "app-id", ascii "x:y", .v1⟩ = true := by decide

theorem validate_v1_iff {n p : Bytes} : validate ⟨n, p, .v1⟩ = true ↔ colon ∉ n := by
  simp [validate]

/-! ## V2 -/

/-- Inverse of the short escapes. -/
def unshort (c : UInt8) : UInt8 :=
  if c = 0x62 then 0x08 else if c = 0x66 then 0x0c else if c = 0x6e then 0x0a
  else if c = 0x72 then 0x0d else if c = 0x74 then 0x09 else c

def unhex (c : UInt8) : UInt8 := if c ≤ 0x39 then c - 0x30 else c - 0x61 + 10

/-- Decode one escaped byte from the front of a JSON string body. -/
def decodeByte : Bytes → Option (UInt8 × Bytes)
  | [] => none
  | b :: r =>
    if b = backslash then
      match r with
      | [] => none
      | c :: r' =>
        if c = 0x75 then
          match r' with
          | _ :: _ :: h :: l :: r'' => some ((unhex h <<< 4) ||| unhex l, r'')
          | _ => none
        else some (unshort c, r')
    else some (b, r)

theorem unhex_hexDigit : ∀ b : UInt8, (unhex (hexDigit (b >>> 4)) <<< 4) ||| unhex (hexDigit (b &&& 0xf)) = b := by
  decide

theorem decodeByte_escapeByte (b : UInt8) (x : Bytes) : decodeByte (escapeByte b ++ x) = some (b, x) := by
  unfold escapeByte
  split
  · subst_vars; rfl
  split
  · subst_vars; rfl
  split
  · subst_vars; rfl
  split
  · subst_vars; rfl
  split
  · subst_vars; rfl
  split
  · subst_vars; rfl
  split
  · subst_vars; rfl
  split
  · simp only [List.cons_append, List.nil_append, decodeByte, backslash]
    simp [unhex_hexDigit]
  · rename_i _ h _ _ _ _ _ _
    simp [decodeByte, backslash, h]

theorem escapeByte_head : ∀ b : UInt8, (escapeByte b).head? ≠ some quote := by decide

theorem escapeByte_ne_nil : ∀ b : UInt8, escapeByte b ≠ [] := by decide

theorem escapeByte_head_ne_quote (b : UInt8) (x x' : Bytes) : escapeByte b ++ x ≠ quote :: x' := by
  intro h
  cases hb : escapeByte b with
  | nil => exact escapeByte_ne_nil b hb
  | cons y ys =>
    have := escapeByte_head b
    rw [hb] at h this
    simp only [List.cons_append, List.cons.injEq] at h
    exact this (by simp [h.1])

/-- Escaped contents followed by the closing quote determine the contents and
the remainder: the escaper is uniquely decodable. -/
theorem escapeStr_quote_cancel :
    ∀ (n n' r r' : Bytes), escapeStr n ++ quote :: r = escapeStr n' ++ quote :: r' → n = n' ∧ r = r'
  | [], [], _, _, h => ⟨rfl, by simpa [escapeStr] using h⟩
  | [], b :: bs, r, r', h => by
      simp only [escapeStr, List.flatMap_cons, List.flatMap_nil, List.nil_append,
        List.append_assoc] at h
      exact absurd h.symm (escapeByte_head_ne_quote b _ _)
  | b :: bs, [], r, r', h => by
      simp only [escapeStr, List.flatMap_cons, List.flatMap_nil, List.nil_append,
        List.append_assoc] at h
      exact absurd h (escapeByte_head_ne_quote b _ _)
  | b :: bs, b' :: bs', r, r', h => by
      simp only [escapeStr, List.flatMap_cons, List.append_assoc] at h
      have hd := congrArg decodeByte h
      rw [decodeByte_escapeByte, decodeByte_escapeByte] at hd
      simp only [Option.some.injEq, Prod.mk.injEq] at hd
      have := escapeStr_quote_cancel bs bs' r r' hd.2
      exact ⟨by rw [hd.1, this.1], this.2⟩

theorem jsonString_cancel {n n' r r' : Bytes} (h : jsonString n ++ r = jsonString n' ++ r') :
    n = n' ∧ r = r' := by
  simp only [jsonString, List.append_assoc, List.cons_append,
    List.cons.injEq, true_and] at h
  exact escapeStr_quote_cancel n n' r r' h

theorem hexEncode_injective : ∀ {p p' : Bytes}, hexEncode p = hexEncode p' → p = p'
  | [], [], _ => rfl
  | [], _ :: _, h => by simp [hexEncode] at h
  | _ :: _, [], h => by simp [hexEncode] at h
  | b :: bs, b' :: bs', h => by
      simp only [hexEncode, List.flatMap_cons, List.cons_append, List.nil_append,
        List.cons.injEq] at h
      have hb : b = b' := by rw [← unhex_hexDigit b, ← unhex_hexDigit b', h.1, h.2.1]
      exact hb ▸ congrArg _ (hexEncode_injective h.2.2)

/-- V2 canonical JSON is injective in `(name, payload)`, for every name. -/
theorem canonicalEventJsonV2_injective {n n' p p' : Bytes}
    (h : canonicalEventJsonV2 n p = canonicalEventJsonV2 n' p') : n = n' ∧ p = p' := by
  simp only [canonicalEventJsonV2, List.append_assoc] at h
  have h1 := jsonString_cancel (List.append_cancel_left h)
  have h2 := jsonString_cancel (List.append_cancel_left h1.2)
  exact ⟨h1.1, hexEncode_injective h2.1⟩

/-! ## Both versions -/

theorem preimageV1_ne_v2 (n p n' p' : Bytes) : preimageV1 n p ≠ canonicalEventJsonV2 n' p' := by
  intro h
  have hl : ascii "{\"name\":" = 0x7b :: ascii "\"name\":" := by decide
  have := congrArg List.head? h
  simp only [preimageV1, canonicalEventJsonV2, eventTypeLE_eq, hl, List.append_assoc,
    List.cons_append, List.head?_cons] at this
  exact absurd this (by decide)

/-- On events accepted by `validate`, the preimage determines the event. -/
theorem preimage_injective {e e' : RuntimeEvent} (hv : validate e = true) (hv' : validate e' = true)
    (h : preimage e = preimage e') : e = e' := by
  obtain ⟨n, p, v⟩ := e
  obtain ⟨n', p', v'⟩ := e'
  cases v <;> cases v' <;> simp only [preimage] at h
  · obtain ⟨rfl, rfl⟩ := preimageV1_injective (validate_v1_iff.mp hv) (validate_v1_iff.mp hv') h
    rfl
  · exact absurd h (preimageV1_ne_v2 _ _ _ _)
  · exact absurd h.symm (preimageV1_ne_v2 _ _ _ _)
  · obtain ⟨rfl, rfl⟩ := canonicalEventJsonV2_injective h
    rfl

/-! ## Replay (`replay_events`) -/

section Replay

variable {D : Type} (dg : RuntimeEvent → D) (extend : D → D → D) (zeros : D)

/-- The loop body of `replay_events` from register `mr`. -/
def replayFrom (toEvent : Option Bytes) : D → List RuntimeEvent → D
  | mr, [] => mr
  | mr, e :: es =>
    let mr' := extend mr (dg e)
    if toEvent = some e.event then mr' else replayFrom toEvent mr' es

/-- `replay_events::<H>(eventlog, to_event)` with `H::zeros()` = `zeros` and
`H::hash((mr, d))` = `extend mr d`. -/
def replayEvents (log : List RuntimeEvent) (toEvent : Option Bytes) : D :=
  replayFrom dg extend toEvent zeros log

def step (mr : D) (e : RuntimeEvent) : D := extend mr (dg e)

theorem replayFrom_none (mr : D) (log : List RuntimeEvent) :
    replayFrom dg extend none mr log = log.foldl (step dg extend) mr := by
  induction log generalizing mr with
  | nil => rfl
  | cons e es ih => simp [replayFrom, ih, step]

/-- Without `to_event`, replay is a left fold of `extend` from zeros. -/
theorem replayEvents_none (log : List RuntimeEvent) :
    replayEvents dg extend zeros log none = log.foldl (step dg extend) zeros :=
  replayFrom_none dg extend zeros log

theorem replayEvents_append (l₁ l₂ : List RuntimeEvent) :
    replayEvents dg extend zeros (l₁ ++ l₂) none =
      l₂.foldl (step dg extend) (replayEvents dg extend zeros l₁ none) := by
  simp [replayEvents_none, List.foldl_append]

/-- Appending one event performs one RTMR extend. -/
theorem replayEvents_snoc (l : List RuntimeEvent) (e : RuntimeEvent) :
    replayEvents dg extend zeros (l ++ [e]) none = extend (replayEvents dg extend zeros l none) (dg e) := by
  simp [replayEvents_append, step]

/-- `to_event`: replay stops right after the first event with that name. -/
theorem replayEvents_to_event (pre post : List RuntimeEvent) (e : RuntimeEvent) (t : Bytes)
    (hpre : ∀ x ∈ pre, x.event ≠ t) (he : e.event = t) :
    replayEvents dg extend zeros (pre ++ e :: post) (some t) = replayEvents dg extend zeros (pre ++ [e]) none := by
  unfold replayEvents
  rw [replayFrom_none]
  generalize zeros = mr
  induction pre generalizing mr with
  | nil => simp [replayFrom, he, step]
  | cons x xs ih =>
    have hx : ¬ (some t = some x.event) := fun h => hpre x List.mem_cons_self (Option.some.inj h).symm
    simp only [List.cons_append, replayFrom, hx, ite_false, List.foldl_cons]
    exact ih (fun y hy => hpre y (List.mem_cons_of_mem _ hy)) _

/-- `to_event` that matches no event replays the whole log. -/
theorem replayEvents_to_event_absent (log : List RuntimeEvent) (t : Bytes) (h : ∀ x ∈ log, x.event ≠ t) :
    replayEvents dg extend zeros log (some t) = replayEvents dg extend zeros log none := by
  unfold replayEvents
  generalize zeros = mr
  induction log generalizing mr with
  | nil => rfl
  | cons x xs ih =>
    have hx : ¬ (some t = some x.event) := fun he => h x List.mem_cons_self (Option.some.inj he).symm
    simp only [replayFrom, hx, ite_false]
    exact ih (fun y hy => h y (List.mem_cons_of_mem _ hy)) _

def PairInjective (f : D → D → D) : Prop := ∀ a b a' b', f a b = f a' b' → a = a' ∧ b = b'

theorem foldr_rev_binds (hinj : PairInjective extend) :
    ∀ (r r' : List RuntimeEvent), (r.length = r'.length ∨ ∀ a b, extend a b ≠ zeros) →
      r.foldr (fun x y => step dg extend y x) zeros = r'.foldr (fun x y => step dg extend y x) zeros →
      r.map dg = r'.map dg
  | [], [], _, _ => rfl
  | [], x :: xs, hl, h => by
      rcases hl with hl | hz
      · simp at hl
      · exact absurd h.symm (hz _ _)
  | x :: xs, [], hl, h => by
      rcases hl with hl | hz
      · simp at hl
      · exact absurd h (hz _ _)
  | x :: xs, x' :: xs', hl, h => by
      simp only [List.foldr_cons, step] at h
      have ⟨h1, h2⟩ := hinj _ _ _ _ h
      have hl' : xs.length = xs'.length ∨ ∀ a b, extend a b ≠ zeros := by
        rcases hl with hl | hz
        · exact Or.inl (by simpa using hl)
        · exact Or.inr hz
      simp [h2, foldr_rev_binds hinj xs xs' hl' h1]

/-- Equal replay results under a pair-injective `extend` bind the digest
sequence, provided the logs have equal length or `extend` never yields the zero
register. -/
theorem replay_binds_digests (hinj : PairInjective extend) {l l' : List RuntimeEvent}
    (hl : l.length = l'.length ∨ ∀ a b, extend a b ≠ zeros)
    (h : replayEvents dg extend zeros l none = replayEvents dg extend zeros l' none) :
    l.map dg = l'.map dg := by
  rw [replayEvents_none, replayEvents_none, List.foldl_eq_foldr_reverse, List.foldl_eq_foldr_reverse] at h
  have hl' : l.reverse.length = l'.reverse.length ∨ ∀ a b, extend a b ≠ zeros := by simpa using hl
  have := foldr_rev_binds dg extend zeros hinj _ _ hl' h
  rw [List.map_reverse, List.map_reverse] at this
  exact List.reverse_inj.mp this

end Replay

theorem map_injective_on {α β : Type} (f : α → β) (P : α → Prop)
    (hf : ∀ a a', P a → P a' → f a = f a' → a = a') :
    ∀ l l' : List α, (∀ x ∈ l, P x) → (∀ x ∈ l', P x) → l.map f = l'.map f → l = l'
  | [], [], _, _, _ => rfl
  | [], _ :: _, _, _, h => by simp at h
  | _ :: _, [], _, _, h => by simp at h
  | x :: xs, y :: ys, hp, hp', h => by
      simp only [List.map_cons, List.cons.injEq] at h
      rw [hf x y (hp x List.mem_cons_self) (hp' y List.mem_cons_self) h.1,
        map_injective_on f P hf xs ys (fun z hz => hp z (List.mem_cons_of_mem _ hz))
          (fun z hz => hp' z (List.mem_cons_of_mem _ hz)) h.2]

/-- End to end: with an injective byte hash, a pair-injective extend that never
yields zeros, and logs whose events all pass `validate`, equal replayed
registers imply identical logs (names, payloads, versions, order, length). -/
theorem replay_binds_log {D : Type} (hash : Bytes → D) (extend : D → D → D) (zeros : D)
    (hhash : ∀ a b, hash a = hash b → a = b) (hinj : PairInjective extend)
    (hz : ∀ a b, extend a b ≠ zeros) {l l' : List RuntimeEvent}
    (hv : ∀ e ∈ l, validate e = true) (hv' : ∀ e ∈ l', validate e = true)
    (h : replayEvents (digest hash) extend zeros l none = replayEvents (digest hash) extend zeros l' none) :
    l = l' :=
  map_injective_on (digest hash) (fun e => validate e = true)
    (fun _ _ ha hb hd => preimage_injective ha hb (hhash _ _ hd)) l l' hv hv'
    (replay_binds_digests (digest hash) extend zeros hinj (Or.inr hz) h)

/-! ## `validate_v2_preimages` -/

/-- The fields of `cc_eventlog::TdxEvent` used by `validate_v2_preimages`. -/
structure TdxEvent (D : Type) where
  eventType : Nat
  digest : D
  event : Bytes
  payload : Bytes
  version : Version
  preimage : Option String

/-- `TdxEvent::to_runtime_event` on a runtime event. -/
def TdxEvent.toRuntime {D : Type} (e : TdxEvent D) : RuntimeEvent := ⟨e.event, e.payload, e.version⟩

/-- Per-event check of `validate_v2_preimages`; `hexDecode` is `hex::decode`. -/
def checkV2 {D : Type} [DecidableEq D] (sha : Bytes → D) (hexDecode : String → Option Bytes)
    (e : TdxEvent D) : Bool :=
  if e.eventType ≠ runtimeEventType ∨ e.version ≠ .v2 then true
  else
    match e.preimage with
    | none => false
    | some s =>
      match hexDecode s with
      | none => false
      | some supplied => decide (sha supplied = e.digest) && decide (supplied = preimage e.toRuntime)

/-- `validate_v2_preimages` (Ok ↔ `true`). -/
def validateV2Preimages {D : Type} [DecidableEq D] (sha : Bytes → D) (hexDecode : String → Option Bytes)
    (events : List (TdxEvent D)) : Bool :=
  events.all (checkV2 sha hexDecode)

theorem validateV2Preimages_iff {D : Type} [DecidableEq D] (sha : Bytes → D)
    (hexDecode : String → Option Bytes) (events : List (TdxEvent D)) :
    validateV2Preimages sha hexDecode events = true ↔
      ∀ e ∈ events, e.eventType = runtimeEventType → e.version = .v2 →
        ∃ s, e.preimage = some s ∧ hexDecode s = some (preimage e.toRuntime) ∧
          sha (preimage e.toRuntime) = e.digest := by
  simp only [validateV2Preimages, List.all_eq_true]
  refine forall_congr' fun e => imp_congr_right fun _ => ?_
  unfold checkV2
  by_cases ht : e.eventType = runtimeEventType <;> by_cases hv : e.version = .v2 <;> simp [ht, hv]
  cases e.preimage with
  | none => simp
  | some s =>
    simp only [Option.some.injEq, exists_eq_left']
    cases hexDecode s with
    | none => simp
    | some b =>
      simp only [Bool.and_eq_true, decide_eq_true_eq, Option.some.injEq]
      constructor
      · rintro ⟨h1, rfl⟩; exact ⟨rfl, h1⟩
      · rintro ⟨rfl, h1⟩; exact ⟨h1, rfl⟩

/-- An accepted V2 event's advertised digest determines its displayed name and
payload, for an injective `sha`. -/
theorem validateV2Preimages_binds_fields {D : Type} [DecidableEq D] (sha : Bytes → D)
    (hsha : ∀ a b, sha a = sha b → a = b) (hexDecode : String → Option Bytes)
    {e e' : TdxEvent D} (h : validateV2Preimages sha hexDecode [e, e'] = true)
    (ht : e.eventType = runtimeEventType) (ht' : e'.eventType = runtimeEventType)
    (hv : e.version = .v2) (hv' : e'.version = .v2) (hd : e.digest = e'.digest) :
    e.event = e'.event ∧ e.payload = e'.payload := by
  have h := (validateV2Preimages_iff sha hexDecode _).mp h
  obtain ⟨_, _, _, h1⟩ := h e List.mem_cons_self ht hv
  obtain ⟨_, _, _, h2⟩ := h e' (List.mem_cons_of_mem _ List.mem_cons_self) ht' hv'
  have := hsha _ _ (h1.trans (hd.trans h2.symm))
  simp only [preimage, TdxEvent.toRuntime, hv, hv'] at this
  exact canonicalEventJsonV2_injective this

end DstackFormal.Guest.EventLog
