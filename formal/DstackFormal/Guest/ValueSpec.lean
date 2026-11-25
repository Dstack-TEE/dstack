-- SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
--
-- SPDX-License-Identifier: Apache-2.0

/-!
# Value specs: canonical integers and range checks

Models `dstack/value-spec/src/lib.rs`: the `int` parser (the grammar
`"0" | "-"? [1-9] [0-9]*`, `MAX_NUMBER_LEN` and `str::parse::<i128>`), the
bound comparison of `range`, `has_int`, and `ValueSpec::matches` for `int`
specs.

Proven:
* `parseI128_iff`: a text parses to `n` iff `n` is an `i128` and the text is
  the one spelling Rust's `i128::to_string` prints; hence no two accepted
  texts denote the same integer (`parseI128_inj`) and `MAX_NUMBER_LEN` never
  rejects an `i128` (`renderInt_length`).
* `matchesInt_iff`: an `int` spec accepts exactly the canonical spellings of
  the `i128` values inside one of its ranges.
* `ordered_of_contains`: the bound comparison of `range` rejects only ranges
  that hold no value, for `int` and `float` alike; `contains_of_ordered`: an
  accepted range with an inclusive bound holds that bound.
* `hasInt_iff`: `has_int` holds iff the range holds an `i128`, so an accepted
  `int` range is never empty.

Assumptions: `BigDecimal`'s ordering is a parameter `lt` required to be
transitive.
Modeling gaps: a text is a sign and a list of digit values, so ASCII decoding
and non-digit characters are not modeled; `i128::to_string` is modeled as
`renderInt`; the `float` grammar, the spec syntax (the winnow parser) and
regexes are not modeled. An accepted `float` range between two bounds may
still hold no decimal of at most `MAX_NUMBER_LEN` bytes.
-/

namespace DstackFormal.Guest.ValueSpec

/-! ## Digit strings -/

/-- Value of a digit string, least significant digit first. -/
def val : List Nat → Nat
  | [] => 0
  | d :: ds => d + 10 * val ds

/-- Digits below ten whose most significant (last) digit is nonzero. -/
def Trimmed : List Nat → Prop
  | [] => True
  | d :: ds => d < 10 ∧ (ds = [] → d ≠ 0) ∧ Trimmed ds

theorem val_eq_zero {ds : List Nat} (h : Trimmed ds) (hv : val ds = 0) : ds = [] := by
  induction ds with
  | nil => rfl
  | cons d ds ih =>
    simp only [val] at hv
    obtain ⟨_, hd, ht⟩ := h
    exact absurd (by omega) (hd (ih ht (by omega)))

theorem val_inj {a b : List Nat} (ha : Trimmed a) (hb : Trimmed b) (h : val a = val b) :
    a = b := by
  induction a generalizing b with
  | nil => exact (val_eq_zero hb h.symm).symm
  | cons d ds ih =>
    cases b with
    | nil => exact val_eq_zero ha h
    | cons e es =>
      simp only [val] at h
      obtain ⟨hd, _, hds⟩ := ha
      obtain ⟨he, _, hes⟩ := hb
      rw [ih hds hes (by omega), show d = e by omega]

theorem trimmed_append (xs : List Nat) (d : Nat) :
    Trimmed (xs ++ [d]) ↔ (∀ x ∈ xs, x < 10) ∧ d < 10 ∧ d ≠ 0 := by
  induction xs with
  | nil => simp [Trimmed]
  | cons x xs ih =>
    simp only [List.cons_append, Trimmed, ih, List.mem_cons, forall_eq_or_imp]
    constructor
    · rintro ⟨hx, -, hxs, hd⟩
      exact ⟨⟨hx, hxs⟩, hd⟩
    · rintro ⟨⟨hx, hxs⟩, hd⟩
      exact ⟨hx, fun h => absurd h (by simp), hxs, hd⟩

/-- Digits of `n`, least significant first; empty for zero. -/
def digits (n : Nat) : List Nat :=
  if n = 0 then [] else n % 10 :: digits (n / 10)
termination_by n
decreasing_by omega

theorem digits_spec (n : Nat) : Trimmed (digits n) ∧ val (digits n) = n := by
  induction n using Nat.strongRecOn with
  | _ n ih =>
    unfold digits
    split
    · next h => exact ⟨trivial, h.symm⟩
    · next h =>
      obtain ⟨ht, hv⟩ := ih (n / 10) (by omega)
      refine ⟨⟨by omega, fun he => ?_, ht⟩, by simp only [val, hv]; omega⟩
      rw [he] at hv
      simp only [val] at hv
      omega

theorem digits_length (k n : Nat) (h : n < 10 ^ k) : (digits n).length ≤ k := by
  induction k generalizing n with
  | zero =>
    have : n = 0 := by simpa using h
    subst this
    simp [digits]
  | succ k ih =>
    unfold digits
    split
    · simp
    · have := ih (n / 10) (by rw [Nat.pow_succ] at h; omega)
      simp only [List.length_cons]
      omega

/-! ## Canonical integer texts -/

/-- The grammar `"0" | [1-9] [0-9]*`, most significant digit first. -/
def canonNat : List Nat → Bool
  | [] => false
  | [0] => true
  | d :: ds => decide (0 < d ∧ d < 10) && ds.all (· < 10)

def parseNat (t : List Nat) : Option Nat :=
  if canonNat t then some (val t.reverse) else none

/-- `to_string` of an unsigned magnitude. -/
def render (n : Nat) : List Nat :=
  if n = 0 then [0] else (digits n).reverse

theorem canonNat_iff (t : List Nat) :
    canonNat t = true ↔ t = [0] ∨ (t ≠ [] ∧ Trimmed t.reverse) := by
  match t with
  | [] => simp [canonNat]
  | [0] => simp [canonNat]
  | [d + 1] => simp [canonNat, Trimmed]
  | d :: e :: ds =>
    rw [List.reverse_cons, trimmed_append]
    simp only [canonNat, Bool.and_eq_true, decide_eq_true_eq, List.all_eq_true, List.mem_cons,
      forall_eq_or_imp, reduceCtorEq, List.cons.injEq, and_false, false_or, ne_eq,
      not_false_eq_true, true_and, List.mem_reverse]
    constructor
    · rintro ⟨⟨h0, h10⟩, he, h⟩
      exact ⟨⟨he, h⟩, h10, by omega⟩
    · rintro ⟨⟨he, h⟩, h10, h0⟩
      exact ⟨⟨by omega, h10⟩, he, h⟩

theorem parseNat_iff (t : List Nat) (n : Nat) : parseNat t = some n ↔ t = render n := by
  obtain ⟨ht, hv⟩ := digits_spec n
  unfold parseNat render
  constructor
  · intro h
    split at h
    · next hc =>
      have hn : val t.reverse = n := by simpa using h
      rcases (canonNat_iff t).1 hc with rfl | ⟨hne, htr⟩
      · simp [← hn, val]
      · have hrev : t.reverse = digits n := val_inj htr ht (by rw [hn, hv])
        have : n ≠ 0 := by
          rintro rfl
          rw [digits] at hrev
          simp at hrev
          exact hne hrev
        simp only [this, ↓reduceIte, ← hrev, List.reverse_reverse]
    · simp at h
  · rintro rfl
    split
    · next hn =>
      subst hn
      simp [canonNat, val]
    · next hn =>
      have hne : digits n ≠ [] := by
        intro he
        rw [he] at hv
        exact hn hv.symm
      have : canonNat (digits n).reverse = true :=
        (canonNat_iff _).2 (.inr ⟨by simpa using hne, by simpa using ht⟩)
      simp [this, hv]

/-- `MAX_NUMBER_LEN`. -/
def maxLen : Nat := 64

def InI128 (n : Int) : Prop := -2 ^ 127 ≤ n ∧ n < 2 ^ 127

instance (n : Int) : Decidable (InI128 n) := inferInstanceAs (Decidable (_ ∧ _))

/-- Byte length of a text: one per digit plus the sign. -/
def textLen (neg : Bool) (t : List Nat) : Nat := (if neg then 1 else 0) + t.length

/-- The grammar `"0" | "-"? [1-9] [0-9]*`. -/
def parseInt (neg : Bool) (t : List Nat) : Option Int :=
  match parseNat t with
  | some m => if neg then (if m = 0 then none else some (-(m : Int))) else some m
  | none => none

/-- The `int` parser: grammar, length limit, then `str::parse::<i128>`. -/
def parseI128 (neg : Bool) (t : List Nat) : Option Int :=
  if textLen neg t ≤ maxLen then (parseInt neg t).filter (InI128 ·) else none

/-- `i128::to_string`. -/
def renderInt (n : Int) : Bool × List Nat := (decide (n < 0), render n.natAbs)

theorem parseInt_iff (neg : Bool) (t : List Nat) (n : Int) :
    parseInt neg t = some n ↔ (neg, t) = renderInt n := by
  unfold parseInt renderInt
  constructor
  · intro h
    split at h
    · next m hm =>
      rw [parseNat_iff] at hm
      subst hm
      cases neg
      · simp only [Bool.false_eq_true, ↓reduceIte, Option.some.injEq] at h
        subst h
        simp
      · simp only [↓reduceIte] at h
        split at h
        · simp at h
        · next hm =>
          simp only [Option.some.injEq] at h
          subst h
          simp
          omega
    · simp at h
  · intro h
    simp only [Prod.mk.injEq] at h
    obtain ⟨rfl, rfl⟩ := h
    rw [(parseNat_iff _ _).2 rfl]
    by_cases hn : n < 0
    · have : n.natAbs ≠ 0 := by omega
      simp only [hn, decide_true, ↓reduceIte, this, Option.some.injEq]
      omega
    · simp only [hn, decide_false, Bool.false_eq_true, ↓reduceIte, Option.some.injEq]
      omega

/-- An `i128` prints in at most 40 bytes, below `MAX_NUMBER_LEN`. -/
theorem renderInt_length (n : Int) (h : InI128 n) :
    textLen (renderInt n).1 (renderInt n).2 ≤ 40 := by
  have hlen : (render n.natAbs).length ≤ 39 := by
    unfold render
    split
    · simp
    · rw [List.length_reverse]
      refine digits_length 39 _ ?_
      have : (2 : Nat) ^ 127 < 10 ^ 39 := by decide
      have h2 : ((2 : Nat) ^ 127 : Int) = (2 : Int) ^ 127 := by decide
      obtain ⟨h1, h3⟩ := h
      omega
  simp only [renderInt, textLen]
  by_cases hn : n < 0 <;> simp only [hn, decide_true, decide_false, Bool.false_eq_true,
    ↓reduceIte] <;> omega

theorem parseI128_iff (neg : Bool) (t : List Nat) (n : Int) :
    parseI128 neg t = some n ↔ InI128 n ∧ (neg, t) = renderInt n := by
  unfold parseI128
  constructor
  · intro h
    split at h
    · rw [Option.filter_eq_some_iff] at h
      exact ⟨by simpa using h.2, (parseInt_iff _ _ _).1 h.1⟩
    · simp at h
  · rintro ⟨hn, h⟩
    have hlen : textLen neg t ≤ 40 := by
      have := renderInt_length n hn
      rw [← h] at this
      exact this
    have : textLen neg t ≤ maxLen := by unfold maxLen; omega
    simp [this, (parseInt_iff _ _ _).2 h, Option.filter, hn]

theorem parseI128_inj {neg neg' : Bool} {t t' : List Nat} {n : Int}
    (h : parseI128 neg t = some n) (h' : parseI128 neg' t' = some n) :
    (neg, t) = (neg', t') :=
  ((parseI128_iff _ _ _).1 h).2.trans ((parseI128_iff _ _ _).1 h').2.symm

/-! ## Ranges -/

inductive Bound (α : Type) where
  | incl (a : α)
  | excl (a : α)
  | unb

abbrev Range (α : Type) := Bound α × Bound α

section Order

variable {α : Type} (lt : α → α → Prop)

def Le (a b : α) : Prop := lt a b ∨ a = b

def Above : Bound α → α → Prop
  | .incl s, x => Le lt s x
  | .excl s, x => lt s x
  | .unb, _ => True

def Below : Bound α → α → Prop
  | .incl e, x => Le lt x e
  | .excl e, x => lt x e
  | .unb, _ => True

/-- `RangeBounds::contains` on a pair of bounds. -/
def Contains (r : Range α) (x : α) : Prop := Above lt r.1 x ∧ Below lt r.2 x

/-- The bound comparison a range must pass in `range`. -/
def Ordered : Range α → Prop
  | (.incl s, .incl e) => Le lt s e
  | (.incl s, .excl e) | (.excl s, .incl e) | (.excl s, .excl e) => lt s e
  | _ => True

/-- A range holding a value passes the comparison: only empty ranges are
rejected. -/
theorem ordered_of_contains (trans : ∀ {a b c}, lt a b → lt b c → lt a c)
    (r : Range α) (x : α) (h : Contains lt r x) : Ordered lt r := by
  obtain ⟨s, e⟩ := r
  cases s <;> cases e <;> simp only [Ordered] <;> simp only [Contains, Above, Below] at h
  · rcases h with ⟨hs | rfl, he | rfl⟩
    · exact .inl (trans hs he)
    · exact .inl hs
    · exact .inl he
    · exact .inr rfl
  · rcases h with ⟨hs | rfl, he⟩
    · exact trans hs he
    · exact he
  · rcases h with ⟨hs, he | rfl⟩
    · exact trans hs he
    · exact hs
  · exact trans h.1 h.2

/-- An accepted range with an inclusive bound holds that bound. -/
theorem contains_of_ordered (r : Range α) (h : Ordered lt r) :
    match r with
    | (.incl s, .incl _) | (.incl s, .excl _) | (.incl s, .unb) => Contains lt r s
    | (.excl _, .incl e) | (.unb, .incl e) => Contains lt r e
    | _ => True := by
  obtain ⟨s, e⟩ := r
  cases s <;> cases e <;> first
    | trivial
    | exact ⟨.inr rfl, h⟩
    | exact ⟨h, .inr rfl⟩
    | exact ⟨.inr rfl, trivial⟩
    | exact ⟨trivial, .inr rfl⟩

end Order

/-! ## Integer ranges -/

def ContainsInt (r : Range Int) (n : Int) : Prop := Contains (· < ·) r n

/-- Smallest candidate of a start bound; `checked_add` fails at `i128::MAX`. -/
def first : Bound Int → Option Int
  | .incl n => some n
  | .excl n => if n + 1 < 2 ^ 127 then some (n + 1) else none
  | .unb => some (-2 ^ 127)

/-- Largest candidate of an end bound; `checked_sub` fails at `i128::MIN`. -/
def last : Bound Int → Option Int
  | .incl n => some n
  | .excl n => if -2 ^ 127 ≤ n - 1 then some (n - 1) else none
  | .unb => some (2 ^ 127 - 1)

/-- `has_int`. -/
def HasInt (r : Range Int) : Prop :=
  match first r.1, last r.2 with
  | some f, some l => f ≤ l
  | _, _ => False

instance (r : Range Int) : Decidable (HasInt r) := by
  unfold HasInt
  split <;> infer_instance

def BoundInI128 : Bound Int → Prop
  | .incl n | .excl n => InI128 n
  | .unb => True

theorem first_spec (b : Bound Int) (hb : BoundInI128 b) :
    match first b with
    | some f => InI128 f ∧ Above (· < ·) b f ∧ ∀ n, InI128 n → (Above (· < ·) b n ↔ f ≤ n)
    | none => ∀ n, InI128 n → ¬Above (· < ·) b n := by
  cases b with
  | incl a => exact ⟨hb, .inr rfl, fun n _ => by simp only [Above, Le]; omega⟩
  | excl a =>
    simp only [BoundInI128, InI128] at hb
    by_cases c : a + 1 < 2 ^ 127
    · rw [show first (.excl a) = some (a + 1) by simp [first]; omega]
      refine ⟨by simp only [InI128]; omega, ?_, fun n _ => ?_⟩ <;> simp only [Above] <;> omega
    · rw [show first (.excl a) = none by simp [first]; omega]
      intro n hn
      simp only [Above, InI128] at hn ⊢
      omega
  | unb =>
    exact ⟨by simp only [InI128]; omega, trivial, fun n hn => ⟨fun _ => hn.1, fun _ => trivial⟩⟩

theorem last_spec (b : Bound Int) (hb : BoundInI128 b) :
    match last b with
    | some l => InI128 l ∧ Below (· < ·) b l ∧ ∀ n, InI128 n → (Below (· < ·) b n ↔ n ≤ l)
    | none => ∀ n, InI128 n → ¬Below (· < ·) b n := by
  cases b with
  | incl a => exact ⟨hb, .inr rfl, fun n _ => by simp only [Below, Le]; omega⟩
  | excl a =>
    simp only [BoundInI128, InI128] at hb
    by_cases c : -2 ^ 127 ≤ a - 1
    · rw [show last (.excl a) = some (a - 1) by simp [last]; omega]
      refine ⟨by simp only [InI128]; omega, ?_, fun n _ => ?_⟩ <;> simp only [Below] <;> omega
    · rw [show last (.excl a) = none by simp [last]; omega]
      intro n hn
      simp only [Below, InI128] at hn ⊢
      omega
  | unb =>
    refine ⟨by simp only [InI128]; omega, trivial, fun n hn => ⟨fun _ => ?_, fun _ => trivial⟩⟩
    have := hn.2
    omega

/-- `has_int` holds iff the range holds an `i128`. -/
theorem hasInt_iff (r : Range Int) (hs : BoundInI128 r.1) (he : BoundInI128 r.2) :
    HasInt r ↔ ∃ n, InI128 n ∧ ContainsInt r n := by
  have hf := first_spec r.1 hs
  have hl := last_spec r.2 he
  simp only [HasInt, ContainsInt, Contains]
  revert hf hl
  cases first r.1 <;> cases last r.2 <;> intro hf hl <;> dsimp only at hf hl ⊢
  · exact ⟨False.elim, fun ⟨n, hn, ha, _⟩ => hf n hn ha⟩
  · exact ⟨False.elim, fun ⟨n, hn, ha, _⟩ => hf n hn ha⟩
  · exact ⟨False.elim, fun ⟨n, hn, _, hb⟩ => hl n hn hb⟩
  · next f l =>
    constructor
    · exact fun h => ⟨f, hf.1, hf.2.1, (hl.2.2 f hf.1).2 h⟩
    · rintro ⟨n, hn, ha, hb⟩
      exact Int.le_trans ((hf.2.2 n hn).1 ha) ((hl.2.2 n hn).1 hb)

/-- An `int` range that passes `has_int` also passes the bound comparison. -/
theorem ordered_of_hasInt (r : Range Int) (hs : BoundInI128 r.1) (he : BoundInI128 r.2)
    (h : HasInt r) : Ordered (· < ·) r :=
  let ⟨n, _, hn⟩ := (hasInt_iff r hs he).1 h
  ordered_of_contains (· < ·) Int.lt_trans r n hn

/-! ## `ValueSpec::matches` for `int` specs -/

def MatchesInt (ranges : List (Range Int)) (neg : Bool) (t : List Nat) : Prop :=
  ∃ n, parseI128 neg t = some n ∧ ∃ r ∈ ranges, ContainsInt r n

/-- An `int` spec accepts exactly the canonical spellings of the `i128` values
inside one of its ranges. -/
theorem matchesInt_iff (ranges : List (Range Int)) (neg : Bool) (t : List Nat) :
    MatchesInt ranges neg t ↔
      ∃ n, InI128 n ∧ (neg, t) = renderInt n ∧ ∃ r ∈ ranges, ContainsInt r n := by
  simp only [MatchesInt, parseI128_iff, and_assoc]

/-! ## Rust unit tests restated -/

-- `values_must_be_canonical`: "0", "7", "-7", "10"; then "", "-", "07", "-0", "00".
example : parseI128 false [0] = some 0 := by decide
example : parseI128 false [7] = some 7 := by decide
example : parseI128 true [7] = some (-7) := by decide
example : parseI128 false [1, 0] = some 10 := by decide
example : parseI128 false [] = none := by decide
example : parseI128 true [] = none := by decide
example : parseI128 false [0, 7] = none := by decide
example : parseI128 true [0] = none := by decide
example : parseI128 false [0, 0] = none := by decide

-- `empty_ranges_are_rejected`: `5..<5`, `5<..=5`, `5<..<5`, `5<..<6`, `5..=4`.
example : ¬HasInt (.incl 5, .excl 5) := by decide
example : ¬HasInt (.excl 5, .incl 5) := by decide
example : ¬HasInt (.excl 5, .excl 5) := by decide
example : ¬HasInt (.excl 5, .excl 6) := by decide
example : ¬HasInt (.incl 5, .incl 4) := by decide
example : HasInt (.excl 4, .excl 6) := by decide

-- `int_is_bounded_by_i128`: `..<MIN` and `MAX<..` hold no `i128`.
example : ¬HasInt (.unb, .excl (-2 ^ 127)) := by decide
example : ¬HasInt (.excl (2 ^ 127 - 1), .unb) := by decide
example : HasInt (.incl (-2 ^ 127), .incl (2 ^ 127 - 1)) := by decide

end DstackFormal.Guest.ValueSpec
