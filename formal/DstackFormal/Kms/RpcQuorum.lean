-- SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
--
-- SPDX-License-Identifier: Apache-2.0

/-!
# RPC quorum: n of m providers

Models `quorumTransport` in `dstack/kms/auth-eth/index.ts`: `agree`, which
answers `eth_chainId`, `eth_call` and a block read by number, and `reached`,
which resolves a block tag.

Proven, for a threshold `n` and fewer than `n` faulty providers:
* `agree_honest`: an answer `agree` returns is the one the honest providers
  give; `agree_complete`: `n` honest votes for it are enough to get it.
* `agree_unique`: with `2n > m` at most one answer can gather `n` votes, so
  the result does not depend on the order the votes arrive in.
* `reached_le_honest`: the block a tag resolves to is no higher than one an
  honest provider has reached.
* `reached_ge_honest`: it is no lower than one an honest provider has reached
  when `n` honest providers answer, which takes at most `m - n` faulty or
  silent ones. `reached_stale` shows the bound is tight: with `m/m`, one
  provider holds the block back as far as it likes.

Assumptions: an honest provider answers a read pinned to a block with the one
true answer or not at all, and reports a block it has reached.
Modeling gaps: answers are compared as the code's keys (the result, or
`hash:number:timestamp`); timeouts, the HTTP layer and `resolveBlock`, which
chains a tag, a block read and the calls, are not modeled.
-/

namespace DstackFormal.Kms.RpcQuorum

theorem countP_le_add {β : Type} (p q r : β → Bool) (l : List β)
    (h : ∀ x ∈ l, r x = true → p x = true ∨ q x = true) :
    l.countP r ≤ l.countP p + l.countP q := by
  induction l with
  | nil => simp
  | cons x xs ih =>
    have ih := ih fun y hy => h y (List.mem_cons_of_mem x hy)
    have hx := h x List.mem_cons_self
    simp only [List.countP_cons]
    cases hr : r x <;> cases hp : p x <;> cases hq : q x <;> simp_all <;> omega

/-! ## Agreement on one answer -/

section Agree
variable {α : Type} [DecidableEq α]

/-- `agree`: the votes in the order they arrive, `none` for a provider that
fails; `seen` holds the answers counted so far. -/
def agreeFrom (n : Nat) (seen : List α) : List (Option α) → Option α
  | [] => none
  | none :: rest => agreeFrom n seen rest
  | some a :: rest => if n ≤ seen.count a + 1 then some a else agreeFrom n (a :: seen) rest

def agree (n : Nat) (votes : List (Option α)) : Option α := agreeFrom n [] votes

theorem agreeFrom_count {n : Nat} {v : α} (votes : List (Option α)) (seen : List α)
    (h : agreeFrom n seen votes = some v) : n ≤ seen.count v + votes.count (some v) := by
  induction votes generalizing seen with
  | nil => simp [agreeFrom] at h
  | cons vote rest ih =>
    cases vote with
    | none => have := ih seen (by simpa [agreeFrom] using h); simpa using this
    | some a =>
      simp only [agreeFrom] at h
      split at h
      · cases h; simp; omega
      · have := ih (a :: seen) h
        simp only [List.count_cons] at this ⊢
        by_cases hav : a = v <;> simp_all <;> omega

/-- An answer `agree` returns has `n` votes. -/
theorem agree_count {n : Nat} {v : α} {votes : List (Option α)} (h : agree n votes = some v) :
    n ≤ votes.count (some v) := by
  simpa using agreeFrom_count votes [] h

theorem agreeFrom_isSome {n : Nat} {v : α} (votes : List (Option α)) (seen : List α)
    (hseen : ∀ x, seen.count x < n) (h : n ≤ seen.count v + votes.count (some v)) :
    (agreeFrom n seen votes).isSome := by
  induction votes generalizing seen with
  | nil => have := hseen v; simp at h; omega
  | cons vote rest ih =>
    cases vote with
    | none => simpa [agreeFrom] using ih seen hseen (by simpa using h)
    | some a =>
      simp only [agreeFrom]
      split
      · rfl
      · next hlt =>
        refine ih (a :: seen) (fun x => ?_) ?_
        · have := hseen x
          simp only [List.count_cons]
          by_cases hax : a = x <;> simp_all <;> omega
        · simp only [List.count_cons] at h ⊢
          by_cases hav : a = v <;> simp_all <;> omega

/-- One provider's vote. -/
structure Vote (α : Type) where
  honest : Bool
  answer : Option α

/-- With fewer than `n` faulty providers, `agree` returns only the answer of
the honest ones. -/
theorem agree_honest {n : Nat} {t v : α} {votes : List (Vote α)}
    (hfaulty : votes.countP (fun x => !x.honest) < n)
    (hhonest : ∀ x ∈ votes, x.honest = true → x.answer = none ∨ x.answer = some t)
    (h : agree n (votes.map (·.answer)) = some v) : v = t := by
  refine Classical.byContradiction fun hne => ?_
  have hcount := agree_count h
  rw [List.count_eq_countP, List.countP_map] at hcount
  have := List.countP_mono_left (l := votes) (p := (· == some v) ∘ (·.answer))
    (q := fun x => !x.honest) fun x hx hv => by
      cases hh : x.honest
      · rfl
      · rcases hhonest x hx hh with h0 | h0 <;> simp_all
  omega

/-- `n` honest votes for an answer are enough for `agree` to return it. -/
theorem agree_complete {n : Nat} {t : α} {votes : List (Vote α)} (hn : 0 < n)
    (hfaulty : votes.countP (fun x => !x.honest) < n)
    (hhonest : ∀ x ∈ votes, x.honest = true → x.answer = none ∨ x.answer = some t)
    (h : n ≤ votes.countP (fun x => x.honest && x.answer == some t)) :
    agree n (votes.map (·.answer)) = some t := by
  have hsome : (agree n (votes.map (·.answer))).isSome := by
    refine agreeFrom_isSome (v := t) _ [] (fun _ => by simpa using hn) ?_
    rw [List.count_nil, Nat.zero_add, List.count_eq_countP, List.countP_map]
    have := List.countP_mono_left (l := votes) (p := fun x => x.honest && x.answer == some t)
      (q := (· == some t) ∘ (·.answer)) fun x _ hx => by simp_all
    simp; omega
  obtain ⟨v, hv⟩ := Option.isSome_iff_exists.mp hsome
  rw [hv, agree_honest hfaulty hhonest hv]

theorem count_add_le {v w : α} (hne : v ≠ w) (l : List (Option α)) :
    l.count (some v) + l.count (some w) ≤ l.length := by
  induction l with
  | nil => simp
  | cons x xs ih =>
    simp only [List.count_cons, List.length_cons]
    by_cases h1 : x = some v <;> by_cases h2 : x = some w <;> simp_all <;> omega

/-- With `2n > m`, two answers cannot both gather `n` votes. -/
theorem agree_unique {n : Nat} {v w : α} {votes : List (Option α)}
    (hmajority : votes.length < 2 * n)
    (hv : n ≤ votes.count (some v)) (hw : n ≤ votes.count (some w)) : v = w := by
  refine Classical.byContradiction fun hne => ?_
  have := count_add_le hne votes
  omega

end Agree

/-! ## The block a tag resolves to -/

/-- `reached`: the `n`-th highest of the blocks the providers report. -/
def reached (n : Nat) (heights : List Nat) : Option Nat :=
  (heights.mergeSort fun a b => decide (b ≤ a))[n - 1]?

theorem sorted_nth (l : List Nat) (hp : l.Pairwise fun a b => b ≤ a) (i h : Nat)
    (hi : l[i]? = some h) :
    i + 1 ≤ l.countP (fun x => decide (h ≤ x)) ∧ l.countP (fun x => decide (h < x)) ≤ i := by
  induction l generalizing i with
  | nil => simp at hi
  | cons x xs ih =>
    have ⟨hx, hxs⟩ := List.pairwise_cons.mp hp
    cases i with
    | zero =>
      simp at hi; subst hi
      refine ⟨by simp, ?_⟩
      have : xs.countP (fun y => decide (x < y)) = 0 := by
        rw [List.countP_eq_zero]; intro y hy; have := hx y hy; simp; omega
      simp [this]
    | succ k =>
      have hk : xs[k]? = some h := by simpa using hi
      have ⟨h1, h2⟩ := ih hxs k hk
      have hle : h ≤ x := hx h (List.mem_of_getElem? hk)
      simp only [List.countP_cons]
      refine ⟨by simp [hle]; omega, ?_⟩
      split <;> omega

/-- `n` providers have reached the block, and fewer than `n` a higher one. -/
theorem reached_spec {n h : Nat} {heights : List Nat} (hn : 0 < n)
    (hr : reached n heights = some h) :
    n ≤ heights.countP (fun x => decide (h ≤ x)) ∧ heights.countP (fun x => decide (h < x)) < n := by
  have hsorted := List.pairwise_mergeSort (le := fun a b : Nat => decide (b ≤ a))
    (fun a b c hab hbc => by simp_all; omega) (fun a b => by simp; omega) heights
  have hperm := List.mergeSort_perm heights fun a b => decide (b ≤ a)
  have ⟨h1, h2⟩ := sorted_nth _ (hsorted.imp (by simp)) (n - 1) h hr
  rw [hperm.countP_eq] at h1 h2
  omega

/-- With fewer than `n` faulty providers, an honest one has reached the block:
it exists, and no earlier than they say. -/
theorem reached_le_honest {n h : Nat} {reports : List (Bool × Nat)} (hn : 0 < n)
    (hfaulty : reports.countP (fun r => !r.1) < n)
    (hr : reached n (reports.map (·.2)) = some h) :
    ∃ r ∈ reports, r.1 = true ∧ h ≤ r.2 := by
  refine Classical.byContradiction fun hnone => ?_
  have ⟨h1, _⟩ := reached_spec hn hr
  rw [List.countP_map] at h1
  have := List.countP_mono_left (l := reports) (p := (fun x => decide (h ≤ x)) ∘ (·.2))
    (q := fun r => !r.1) fun r hr hle => by
      cases hh : r.1
      · rfl
      · exact absurd ⟨r, hr, hh, by simpa using hle⟩ hnone
  omega

/-- When `n` honest providers answer, the block is no lower than one of them
has reached. `reports` holds the providers that answered, so the hypothesis
allows `m - n` faulty or silent ones. -/
theorem reached_ge_honest {n h : Nat} {reports : List (Bool × Nat)} (hn : 0 < n)
    (hhonest : reports.countP (fun r => !r.1) + n ≤ reports.length)
    (hr : reached n (reports.map (·.2)) = some h) :
    ∃ r ∈ reports, r.1 = true ∧ r.2 ≤ h := by
  refine Classical.byContradiction fun hnone => ?_
  have ⟨_, h2⟩ := reached_spec hn hr
  rw [List.countP_map] at h2
  have := countP_le_add (fun r => !r.1) ((fun x => decide (h < x)) ∘ (·.2)) (fun _ => true) reports
    fun r hr _ => by
      cases hh : r.1
      · simp
      · refine Or.inr ?_
        have : ¬ r.2 ≤ h := fun hle => hnone ⟨r, hr, hh, hle⟩
        simp; omega
  simp at this
  omega

/-- The bound of `reached_ge_honest` is tight: with `m/m`, the block is no
higher than any one provider reports, so one of them holds it back as far as it
likes. -/
theorem reached_stale {n x : Nat} {heights : List Nat} (hn : 0 < n)
    (hall : heights.length = n) (hx : x ∈ heights) :
    ∃ h, reached n heights = some h ∧ h ≤ x := by
  have hlt : n - 1 < (heights.mergeSort fun a b => decide (b ≤ a)).length := by
    rw [List.length_mergeSort]; omega
  generalize hh : (heights.mergeSort fun a b => decide (b ≤ a))[n - 1] = h
  have hr : reached n heights = some h := by rw [← hh]; exact List.getElem?_eq_getElem hlt
  have ⟨h1, _⟩ := reached_spec hn hr
  have hle := List.countP_le_length (p := fun y => decide (h ≤ y)) (l := heights)
  have hall' : heights.countP (fun y => decide (h ≤ y)) = heights.length := by omega
  exact ⟨h, hr, by simpa using List.countP_eq_length.mp hall' x hx⟩

end DstackFormal.Kms.RpcQuorum
