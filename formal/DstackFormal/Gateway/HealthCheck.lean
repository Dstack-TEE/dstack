-- SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
--
-- SPDX-License-Identifier: Apache-2.0

/-!
# Health hysteresis and backend selection

Models `apply_hysteresis` (`dstack/gateway/src/proxy/health_check.rs`) and, from
`dstack/gateway/src/main_service.rs`, `ProxyState::is_eligible`, `handshake_is_fresh`,
`retain_healthy`, the app-id path of `select_top_n_hosts`, and the candidate set of
`random_select_a_host`. `HealthState::is_healthy` and `InstanceInfo::is_ready` come from
`models.rs`.

Proven (hysteresis, per target; the `failures` map entry is a counter, absent = 0):
* `counter_is_trailing_failures`: the counter is the number of trailing consecutive unreachable
  polls since the last answered poll.
* `unreachable_demotes_iff`: an unreachable poll yields `Unhealthy` iff it completes a run of at
  least `max threshold 1` consecutive failures; otherwise it yields no verdict.
* `healthy_survives_short_outage`, `demoted_after_threshold`: an instance's state is unchanged
  by fewer than `threshold` consecutive failures and is `Unhealthy` after `threshold`; an
  answered poll resets the counter (`answer_resets`).

Proven (selection, `connect_top_n = n`):
* `select_eligible`: every selected address is an eligible instance of the app.
* `select_prefers_healthy`: if some eligible instance is healthy, every selected one is.
* `select_nonempty`: with `n ≥ 1`, the selection is nonempty iff some instance is eligible
  (fail-open on health, fail-closed on the operator gate and on stale tunnels).
* `select_fresher_first`: selected candidates are ordered by handshake age.
* `random_candidates_*`: the same three facts for the `n = 0` random path's candidate set.
* `instance_id_bypasses_gate`: addressing an instance id returns it whatever its gate or health
  (documented in the code).

Modeling gap: the `top_n` cache (a cached selection is reused for up to `cache_top_n`), the
`localhost` shortcut, the handshake-read failure fallback, the rate-limited warning, and
connection counters are not modeled. Durations are `Nat`; the counter is `Nat` (Rust `u32`
`+= 1` would overflow only after 2^32 consecutive failures).
-/

namespace DstackFormal.Gateway.HealthCheck

/-- `models::HealthState`. -/
inductive HealthState where
  | unknown
  | healthy
  | unhealthy
  | ungated
deriving DecidableEq, Repr

/-- `HealthState::is_healthy`. -/
def HealthState.isHealthy : HealthState → Bool
  | .healthy | .ungated => true
  | _ => false

/-- `PollResult` (reasons dropped). -/
inductive PollResult where
  | healthy
  | unhealthy
  | unreachable
deriving DecidableEq, Repr

/-- `apply_hysteresis` for one target: the observation and the new counter. -/
def applyHysteresis (threshold : Nat) (failures : Nat) : PollResult → Option HealthState × Nat
  | .healthy => (some .healthy, 0)
  | .unhealthy => (some .unhealthy, 0)
  | .unreachable =>
    let seen := failures + 1
    if seen < threshold then (none, seen) else (some .unhealthy, seen)

/-- The instance's state after an observation (`set_health` on `Some`, unchanged on `None`). -/
def observe (s : HealthState) : Option HealthState → HealthState
  | some s' => s'
  | none => s

/-- A run of polls from `(state, counter)`. -/
def runPolls (threshold : Nat) : HealthState × Nat → List PollResult → HealthState × Nat
  | st, [] => st
  | (s, c), p :: ps =>
    let r := applyHysteresis threshold c p
    runPolls threshold (observe s r.1, r.2) ps

/-- Number of trailing `unreachable` polls. -/
def trailing (ps : List PollResult) : Nat :=
  (ps.reverse.takeWhile (· == .unreachable)).length

theorem runPolls_append (threshold : Nat) (st : HealthState × Nat) (ps qs : List PollResult) :
    runPolls threshold st (ps ++ qs) = runPolls threshold (runPolls threshold st ps) qs := by
  induction ps generalizing st with
  | nil => rfl
  | cons p ps ih => obtain ⟨s, c⟩ := st; simp [runPolls, ih]

theorem counter_step (threshold c : Nat) (p : PollResult) :
    (applyHysteresis threshold c p).2 = if p = .unreachable then c + 1 else 0 := by
  cases p <;> simp [applyHysteresis] <;> split <;> rfl

theorem counter_is_trailing_failures (threshold : Nat) (s : HealthState) :
    ∀ ps : List PollResult, (runPolls threshold (s, 0) ps).2 = trailing ps := by
  intro ps
  induction h : ps.length using Nat.strongRecOn generalizing ps with
  | ind k ih =>
    rcases List.eq_nil_or_concat ps with rfl | ⟨qs, p, rfl⟩
    · rfl
    · simp only [List.concat_eq_append] at h ⊢
      rw [runPolls_append]
      rcases hrun : runPolls threshold (s, 0) qs with ⟨s', c'⟩
      have hc : c' = trailing qs := by
        rw [← ih qs.length (by simp at h; omega) qs rfl, hrun]
      simp only [runPolls, counter_step, trailing, List.reverse_append, List.reverse_cons,
        List.reverse_nil, List.nil_append, List.singleton_append]
      cases p <;> simp [hc, trailing]

theorem unreachable_demotes_iff (threshold c : Nat) :
    (applyHysteresis threshold c .unreachable).1 =
      if max threshold 1 ≤ c + 1 then some .unhealthy else none := by
  simp only [applyHysteresis]
  by_cases h : c + 1 < threshold
  · simp [h]; omega
  · simp [h]; omega

theorem answer_resets (threshold c : Nat) :
    applyHysteresis threshold c .healthy = (some .healthy, 0) ∧
    applyHysteresis threshold c .unhealthy = (some .unhealthy, 0) := ⟨rfl, rfl⟩

theorem runPolls_unreachable (threshold : Nat) (s : HealthState) (c j : Nat)
    (h : c + j < threshold) :
    runPolls threshold (s, c) (List.replicate j .unreachable) = (s, c + j) := by
  induction j generalizing c with
  | zero => rfl
  | succ j ih =>
    simp only [List.replicate_succ, runPolls, applyHysteresis]
    have : c + 1 < threshold := by omega
    simp only [this, ↓reduceIte, observe]
    rw [ih (c + 1) (by omega)]; congr 1; omega

/-- Fewer than `threshold` consecutive failures leave the state as it was. -/
theorem healthy_survives_short_outage (threshold : Nat) (s : HealthState) (c j : Nat)
    (h : c + j < threshold) :
    (runPolls threshold (s, c) (List.replicate j .unreachable)).1 = s := by
  rw [runPolls_unreachable threshold s c j h]

/-- `threshold` consecutive failures (from any counter) leave the instance unhealthy. -/
theorem demoted_after_threshold (threshold : Nat) (s : HealthState) (c : Nat) :
    ∀ j, max threshold 1 ≤ j →
      (runPolls threshold (s, c) (List.replicate j .unreachable)).1 = .unhealthy := by
  intro j hj
  have key : ∀ (k : Nat) (s : HealthState) (c : Nat), max threshold 1 ≤ c + 1 →
      (runPolls threshold (s, c) (List.replicate (k + 1) .unreachable)).1 = .unhealthy := by
    intro k
    induction k with
    | zero =>
      intro s c hc
      simp only [List.replicate, runPolls, applyHysteresis]
      have : ¬ c + 1 < threshold := by omega
      simp [this, observe]
    | succ k ih =>
      intro s c hc
      rw [List.replicate_succ, runPolls]
      exact ih _ _ (by simp [counter_step]; omega)
  by_cases hc : max threshold 1 ≤ c + 1
  · obtain ⟨k, rfl⟩ : ∃ k, j = k + 1 := ⟨j - 1, by omega⟩
    exact key k s c hc
  · obtain ⟨m, hm⟩ : ∃ m, c + m + 1 = max threshold 1 := ⟨max threshold 1 - c - 1, by omega⟩
    have hsplit : List.replicate j PollResult.unreachable =
        List.replicate m .unreachable ++ List.replicate (j - m) .unreachable := by
      rw [List.replicate_append_replicate]; congr 1; omega
    rw [hsplit, runPolls_append, runPolls_unreachable threshold s c m (by omega)]
    obtain ⟨k, hk⟩ : ∃ k, j - m = k + 1 := ⟨j - m - 1, by omega⟩
    rw [hk]
    exact key k s (c + m) (by omega)

-- a_single_failure_does_not_demote
#guard (applyHysteresis 2 0 .unreachable).1 == none
-- consecutive_failures_reach_the_threshold_and_demote
#guard (runPolls 2 (.healthy, 0) [.unreachable, .unreachable]).1 == .unhealthy
-- a success resets the count
#guard (runPolls 2 (.healthy, 0) [.unreachable, .healthy, .unreachable]).1 == .healthy
-- threshold zero or one demotes on the first failure
#guard [0, 1].all fun t => (applyHysteresis t 0 .unreachable).1 == some .unhealthy

/-! ## Selection -/

/-- The fields of `InstanceInfo` selection reads. -/
structure Inst where
  id : Nat
  ip : Nat
  publicKey : Nat
  ready : Option Bool
  health : HealthState
deriving DecidableEq, Repr

/-- `InstanceInfo::is_ready`. -/
def Inst.isReady (i : Inst) : Bool := i.ready.getD true

structure SelCfg where
  handshakeStale : Nat
  healthGating : Bool
  topN : Nat

/-- `handshake_is_fresh`; `hs` maps a public key to the elapsed time since its handshake. -/
def handshakeIsFresh (cfg : SelCfg) (hs : Nat → Option Nat) (i : Inst) : Bool :=
  match hs i.publicKey with
  | some e => decide (e < cfg.handshakeStale)
  | none => false

/-- `ProxyState::is_eligible`. -/
def isEligible (cfg : SelCfg) (hs : Nat → Option Nat) (i : Inst) : Bool :=
  i.isReady && handshakeIsFresh cfg hs i

/-- `Candidate`. -/
structure Candidate where
  inst : Inst
  age : Nat
  healthy : Bool

/-- The `filter_map` building candidates in `select_top_n_hosts`. -/
def candidates (cfg : SelCfg) (hs : Nat → Option Nat) (app : List Inst) : List Candidate :=
  app.filterMap fun i =>
    if isEligible cfg hs i then
      (hs i.publicKey).map fun e => ⟨i, e, !cfg.healthGating || i.health.isHealthy⟩
    else none

/-- `retain_healthy`. -/
def retainHealthy {α : Type} (healthy : α → Bool) (cs : List α) : List α :=
  if cs.any healthy then cs.filter healthy else cs

/-- The app-id path of `select_top_n_hosts` (cache and fallbacks aside). -/
def selectTopN (cfg : SelCfg) (hs : Nat → Option Nat) (app : List Inst) : List Inst :=
  (((retainHealthy (·.healthy) (candidates cfg hs app)).mergeSort
    (fun a b => decide (a.age ≤ b.age))).take cfg.topN).map (·.inst)

/-- The candidates `random_select_a_host` chooses from. -/
def randomCandidates (cfg : SelCfg) (hs : Nat → Option Nat) (app : List Inst) : List Inst :=
  ((retainHealthy (·.2) (app.filterMap fun i =>
    if isEligible cfg hs i then some (i, !cfg.healthGating || i.health.isHealthy) else none))).map
    (·.1)

/-- `select_top_n_hosts` when `id` names an instance: the instance, unconditionally. -/
def selectById (instances : List Inst) (id : Nat) : Option Inst := instances.find? (·.id == id)

/-- Whether an instance counts as healthy for selection. -/
def healthyFor (cfg : SelCfg) (i : Inst) : Bool := !cfg.healthGating || i.health.isHealthy

theorem mem_candidates {cfg : SelCfg} {hs : Nat → Option Nat} {app : List Inst} {c : Candidate} :
    c ∈ candidates cfg hs app ↔
      c.inst ∈ app ∧ isEligible cfg hs c.inst = true ∧ hs c.inst.publicKey = some c.age ∧
        c.healthy = healthyFor cfg c.inst := by
  unfold candidates
  rw [List.mem_filterMap]
  constructor
  · rintro ⟨i, hi, he⟩
    by_cases hel : isEligible cfg hs i = true
    · simp only [hel, ↓reduceIte, Option.map_eq_some_iff] at he
      obtain ⟨e, he1, rfl⟩ := he
      exact ⟨hi, hel, he1, rfl⟩
    · simp [hel] at he
  · rintro ⟨hi, hel, hage, hh⟩
    refine ⟨c.inst, hi, ?_⟩
    simp only [hel, ↓reduceIte, hage, Option.map_some, Option.some.injEq]
    cases c; simp_all [healthyFor]

theorem retainHealthy_sub {α : Type} {h : α → Bool} {cs : List α} {x : α}
    (hx : x ∈ retainHealthy h cs) : x ∈ cs := by
  unfold retainHealthy at hx; split at hx
  · exact (List.mem_filter.mp hx).1
  · exact hx

theorem retainHealthy_healthy {α : Type} {h : α → Bool} {cs : List α}
    (hany : ∃ x ∈ cs, h x = true) {x : α} (hx : x ∈ retainHealthy h cs) : h x = true := by
  unfold retainHealthy at hx
  have : cs.any h = true := List.any_eq_true.mpr hany
  simp only [this, ↓reduceIte] at hx
  exact (List.mem_filter.mp hx).2

theorem retainHealthy_ne_nil {α : Type} {h : α → Bool} {cs : List α} (hne : cs ≠ []) :
    retainHealthy h cs ≠ [] := by
  unfold retainHealthy
  split
  · rename_i ha
    obtain ⟨x, hx, hh⟩ := List.any_eq_true.mp ha
    intro he
    have : x ∈ cs.filter h := List.mem_filter.mpr ⟨hx, hh⟩
    rw [he] at this; simp at this
  · exact hne

theorem retainHealthy_nil {α : Type} {h : α → Bool} : retainHealthy h ([] : List α) = [] := rfl

theorem mem_select {cfg : SelCfg} {hs : Nat → Option Nat} {app : List Inst} {i : Inst}
    (h : i ∈ selectTopN cfg hs app) :
    ∃ c ∈ retainHealthy (·.healthy) (candidates cfg hs app), c.inst = i := by
  unfold selectTopN at h
  obtain ⟨c, hc, rfl⟩ := List.mem_map.mp h
  exact ⟨c, List.mem_mergeSort.mp (List.mem_of_mem_take hc), rfl⟩

theorem select_eligible {cfg : SelCfg} {hs : Nat → Option Nat} {app : List Inst} {i : Inst}
    (h : i ∈ selectTopN cfg hs app) : i ∈ app ∧ isEligible cfg hs i = true := by
  obtain ⟨c, hc, rfl⟩ := mem_select h
  have := mem_candidates.mp (retainHealthy_sub hc)
  exact ⟨this.1, this.2.1⟩

theorem select_prefers_healthy {cfg : SelCfg} {hs : Nat → Option Nat} {app : List Inst}
    (hex : ∃ j ∈ app, isEligible cfg hs j = true ∧ healthyFor cfg j = true) {i : Inst}
    (h : i ∈ selectTopN cfg hs app) : healthyFor cfg i = true := by
  obtain ⟨c, hc, rfl⟩ := mem_select h
  obtain ⟨j, hj, hel, hhj⟩ := hex
  have hfresh : ∃ e, hs j.publicKey = some e := by
    unfold isEligible handshakeIsFresh at hel
    cases he : hs j.publicKey with
    | none => simp [he] at hel
    | some e => exact ⟨e, rfl⟩
  obtain ⟨e, he⟩ := hfresh
  have hcj : (⟨j, e, healthyFor cfg j⟩ : Candidate) ∈ candidates cfg hs app :=
    mem_candidates.mpr ⟨hj, hel, he, rfl⟩
  have := retainHealthy_healthy ⟨_, hcj, hhj⟩ hc
  rw [(mem_candidates.mp (retainHealthy_sub hc)).2.2.2] at this
  exact this

theorem candidates_ne_nil {cfg : SelCfg} {hs : Nat → Option Nat} {app : List Inst} :
    candidates cfg hs app ≠ [] ↔ ∃ j ∈ app, isEligible cfg hs j = true := by
  constructor
  · intro hne
    obtain ⟨c, hc⟩ := List.exists_mem_of_ne_nil _ hne
    have := mem_candidates.mp hc
    exact ⟨c.inst, this.1, this.2.1⟩
  · rintro ⟨j, hj, hel⟩
    have hfresh : ∃ e, hs j.publicKey = some e := by
      unfold isEligible handshakeIsFresh at hel
      cases he : hs j.publicKey with
      | none => simp [he] at hel
      | some e => exact ⟨e, rfl⟩
    obtain ⟨e, he⟩ := hfresh
    have hcj : (⟨j, e, healthyFor cfg j⟩ : Candidate) ∈ candidates cfg hs app :=
      mem_candidates.mpr ⟨hj, hel, he, rfl⟩
    intro hn; rw [hn] at hcj; simp at hcj

theorem select_nonempty {cfg : SelCfg} {hs : Nat → Option Nat} {app : List Inst}
    (hn : 1 ≤ cfg.topN) :
    selectTopN cfg hs app ≠ [] ↔ ∃ j ∈ app, isEligible cfg hs j = true := by
  rw [← candidates_ne_nil]
  unfold selectTopN
  constructor
  · intro h hc
    apply h
    rw [hc, retainHealthy_nil]; simp
  · intro hc
    have h1 := retainHealthy_ne_nil (h := (·.healthy)) hc
    have h2 : (retainHealthy (·.healthy) (candidates cfg hs app)).mergeSort
        (fun a b => decide (a.age ≤ b.age)) ≠ [] := by
      intro he
      have := congrArg List.length he
      rw [List.length_mergeSort] at this
      exact h1 (List.eq_nil_of_length_eq_zero this)
    obtain ⟨x, xs, hx⟩ := List.exists_cons_of_ne_nil h2
    rw [hx]
    obtain ⟨k, hk⟩ : ∃ k, cfg.topN = k + 1 := ⟨cfg.topN - 1, by omega⟩
    rw [hk]; simp

theorem select_fresher_first {cfg : SelCfg} {hs : Nat → Option Nat} {app : List Inst} :
    (((retainHealthy (·.healthy) (candidates cfg hs app)).mergeSort
      (fun a b => decide (a.age ≤ b.age))).take cfg.topN).Pairwise (fun a b => a.age ≤ b.age) := by
  have := List.pairwise_mergeSort (le := fun a b : Candidate => decide (a.age ≤ b.age))
    (by intro a b c h1 h2; simp only [decide_eq_true_eq] at *; omega)
    (by intro a b; simp only [Bool.or_eq_true, decide_eq_true_eq]; omega)
    (retainHealthy (·.healthy) (candidates cfg hs app))
  exact (this.imp (by simp)).sublist (List.take_sublist _ _)

theorem mem_randomCandidates {cfg : SelCfg} {hs : Nat → Option Nat} {app : List Inst}
    {i : Inst} (h : i ∈ randomCandidates cfg hs app) : i ∈ app ∧ isEligible cfg hs i = true := by
  unfold randomCandidates at h
  obtain ⟨p, hp, rfl⟩ := List.mem_map.mp h
  obtain ⟨j, hj, he⟩ := List.mem_filterMap.mp (retainHealthy_sub hp)
  by_cases hel : isEligible cfg hs j = true
  · simp only [hel, ↓reduceIte, Option.some.injEq] at he
    subst he; exact ⟨hj, hel⟩
  · simp [hel] at he

theorem random_candidates_prefer_healthy {cfg : SelCfg} {hs : Nat → Option Nat}
    {app : List Inst} (hex : ∃ j ∈ app, isEligible cfg hs j = true ∧ healthyFor cfg j = true)
    {i : Inst} (h : i ∈ randomCandidates cfg hs app) : healthyFor cfg i = true := by
  unfold randomCandidates at h
  obtain ⟨p, hp, rfl⟩ := List.mem_map.mp h
  obtain ⟨j, hj, hel, hhj⟩ := hex
  have hmem : (j, healthyFor cfg j) ∈ app.filterMap fun i =>
      if isEligible cfg hs i then some (i, !cfg.healthGating || i.health.isHealthy) else none :=
    List.mem_filterMap.mpr ⟨j, hj, by simp [hel, healthyFor]⟩
  have := retainHealthy_healthy ⟨_, hmem, hhj⟩ hp
  obtain ⟨k, _, hk⟩ := List.mem_filterMap.mp (retainHealthy_sub hp)
  by_cases hek : isEligible cfg hs k = true
  · simp only [hek, ↓reduceIte, Option.some.injEq] at hk
    subst hk; simpa [healthyFor] using this
  · simp [hek] at hk

theorem random_candidates_nonempty {cfg : SelCfg} {hs : Nat → Option Nat} {app : List Inst}
    (hex : ∃ j ∈ app, isEligible cfg hs j = true) : randomCandidates cfg hs app ≠ [] := by
  obtain ⟨j, hj, hel⟩ := hex
  unfold randomCandidates
  have hmem : (j, healthyFor cfg j) ∈ app.filterMap fun i =>
      if isEligible cfg hs i then some (i, !cfg.healthGating || i.health.isHealthy) else none :=
    List.mem_filterMap.mpr ⟨j, hj, by simp [hel, healthyFor]⟩
  have := retainHealthy_ne_nil (h := (·.2)) (List.ne_nil_of_mem hmem)
  simpa using this

theorem instance_id_bypasses_gate {instances : List Inst} {i : Inst} (hi : i ∈ instances)
    (hu : ∀ j ∈ instances, j.id = i.id → j = i) : selectById instances i.id = some i := by
  unfold selectById
  cases hf : instances.find? (·.id == i.id) with
  | none =>
    have := List.find?_eq_none.mp hf i hi
    simp at this
  | some j =>
    have hj := List.mem_of_find?_eq_some hf
    have hid := List.find?_some hf
    simp only [beq_iff_eq] at hid
    rw [hu j hj hid]

-- A gated instance and a stale tunnel are both excluded; health only breaks ties.
#guard (selectTopN ⟨10, true, 2⟩ (fun k => if k = 3 then none else some k)
  [⟨1, 101, 1, some false, .healthy⟩, ⟨2, 102, 2, none, .unknown⟩, ⟨3, 103, 3, none, .healthy⟩,
   ⟨4, 104, 4, none, .unhealthy⟩]).map (·.id) == [2, 4]

end DstackFormal.Gateway.HealthCheck
