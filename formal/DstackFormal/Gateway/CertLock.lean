-- SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
--
-- SPDX-License-Identifier: Apache-2.0

/-!
# Certificate renew / ACME rotation lease (`dstack/gateway/src/kv/mod.rs`)

Models `KvStore::try_acquire_lock`, `release_lock`, `lease_still_held` and
`force_release_cert_lock`, as used by `DistributedCertBot` (`distributed_certbot.rs`): a task
acquires, checks `ensure_cert_lock_held` / `ensure_rotation_lock_held` before each committed
write, and releases with the value it acquired.

Tracks branch `fix/gateway-lease-before-commit` at e68a9f8c22, which contains PRs #1599 (lock
value carries a random `nonce`), #1600 (a lease stamped beyond `MAX_CLOCK_DRIFT_SECS` is treated
as expired) and #1601 (release and lease-guarded writes are no-ops once the lease has expired by
the local clock), on wavekv 2.2 (a local write is stamped `max(now, held.timestamp + 1)`; merge is
last-writer-wins on `(timestamp, node, seq)`).

Single node (read, check and write share one write guard, so events are atomic):
* `release_keeps_other_holder`: a holder's release never removes another holder's lock, under any
  clock behaviour and any number of force releases (nonces are fresh).
* `one_unexpired_holder`: with a monotone clock and no force release, at most one holder's lease
  is unexpired. `force_release_now_safe` and `clock_step_back_now_safe` replay the two traces
  that broke ownership before the fix.

Cross node (an LWW register replicated with arbitrary delay):
* `release_loses_to_takeover`: a release by the holder of `L` writes a tombstone that loses LWW
  against the lock of any node that took `L` over, whatever the clock skew, as long as the
  successor's clock is no more than `MAX_CLOCK_DRIFT_SECS` behind `L.started_at` when it judges
  `L`. The argument is the one in the `release_lock` comment: the holder writes only while its
  clock is below `started_at + timeout`, and the successor takes over only once its own clock
  reads at least that, stamping no earlier.
* `guarded_commit_loses_to_successor`: the same for a write guarded by `lease_still_held` against
  any later write by the successor.
* `acquire_deadline`: the hypothesis these need on the lease's own entry holds when no earlier
  entry on the key was stamped within two ticks of the deadline.
* `stale_release_now_noop`, `slow_clock_release_loses`: concrete traces.

Limitations (no compare-and-swap), proven as counterexamples:
* `replication_gap_two_holders`: two nodes both acquire during a replication gap.
* `skew_beyond_drift_breaks_release`: a successor whose clock lags by more than the drift bound
  treats the lease as implausible and takes it over at once; the holder's release then deletes
  the successor's lock.
* `force_release_cross_node`: after a force release on another node, a successor's lock can be
  deleted by the old holder's release, which has not seen the force release.

Assumptions: node ids are distinct; nonces never repeat among outstanding locks (`rand::random`
idealized as an explicit precondition); clocks are monotone within a node where stated; all times
are in one unit (the lock compares whole seconds, wavekv stamps milliseconds; a comparison
against an integer second agrees in both).

Modeling gap: Rust reads the clock separately for the guard and for the wavekv stamp, and drops
the read guard between `lease_still_held` and the committed write; the model uses one clock
reading per event. Encoding failures and corrupt records (decoded as absent) are not modeled.
-/

namespace DstackFormal.Gateway.CertLock

/-- `kv::CertRenewLock`. -/
structure Lock where
  startedAt : Nat
  startedBy : Nat
  nonce : Nat
deriving DecidableEq, Repr

/-- `kv::MAX_CLOCK_DRIFT_SECS`. -/
def maxDrift : Nat := 300

/-- `KvStore::try_acquire_lock` on the local value of the key: the acquired lock, and the new
local value. -/
def tryAcquire (me now timeout nonce : Nat) (cur : Option Lock) : Option Lock × Option Lock :=
  match cur with
  | some e =>
    if e.startedAt ≤ now + maxDrift ∧ now < e.startedAt + timeout then (none, cur)
    else (some ⟨now, me, nonce⟩, some ⟨now, me, nonce⟩)
  | none => (some ⟨now, me, nonce⟩, some ⟨now, me, nonce⟩)

/-- `KvStore::lease_still_held`; also exactly when `release_lock` deletes. -/
def leaseHeld (acquired : Lock) (now timeout : Nat) (cur : Option Lock) : Bool :=
  decide (now < acquired.startedAt + timeout) && cur == some acquired

/-- `KvStore::release_lock` on the local value. -/
def release (acquired : Lock) (now timeout : Nat) (cur : Option Lock) : Option Lock :=
  if leaseHeld acquired now timeout cur then none else cur

theorem tryAcquire_some {me now timeout nonce : Nat} {L : Lock} {L' : Lock}
    (h : (tryAcquire me now timeout nonce (some L)).1 = some L') :
    (L.startedAt + timeout ≤ now ∨ now + maxDrift < L.startedAt) ∧ L' = ⟨now, me, nonce⟩ := by
  unfold tryAcquire at h
  by_cases hb : L.startedAt ≤ now + maxDrift ∧ now < L.startedAt + timeout
  · simp [hb] at h
  · simp only [hb, ↓reduceIte, Option.some.injEq] at h
    exact ⟨by omega, h.symm⟩

/-! ## Single node -/

/-- One node's view: the local value, the outstanding `(task, acquired)` pairs, and the clock. -/
structure Node where
  store : Option Lock
  holders : List (Nat × Lock)
  now : Nat
deriving DecidableEq, Repr

inductive Ev where
  /-- Task `task` calls `try_acquire_lock` at wall-clock `time`, drawing `nonce`. -/
  | acquire (task time nonce : Nat)
  /-- Task `task` calls `release_lock` with the lock it acquired, at wall-clock `time`. -/
  | release (task : Nat) (acquired : Lock) (time : Nat)
  /-- `Admin.ForceReleaseCertLock`. -/
  | forceRelease
deriving DecidableEq, Repr

def Node.apply (me timeout : Nat) (s : Node) : Ev → Node
  | .acquire task time nonce =>
    let r := tryAcquire me time timeout nonce s.store
    { store := r.2, now := time,
      holders := match r.1 with
        | some k => (task, k) :: s.holders
        | none => s.holders }
  | .release task k time =>
    { store := release k time timeout s.store, now := time,
      holders := s.holders.filter (· ≠ (task, k)) }
  | .forceRelease => { s with store := none }

/-- Fresh nonces; only holders release. With `strict`, also a monotone clock and no force
release. -/
def Ev.Allowed (strict : Bool) (s : Node) : Ev → Prop
  | .acquire _ time nonce => (∀ h ∈ s.holders, h.2.nonce ≠ nonce) ∧ (strict = true → s.now ≤ time)
  | .release task k time => (task, k) ∈ s.holders ∧ (strict = true → s.now ≤ time)
  | .forceRelease => strict = false

inductive Reachable (me timeout : Nat) (strict : Bool) : Node → Prop
  | init : Reachable me timeout strict ⟨none, [], 0⟩
  | step (s : Node) (e : Ev) : Reachable me timeout strict s → e.Allowed strict s →
      Reachable me timeout strict (s.apply me timeout e)

theorem nodup_filter_map {p : Nat × Lock → Bool} :
    ∀ {l : List (Nat × Lock)}, (l.map (·.2)).Nodup → ((l.filter p).map (·.2)).Nodup
  | [], _ => by simp
  | x :: l, h => by
    simp only [List.map_cons, List.nodup_cons, List.mem_map] at h
    by_cases hp : p x = true
    · simp only [List.filter_cons, hp, ↓reduceIte, List.map_cons, List.nodup_cons, List.mem_map,
        List.mem_filter]
      exact ⟨fun ⟨a, ha, he⟩ => h.1 ⟨a, ha.1, he⟩, nodup_filter_map h.2⟩
    · simp only [List.filter_cons, hp, Bool.false_eq_true, ↓reduceIte]
      exact nodup_filter_map h.2

theorem eq_of_snd_eq {l : List (Nat × Lock)} (hn : (l.map (·.2)).Nodup) :
    ∀ {a b}, a ∈ l → b ∈ l → a.2 = b.2 → a = b := by
  induction l with
  | nil => intro a b ha; simp at ha
  | cons x l ih =>
    intro a b ha hb he
    simp only [List.map_cons, List.nodup_cons, List.mem_map] at hn
    simp only [List.mem_cons] at ha hb
    rcases ha with rfl | ha <;> rcases hb with rfl | hb
    · rfl
    · exact absurd ⟨b, hb, he.symm⟩ hn.1
    · exact absurd ⟨a, ha, he⟩ hn.1
    · exact ih hn.2 ha hb he

/-- Outstanding locks are pairwise distinct, under any clock and any force releases. -/
theorem reachable_nodup {me timeout : Nat} {strict : Bool} {s : Node}
    (h : Reachable me timeout strict s) : (s.holders.map (·.2)).Nodup := by
  induction h with
  | init => simp
  | step s e _ hall ih =>
    cases e with
    | acquire task time nonce =>
      simp only [Node.apply]
      split
      · rename_i k hk
        simp only [List.map_cons, List.nodup_cons, List.mem_map]
        refine ⟨?_, ih⟩
        rintro ⟨h, hh, he⟩
        have hn : k.nonce = nonce := by
          unfold tryAcquire at hk
          split at hk
          · split at hk
            · simp at hk
            · simp only [Option.some.injEq] at hk; rw [← hk]
          · simp only [Option.some.injEq] at hk; rw [← hk]
        exact hall.1 h hh (by rw [he, hn])
      · exact ih
    | release task k time => exact nodup_filter_map ih
    | forceRelease => exact ih

/-- (a) A holder's release never deletes the lock of a different holder: the comparison is on the
whole value, nonce included. Holds with force releases and with a clock that steps back. -/
theorem release_keeps_other_holder {me timeout : Nat} {strict : Bool} {s : Node}
    (hr : Reachable me timeout strict s) {i j : Nat} {k k' : Lock} (hi : (i, k) ∈ s.holders)
    (hj : (j, k') ∈ s.holders) (hij : i ≠ j) (hst : s.store = some k') (time : Nat) :
    (s.apply me timeout (.release i k time)).store = some k' := by
  have hne : k' ≠ k := by
    intro he
    have := eq_of_snd_eq (reachable_nodup hr) hj hi he
    simp only [Prod.mk.injEq] at this
    exact hij this.1.symm
  simp [Node.apply, hst, release, leaseHeld, hne]

structure NInv (timeout : Nat) (s : Node) : Prop where
  nodup : (s.holders.map (·.2)).Nodup
  expired : ∀ h ∈ s.holders, s.store ≠ some h.2 → h.2.startedAt + timeout ≤ s.now
  past : ∀ L, s.store = some L → L.startedAt ≤ s.now

theorem reachable_inv {me timeout : Nat} {s : Node}
    (h : Reachable me timeout true s) : NInv timeout s := by
  have hnd := reachable_nodup h
  induction h with
  | init => exact ⟨by simp, by simp, by simp⟩
  | step s e hprev hall ih =>
    have ih := ih (reachable_nodup hprev)
    cases e with
    | acquire task time nonce =>
      obtain ⟨_, hmono⟩ := hall
      have hmono := hmono rfl
      refine ⟨hnd, ?_, ?_⟩
      · cases hs : s.store with
        | none =>
          intro h hh hne
          simp only [Node.apply, tryAcquire, hs, List.mem_cons] at hh hne ⊢
          rcases hh with rfl | hh
          · exact absurd rfl hne
          · have := ih.expired h hh (by rw [hs]; simp); omega
        | some L =>
          have hL := ih.past L hs
          by_cases hlt : time < L.startedAt + timeout
          · have hb : L.startedAt ≤ time + maxDrift ∧ time < L.startedAt + timeout :=
              ⟨by omega, hlt⟩
            intro h hh hne
            simp only [Node.apply, tryAcquire, hs, hb, and_self, ↓reduceIte] at hh hne ⊢
            have := ih.expired h hh (by rw [hs]; exact hne); omega
          · have hb : ¬ (L.startedAt ≤ time + maxDrift ∧ time < L.startedAt + timeout) :=
              fun h => hlt h.2
            intro h hh hne
            simp only [Node.apply, tryAcquire, hs, hb, ↓reduceIte, List.mem_cons] at hh hne ⊢
            rcases hh with rfl | hh
            · exact absurd rfl hne
            · by_cases hL' : L = h.2
              · subst hL'; omega
              · have := ih.expired h hh (by rw [hs]; simp [hL']); omega
      · intro L hL
        simp only [Node.apply] at hL ⊢
        cases hs : s.store with
        | none => simp [tryAcquire, hs] at hL; rw [← hL]; exact Nat.le_refl _
        | some L₀ =>
          simp only [tryAcquire, hs] at hL
          split at hL
          · simp only [Option.some.injEq] at hL; subst hL; have := ih.past _ hs; omega
          · simp only [Option.some.injEq] at hL; rw [← hL]; exact Nat.le_refl _
    | release task k time =>
      obtain ⟨hk, hmono⟩ := hall
      have hmono := hmono rfl
      refine ⟨hnd, ?_, ?_⟩
      · intro h hh hne
        simp only [Node.apply, List.mem_filter, decide_eq_true_eq] at hh hne ⊢
        have hk' : h.2 ≠ k := fun he => hh.2 (eq_of_snd_eq ih.nodup hh.1 hk he)
        by_cases hd : leaseHeld k time timeout s.store = true
        · have hsk : s.store = some k := by
            simp only [leaseHeld, Bool.and_eq_true, decide_eq_true_eq, beq_iff_eq] at hd
            exact hd.2
          have := ih.expired h hh.1 (by rw [hsk]; exact fun he => hk' (Option.some.inj he).symm)
          omega
        · have hst : release k time timeout s.store = s.store := by simp [release, hd]
          rw [hst] at hne
          have := ih.expired h hh.1 hne; omega
      · intro L hL
        simp only [Node.apply, release] at hL ⊢
        split at hL
        · simp at hL
        · have := ih.past L hL; omega
    | forceRelease => exact absurd hall (by simp [Ev.Allowed])

/-- (b) With a monotone clock and no force release, at most one outstanding holder has an
unexpired lease. -/
theorem one_unexpired_holder {me timeout : Nat} {s : Node}
    (hr : Reachable me timeout true s) {h₁ h₂ : Nat × Lock} (hh₁ : h₁ ∈ s.holders)
    (hh₂ : h₂ ∈ s.holders) (hu₁ : s.now < h₁.2.startedAt + timeout)
    (hu₂ : s.now < h₂.2.startedAt + timeout) : h₁ = h₂ := by
  have inv := reachable_inv hr
  have e₁ : s.store = some h₁.2 :=
    Classical.byContradiction fun hn => absurd (inv.expired h₁ hh₁ hn) (by omega)
  have e₂ : s.store = some h₂.2 :=
    Classical.byContradiction fun hn => absurd (inv.expired h₂ hh₂ hn) (by omega)
  rw [e₁] at e₂
  exact eq_of_snd_eq inv.nodup hh₁ hh₂ (Option.some.inj e₂)

def runNode (me timeout : Nat) (evs : List Ev) : Node :=
  evs.foldl (Node.apply me timeout) ⟨none, [], 0⟩

/-- The trace that broke ownership before the nonce: a force release and a re-acquisition in the
same second no longer let the evicted holder delete the new lock. -/
theorem force_release_now_safe :
    let s := runNode 0 600
      [.acquire 1 100 7, .forceRelease, .acquire 2 100 8, .release 1 ⟨100, 0, 7⟩ 100]
    s.store = some ⟨100, 0, 8⟩ := by
  decide

/-- The trace with a clock stepping back: the stale holder's release is now a no-op. -/
theorem clock_step_back_now_safe :
    let s := runNode 0 600
      [.acquire 1 1000 1, .acquire 2 1600 2, .release 2 ⟨1600, 0, 2⟩ 1600, .acquire 3 1000 3,
        .release 1 ⟨1000, 0, 1⟩ 1000]
    s.store = some ⟨1000, 0, 3⟩ := by
  decide

-- a_holder_that_was_taken_over_does_not_release_the_new_holder_lock
#guard release ⟨100, 1, 0⟩ 101 600 (some ⟨101, 2, 0⟩) == some ⟨101, 2, 0⟩
-- an expired holder leaves the lease to be taken over
#guard release ⟨100, 1, 0⟩ 700 600 (some ⟨100, 1, 0⟩) == some ⟨100, 1, 0⟩
-- a lease stamped beyond the drift bound is treated as expired
#guard (tryAcquire 1 100 600 5 (some ⟨1000, 2, 0⟩)).1 == some ⟨100, 1, 5⟩
-- two_tasks_on_one_node_cannot_both_acquire
#guard ((runNode 1 600 [.acquire 1 100 1, .acquire 2 100 2]).holders.map (·.1)) == [1]

/-! ## Cross node: LWW register replicated with delay -/

/-- A replica's entry for a key: value (`none` = tombstone) and wavekv `Metadata`. -/
structure Entry where
  value : Option Lock
  ts : Nat
  writer : Nat
  seq : Nat
deriving DecidableEq, Repr

/-- `wavekv::beats`: `e` replaces `old` iff `(ts, node, seq)` of `old` is smaller. -/
def Entry.beats (e old : Entry) : Bool :=
  old.ts < e.ts || (old.ts == e.ts && (old.writer < e.writer ||
    (old.writer == e.writer && old.seq < e.seq)))

/-- `Node::alloc_entry_meta`'s timestamp: `max(now, held.timestamp + 1)`, or `now` if absent. -/
def stamp (now : Nat) : Option Entry → Nat
  | some h => max now (h.ts + 1)
  | none => now

theorem stamp_ge (now : Nat) (h : Option Entry) : now ≤ stamp now h := by
  cases h <;> simp [stamp]; omega

theorem beats_of_ts {e old : Entry} (h : old.ts < e.ts) : e.beats old = true := by
  simp [Entry.beats, h]

theorem beats_trans {a b c : Entry} (h₁ : a.beats b = true) (h₂ : b.beats c = true) :
    a.beats c = true := by
  simp only [Entry.beats, Bool.or_eq_true, decide_eq_true_eq, Bool.and_eq_true, beq_iff_eq]
    at h₁ h₂ ⊢
  omega

/-- A local write always beats the entry it was stamped over. -/
theorem write_beats_held (v : Option Lock) (now n q : Nat) (h : Entry) :
    (Entry.mk v (stamp now (some h)) n q).beats h = true :=
  beats_of_ts (by simp [stamp]; omega)

/-- The release of `L` (stamped over the lease's own entry `e`, read by the releasing node) loses
LWW against the lock of a node that took `L` over (stamped over the same entry: only one write
carries `L`, since its nonce is fresh), and against
everything that later beats that lock. Hypotheses: the release passed its guard, the takeover
happened, the successor's clock was at most `maxDrift` behind `L.started_at`, and `e` itself was
stamped before the deadline. -/
theorem release_loses_to_takeover {e : Entry} {L L' : Lock} {timeout nowA nowB b nonce : Nat}
    (hA : leaseHeld L nowA timeout (some L) = true)
    (hB : (tryAcquire b nowB timeout nonce (some L)).1 = some L')
    (hskew : L.startedAt ≤ nowB + maxDrift) (hdeadline : e.ts + 1 < L.startedAt + timeout)
    (a sa sb : Nat) :
    let tomb : Entry := ⟨none, stamp nowA (some e), a, sa⟩
    let succ : Entry := ⟨some L', stamp nowB (some e), b, sb⟩
    succ.beats tomb = true ∧ ∀ later : Entry, later.beats succ = true → later.beats tomb = true := by
  intro tomb succ
  have h1 : succ.beats tomb = true := by
    obtain ⟨hexp, _⟩ := tryAcquire_some hB
    have hlt : nowA < L.startedAt + timeout := by
      simp only [leaseHeld, Bool.and_eq_true, decide_eq_true_eq] at hA; exact hA.1
    have : L.startedAt + timeout ≤ nowB := by omega
    apply beats_of_ts
    simp only [tomb, succ, stamp]; omega
  exact ⟨h1, fun later hl => beats_trans hl h1⟩

/-- A write guarded by `lease_still_held` (stamped over the data entry `d` its writer holds)
loses LWW against any write the successor makes once it holds the lease, at a clock no earlier
than its takeover (monotone clock), provided `d` was stamped before the deadline. -/
theorem guarded_commit_loses_to_successor {L L' : Lock}
    {timeout nowA nowB nowB' b nonce : Nat} {d : Option Entry} {d' : Option Entry}
    (hA : leaseHeld L nowA timeout (some L) = true)
    (hB : (tryAcquire b nowB timeout nonce (some L)).1 = some L')
    (hskew : L.startedAt ≤ nowB + maxDrift) (hmono : nowB ≤ nowB')
    (hdeadline : ∀ x, d = some x → x.ts + 1 < L.startedAt + timeout)
    (v v' : Option Lock) (a sa sb : Nat) :
    (Entry.mk v' (stamp nowB' d') b sb).beats ⟨v, stamp nowA d, a, sa⟩ = true := by
  obtain ⟨hexp, _⟩ := tryAcquire_some hB
  have hlt : nowA < L.startedAt + timeout := by
    simp only [leaseHeld, Bool.and_eq_true, decide_eq_true_eq] at hA; exact hA.1
  have hsucc := stamp_ge nowB' d'
  apply beats_of_ts
  have : stamp nowA d < L.startedAt + timeout := by
    cases d with
    | none => simp [stamp]; omega
    | some x => have := hdeadline x rfl; simp [stamp]; omega
  simp only; omega

/-- The lease's own entry meets the deadline hypothesis when it was written at the acquiring
node's clock over an entry stamped more than two ticks before the deadline. -/
theorem acquire_deadline {s timeout n q : Nat} {L : Lock} {prev : Option Entry}
    (hT : 1 < timeout) (hprev : ∀ p, prev = some p → p.ts + 2 < s + timeout) :
    (Entry.mk (some L) (stamp s prev) n q).ts + 1 < s + timeout := by
  cases prev with
  | none => simp [stamp]; omega
  | some p => have := hprev p rfl; simp [stamp]; omega

/-! ## Cluster traces -/

/-- One node's replica of the lock key and its write sequence counter. -/
structure Replica where
  entry : Option Entry
  seq : Nat
deriving DecidableEq, Repr

abbrev Cluster := List Replica

def Cluster.get (c : Cluster) (n : Nat) : Replica := c.getD n ⟨none, 0⟩

def Cluster.value (c : Cluster) (n : Nat) : Option Lock := (c.get n).entry.bind (·.value)

/-- A local `put` / `delete` on node `n` at clock `now`. -/
def Cluster.write (c : Cluster) (n now : Nat) (v : Option Lock) : Cluster :=
  let r := c.get n
  c.set n ⟨some ⟨v, stamp now r.entry, n, r.seq + 1⟩, r.seq + 1⟩

def Cluster.acquire (c : Cluster) (n now timeout nonce : Nat) : Option Lock × Cluster :=
  match tryAcquire n now timeout nonce (c.value n) with
  | (some k, _) => (some k, c.write n now (some k))
  | (none, _) => (none, c)

def Cluster.release (c : Cluster) (n now timeout : Nat) (k : Lock) : Cluster :=
  if leaseHeld k now timeout (c.value n) then c.write n now none else c

def Cluster.forceRelease (c : Cluster) (n now : Nat) : Cluster := c.write n now none

/-- Replication of node `src`'s entry to `dst` (`Node::sync`). -/
def Cluster.sync (c : Cluster) (src dst : Nat) : Cluster :=
  match (c.get src).entry with
  | none => c
  | some e =>
    match (c.get dst).entry with
    | some old => if e.beats old then c.set dst { c.get dst with entry := some e } else c
    | none => c.set dst { c.get dst with entry := some e }

def empty (n : Nat) : Cluster := List.replicate n ⟨none, 0⟩

/-- The pre-fix stale-release trace: node 0's release after its lease expired is now a no-op. -/
theorem stale_release_now_noop :
    let (_, c₁) := (empty 2).acquire 0 100 600 1
    let c₂ := c₁.sync 0 1
    let (b, c₃) := c₂.acquire 1 700 600 2
    let c₄ := (c₃.release 0 701 600 ⟨100, 0, 1⟩).sync 0 1
    b = some ⟨700, 1, 2⟩ ∧ c₄.value 1 = some ⟨700, 1, 2⟩ := by
  decide

/-- Node 0's clock runs slow: it still releases at its own clock 650, but the tombstone loses
to node 1's takeover at clock 700 in both directions of replication. -/
theorem slow_clock_release_loses :
    let (_, c₁) := (empty 2).acquire 0 100 600 1
    let c₂ := c₁.sync 0 1
    let (_, c₃) := c₂.acquire 1 700 600 2
    let c₄ := ((c₃.release 0 650 600 ⟨100, 0, 1⟩).sync 0 1).sync 1 0
    c₄.value 1 = some ⟨700, 1, 2⟩ ∧ c₄.value 0 = some ⟨700, 1, 2⟩ := by
  decide

/-- Limitation: nodes 0 and 1 both acquire at time 100 before either write replicates. After a
full sync node 1's write wins everywhere, and node 0's release sees the other value and writes
nothing. -/
theorem replication_gap_two_holders :
    let (a, c₁) := (empty 2).acquire 0 100 600 1
    let (b, c₂) := c₁.acquire 1 100 600 2
    let c₃ := (c₂.sync 0 1).sync 1 0
    a = some ⟨100, 0, 1⟩ ∧ b = some ⟨100, 1, 2⟩ ∧
    c₃.release 0 101 600 ⟨100, 0, 1⟩ = c₃ ∧ c₃.value 0 = some ⟨100, 1, 2⟩ := by
  decide

/-- Limitation: node 1's clock lags node 0's by 400 > `maxDrift`. It sees node 0's lease started
"in the future", takes it over at once, and node 0's in-lease release then deletes node 1's lock
cluster-wide. -/
theorem skew_beyond_drift_breaks_release :
    let (_, c₁) := (empty 2).acquire 0 1000 600 1
    let c₂ := c₁.sync 0 1
    let (b, c₃) := c₂.acquire 1 600 600 2
    let c₄ := (c₃.release 0 1005 600 ⟨1000, 0, 1⟩).sync 0 1
    b = some ⟨600, 1, 2⟩ ∧ c₄.value 1 = none := by
  decide

/-- Limitation: node 2 force-releases node 0's lease; node 1 acquires; node 0, which has not seen
the force release, releases within its lease and deletes node 1's lock. -/
theorem force_release_cross_node :
    let (_, c₁) := (empty 3).acquire 0 100 600 1
    let c₂ := (c₁.sync 0 1).sync 0 2
    let c₃ := (c₂.forceRelease 2 110).sync 2 1
    let (b, c₄) := c₃.acquire 1 120 600 2
    let c₅ := (c₄.release 0 130 600 ⟨100, 0, 1⟩).sync 0 1
    b = some ⟨120, 1, 2⟩ ∧ c₅.value 1 = none := by
  decide

end DstackFormal.Gateway.CertLock
