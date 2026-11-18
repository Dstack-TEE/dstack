-- SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
--
-- SPDX-License-Identifier: Apache-2.0

/-!
# Certificate renew / ACME rotation lease (`dstack/gateway/src/kv/mod.rs`)

Models `KvStore::try_acquire_lock` and `KvStore::release_lock` (wrapped by
`try_acquire_cert_lock`, `release_cert_lock`, `try_acquire_rotation_lock`,
`release_rotation_lock`, and `force_release_cert_lock`), as used by
`DistributedCertBot::renew_domain` and `acquire_acme_lock` in `distributed_certbot.rs`: a task
acquires, does its work, and releases with the value it acquired.

Single node (the read-check-write runs under one write guard, so events are atomic):
* `release_keeps_other_holder`: a holder's release never removes another holder's lock.
* `one_unexpired_holder`: at most one holder's lease is unexpired at any time.
Both assume the wall clock is monotone, the timeout is positive, and nobody calls
`force_release_cert_lock`. `force_release_breaks_ownership` and
`clock_step_back_breaks_ownership` show each assumption is needed: the lock value is
`(started_at, started_by)` in whole seconds, so a re-acquisition by the same node in the same
second as an outstanding stale token produces an equal value.

Cross node: the key is a last-writer-wins register replicated with delay, ordered by
`(timestamp, node)` as in `wavekv` (`Metadata::cmp`; the per-node `seq` tiebreak is omitted).
* `replication_gap_two_holders`: two nodes both acquire during a replication gap (as the code
  comment says); after sync the loser's release detects the takeover and writes nothing.
* `stale_release_deletes_successor`: a node that has not yet seen a takeover deletes its
  successor's lock cluster-wide, and a third acquisition then overlaps the successor's lease.
Cross-node mutual exclusion is therefore not a property of this code.

Modeling gap: encoding failures (`put_encoded(..).ok()?`) and corrupt records (decode as absent)
are not modeled; time is seconds as `Nat`; `now_secs` is an event parameter.
-/

namespace DstackFormal.Gateway.CertLock

/-- `kv::CertRenewLock`. -/
structure Lock where
  startedAt : Nat
  startedBy : Nat
deriving DecidableEq, Repr

/-- `KvStore::try_acquire_lock` on the local value of the key: the acquired lock, and the new local
value. -/
def tryAcquire (me now timeout : Nat) (cur : Option Lock) : Option Lock × Option Lock :=
  match cur with
  | some e =>
    if now < e.startedAt + timeout then (none, cur)
    else (some ⟨now, me⟩, some ⟨now, me⟩)
  | none => (some ⟨now, me⟩, some ⟨now, me⟩)

/-- `KvStore::release_lock` on the local value: deletes unless a different lock is present. -/
def release (acquired : Lock) (cur : Option Lock) : Option Lock :=
  match cur with
  | some c => if c ≠ acquired then some c else none
  | none => none

theorem tryAcquire_blocked {me now timeout : Nat} {e : Lock} (h : now < e.startedAt + timeout) :
    (tryAcquire me now timeout (some e)).1 = none := by
  simp [tryAcquire, h]

/-! ## Single node -/

/-- One node's view: the local value, the outstanding `(task, acquired)` pairs, and the clock. -/
structure Node where
  store : Option Lock
  holders : List (Nat × Lock)
  now : Nat
deriving DecidableEq, Repr

inductive Ev where
  /-- Task `task` calls `try_acquire_lock` at wall-clock `time`. -/
  | acquire (task time : Nat)
  /-- Task `task` calls `release_lock` with the lock it acquired. -/
  | release (task : Nat) (acquired : Lock)
  /-- `Admin.ForceReleaseCertLock`. -/
  | forceRelease
deriving DecidableEq, Repr

def Node.apply (me timeout : Nat) (s : Node) : Ev → Node
  | .acquire task time =>
    let r := tryAcquire me time timeout s.store
    { store := r.2, now := time,
      holders := match r.1 with
        | some k => (task, k) :: s.holders
        | none => s.holders }
  | .release task k =>
    { s with store := release k s.store, holders := s.holders.filter (· ≠ (task, k)) }
  | .forceRelease => { s with store := none }

/-- Monotone clock, releases only by holders, no force release. -/
def Ev.Allowed (s : Node) : Ev → Prop
  | .acquire _ time => s.now ≤ time
  | .release task k => (task, k) ∈ s.holders
  | .forceRelease => False

inductive Reachable (me timeout : Nat) : Node → Prop
  | init : Reachable me timeout ⟨none, [], 0⟩
  | step (s : Node) (e : Ev) : Reachable me timeout s → e.Allowed s →
      Reachable me timeout (s.apply me timeout e)

structure NInv (timeout : Nat) (s : Node) : Prop where
  nodup : (s.holders.map (·.2)).Nodup
  expired : ∀ h ∈ s.holders, s.store ≠ some h.2 → h.2.startedAt + timeout ≤ s.now

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

theorem reachable_inv {me timeout : Nat} (hT : 0 < timeout) {s : Node}
    (h : Reachable me timeout s) : NInv timeout s := by
  induction h with
  | init => exact ⟨by simp, by simp⟩
  | step s e _ hall ih =>
    cases e with
    | acquire task time =>
      simp only [Ev.Allowed] at hall
      cases hs : s.store with
      | none =>
        have hold : ∀ h ∈ s.holders, h.2.startedAt + timeout ≤ s.now :=
          fun h hh => ih.expired h hh (by rw [hs]; simp)
        refine ⟨?_, ?_⟩
        · simp only [Node.apply, tryAcquire, hs, List.map_cons, List.nodup_cons, List.mem_map]
          refine ⟨?_, ih.nodup⟩
          rintro ⟨h, hh, he⟩
          have := hold h hh
          rw [he] at this
          simp at this; omega
        · intro h hh hne
          simp only [Node.apply, tryAcquire, hs, List.mem_cons] at hh hne ⊢
          rcases hh with rfl | hh
          · exact absurd rfl hne
          · have := hold h hh; omega
      | some L =>
        by_cases hlt : time < L.startedAt + timeout
        · refine ⟨?_, ?_⟩
          · simpa [Node.apply, tryAcquire, hs, hlt] using ih.nodup
          · intro h hh hne
            simp only [Node.apply, tryAcquire, hs, hlt, ↓reduceIte] at hh hne ⊢
            have := ih.expired h hh (by rw [hs]; exact hne); omega
        · have hold : ∀ h ∈ s.holders, h.2.startedAt + timeout ≤ time := by
            intro h hh
            by_cases hL : L = h.2
            · subst hL; omega
            · have := ih.expired h hh (by rw [hs]; simp [hL]); omega
          refine ⟨?_, ?_⟩
          · simp only [Node.apply, tryAcquire, hs, hlt, ↓reduceIte, List.map_cons,
              List.nodup_cons, List.mem_map]
            refine ⟨?_, ih.nodup⟩
            rintro ⟨h, hh, he⟩
            have := hold h hh
            rw [he] at this
            simp at this; omega
          · intro h hh hne
            simp only [Node.apply, tryAcquire, hs, hlt, ↓reduceIte, List.mem_cons] at hh hne ⊢
            rcases hh with rfl | hh
            · exact absurd rfl hne
            · exact hold h hh
    | release task k =>
      simp only [Ev.Allowed] at hall
      refine ⟨nodup_filter_map ih.nodup, ?_⟩
      intro h hh hne
      simp only [Node.apply, List.mem_filter, decide_eq_true_eq] at hh hne ⊢
      apply ih.expired h hh.1
      intro hst
      apply hne
      rw [hst]
      simp only [release]
      have hk : h.2 ≠ k := by
        intro he
        exact hh.2 (eq_of_snd_eq ih.nodup hh.1 hall he)
      simp [hk]
    | forceRelease => exact absurd hall (by simp [Ev.Allowed])

/-- (a) A holder's release never deletes the lock of a different holder, whatever the order. -/
theorem release_keeps_other_holder {me timeout : Nat} (hT : 0 < timeout) {s : Node}
    (hr : Reachable me timeout s) {i j : Nat} {k k' : Lock} (hi : (i, k) ∈ s.holders)
    (hj : (j, k') ∈ s.holders) (hij : i ≠ j) (hst : s.store = some k') :
    (s.apply me timeout (.release i k)).store = some k' := by
  have hne : k' ≠ k := by
    intro he
    have := eq_of_snd_eq (reachable_inv hT hr).nodup hj hi he
    simp only [Prod.mk.injEq] at this
    exact hij this.1.symm
  simp [Node.apply, hst, release, hne]

/-- (b) On one node, at most one outstanding holder has an unexpired lease. -/
theorem one_unexpired_holder {me timeout : Nat} (hT : 0 < timeout) {s : Node}
    (hr : Reachable me timeout s) {h₁ h₂ : Nat × Lock} (hh₁ : h₁ ∈ s.holders)
    (hh₂ : h₂ ∈ s.holders) (hu₁ : s.now < h₁.2.startedAt + timeout)
    (hu₂ : s.now < h₂.2.startedAt + timeout) : h₁ = h₂ := by
  have inv := reachable_inv hT hr
  have e₁ : s.store = some h₁.2 :=
    Classical.byContradiction fun hn => absurd (inv.expired h₁ hh₁ hn) (by omega)
  have e₂ : s.store = some h₂.2 :=
    Classical.byContradiction fun hn => absurd (inv.expired h₂ hh₂ hn) (by omega)
  rw [e₁] at e₂
  exact eq_of_snd_eq inv.nodup hh₁ hh₂ (Option.some.inj e₂)

/-- The holder whose value is stored is unique, so its lease blocks every other acquisition. -/
theorem acquire_blocked_while_held {me timeout : Nat} {s : Node} {k : Lock} {task time : Nat}
    (hst : s.store = some k) (hlt : time < k.startedAt + timeout) :
    (s.apply me timeout (.acquire task time)).holders = s.holders := by
  simp [Node.apply, tryAcquire, hst, hlt]

/-! ## Single-node counterexamples to dropping an assumption -/

def runNode (me timeout : Nat) (evs : List Ev) : Node :=
  evs.foldl (Node.apply me timeout) ⟨none, [], 0⟩

/-- A force release followed by a re-acquisition in the same second issues a value equal to the
evicted holder's, whose later release then deletes the new holder's lock. -/
theorem force_release_breaks_ownership :
    let s := runNode 0 600 [.acquire 1 100, .forceRelease, .acquire 2 100, .release 1 ⟨100, 0⟩]
    s.store = none ∧ (2, ⟨100, 0⟩) ∈ s.holders ∧ s.now < 100 + 600 := by
  decide

/-- A wall clock that steps back lets a re-acquisition reproduce a stale holder's value; the stale
holder's release then deletes the new lock. -/
theorem clock_step_back_breaks_ownership :
    let s := runNode 0 600
      [.acquire 1 1000, .acquire 2 1600, .release 2 ⟨1600, 0⟩, .acquire 3 1000,
        .release 1 ⟨1000, 0⟩]
    s.store = none ∧ (3, ⟨1000, 0⟩) ∈ s.holders ∧ s.now < 1000 + 600 := by
  decide

-- a_holder_that_was_taken_over_does_not_release_the_new_holder_lock
#guard release ⟨100, 1⟩ (some ⟨101, 2⟩) == some ⟨101, 2⟩
#guard (tryAcquire 1 101 600 (some ⟨101, 2⟩)).1 == none
-- two_tasks_on_one_node_cannot_both_acquire
#guard ((runNode 1 600 [.acquire 1 100, .acquire 2 100]).holders.map (·.1)) == [1]

/-! ## Cross node: LWW register replicated with delay -/

/-- A replica's entry for the key: value (`none` = tombstone) and LWW metadata. -/
structure Entry where
  value : Option Lock
  ts : Nat
  writer : Nat
deriving DecidableEq, Repr

/-- `wavekv::beats`: `(timestamp, node)` order. -/
def Entry.beats (e old : Entry) : Bool :=
  old.ts < e.ts || (old.ts == e.ts && old.writer < e.writer)

/-- Per-node replicas, indexed by node id. -/
abbrev Cluster := List Entry

def Cluster.get (c : Cluster) (n : Nat) : Entry := c.getD n ⟨none, 0, 0⟩

/-- `try_acquire_lock` on node `n` at `time`: a local `put` on success. -/
def Cluster.acquire (c : Cluster) (n time timeout : Nat) : Option Lock × Cluster :=
  match tryAcquire n time timeout (c.get n).value with
  | (some k, _) => (some k, c.set n ⟨some k, time, n⟩)
  | (none, _) => (none, c)

/-- `release_lock` on node `n` at `time`: a local tombstone unless another lock is visible. -/
def Cluster.release (c : Cluster) (n time : Nat) (k : Lock) : Cluster :=
  match (c.get n).value with
  | some cur => if cur ≠ k then c else c.set n ⟨none, time, n⟩
  | none => c.set n ⟨none, time, n⟩

/-- Replication of node `src`'s entry to `dst` (`Node::sync`). -/
def Cluster.sync (c : Cluster) (src dst : Nat) : Cluster :=
  if (c.get src).beats (c.get dst) then c.set dst (c.get src) else c

def empty2 : Cluster := [⟨none, 0, 0⟩, ⟨none, 0, 0⟩]

/-- (c) Nodes 0 and 1 both acquire at time 100 before either write replicates; both leases are
unexpired. After a full sync node 1's write wins everywhere, and node 0's release sees the
other value and writes nothing. -/
theorem replication_gap_two_holders :
    let (a, c₁) := empty2.acquire 0 100 600
    let (b, c₂) := c₁.acquire 1 100 600
    let c₃ := (c₂.sync 0 1).sync 1 0
    a = some ⟨100, 0⟩ ∧ b = some ⟨100, 1⟩ ∧
    c₃.release 0 101 ⟨100, 0⟩ = c₃ ∧ (c₃.get 0).value = some ⟨100, 1⟩ := by
  decide

/-- (c') Node 1 takes over an expired lease; node 0, not yet having seen it, releases with a later
timestamp, and its tombstone replicates over node 1's live lock. Node 0 then acquires again
while node 1's lease (until 1300) is still running. -/
theorem stale_release_deletes_successor :
    let (_, c₁) := empty2.acquire 0 100 600
    let c₂ := c₁.sync 0 1
    let (b, c₃) := c₂.acquire 1 700 600
    let c₄ := (c₃.release 0 701 ⟨100, 0⟩).sync 0 1
    let (a', _) := c₄.acquire 0 702 600
    b = some ⟨700, 1⟩ ∧ (c₄.get 1).value = none ∧ a' = some ⟨702, 0⟩ ∧ 702 < 700 + 600 := by
  decide

end DstackFormal.Gateway.CertLock
