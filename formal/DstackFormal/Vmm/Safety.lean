-- SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
--
-- SPDX-License-Identifier: Apache-2.0

import DstackFormal.Vmm.Lifecycle

/-!
# dstack-vmm CVM lifecycle: safety invariants

Proofs over the model in `Vmm.Lifecycle` (`dstack/vmm/src/app.rs`, `main_service.rs`,
`app/workdir.rs`, `dstack/supervisor/src/supervisor.rs`; `next` at ca4717064d with #1610-#1614,
#1616 and #1617 applied). `Inv` is an inductive invariant of every configuration with the
#1609, #1610, #1616 and #1617 fixes (`Good`); `reachable_inv` proves it by induction over
`Step`, one field at a time.

Proven (for `fixed`):
* (a') `removal_holds_no_deploy`: once `finish_remove_vm` holds the launch lock, no step makes
  the process run; `running_needs_start`: only a start holding the lock and awaiting `deploy`
  does. The literal (a) -- nothing runs while the id is in the removing set -- is false by
  design (`Traces.deploy_while_removing`): `remove_vm` claims the id without the lock, a start
  past its under-lock check still deploys, and the removal stops it once it holds the lock.
* (b) `at_most_one_running`: at most one running QEMU process per id, with no assumption on
  cancellation: since #1617 a dropped caller does not release the lock mid-launch. Before
  #1617 it is false (`Traces.cancel_two_running`).
* (c) `stop_sticks`, `stop_sticks_started`: after an acknowledged stop, until an explicit start
  commits, nothing deploys the VM and `started` stays false: no automatic restart, guest event,
  boot or reload start. Before #1616 it is false (`Traces.reload_start_overrides_stop`).
* (d) `removal_targets_marked_or_gone`: every removal past its claim, including the ones crash
  recovery resumes or starts, targets a workdir with `.removing` or none, so no stop by a
  removal hits an unmarked workdir; `boot_keeps_stopped`: the boot reload never sets a stopped
  VM's `started`; `boot_end_loaded`: when it hands over, every loadable unmarked workdir is
  loaded.
* (e) `removal_delete_safe`, `dir_deleted_only_by`: `remove_all` runs only with no process
  running and nothing held at netd; the only other deletion is `create_vm`'s cleanup of a VM
  that failed to load.
* (f) `reload_claim_needs_delete`: the reload RPC claims a removal for a VM missing on disk only
  after a removal deleted its workdir, so never for a VM whose create is in flight.
* (g) `poweroff_respects_later_start`: a power-off record clears `started` only if no start
  reset the shutdown progress since the report.
* `gone_stays_gone` (#1612): a deleted workdir never comes back; `env_window_own_boot`,
  `adopt_keeps_env_window` (#1614).

Assumptions and gaps: those of `Vmm.Lifecycle`. The invariant fields are documented where
they are declared.
-/

namespace DstackFormal.Vmm

/-- The fixes and assumptions the safety proofs need. -/
structure Good (c : Config) : Prop where
  keepRunning : c.keepRunning = true
  snapshotFirst : c.snapshotFirst = true
  startSpawned : c.startSpawned = true
  loadRecheck : c.loadRecheck = true

theorem good_fixed : Good fixed := ⟨rfl, rfl, rfl, rfl⟩

/-! ## Observers -/

def Held.past : Held → Bool
  | .start _ pc => pc.pastCommit
  | .stop _ | .record | .update | .reconcile => false

def Held.stopLate : Held → Bool
  | .stop .stopProc | .stop .release => true
  | .stop .check | .stop .setFalse => false
  | .start _ _ | .record | .update | .reconcile => false

def RmPc.late : RmPc → Bool
  | .release | .delete | .finish => true
  | .pre | .wait | .stop | .exit => false

def RmPc.mid : RmPc → Bool
  | .wait | .stop | .exit | .release => true
  | .pre | .delete | .finish => false

/-- Past `remove_vm`'s `.removing` write (or claimed by a reload). -/
def RmPc.claimed : RmPc → Bool
  | .pre => false
  | .wait | .stop | .exit | .release | .delete | .finish => true

def RmPc.isDelete : RmPc → Bool
  | .delete => true
  | .pre | .wait | .stop | .exit | .release | .finish => false

def Phase.isBooting : Phase → Bool
  | .booting _ => true
  | .ready => false

def Phase.svHas : Phase → Bool
  | .booting b => b.svHas
  | .ready => false

def Phase.markerSeen : Phase → Bool
  | .booting b => b.markerSeen
  | .ready => false

/-- Before `bootLoad` has run. -/
def BootPc.early : BootPc → Bool
  | .list | .load => true
  | .await | .markers | .orphan => false

def Phase.early : Phase → Bool
  | .booting b => b.pc.early
  | .ready => false

def Phase.atList : Phase → Bool
  | .booting b => b.pc == .list
  | .ready => false

def Phase.atAwait : Phase → Bool
  | .booting b => b.pc == .await
  | .ready => false

def Removal.goneOk (rm : Removal) : Bool := rm.pc == .finish || (rm.pc.mid && !rm.delete)

attribute [local simp] State.release State.released State.lockFree replaceReload unclaimed
  Disk.empty Removal.goneOk Reload.fresh
attribute [local simp] StartPc.pastCommit.eq_1 StartPc.pastCommit.eq_2 StartPc.pastCommit.eq_3
attribute [local simp] StartPc.pastCommit.eq_4 StartPc.pastCommit.eq_5 StartPc.pastCommit.eq_6
attribute [local simp] StartPc.pastCommit.eq_7 RmPc.holds.eq_1 RmPc.holds.eq_2 RmPc.holds.eq_3
attribute [local simp] RmPc.holds.eq_4 RmPc.holds.eq_5 RmPc.holds.eq_6 RmPc.holds.eq_7
attribute [local simp] Held.isBootStart.eq_1 Held.isBootStart.eq_2 Held.isBootStart.eq_3
attribute [local simp] Held.isBootStart.eq_4 Held.isBootStart.eq_5 removalHolds.eq_1
attribute [local simp] removalHolds.eq_2 Waiter.entry.eq_1 Waiter.entry.eq_2 Waiter.entry.eq_3
attribute [local simp] Waiter.entry.eq_4 Waiter.entry.eq_5 Held.past.eq_1 Held.past.eq_2
attribute [local simp] Held.past.eq_3 Held.past.eq_4 Held.past.eq_5 Held.stopLate.eq_1
attribute [local simp] Held.stopLate.eq_2 Held.stopLate.eq_3 Held.stopLate.eq_4 Held.stopLate.eq_5
attribute [local simp] Held.stopLate.eq_6 Held.stopLate.eq_7 Held.stopLate.eq_8 RmPc.late.eq_1
attribute [local simp] RmPc.late.eq_2 RmPc.late.eq_3 RmPc.late.eq_4 RmPc.late.eq_5 RmPc.late.eq_6
attribute [local simp] RmPc.late.eq_7 RmPc.mid.eq_1 RmPc.mid.eq_2 RmPc.mid.eq_3 RmPc.mid.eq_4
attribute [local simp] RmPc.claimed.eq_1 RmPc.claimed.eq_2 RmPc.claimed.eq_3 RmPc.claimed.eq_4
attribute [local simp] RmPc.claimed.eq_5 RmPc.claimed.eq_6 RmPc.claimed.eq_7
attribute [local simp] RmPc.mid.eq_5 RmPc.mid.eq_6 RmPc.mid.eq_7 RmPc.isDelete.eq_1
attribute [local simp] RmPc.isDelete.eq_2 RmPc.isDelete.eq_3 RmPc.isDelete.eq_4 RmPc.isDelete.eq_5
attribute [local simp] RmPc.isDelete.eq_6 RmPc.isDelete.eq_7 Phase.isBooting.eq_1
attribute [local simp] Phase.isBooting.eq_2 Phase.svHas.eq_1 Phase.svHas.eq_2
attribute [local simp] Phase.markerSeen.eq_1 Phase.markerSeen.eq_2 BootPc.early.eq_1
attribute [local simp] BootPc.early.eq_2 BootPc.early.eq_3 BootPc.early.eq_4 BootPc.early.eq_5
attribute [local simp] Phase.early.eq_1 Phase.early.eq_2 Phase.atList.eq_1 Phase.atList.eq_2
attribute [local simp] Phase.atAwait.eq_1 Phase.atAwait.eq_2

set_option linter.unusedSimpArgs false

/-- For a goal `∀ x ∈ l', P x`: introduce `x`, split `l'` into the new head and members of the
old list, and instantiate `h : ∀ x ∈ l, Q x` at an old member. -/
macro "memIntro " h:ident : tactic => `(tactic| (
  intro x hx
  try simp only [replaceReload, List.mem_cons] at hx
  try rcases hx with rfl | hx
  all_goals try replace hx := List.mem_of_mem_erase hx
  all_goals try have := $h _ hx))

/-- Close what `simp_all` leaves by splitting on one Boolean. -/
macro "bsplit " e:term : tactic => `(tactic| (cases _h : $e <;> simp_all <;> done))

theorem late_holds (o : Option Removal) (h : o.any (·.pc.late) = true) : removalHolds o = true := by
  rcases o with _ | ⟨_, _, pc⟩
  · simp at h
  · cases pc <;> simp_all

theorem phase_facts (p : Phase) :
    (p.early = true → p.isBooting = true) ∧ (p.atAwait = true → p.isBooting = true) ∧
    (p.atList = true → p.early = true) ∧ (p.atAwait = true → p.early = false) ∧
    (p.markerSeen = true → p.isBooting = true) ∧ (p.svHas = true → p.isBooting = true) := by
  rcases p with ⟨pc, _, _⟩ | _
  · cases pc <;> simp
  · simp

theorem delete_holds (o : Option Removal) (h : o.any (·.pc.isDelete) = true) :
    removalHolds o = true := by
  rcases o with _ | ⟨_, _, pc⟩
  · simp at h
  · cases pc <;> simp_all

theorem mem_erase_imp {α : Type} [BEq α] [LawfulBEq α] {a b : α} {l : List α}
    (h : a ∈ l.erase b) : a ∈ l := List.mem_of_mem_erase h

theorem not_mem_erase {α : Type} [BEq α] [LawfulBEq α] {a b : α} {l : List α}
    (h : a ∉ l) : a ∉ l.erase b := fun h' => h (List.mem_of_mem_erase h')

def ReqsOk (s : State) : Prop :=
  s.reqs = [] ∨ ∃ k r, s.held = some (.start k .await) ∧ s.reqs = [r] ∧ r.attached = true ∧
    (r.checked = true → s.entry ≠ .running)

def ReloadOk (s : State) (r : Reload) : Prop :=
  ((r.pc = .list ∨ r.pc = .first) → r.inMem = false) ∧
  (r.pc = .second → r.inMem = true →
    (s.disk.dir = true ∧ s.disk.manifestOk = true) ∨ s.g.everDeleted = true) ∧
  (r.pc = .claim → r.inMem = true → r.inFs = false → s.g.everDeleted = true) ∧
  (r.markerSeen = true → s.disk.marker = true ∨ s.disk.dir = false)

/-- The inductive invariant of `Good` configurations. -/
structure Inv (s : State) : Prop where
  lock : s.held.isSome = true → removalHolds s.removal = false
  reqs : ReqsOk s
  untracked : s.untracked = 0
  netd : s.netd = true → s.disk.pending = true
  netdLive : s.netd = true → (s.disk.dir = true ∧ s.disk.manifestOk = true) ∨ s.creating = none
  past : s.held.any Held.past = true → s.disk.dir = true ∧ s.disk.manifestOk = true
  fresh : s.created = false → s.disk = Disk.empty ∧ s.netd = false ∧ s.entry = .none ∧
    s.loaded = false ∧ s.removal = none ∧ s.creating = none ∧ s.g.stopAcked = false ∧
    s.g.everDeleted = false ∧ s.g.gone = false ∧ s.phase.svHas = false ∧
    s.phase.markerSeen = false
  freshReload : s.created = false → ∀ r ∈ s.reloads,
    r.inMem = false ∧ r.markerSeen = false ∧ r.svHas = false
  stopLate : s.held.any Held.stopLate = true → s.disk.started = false ∧ s.created = true
  rmRun : s.removal.any (·.pc.late) = true → s.entry ≠ .running
  rmDel : s.removal.any (·.pc.isDelete) = true → s.netd = false
  intent : s.removal.any (·.pc.claimed) = true → s.disk.marker = true ∨ s.disk.dir = false
  deleted : s.g.everDeleted = true → s.disk.marker = true ∨ s.disk.dir = false
  loaded : s.loaded = true → (s.disk.dir = true ∧ s.disk.manifestOk = true) ∨ s.g.everDeleted = true
  reload : ∀ r ∈ s.reloads, ReloadOk s r
  boot : s.phase.isBooting = true → s.reloads = [] ∧ s.creating = none ∧ s.rawRecords = 0 ∧
    s.held.all Held.isBootStart = true
  bootWaiters : s.phase.isBooting = true → ∀ w ∈ s.waiters, w = .start .boot
  bootMarker : s.phase.markerSeen = true → s.disk.marker = true ∨ s.disk.dir = false
  early : s.phase.early = true → s.held = none ∧ s.waiters = [] ∧ s.removal = none ∧
    s.loaded = false
  bootTask : (Waiter.start .boot ∈ s.waiters ∨ s.held.any Held.isBootStart = true) →
    s.phase.atAwait = true ∧ s.disk.started = true ∧ s.removal = none
  bootLoaded : s.phase.isBooting = true → s.phase.early = false → s.disk.dir = true →
    s.disk.manifestOk = true → s.disk.marker = false → s.loaded = true
  off : s.g.startSinceOff = true → s.poweringOff = false
  env : s.envWindow = true → s.g.freshSinceCrash = true
  gone : s.g.gone = true → s.disk = Disk.empty ∧ (s.loaded = true → s.removal.isSome = true) ∧
    s.removal.all Removal.goneOk = true

theorem inv_init : Inv State.init := by
  constructor <;> simp [State.init, ReqsOk]

/-! ## Preservation, field by field -/

section
variable {c : Config} {s s' : State}

theorem step_lock (hi : Inv s) (hs : Step c s s') :
    s'.held.isSome = true → removalHolds s'.removal = false := by
  have := hi.lock; clear hi
  cases hs <;> simp_all

theorem step_reqs (hc : Good c) (hi : Inv s) (hs : Step c s s') : ReqsOk s' := by
  have := hi.lock; have hr := hi.reqs; have := hc.startSpawned; clear hi
  unfold ReqsOk at *
  rcases hr with h | ⟨k, r, hh, hr, ha, hck⟩
  · cases hs <;> simp_all
  · cases hs <;> simp_all

theorem step_untracked (hi : Inv s) (hs : Step c s s') : s'.untracked = 0 := by
  have hr := hi.reqs; have := hi.untracked; clear hi
  unfold ReqsOk at *
  rcases hr with h | ⟨k, r, hh, hr, ha, hck⟩
  · cases hs <;> simp_all
  · cases hs <;> simp_all

theorem step_netd (hi : Inv s) (hs : Step c s s') : s'.netd = true → s'.disk.pending = true := by
  have := hi.netd; have h1 := hi.fresh; have := hi.rmDel; have := hi.netdLive; clear hi
  cases hs <;> simp_all
  all_goals cases h : s.netd <;> simp_all

theorem step_netdLive (hi : Inv s) (hs : Step c s s') :
    s'.netd = true → (s'.disk.dir = true ∧ s'.disk.manifestOk = true) ∨ s'.creating = none := by
  have := hi.netdLive; have := hi.past; have := hi.fresh; have := hi.rmDel; have := hi.boot
  clear hi
  cases hs <;> simp_all <;> grind

theorem step_past (hi : Inv s) (hs : Step c s s') :
    s'.held.any Held.past = true → s'.disk.dir = true ∧ s'.disk.manifestOk = true := by
  have := hi.past; have := hi.lock; have := hi.fresh; have := hi.early; clear hi
  cases hs <;> simp_all
  case createFail => bsplit s.held.any Held.past
  case acquire => cases (‹Waiter›) <;> simp_all

theorem step_fresh (hi : Inv s) (hs : Step c s s') :
    s'.created = false → s'.disk = Disk.empty ∧ s'.netd = false ∧ s'.entry = .none ∧
      s'.loaded = false ∧ s'.removal = none ∧ s'.creating = none ∧ s'.g.stopAcked = false ∧
      s'.g.everDeleted = false ∧ s'.g.gone = false ∧ s'.phase.svHas = false ∧
      s'.phase.markerSeen = false := by
  have := hi.fresh; have := hi.past; have hr := hi.reqs; have := hi.stopLate
  have := hi.freshReload; clear hi
  unfold ReqsOk at hr
  rcases hr with h | ⟨k, r, hh, hr, ha, hck⟩
  · cases hs <;> simp_all <;> bsplit s.created
  · cases hs <;> simp_all <;> bsplit s.created

theorem step_stopLate (hi : Inv s) (hs : Step c s s') :
    s'.held.any Held.stopLate = true → s'.disk.started = false ∧ s'.created = true := by
  have := hi.stopLate; have := hi.fresh; have := hi.lock; clear hi
  cases hs <;> simp_all
  case acquire => cases (‹Waiter›) <;> simp_all
  all_goals bsplit s.created

theorem step_rmRun (hi : Inv s) (hs : Step c s s') :
    s'.removal.any (·.pc.late) = true → s'.entry ≠ .running := by
  have := hi.rmRun; have := hi.lock; have hr := hi.reqs; have := late_holds s.removal; clear hi
  unfold ReqsOk at hr
  rcases hr with h | ⟨k, r, hh, hr, ha, hck⟩
  · cases hs <;> simp_all
  · cases hs <;> simp_all

theorem step_rmDel (hi : Inv s) (hs : Step c s s') :
    s'.removal.any (·.pc.isDelete) = true → s'.netd = false := by
  have := hi.rmDel; have := hi.lock; have := hi.netd; have := delete_holds s.removal; clear hi
  cases hs <;> simp_all
  all_goals cases h : s.netd <;> simp_all

theorem step_intent (hc : Good c) (hi : Inv s) (hs : Step c s s') :
    s'.removal.any (·.pc.claimed) = true → s'.disk.marker = true ∨ s'.disk.dir = false := by
  have := hi.intent; have := hi.deleted; have hrl := hi.reload; have := hi.bootMarker
  have := hi.fresh; have := hc.keepRunning; clear hi
  cases hs
  case rlClaim r hr _ _ _ _ => have := hrl r hr; simp_all [ReloadOk]
  case rlMarkers r hr _ _ _ => have := hrl r hr; simp_all [ReloadOk]
  all_goals simp_all

theorem step_deleted (hi : Inv s) (hs : Step c s s') :
    s'.g.everDeleted = true → s'.disk.marker = true ∨ s'.disk.dir = false := by
  have := hi.deleted; have := hi.fresh; clear hi
  cases hs <;> simp_all

theorem step_loaded (hi : Inv s) (hs : Step c s s') :
    s'.loaded = true → (s'.disk.dir = true ∧ s'.disk.manifestOk = true) ∨ s'.g.everDeleted = true := by
  have := hi.loaded; have := hi.early; have := hi.fresh; clear hi
  cases hs <;> simp_all <;> grind

theorem step_freshReload (hi : Inv s) (hs : Step c s s') :
    s'.created = false → ∀ r ∈ s'.reloads, r.inMem = false ∧ r.markerSeen = false ∧ r.svHas = false := by
  have hf := hi.freshReload; have := hi.fresh; clear hi
  intro hcr
  cases hs
  all_goals
    try simp only at hcr
    try have hf := hf hcr
    try have := (by assumption : s.created = false)
  all_goals memIntro hf
  all_goals simp_all

theorem step_reload (hc : Good c) (hi : Inv s) (hs : Step c s s') :
    ∀ r ∈ s'.reloads, ReloadOk s' r := by
  have hrl := hi.reload; have := hi.loaded; have := hi.boot; have := hi.freshReload
  have := hi.fresh; have := hc.snapshotFirst; clear hi
  unfold ReloadOk at *
  cases hs
  all_goals memIntro hrl
  all_goals simp_all
  all_goals grind

theorem step_boot (hi : Inv s) (hs : Step c s s') :
    s'.phase.isBooting = true → s'.reloads = [] ∧ s'.creating = none ∧ s'.rawRecords = 0 ∧
      s'.held.all Held.isBootStart = true := by
  have := hi.boot; have hw := hi.bootWaiters; clear hi
  cases hs
  case acquire w hw' _ =>
    intro hb; have := hw hb w hw'; simp_all
  all_goals simp_all
  all_goals grind

theorem step_bootWaiters (hi : Inv s) (hs : Step c s s') :
    s'.phase.isBooting = true → ∀ w ∈ s'.waiters, w = .start .boot := by
  have hw := hi.bootWaiters; have := hi.boot; clear hi
  intro hb
  cases hs
  all_goals
    try simp only at hb
    try have hw := hw hb
  all_goals intro x hx
  all_goals
    try simp only [mem_addIf, List.mem_cons] at hx
    try replace hx := List.mem_of_mem_erase hx
  all_goals first | exact hw _ hx | simp_all
  all_goals first | exact hw _ ‹_› | grind

theorem step_bootMarker (hi : Inv s) (hs : Step c s s') :
    s'.phase.markerSeen = true → s'.disk.marker = true ∨ s'.disk.dir = false := by
  have := hi.bootMarker; have := hi.boot; clear hi
  cases hs <;> simp_all

theorem step_early (hi : Inv s) (hs : Step c s s') :
    s'.phase.early = true → s'.held = none ∧ s'.waiters = [] ∧ s'.removal = none ∧
      s'.loaded = false := by
  have := hi.early; have := hi.boot; have := phase_facts s.phase; clear hi
  cases hs <;> simp_all <;> grind

theorem step_bootTask (hi : Inv s) (hs : Step c s s') :
    (Waiter.start .boot ∈ s'.waiters ∨ s'.held.any Held.isBootStart = true) →
      s'.phase.atAwait = true ∧ s'.disk.started = true ∧ s'.removal = none := by
  have := hi.bootTask; have := hi.boot; have := hi.early; have := hi.lock
  have := phase_facts s.phase; clear hi
  cases hs
  case acquire w hw' _ => cases w <;> simp_all <;> grind [List.mem_of_mem_erase]
  case drop w hw' => cases w <;> simp_all <;> grind [List.mem_of_mem_erase]
  all_goals simp_all
  all_goals grind

theorem step_bootLoaded (hi : Inv s) (hs : Step c s s') :
    s'.phase.isBooting = true → s'.phase.early = false → s'.disk.dir = true →
      s'.disk.manifestOk = true → s'.disk.marker = false → s'.loaded = true := by
  have := hi.bootLoaded; have := hi.intent; have := hi.boot; have := hi.early
  have := phase_facts s.phase; clear hi
  cases hs <;> simp_all <;> grind

theorem step_off (hi : Inv s) (hs : Step c s s') :
    s'.g.startSinceOff = true → s'.poweringOff = false := by
  have := hi.off; clear hi
  cases hs <;> simp_all

theorem step_env (hi : Inv s) (hs : Step c s s') :
    s'.envWindow = true → s'.g.freshSinceCrash = true := by
  have := hi.env; clear hi
  cases hs <;> simp_all

theorem step_gone (hi : Inv s) (hs : Step c s s') :
    s'.g.gone = true → s'.disk = Disk.empty ∧ (s'.loaded = true → s'.removal.isSome = true) ∧
      s'.removal.all Removal.goneOk = true := by
  have := hi.gone; have := hi.past; have := hi.fresh; clear hi
  cases hs <;> simp_all <;> grind

theorem inv_step (hc : Good c) (hi : Inv s) (hs : Step c s s') : Inv s' :=
  ⟨step_lock hi hs, step_reqs hc hi hs, step_untracked hi hs, step_netd hi hs, step_netdLive hi hs,
   step_past hi hs, step_fresh hi hs, step_freshReload hi hs, step_stopLate hi hs,
   step_rmRun hi hs, step_rmDel hi hs, step_intent hc hi hs, step_deleted hi hs,
   step_loaded hi hs, step_reload hc hi hs, step_boot hi hs, step_bootWaiters hi hs,
   step_bootMarker hi hs, step_early hi hs, step_bootTask hi hs, step_bootLoaded hi hs,
   step_off hi hs, step_env hi hs,
   step_gone hi hs⟩

end

theorem reachable_inv {c : Config} (hc : Good c) {s : State} (h : Reachable c s) : Inv s := by
  induction h with
  | init => exact inv_init
  | step _ hs ih => exact inv_step hc ih hs

/-! ## Safety theorems -/

/-- The number of running QEMU processes for the id: the supervisor's entry, plus children of
entries a second deploy replaced. -/
def State.running (s : State) : Nat := (if s.entry = .running then 1 else 0) + s.untracked

/-- (b) At most one running supervisor process per id. No assumption on cancellation: since
#1617 a start runs in its own task, so a dropped caller cannot release the launch lock while
its `deploy` is in flight. -/
theorem at_most_one_running {c : Config} (hc : Good c) {s : State} (h : Reachable c s) :
    s.running ≤ 1 := by
  have := (reachable_inv hc h).untracked
  simp only [State.running, this]; split <;> omega

/-- Only a deploy request makes the process run; one is in flight only while a start holds
the launch lock and awaits it. -/
theorem running_needs_start {c : Config} (hc : Good c) {s s' : State} (h : Reachable c s)
    (hs : Step c s s') (hr : s'.entry = .running) (hn : s.entry ≠ .running) :
    ∃ k, s.held = some (.start k .await) := by
  have hreq := (reachable_inv hc h).reqs
  unfold ReqsOk at hreq
  cases hs <;> simp_all
  all_goals rcases hreq with h | ⟨k, r, hh, _⟩ <;> simp_all

/-- (a') Once the removal holds the launch lock -- from its stop until it drops the entry --
no step makes the process run. -/
theorem removal_holds_no_deploy {c : Config} (hc : Good c) {s s' : State} (h : Reachable c s)
    (hrm : removalHolds s.removal = true) (hs : Step c s s') (hr : s'.entry = .running) :
    s.entry = .running := by
  refine Classical.byContradiction fun hn => ?_
  obtain ⟨k, hk⟩ := running_needs_start hc h hs hr hn
  have := (reachable_inv hc h).lock
  simp_all

/-- (a') A start acting while a removal is claimed passed its under-lock check before the
claim: a start at its check with a removal claimed can only give up. -/
theorem removing_start_check_aborts {c : Config} {s s' : State} {k : Kind}
    (hh : s.held = some (.start k .check)) (hrm : s.removal.isSome = true) (hs : Step c s s') :
    s'.held = none ∨ s'.held = s.held := by
  cases hs <;> simp_all

/-- (e) A removal deletes the workdir only with no process running for the id and nothing held
at netd. -/
theorem removal_delete_safe {c : Config} (hc : Good c) {s : State} (h : Reachable c s)
    {o : Origin} {d : Bool} (hrm : s.removal = some ⟨o, d, .delete⟩) :
    s.running = 0 ∧ s.netd = false := by
  have hi := reachable_inv hc h
  have := hi.rmRun; have := hi.rmDel; have := hi.untracked
  simp_all [State.running]

/-- (e) Removal's `remove_all` and `create_vm`'s cleanup of a VM that failed to load are the
only steps that delete the workdir. -/
theorem dir_deleted_only_by {c : Config} {s s' : State} (hs : Step c s s')
    (hd : s.disk.dir = true) (hd' : s'.disk.dir = false) :
    (∃ o d, s.removal = some ⟨o, d, .delete⟩) ∨
      (s.creating.isSome = true ∧ s.disk.manifestOk = false) := by
  cases hs <;> simp_all

/-- (d) Every removal past `remove_vm`'s marker write -- the user's, a `.removing` marker
resumed by a reload, a boot orphan, a VM the reload RPC did not find -- targets a VM whose
workdir has `.removing` or is gone. In particular its stop (`rmStop`) never takes down a VM whose
workdir is still there and unmarked: #1609 at boot, #1610 in the reload RPC. -/
theorem removal_targets_marked_or_gone {c : Config} (hc : Good c) {s : State} (h : Reachable c s)
    {o : Origin} {d : Bool} {pc : RmPc} (hrm : s.removal = some ⟨o, d, pc⟩) (hpc : pc ≠ .pre) :
    s.disk.marker = true ∨ s.disk.dir = false := by
  have := (reachable_inv hc h).intent
  cases pc <;> simp_all

/-- (d) Crash recovery never writes `started = true` over a VM whose persisted intent is
stopped: while the boot reload runs, a `started = false` stays false. -/
theorem boot_keeps_stopped {c : Config} (hc : Good c) {s s' : State} (h : Reachable c s)
    (hb : s.phase.isBooting = true) (hs : Step c s s') (hst : s.disk.started = false) :
    s'.disk.started = false := by
  have hi := reachable_inv hc h
  have := hi.bootTask; have := hi.boot; have := hi.early; have := hi.fresh
  cases hs <;> simp_all

/-- (d) When the boot reload hands over to the RPC server, every loadable workdir without
`.removing` is loaded. -/
theorem boot_end_loaded {c : Config} (hc : Good c) {s s' : State} (h : Reachable c s)
    (hb : s.phase.isBooting = true) (hs : Step c s s') (hr : s'.phase = .ready) :
    s'.disk.dir = true → s'.disk.manifestOk = true → s'.disk.marker = false → s'.loaded = true := by
  have hi := reachable_inv hc h
  have := hi.bootLoaded; have := phase_facts s.phase
  cases hs <;> simp_all

/-- (f) The reload RPC claims a removal for a VM it found in memory but not on disk only after
a removal deleted that VM's workdir: a VM whose create is in flight (or done) and that nobody
removed is never torn down by a concurrent reload (#1610). -/
theorem reload_claim_needs_delete {c : Config} (hc : Good c) {s s' : State} (h : Reachable c s)
    (hs : Step c s s') (hn : s.removal = none) {d : Bool} {pc : RmPc}
    (hr : s'.removal = some ⟨.rpc, d, pc⟩) : s.g.everDeleted = true := by
  have hi := reachable_inv hc h
  cases hs
  case rlClaim r hr' _ _ _ _ =>
    have := hi.reload r hr'
    simp_all [ReloadOk]
  all_goals simp_all

theorem rawRecords_zero {c : Config} (hp : c.poweroffSerialized = true) {s : State}
    (h : Reachable c s) : s.rawRecords = 0 := by
  induction h with
  | init => rfl
  | step _ hs ih => cases hs <;> simp_all

/-- (g) Under #1611, a step that turns `started` from true to false is a stop, a removal's
deletion, `create_vm`'s cleanup, or a guest power-off record -- and the record only when no
start reset the shutdown progress since the "powering off" report it acts on. -/
theorem poweroff_respects_later_start {c : Config} (hc : Good c)
    (hp : c.poweroffSerialized = true) {s s' : State} (h : Reachable c s) (hs : Step c s s')
    (h1 : s.disk.started = true) (h2 : s'.disk.started = false) :
    s.held = some (.stop .setFalse) ∨ (∃ o d, s.removal = some ⟨o, d, .delete⟩) ∨
      s.creating.isSome = true ∨ (s.held = some .record ∧ s.g.startSinceOff = false) := by
  have := (reachable_inv hc h).off
  have := (reachable_inv hc h).fresh
  have := rawRecords_zero hp h
  cases hs <;> simp_all

/-- A full deletion is final: the workdir never comes back (with #1612, `set_started` refuses a
missing workdir instead of recreating it). -/
theorem gone_stays_gone {c : Config} (hc : Good c) {s : State} (h : Reachable c s)
    (hg : s.g.gone = true) : s.disk.dir = false := by
  have := (reachable_inv hc h).gone
  simp_all

/-- #1614: the sealed-env window is open only for a boot this VMM process launched since its
last crash, and a start that adopts a running VM leaves it as it is. -/
theorem env_window_own_boot {c : Config} (hc : Good c) {s : State} (h : Reachable c s)
    (hw : s.envWindow = true) : s.g.freshSinceCrash = true :=
  (reachable_inv hc h).env hw

theorem adopt_keeps_env_window {c : Config} {s s' : State} {k : Kind}
    (hh : s.held = some (.start k (.reset true))) (hs : Step c s s') (hd : s'.held = none)
    (hr : s'.phase = .ready) : s'.envWindow = s.envWindow := by
  cases hs <;> simp_all

/-! ## (c) A stop sticks -/

/-- Holders allowed while a stop is acknowledged: a start before its check (not the boot one),
an explicit start that has not yet committed, or a non-start. -/
def Held.ackOk : Held → Bool
  | .start k .check => k != .boot
  | .start k .info => k == .explicit
  | .start k (.commit _) => k == .explicit
  | .start _ (.reset _) | .start _ .prepare | .start _ .send | .start _ .await => false
  | .stop _ | .record | .update | .reconcile => true

attribute [local simp] Held.ackOk.eq_1 Held.ackOk.eq_2 Held.ackOk.eq_3 Held.ackOk.eq_4
  Held.ackOk.eq_5 Held.ackOk.eq_6 Held.ackOk.eq_7 Held.ackOk.eq_8 Held.ackOk.eq_9
  Held.ackOk.eq_10 Held.ackOk.eq_11

structure Ack (s : State) : Prop where
  started : s.g.stopAcked = true → s.disk.started = false
  held : s.g.stopAcked = true → s.held.all Held.ackOk = true
  waiters : s.g.stopAcked = true → Waiter.start .boot ∉ s.waiters

theorem ack_step {c : Config} (hr : c.loadRecheck = true) {s s' : State} (hi : Inv s)
    (ha : Ack s) (hs : Step c s s') : Ack s' := by
  obtain ⟨a1, a2, a3⟩ := ha
  have := hi.stopLate; have := hi.boot; have := hi.bootTask; have := hi.fresh
  have := phase_facts s.phase
  refine ⟨?_, ?_, ?_⟩ <;> cases hs <;> simp_all
  all_goals first
    | (cases (‹Waiter›) <;> simp_all <;> grind [List.mem_of_mem_erase])
    | (cases (‹Kind›) <;> simp_all <;> grind)
    | grind [List.mem_of_mem_erase]

theorem reachable_ack {c : Config} (hc : Good c) {s : State}
    (h : Reachable c s) : Ack s := by
  induction h with
  | init => exact ⟨by simp [State.init], by simp [State.init], by simp [State.init]⟩
  | step h0 hs ih => exact ack_step hc.loadRecheck (reachable_inv hc h0) ih hs

/-- (c) After an acknowledged stop and until an explicit start commits, nothing deploys the VM:
no automatic restart, guest event, boot or reload start. #1616 makes the starts `load_vm` and
`load_or_update_vm` queue recheck `started` under the lock, as the automatic restart does;
without it the statement is false: `Traces.reload_start_overrides_stop`. -/
theorem stop_sticks {c : Config} (hc : Good c) {s s' : State}
    (h : Reachable c s) (hack : s.g.stopAcked = true) (hs : Step c s s')
    (hrun : s'.entry = .running) : s.entry = .running := by
  refine Classical.byContradiction fun hn => ?_
  obtain ⟨k, hk⟩ := running_needs_start hc h hs hrun hn
  have := (reachable_ack hc h).held hack
  simp_all

/-- (c) While a stop is acknowledged, `started` stays false except by an explicit start. -/
theorem stop_sticks_started {c : Config} (hc : Good c) {s : State}
    (h : Reachable c s) (hack : s.g.stopAcked = true) : s.disk.started = false :=
  (reachable_ack hc h).started hack

end DstackFormal.Vmm
