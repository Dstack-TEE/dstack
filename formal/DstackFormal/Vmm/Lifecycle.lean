-- SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
--
-- SPDX-License-Identifier: Apache-2.0

/-!
# dstack-vmm CVM lifecycle: the model

The per-VM state machine of `dstack-vmm` and its supervisor, for one VM id. Proofs are in
`Vmm.Safety`, concrete traces in `Vmm.Traces`.

Models (fn by fn; one model step per stretch of code between two awaits):
* `dstack/vmm/src/app.rs`: `App::start_vm_with_restart_policy` (pcs `StartPc`), `stop_vm`
  (`StopPc`), `remove_vm`, `finish_remove_vm` and `spawn_finish_remove` (`RmPc`, the removing set
  and `RemovalMark`), `reload_vms` (boot, `BootPc`), `reload_vms_sync` and `load_or_update_vm`
  (`ReloadPc`), `vm_event_report` and `record_guest_power_off`, `try_restart_exited_vms`,
  `reconcile_vm_network_cleanup`, `release_vm_interfaces`, `launch_lock`, `refuse_if_removing`,
  `VmStateMut::start`.
* `dstack/vmm/src/main_service.rs`: `create_vm`, `start_vm`, `stop_vm`, `remove_vm`,
  `update_vm` / `resize_vm` (both: check, write the manifest, `load_vm`), `reload_vms`.
* `dstack/vmm/src/app/workdir.rs`: `set_started` (fails without the workdir), `remove_all`
  (`.removing` last), `set_removing`, `.netd-pending`.
* `dstack/supervisor/src/supervisor.rs`: `deploy` (check `is_running`, then spawn and insert:
  two steps), `stop`, `remove`; `process.rs`: exit.

Tracks `next` at ca4717064d (#1609) with #1610 (5c681af5ee), #1611 (59ae8f8c28), #1612
(e63fd16999), #1613 (ee8be15597) and #1614 (464a7975cb) applied. `Config` switches #1609,
#1610 and #1611 off to replay the bugs they fix, and adds a recheck the code lacks
(`reloadRecheck`) and the cancellation assumption (`cancel`).

State: disk (`Disk`: workdir, loadable manifest, `.state` started flag, `.removing`,
`.netd-pending`), netd (holds interfaces or not), supervisor (the tracked entry, its `started`
flag, `untracked` children whose entry a second deploy replaced, in-flight `deploy` requests),
memory (loaded, the removing set as `removal`, `shutdown_progress == "powering off"`, the sealed
env window, the launch-lock holder `held` and its waiters), and the in-flight RPC / boot tasks.
`Ghost` fields only record history for the theorems.

Assumptions:
* Only the VMM calls the supervisor (the `sv_stop` / `sv_remove` RPCs and `supervisor` CLI are
  not modeled) and only the VMM writes `run_path`.
* VM ids are fresh: `create` happens once per id.
* The supervisor runs detached and survives a VMM crash. A crash lets in-flight supervisor
  requests land before the restarted VMM's first supervisor call (`crash` requires no request in
  flight).
* Futures dropped at an await (a client that gave up) are modeled as `drop` / `abort`; dropping a
  start while its `deploy` request is in flight (`startCancel`) is behind `Config.cancel`.
* Any step may fail where the Rust code may return an error; failures are over-approximated
  (`drop`, `abort`, `rmGiveUp`, `svFail`, a failed netd release).

Gaps: one VM id (the launch lock and the removing set are per id; CIDs, GPUs, ports and other VMs
are out of scope); sidecar processes, the vm-launcher graceful stop and the auto-restart backoff
are not modeled (a tick may fire whenever the VM looks restartable); tokio's FIFO lock order is
not modeled (any waiter may acquire); the guest's own boot is reduced to the events it reports;
the start `load_vm` / `load_or_update_vm` await inline is queued as a waiter (the boot waits for
it in `BootPc.await`); `try_restart_exited_vms` reads the entry's `removing` flag, modeled as the
removing set; a loadable manifest only becomes unloadable across a restart (`imageLost`) or by
`remove_all`.
-/

namespace DstackFormal.Vmm

/-- The supervisor's tracked process for the id (`Exited` and `Stopped` are both `stopped`). -/
inductive Entry where
  | none
  | running
  | stopped
  deriving DecidableEq, Repr

/-- A `deploy` request in flight at the supervisor. `checked`: it passed the `is_running` check.
`attached`: the VMM future that sent it still awaits it. -/
structure Req where
  checked : Bool
  attached : Bool
  deriving DecidableEq, Repr

/-- The workdir. `manifestOk`: `load_vm` succeeds (manifest and image readable). -/
structure Disk where
  dir : Bool
  manifestOk : Bool
  started : Bool
  marker : Bool
  pending : Bool
  deriving DecidableEq, Repr

def Disk.empty : Disk := ⟨false, false, false, false, false⟩

/-- Who asked for a start: `StartVm` / `create_vm`, the auto-restart timer, `load_vm` at boot,
or `load_or_update_vm` in the reload RPC. -/
inductive Kind where
  | explicit
  | auto
  | boot
  | reload
  deriving DecidableEq, Repr

/-- `start_vm_with_restart_policy` under the launch lock. `check`: recheck removing (and
`started`, for an automatic restart); `info`: `supervisor.info` and `wait_for_exit`; `commit`:
`sync_dynamic_config` and `set_started(true)`; `reset`: the in-memory block (`env_update`,
`VmStateMut::start`); `prepare`: `prepare_netd_networks` and the QEMU config; `send` / `await`:
`supervisor.deploy`. `adopt`: the process was already running. -/
inductive StartPc where
  | check
  | info
  | commit (adopt : Bool)
  | reset (adopt : Bool)
  | prepare
  | send
  | await
  deriving DecidableEq, Repr

def StartPc.pastCommit : StartPc → Bool
  | .reset _ | .prepare | .send | .await => true
  | .check | .info | .commit _ => false

/-- `stop_vm` under the launch lock. -/
inductive StopPc where
  | check
  | setFalse
  | stopProc
  | release
  deriving DecidableEq, Repr

/-- The launch-lock holder (other than a removal). -/
inductive Held where
  | start (k : Kind) (pc : StartPc)
  | stop (pc : StopPc)
  | record
  | update
  | reconcile
  deriving DecidableEq, Repr

/-- The holder is the start `load_vm` runs at boot. -/
def Held.isBootStart : Held → Bool
  | .start k _ => k == .boot
  | .stop _ | .record | .update | .reconcile => false

/-- A task waiting for the launch lock. -/
inductive Waiter where
  | start (k : Kind)
  | stop
  | record
  | update
  | reconcile
  deriving DecidableEq, Repr

def Waiter.entry : Waiter → Held
  | .start k => .start k .check
  | .stop => .stop .check
  | .record => .record
  | .update => .update
  | .reconcile => .reconcile

/-- Who claimed the removal: `remove_vm`, a `.removing` marker found by a reload, an orphaned
supervisor process at boot, or a VM whose directory the reload RPC did not find. -/
inductive Origin where
  | user
  | marker
  | orphan
  | rpc
  deriving DecidableEq, Repr

/-- `remove_vm` (`pre`: claimed, `.removing` not yet written) and `finish_remove_vm`. -/
inductive RmPc where
  | pre
  | wait
  | stop
  | exit
  | release
  | delete
  | finish
  deriving DecidableEq, Repr

/-- `finish_remove_vm` holds the launch lock from `stop` on. -/
def RmPc.holds : RmPc → Bool
  | .stop | .exit | .release | .delete | .finish => true
  | .pre | .wait => false

/-- The removal owning the id: `RemovalMark`, i.e. membership in `AppState::removing`. -/
structure Removal where
  origin : Origin
  delete : Bool
  pc : RmPc
  deriving DecidableEq, Repr

def removalHolds : Option Removal → Bool
  | some r => r.pc.holds
  | none => false

/-- `reload_vms_sync`: `list` (`supervisor.list`), `first` / `second` (memory snapshot and
directory scan, in the order `Config.snapshotFirst` says), `claim` (`spawn_finish_remove` for
`memory - fs`), `load` (`load_or_update_vm`, auto start), `markers` (resume `.removing`). -/
inductive ReloadPc where
  | list
  | first
  | second
  | claim
  | load
  | markers
  deriving DecidableEq, Repr

structure Reload where
  pc : ReloadPc
  svHas : Bool
  inMem : Bool
  inFs : Bool
  markerSeen : Bool
  deriving DecidableEq, Repr

/-- `reload_vms` at boot: `list`, `load` (`load_vm`; the start is awaited in `await`), `markers`
(resume `.removing`), `orphan` (orphaned supervisor processes). -/
inductive BootPc where
  | list
  | load
  | await
  | markers
  | orphan
  deriving DecidableEq, Repr

structure Boot where
  pc : BootPc
  svHas : Bool
  markerSeen : Bool
  deriving DecidableEq, Repr

/-- `booting`: `main` runs `reload_vms` before it serves RPCs or starts the timers. -/
inductive Phase where
  | booting (b : Boot)
  | ready
  deriving DecidableEq, Repr

/-- History, for stating the theorems. `stopAcked`: a stop returned Ok and no explicit start has
committed since. `startSinceOff`: a start reset the shutdown progress after the last "powering
off" report. `everDeleted`: a removal ran `remove_all`. `gone`: it deleted the whole workdir.
`freshSinceCrash`: this VMM process launched (not adopted) a boot. -/
structure Ghost where
  stopAcked : Bool
  startSinceOff : Bool
  everDeleted : Bool
  gone : Bool
  freshSinceCrash : Bool
  deriving DecidableEq, Repr

structure State where
  disk : Disk
  netd : Bool
  entry : Entry
  svStarted : Bool
  untracked : Nat
  reqs : List Req
  created : Bool
  creating : Option Bool
  loaded : Bool
  poweringOff : Bool
  envWindow : Bool
  removal : Option Removal
  held : Option Held
  waiters : List Waiter
  reloads : List Reload
  rawRecords : Nat
  phase : Phase
  g : Ghost
  deriving DecidableEq, Repr

/-- Before `create_vm`: nothing exists for the id. -/
def State.init : State :=
  ⟨Disk.empty, false, .none, false, 0, [], false, none, false, false, false, none, none, [], [],
    0, .ready, ⟨false, false, false, false, false⟩⟩

/-- The launch lock is free. -/
def State.lockFree (s : State) : Bool := s.held.isNone && !removalHolds s.removal

/-- `release_vm_interfaces`: without `.netd-pending` it returns true and asks nothing; otherwise
a successful `remove_vm` at netd clears both. -/
def State.release (s : State) (ok : Bool) : State :=
  { s with
    netd := s.netd && !(s.disk.pending && ok)
    disk := { s.disk with pending := s.disk.pending && !ok } }

def State.released (s : State) (ok : Bool) : Bool := !s.disk.pending || ok

def Reload.fresh : Reload := ⟨.list, false, false, false, false⟩

/-- Fixes that can be switched off, and the environment assumption about cancellation. -/
structure Config where
  /-- #1609: boot treats a process as an orphan only if its workdir is gone. -/
  keepRunning : Bool
  /-- #1610: the reload RPC snapshots memory before scanning the directory. -/
  snapshotFirst : Bool
  /-- #1611: a guest power-off is recorded under the launch lock, if still current. -/
  poweroffSerialized : Bool
  /-- Not in the code: the reload RPC's start rechecks `started` under the lock, like the
  automatic restart. -/
  reloadRecheck : Bool
  /-- Environment: a start future may be dropped while its `deploy` request is in flight. -/
  cancel : Bool
  deriving DecidableEq, Repr

/-- The code after the fix PRs. -/
def fixed : Config := ⟨true, true, true, false, false⟩

def replaceReload (rs : List Reload) (r r' : Reload) : List Reload := r' :: rs.erase r

/-- `ws` with `w` pushed when `b`. -/
def addIf (b : Bool) (w : Waiter) (ws : List Waiter) : List Waiter := if b then w :: ws else ws

@[simp] theorem mem_addIf {b : Bool} {w w' : Waiter} {ws : List Waiter} :
    w' ∈ addIf b w ws ↔ (b = true ∧ w' = w) ∨ w' ∈ ws := by
  cases b <;> simp [addIf]

/-- The removal claims a reload makes: `spawn_finish_remove(id)`, which does nothing when a
removal already owns the id. -/
def unclaimed (s : State) : Bool := s.removal.isNone

inductive Step (c : Config) : State → State → Prop
  -- RPCs and events, served once the boot reload is done.
  /-- `create_vm`: `put_manifest`, `prepare_work_dir`, `set_started(!stopped)`. -/
  | create (s : State) (startAfter manifestOk : Bool) (hr : s.phase = .ready)
      (hc : s.created = false) :
      Step c s { s with
        created := true, creating := some startAfter,
        disk := ⟨true, manifestOk, startAfter, false, false⟩ }
  /-- `create_vm`: `load_vm`, then `start_vm` unless created stopped. -/
  | createLoad (s : State) (sa : Bool) (hc : s.creating = some sa) (hd : s.disk.dir = true)
      (hm : s.disk.manifestOk = true) :
      Step c s { s with creating := none, loaded := true, waiters := addIf sa (.start .explicit) s.waiters }
  /-- `create_vm`: `load_vm` failed, `remove_dir_all`. -/
  | createFail (s : State) (sa : Bool) (hc : s.creating = some sa)
      (hf : (s.disk.dir && s.disk.manifestOk) = false) :
      Step c s { s with creating := none, disk := Disk.empty }
  | startRpc (s : State) (hr : s.phase = .ready) :
      Step c s { s with waiters := .start .explicit :: s.waiters }
  | stopRpc (s : State) (hr : s.phase = .ready) :
      Step c s { s with waiters := .stop :: s.waiters }
  | updateRpc (s : State) (hr : s.phase = .ready) :
      Step c s { s with waiters := .update :: s.waiters }
  /-- `remove_vm`: `state.get(id)?`, then `start_removing`. -/
  | removeRpc (s : State) (hr : s.phase = .ready) (hl : s.loaded = true)
      (hn : s.removal = none) :
      Step c s { s with removal := some ⟨.user, true, .pre⟩ }
  | reloadRpc (s : State) (hr : s.phase = .ready) :
      Step c s { s with reloads := Reload.fresh :: s.reloads }
  /-- `vm_event_report("shutdown.progress", "powering off")`, #1611: unless removing, queue
  `record_guest_power_off`. -/
  | powerOff (s : State) (hr : s.phase = .ready) (hl : s.loaded = true)
      (hc : c.poweroffSerialized = true) :
      Step c s { s with
        poweringOff := true, g := { s.g with startSinceOff := false },
        waiters := addIf (unclaimed s) .record s.waiters }
  /-- Before #1611: `set_started(false)` right after the state lock is dropped (`rawRecord`). -/
  | powerOffRaw (s : State) (hr : s.phase = .ready) (hl : s.loaded = true)
      (hc : c.poweroffSerialized = false) :
      Step c s { s with
        poweringOff := true, g := { s.g with startSinceOff := false },
        rawRecords := s.rawRecords + 1 }
  /-- Any other `shutdown.progress` body. -/
  | otherProgress (s : State) (hr : s.phase = .ready) (hl : s.loaded = true) :
      Step c s { s with poweringOff := false }
  /-- `boot.progress` reaching application code closes the env window. -/
  | appStage (s : State) (hr : s.phase = .ready) (hl : s.loaded = true) :
      Step c s { s with envWindow := false }
  /-- `try_restart_exited_vms` decides to restart (its `started` read and backoff are
  over-approximated: the decisive check is the one under the lock). -/
  | tick (s : State) (hr : s.phase = .ready) (hl : s.loaded = true) (hn : s.removal = none)
      (hs : s.disk.started = true) :
      Step c s { s with waiters := .start .auto :: s.waiters }
  /-- `reconcile_network_cleanup` picks the VM. -/
  | reconcileTick (s : State) (hr : s.phase = .ready) (hp : s.disk.pending = true)
      (hn : s.removal = none) :
      Step c s { s with waiters := .reconcile :: s.waiters }
  -- The launch lock.
  /-- A waiter gives up: `refuse_if_removing` before the lock, an error, or a dropped future. -/
  | drop (s : State) (w : Waiter) (hw : w ∈ s.waiters) :
      Step c s { s with waiters := s.waiters.erase w }
  | acquire (s : State) (w : Waiter) (hw : w ∈ s.waiters) (hf : s.lockFree = true) :
      Step c s { s with waiters := s.waiters.erase w, held := some w.entry }
  /-- The holder returns early (an error, a refusal, a dropped future) and the guard drops.
  A start awaiting `deploy` only leaves through `startDone` or `startCancel`. -/
  | abort (s : State) (h : Held) (hh : s.held = some h) (hna : ∀ k, h ≠ .start k .await) :
      Step c s { s with held := none }
  -- `start_vm_with_restart_policy`.
  | startCheck (s : State) (k : Kind) (hh : s.held = some (.start k .check))
      (hn : s.removal = none)
      (hs : (k = .auto ∨ (k = .reload ∧ c.reloadRecheck = true)) → s.disk.started = true) :
      Step c s { s with held := some (.start k .info) }
  | startInfo (s : State) (k : Kind) (hh : s.held = some (.start k .info))
      (hw : ¬(s.entry = .running ∧ s.svStarted = false)) :
      Step c s { s with held := some (.start k (.commit (s.entry == .running))) }
  | startCommit (s : State) (k : Kind) (a : Bool) (hh : s.held = some (.start k (.commit a)))
      (hd : s.disk.dir = true) (hm : s.disk.manifestOk = true) :
      Step c s { s with
        disk := { s.disk with started := true },
        g := { s.g with stopAcked := s.g.stopAcked && k != .explicit },
        held := some (.start k (.reset a)) }
  /-- #1614: adopting a running VM leaves `env_update` alone; the start ends here. -/
  | startAdopt (s : State) (k : Kind) (hh : s.held = some (.start k (.reset true)))
      (hl : s.loaded = true) :
      Step c s { s with
        poweringOff := false, g := { s.g with startSinceOff := true }, held := none }
  | startFresh (s : State) (k : Kind) (hh : s.held = some (.start k (.reset false)))
      (hl : s.loaded = true) :
      Step c s { s with
        poweringOff := false, envWindow := true,
        g := { s.g with startSinceOff := true, freshSinceCrash := true },
        held := some (.start k .prepare) }
  | startPrepare (s : State) (k : Kind) (hh : s.held = some (.start k .prepare)) :
      Step c s { s with
        netd := true, disk := { s.disk with pending := true }, held := some (.start k .send) }
  | startSend (s : State) (k : Kind) (hh : s.held = some (.start k .send)) :
      Step c s { s with reqs := ⟨false, true⟩ :: s.reqs, held := some (.start k .await) }
  | startDone (s : State) (k : Kind) (hh : s.held = some (.start k .await))
      (hq : ∀ r ∈ s.reqs, r.attached = false) :
      Step c s { s with held := none }
  | startCancel (s : State) (k : Kind) (hc : c.cancel = true)
      (hh : s.held = some (.start k .await)) :
      Step c s { s with held := none, reqs := s.reqs.map fun r => { r with attached := false } }
  -- `stop_vm` (#1613: the removing recheck under the lock).
  | stopCheck (s : State) (hh : s.held = some (.stop .check)) (hn : s.removal = none) :
      Step c s { s with held := some (.stop .setFalse) }
  /-- #1612: `set_started` fails without the workdir. -/
  | stopSetFalse (s : State) (hh : s.held = some (.stop .setFalse)) (hd : s.disk.dir = true) :
      Step c s { s with disk := { s.disk with started := false }, held := some (.stop .stopProc) }
  | stopProc (s : State) (hh : s.held = some (.stop .stopProc)) :
      Step c s { s with svStarted := false, held := some (.stop .release) }
  | stopDone (s : State) (ok : Bool) (hh : s.held = some (.stop .release)) :
      Step c s { s.release ok with held := none, g := { s.g with stopAcked := true } }
  -- `record_guest_power_off` (#1611) and the unserialized write it replaced.
  | record (s : State) (hh : s.held = some .record) (hn : s.removal = none)
      (hl : s.loaded = true) (hp : s.poweringOff = true) (hd : s.disk.dir = true) :
      Step c s { s with disk := { s.disk with started := false }, held := none }
  | rawRecord (s : State) (hr : 0 < s.rawRecords) (hd : s.disk.dir = true) :
      Step c s { s with disk := { s.disk with started := false }, rawRecords := s.rawRecords - 1 }
  /-- `update_vm` / `resize_vm`: removing recheck, `manifest()?`, `put_manifest`, `load_vm`. -/
  | update (s : State) (hh : s.held = some .update) (hn : s.removal = none)
      (hd : s.disk.dir = true) (hm : s.disk.manifestOk = true) :
      Step c s { s with loaded := true, held := none }
  /-- `reconcile_vm_network_cleanup` under the lock. -/
  | reconcile (s : State) (ok : Bool) (hh : s.held = some .reconcile) (hn : s.removal = none)
      (he : s.entry ≠ .running) :
      Step c s { s.release ok with held := none }
  -- `remove_vm` and `finish_remove_vm`.
  | rmMarker (s : State) (o : Origin) (d : Bool) (hrm : s.removal = some ⟨o, d, .pre⟩) :
      Step c s { s with
        disk := { s.disk with marker := true, dir := true }, removal := some ⟨o, d, .wait⟩ }
  /-- `set_removing` failed: `RemovalMark` drops. -/
  | rmGiveUp (s : State) (o : Origin) (d : Bool) (hrm : s.removal = some ⟨o, d, .pre⟩) :
      Step c s { s with removal := none }
  | rmAcquire (s : State) (o : Origin) (d : Bool) (hrm : s.removal = some ⟨o, d, .wait⟩)
      (hf : s.held = none) :
      Step c s { s with removal := some ⟨o, d, .stop⟩ }
  /-- `stop_vm_process` (errors are ignored). -/
  | rmStop (s : State) (o : Origin) (d : Bool) (hrm : s.removal = some ⟨o, d, .stop⟩) :
      Step c s { s with svStarted := false, removal := some ⟨o, d, .exit⟩ }
  /-- The poll loop sees the process not running; `supervisor.remove` fails or is not reached. -/
  | rmExit (s : State) (o : Origin) (d : Bool) (hrm : s.removal = some ⟨o, d, .exit⟩)
      (he : s.entry ≠ .running) :
      Step c s { s with removal := some ⟨o, d, .release⟩ }
  /-- `supervisor.remove` succeeds (it refuses a process still `started`). -/
  | rmExitForget (s : State) (o : Origin) (d : Bool) (hrm : s.removal = some ⟨o, d, .exit⟩)
      (he : s.entry ≠ .running) (hs : s.svStarted = false) :
      Step c s { s with entry := .none, removal := some ⟨o, d, .release⟩ }
  /-- Deleting branch: the release is retried until it lands. -/
  | rmReleaseDel (s : State) (o : Origin) (d ok : Bool) (hrm : s.removal = some ⟨o, d, .release⟩)
      (hd : (d || s.disk.marker) = true) (hok : s.released ok = true) :
      Step c s { s.release ok with removal := some ⟨o, d, .delete⟩ }
  /-- Orphan branch: one release attempt, the workdir is kept. -/
  | rmReleaseKeep (s : State) (o : Origin) (d ok : Bool)
      (hrm : s.removal = some ⟨o, d, .release⟩) (hd : (d || s.disk.marker) = false) :
      Step c s { s.release ok with removal := some ⟨o, d, .finish⟩ }
  /-- `remove_all` deletes everything. -/
  | rmDeleteAll (s : State) (o : Origin) (d : Bool) (hrm : s.removal = some ⟨o, d, .delete⟩) :
      Step c s { s with
        disk := Disk.empty, g := { s.g with everDeleted := true, gone := true },
        removal := some ⟨o, d, .finish⟩ }
  /-- `remove_all` fails part-way: the files `kept` says survive, and `.removing`. -/
  | rmDeletePartial (s : State) (o : Origin) (d : Bool) (kept : Disk)
      (hrm : s.removal = some ⟨o, d, .delete⟩) :
      Step c s { s with
        disk := ⟨true, s.disk.manifestOk && kept.manifestOk, s.disk.started && kept.started, true,
          s.disk.pending && kept.pending⟩,
        g := { s.g with everDeleted := true },
        removal := some ⟨o, d, .finish⟩ }
  /-- Drop the entry, free the CID, drop `RemovalMark`. -/
  | rmFinish (s : State) (o : Origin) (d : Bool) (hrm : s.removal = some ⟨o, d, .finish⟩) :
      Step c s { s with loaded := false, removal := none }
  -- `reload_vms_sync` (#1610: snapshot memory first).
  | rlList (s : State) (r : Reload) (hr : r ∈ s.reloads) (hp : r.pc = .list) :
      Step c s { s with
        reloads := replaceReload s.reloads r { r with pc := .first, svHas := s.entry != .none } }
  | rlSnap1 (s : State) (r : Reload) (hr : r ∈ s.reloads) (hp : r.pc = .first)
      (hc : c.snapshotFirst = true) :
      Step c s { s with reloads := replaceReload s.reloads r { r with pc := .second, inMem := s.loaded } }
  | rlScan2 (s : State) (r : Reload) (hr : r ∈ s.reloads) (hp : r.pc = .second)
      (hc : c.snapshotFirst = true) :
      Step c s { s with reloads := replaceReload s.reloads r { r with pc := .claim, inFs := s.disk.dir } }
  /-- Before #1610: scan first, then snapshot. -/
  | rlScan1 (s : State) (r : Reload) (hr : r ∈ s.reloads) (hp : r.pc = .first)
      (hc : c.snapshotFirst = false) :
      Step c s { s with reloads := replaceReload s.reloads r { r with pc := .second, inFs := s.disk.dir } }
  | rlSnap2 (s : State) (r : Reload) (hr : r ∈ s.reloads) (hp : r.pc = .second)
      (hc : c.snapshotFirst = false) :
      Step c s { s with reloads := replaceReload s.reloads r { r with pc := .claim, inMem := s.loaded } }
  /-- `memory - fs`: `spawn_finish_remove`, which keeps the workdir (no `.removing`). -/
  | rlClaim (s : State) (r : Reload) (hr : r ∈ s.reloads) (hp : r.pc = .claim)
      (hm : r.inMem = true) (hf : r.inFs = false) (hn : s.removal = none) :
      Step c s { s with
        removal := some ⟨.rpc, false, .wait⟩,
        reloads := replaceReload s.reloads r { r with pc := .load } }
  | rlNoClaim (s : State) (r : Reload) (hr : r ∈ s.reloads) (hp : r.pc = .claim)
      (hm : (r.inMem && !r.inFs && unclaimed s) = false) :
      Step c s { s with reloads := replaceReload s.reloads r { r with pc := .load } }
  | rlLoad (s : State) (r : Reload) (hr : r ∈ s.reloads) (hp : r.pc = .load) :
      Step c s { s with
        loaded := s.loaded || (s.disk.dir && s.disk.manifestOk),
        waiters := addIf (s.disk.dir && s.disk.manifestOk && !s.disk.marker && s.disk.started &&
          !r.svHas) (.start .reload) s.waiters,
        reloads := replaceReload s.reloads r
          { r with pc := .markers, markerSeen := s.disk.dir && s.disk.marker } }
  | rlMarkers (s : State) (r : Reload) (hr : r ∈ s.reloads) (hp : r.pc = .markers)
      (hm : r.markerSeen = true) (hn : s.removal = none) :
      Step c s { s with removal := some ⟨.marker, false, .wait⟩, reloads := s.reloads.erase r }
  | rlEnd (s : State) (r : Reload) (hr : r ∈ s.reloads) (hp : r.pc = .markers)
      (hm : (r.markerSeen && unclaimed s) = false) :
      Step c s { s with reloads := s.reloads.erase r }
  | rlDrop (s : State) (r : Reload) (hr : r ∈ s.reloads) :
      Step c s { s with reloads := s.reloads.erase r }
  -- `reload_vms` at boot (#1609: keep a running process whose workdir exists).
  /-- The image went away or the config changed across the restart: `load_vm` will fail. -/
  | imageLost (s : State) (b : Boot) (hp : s.phase = .booting b) (hb : b.pc = .list) :
      Step c s { s with disk := { s.disk with manifestOk := false } }
  | bootList (s : State) (b : Boot) (hp : s.phase = .booting b) (hb : b.pc = .list) :
      Step c s { s with phase := .booting { b with pc := .load, svHas := s.entry != .none } }
  | bootLoad (s : State) (b : Boot) (hp : s.phase = .booting b) (hb : b.pc = .load) :
      Step c s { s with
        loaded := s.loaded || (s.disk.dir && s.disk.manifestOk),
        waiters := addIf (s.disk.dir && s.disk.manifestOk && !s.disk.marker && s.disk.started)
          (.start .boot) s.waiters,
        phase := .booting { b with pc := .await, markerSeen := s.disk.dir && s.disk.marker } }
  /-- `load_vm` awaits its `start_vm`. -/
  | bootAwait (s : State) (b : Boot) (hp : s.phase = .booting b) (hb : b.pc = .await)
      (hw : Waiter.start .boot ∉ s.waiters) (hh : s.held.any Held.isBootStart = false) :
      Step c s { s with phase := .booting { b with pc := .markers } }
  | bootMarkers (s : State) (b : Boot) (hp : s.phase = .booting b) (hb : b.pc = .markers)
      (hm : b.markerSeen = true) (hn : s.removal = none) :
      Step c s { s with removal := some ⟨.marker, false, .wait⟩, phase := .booting { b with pc := .orphan } }
  | bootNoMarkers (s : State) (b : Boot) (hp : s.phase = .booting b) (hb : b.pc = .markers)
      (hm : (b.markerSeen && unclaimed s) = false) :
      Step c s { s with phase := .booting { b with pc := .orphan } }
  /-- An orphan: listed by the supervisor, not loaded, and (#1609) no workdir. -/
  | bootOrphan (s : State) (b : Boot) (hp : s.phase = .booting b) (hb : b.pc = .orphan)
      (hv : b.svHas = true) (hl : s.loaded = false)
      (hd : (!s.disk.dir || !c.keepRunning) = true) (hn : s.removal = none) :
      Step c s { s with removal := some ⟨.orphan, false, .wait⟩, phase := .ready }
  | bootDone (s : State) (b : Boot) (hp : s.phase = .booting b) (hb : b.pc = .orphan)
      (hv : (b.svHas && !s.loaded && (!s.disk.dir || !c.keepRunning) && unclaimed s) = false) :
      Step c s { s with phase := .ready }
  -- The supervisor.
  | svReject (s : State) (r : Req) (hr : r ∈ s.reqs) (hc : r.checked = false)
      (he : s.entry = .running) :
      Step c s { s with reqs := s.reqs.erase r }
  | svPass (s : State) (r : Req) (hr : r ∈ s.reqs) (hc : r.checked = false)
      (he : s.entry ≠ .running) :
      Step c s { s with reqs := { r with checked := true } :: s.reqs.erase r }
  /-- `Process::start` and `processes.insert`. -/
  | svAct (s : State) (r : Req) (hr : r ∈ s.reqs) (hc : r.checked = true)
      (he : s.entry ≠ .running) :
      Step c s { s with entry := .running, svStarted := true, reqs := s.reqs.erase r }
  /-- The same over a running entry, which a concurrent deploy inserted after this one's check:
  the replaced `Process` handle drops, its child keeps running untracked. -/
  | svActReplace (s : State) (r : Req) (hr : r ∈ s.reqs) (hc : r.checked = true)
      (he : s.entry = .running) :
      Step c s { s with
        svStarted := true, reqs := s.reqs.erase r, untracked := s.untracked + 1 }
  | svFail (s : State) (r : Req) (hr : r ∈ s.reqs) (hc : r.checked = true) :
      Step c s { s with reqs := s.reqs.erase r }
  /-- QEMU exits (guest power-off, crash, or the kill a stop sent). -/
  | exit (s : State) (he : s.entry = .running) :
      Step c s { s with entry := .stopped }
  | exitUntracked (s : State) (hu : 0 < s.untracked) :
      Step c s { s with untracked := s.untracked - 1 }
  -- A VMM crash: memory and tasks are lost, disk and supervisor stay.
  | crash (s : State) (hq : s.reqs = []) :
      Step c s { s with
        creating := none, loaded := false, poweringOff := false,
        envWindow := false, removal := none, held := none, waiters := [], reloads := [],
        rawRecords := 0, phase := .booting ⟨.list, false, false⟩,
        g := { s.g with freshSinceCrash := false } }

inductive Reachable (c : Config) : State → Prop
  | init : Reachable c State.init
  | step {s s' : State} : Reachable c s → Step c s s' → Reachable c s'

end DstackFormal.Vmm
