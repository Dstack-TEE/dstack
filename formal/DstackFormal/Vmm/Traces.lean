-- SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
--
-- SPDX-License-Identifier: Apache-2.0

import DstackFormal.Vmm.Safety

/-!
# dstack-vmm CVM lifecycle: concrete traces

Executions of the model in `Vmm.Lifecycle` (same code and commits), each step checked by
`rfl` / `decide` on concrete states. They validate the model against the Rust tests and show
what the fixes and assumptions are for.

Counterexamples:
* `deploy_while_removing`: (a) as stated is false for the fixed code. By design: removal stops
  the process once it holds the lock.
* `cancel_two_running`: (b) needs the assumption that a start future is not dropped while its
  `deploy` request is in flight.
* `reload_start_overrides_stop`: (c) is false for the fixed code (reload RPC start).
* `orphan_stop_before_1609`, `reload_removes_new_vm_before_1610`,
  `poweroff_cancels_start_before_1611`: the bugs #1609, #1610 and #1611 fix.

Rust tests mirrored: `a_running_vm_that_fails_to_load_is_not_treated_as_an_orphan`
(`unloadable_kept_running`), `a_guest_power_off_does_not_override_a_later_start`
(`poweroff_record_after_start`, `poweroff_while_removing_queues_nothing`),
`a_stop_queued_behind_a_removal_is_turned_away` (`stop_behind_removal`),
`an_automatic_restart_does_not_outlive_the_stop_it_raced` (`restart_behind_stop`),
`a_start_on_a_running_vm_keeps_its_env_window` (`adopt_keeps_window`),
`started_is_not_written_into_a_removed_workdir` (`stop_after_removal`).
-/

namespace DstackFormal.Vmm.Traces

open DstackFormal.Vmm

set_option linter.unusedSimpArgs false

/-- The state after `create_vm` launched a VM that is now running. -/
def launchedState : State :=
  { State.init with
    disk := ⟨true, true, true, false, true⟩, netd := true, entry := .running, svStarted := true,
    created := true, loaded := true, envWindow := true,
    g := ⟨false, true, false, false, true⟩ }

/-- `create_vm` with `stopped = false`, its `start_vm`, and the deploy landing. No fix is
involved, so this holds for every configuration. -/
theorem launched (c : Config) : Reachable c launchedState := by
  have h := (Reachable.init (c := c)).step (Step.create _ true true rfl rfl)
  have h := h.step (Step.createLoad _ true rfl rfl rfl)
  have h := h.step (Step.acquire _ (.start .explicit) (by decide) rfl)
  have h := h.step (Step.startCheck _ .explicit rfl rfl (by simp))
  have h := h.step (Step.startInfo _ .explicit rfl (by decide))
  have h := h.step (Step.startCommit _ .explicit false rfl rfl rfl)
  have h := h.step (Step.startFresh _ .explicit rfl rfl)
  have h := h.step (Step.startPrepare _ .explicit rfl)
  have h := h.step (Step.startSend _ .explicit rfl)
  have h := h.step (Step.svPass _ ⟨false, true⟩ (by decide) rfl (by decide))
  have h := h.step (Step.svAct _ ⟨true, true⟩ (by decide) rfl (by decide))
  exact h.step (Step.startDone _ .explicit rfl (by decide))

/-! ## (a) is false as stated: a deploy can land while the id is in the removing set

`remove_vm` claims the id without the launch lock, so a start that passed its under-lock check
before the claim goes on to deploy. This is by design: `finish_remove_vm` then takes the lock
and stops what the start launched (`removal_holds_no_deploy`). -/

theorem deploy_while_removing : ∃ s s', Reachable fixed s ∧ Step fixed s s' ∧
    s.removal = some ⟨.user, true, .pre⟩ ∧ s.entry ≠ .running ∧ s'.entry = .running := by
  have h := (Reachable.init (c := fixed)).step (Step.create _ true true rfl rfl)
  have h := h.step (Step.createLoad _ true rfl rfl rfl)
  have h := h.step (Step.acquire _ (.start .explicit) (by decide) rfl)
  have h := h.step (Step.startCheck _ .explicit rfl rfl (by simp))
  have h := h.step (Step.startInfo _ .explicit rfl (by decide))
  have h := h.step (Step.startCommit _ .explicit false rfl rfl rfl)
  have h := h.step (Step.startFresh _ .explicit rfl rfl)
  have h := h.step (Step.startPrepare _ .explicit rfl)
  have h := h.step (Step.removeRpc _ rfl rfl rfl)
  have h := h.step (Step.startSend _ .explicit rfl)
  have h := h.step (Step.svPass _ ⟨false, true⟩ (by decide) rfl (by decide))
  exact ⟨_, _, h, Step.svAct _ ⟨true, true⟩ (by decide) rfl (by decide), rfl, by decide, rfl⟩

/-! ## (b) needs the no-cancellation assumption

A start future dropped while its `deploy` request is in flight releases the launch lock; the
next start reads "not running" before the orphaned request lands, and the supervisor's
check-then-act lets both deploys through. The second `processes.insert` replaces the first
entry, whose child keeps running untracked. (The same window also lets the second launch
sweep the first QEMU's interfaces, the race the launch lock exists to prevent.) -/

def cancelling : Config := { fixed with cancel := true }

theorem cancel_two_running : ∃ s, Reachable cancelling s ∧ s.running = 2 := by
  have h := (Reachable.init (c := cancelling)).step (Step.create _ true true rfl rfl)
  have h := h.step (Step.createLoad _ true rfl rfl rfl)
  have h := h.step (Step.acquire _ (.start .explicit) (by decide) rfl)
  have h := h.step (Step.startCheck _ .explicit rfl rfl (by simp))
  have h := h.step (Step.startInfo _ .explicit rfl (by decide))
  have h := h.step (Step.startCommit _ .explicit false rfl rfl rfl)
  have h := h.step (Step.startFresh _ .explicit rfl rfl)
  have h := h.step (Step.startPrepare _ .explicit rfl)
  have h := h.step (Step.startSend _ .explicit rfl)
  have h := h.step (Step.startCancel _ .explicit rfl rfl)
  have h := h.step (Step.startRpc _ rfl)
  have h := h.step (Step.acquire _ (.start .explicit) (by decide) rfl)
  have h := h.step (Step.startCheck _ .explicit rfl rfl (by simp))
  have h := h.step (Step.startInfo _ .explicit rfl (by decide))
  have h := h.step (Step.startCommit _ .explicit false rfl rfl rfl)
  have h := h.step (Step.startFresh _ .explicit rfl rfl)
  have h := h.step (Step.startPrepare _ .explicit rfl)
  have h := h.step (Step.startSend _ .explicit rfl)
  have h := h.step (Step.svPass _ ⟨false, true⟩ (by decide) rfl (by decide))
  have h := h.step (Step.svPass _ ⟨false, false⟩ (by decide) rfl (by decide))
  have h := h.step (Step.svAct _ ⟨true, true⟩ (by decide) rfl (by decide))
  have h := h.step (Step.svActReplace _ ⟨true, false⟩ (by decide) rfl rfl)
  exact ⟨_, h, rfl⟩

/-! ## (c) is false for the fixed code: the reload RPC's start overrides an acknowledged stop

`load_or_update_vm` reads `started` and queues `start_vm` with `reset_restart_policy = true`,
which does not reread `started` under the launch lock. A stop that lands in between is undone:
the VM is redeployed after `StopVm` returned Ok. Here the reload races `create_vm`; a VM whose
supervisor entry is missing (supervisor restarted, `sv_remove`) races any stop the same way.
`stop_sticks` proves the property once the reload start rechecks. -/

theorem reload_start_overrides_stop : ∃ s s', Reachable fixed s ∧ s.g.stopAcked = true ∧
    Step fixed s s' ∧ s.entry ≠ .running ∧ s'.entry = .running := by
  have h := (Reachable.init (c := fixed)).step (Step.create _ true true rfl rfl)
  have h := h.step (Step.reloadRpc _ rfl)
  have h := h.step (Step.rlList _ Reload.fresh (by decide) rfl)
  have h := h.step (Step.createLoad _ true rfl rfl rfl)
  have h := h.step (Step.rlSnap1 _ ⟨.first, false, false, false, false⟩ (by decide) rfl rfl)
  have h := h.step (Step.rlScan2 _ ⟨.second, false, true, false, false⟩ (by decide) rfl rfl)
  have h := h.step (Step.rlNoClaim _ ⟨.claim, false, true, true, false⟩ (by decide) rfl rfl)
  have h := h.step (Step.rlLoad _ ⟨.load, false, true, true, false⟩ (by decide) rfl)
  have h := h.step (Step.rlEnd _ ⟨.markers, false, true, true, false⟩ (by decide) rfl rfl)
  -- `create_vm`'s own start launches the VM.
  have h := h.step (Step.acquire _ (.start .explicit) (by decide) rfl)
  have h := h.step (Step.startCheck _ .explicit rfl rfl (by simp))
  have h := h.step (Step.startInfo _ .explicit rfl (by decide))
  have h := h.step (Step.startCommit _ .explicit false rfl rfl rfl)
  have h := h.step (Step.startFresh _ .explicit rfl rfl)
  have h := h.step (Step.startPrepare _ .explicit rfl)
  have h := h.step (Step.startSend _ .explicit rfl)
  have h := h.step (Step.svPass _ ⟨false, true⟩ (by decide) rfl (by decide))
  have h := h.step (Step.svAct _ ⟨true, true⟩ (by decide) rfl (by decide))
  have h := h.step (Step.startDone _ .explicit rfl (by decide))
  -- The user stops it; the stop is acknowledged and QEMU exits.
  have h := h.step (Step.stopRpc _ rfl)
  have h := h.step (Step.acquire _ .stop (by decide) rfl)
  have h := h.step (Step.stopCheck _ rfl rfl)
  have h := h.step (Step.stopSetFalse _ rfl rfl)
  have h := h.step (Step.stopProc _ rfl)
  have h := h.step (Step.stopDone _ true rfl)
  have h := h.step (Step.exit _ rfl)
  -- The reload's start runs on its stale read.
  have h := h.step (Step.acquire _ (.start .reload) (by decide) rfl)
  have h := h.step (Step.startCheck _ .reload rfl rfl (by simp [fixed]))
  have h := h.step (Step.startInfo _ .reload rfl (by decide))
  have h := h.step (Step.startCommit _ .reload false rfl rfl rfl)
  have h := h.step (Step.startFresh _ .reload rfl rfl)
  have h := h.step (Step.startPrepare _ .reload rfl)
  have h := h.step (Step.startSend _ .reload rfl)
  have h := h.step (Step.svPass _ ⟨false, true⟩ (by decide) rfl (by decide))
  exact ⟨_, _, h, rfl, Step.svAct _ ⟨true, true⟩ (by decide) rfl (by decide), by decide, rfl⟩

/-! ## (d) Before #1609 a running VM that fails to load at boot is stopped as an orphan -/

def noKeepRunning : Config := { fixed with keepRunning := false }

set_option hygiene false in
/-- The VMM crashes; at restart the image is gone, so the boot reload cannot load the running
VM. -/
macro "crashUnloadable" c:term : tactic => `(tactic| (
  have h := (launched $c).step (Step.crash _ rfl)
  have h := h.step (Step.imageLost _ _ rfl rfl)
  have h := h.step (Step.bootList _ _ rfl rfl)
  have h := h.step (Step.bootLoad _ _ rfl rfl)
  have h := h.step (Step.bootAwait _ _ rfl rfl (by decide) rfl)
  have h := h.step (Step.bootNoMarkers _ _ rfl rfl rfl)))

theorem orphan_stop_before_1609 : ∃ s, Reachable noKeepRunning s ∧
    s.removal = some ⟨.orphan, false, .stop⟩ ∧ s.disk.dir = true ∧ s.disk.marker = false ∧
    s.entry = .running := by
  crashUnloadable noKeepRunning
  have h := h.step (Step.bootOrphan _ _ rfl rfl rfl rfl rfl rfl)
  exact ⟨_, h.step (Step.rmAcquire _ _ _ rfl rfl), rfl, rfl, rfl, rfl⟩

/-- Mirrors `a_running_vm_that_fails_to_load_is_not_treated_as_an_orphan`: with #1609 the boot
ends with no removal and the VM still running. -/
theorem unloadable_kept_running : ∃ s, Reachable fixed s ∧ s.phase = .ready ∧
    s.removal = none ∧ s.loaded = false ∧ s.disk.dir = true ∧ s.entry = .running := by
  crashUnloadable fixed
  exact ⟨_, h.step (Step.bootDone _ _ rfl rfl rfl), rfl, rfl, rfl, rfl, rfl⟩

/-- With #1609 the orphan claim is not enabled there at all. -/
theorem unloadable_no_orphan_claim : ¬ (!true || !fixed.keepRunning) = true := by decide

/-! ## (f) Before #1610 the reload RPC tears down a VM created during its scan -/

def scanFirst : Config := { fixed with snapshotFirst := false }

theorem reload_removes_new_vm_before_1610 : ∃ s, Reachable scanFirst s ∧
    s.removal = some ⟨.rpc, false, .wait⟩ ∧ s.disk.dir = true ∧ s.disk.marker = false ∧
    s.g.everDeleted = false := by
  have h := (Reachable.init (c := scanFirst)).step (Step.reloadRpc _ rfl)
  have h := h.step (Step.rlList _ Reload.fresh (by decide) rfl)
  have h := h.step (Step.rlScan1 _ ⟨.first, false, false, false, false⟩ (by decide) rfl rfl)
  have h := h.step (Step.create _ false true rfl rfl)
  have h := h.step (Step.createLoad _ false rfl rfl rfl)
  have h := h.step (Step.rlSnap2 _ ⟨.second, false, false, false, false⟩ (by decide) rfl rfl)
  have h := h.step (Step.rlClaim _ ⟨.claim, false, true, false, false⟩ (by decide) rfl rfl rfl rfl)
  exact ⟨_, h, rfl, rfl, rfl, rfl⟩

/-- With #1610 the same interleaving snapshots memory before `create_vm` loads the VM, and the
claim is not enabled. -/
theorem reload_keeps_new_vm : ∃ s, Reachable fixed s ∧ s.reloads = [⟨.claim, false, false, true, false⟩] ∧
    s.loaded = true ∧ ∀ s', Step fixed s s' → s'.removal ≠ some ⟨.rpc, false, .wait⟩ := by
  have h := (Reachable.init (c := fixed)).step (Step.reloadRpc _ rfl)
  have h := h.step (Step.rlList _ Reload.fresh (by decide) rfl)
  have h := h.step (Step.rlSnap1 _ ⟨.first, false, false, false, false⟩ (by decide) rfl rfl)
  have h := h.step (Step.create _ false true rfl rfl)
  have h := h.step (Step.createLoad _ false rfl rfl rfl)
  have h := h.step (Step.rlScan2 _ ⟨.second, false, false, false, false⟩ (by decide) rfl rfl)
  refine ⟨_, h, rfl, rfl, fun s' hs hr => ?_⟩
  have := reload_claim_needs_delete good_fixed h hs rfl hr
  exact absurd this (by decide)

/-! ## (g) Before #1611 a guest power-off cancels a later start -/

def rawPowerOff : Config := { fixed with poweroffSerialized := false }

/-- The guest reports "powering off"; a `StartVm` adopts the running VM and resets the shutdown
progress; only then does the report's `set_started(false)` land. -/
theorem poweroff_cancels_start_before_1611 : ∃ s s', Reachable rawPowerOff s ∧
    Step rawPowerOff s s' ∧ s.g.startSinceOff = true ∧ s.disk.started = true ∧
    s'.disk.started = false ∧ s.held = none ∧ s.removal = none ∧ s.creating = none := by
  have h := (launched rawPowerOff).step (Step.powerOffRaw _ rfl rfl rfl)
  have h := h.step (Step.startRpc _ rfl)
  have h := h.step (Step.acquire _ (.start .explicit) (by decide) rfl)
  have h := h.step (Step.startCheck _ .explicit rfl rfl (by simp))
  have h := h.step (Step.startInfo _ .explicit rfl (by decide))
  have h := h.step (Step.startCommit _ .explicit true rfl rfl rfl)
  have h := h.step (Step.startAdopt _ .explicit rfl rfl)
  exact ⟨_, _, h, Step.rawRecord _ (by decide) rfl, rfl, rfl, rfl, rfl, rfl, rfl⟩

/-- Mirrors `a_guest_power_off_does_not_override_a_later_start`: the report arrives while a
start holds the lock; the start resets the progress; the queued record then holds the lock and
`poweroff_respects_later_start` rules out its write. -/
theorem poweroff_record_after_start : ∃ s, Reachable fixed s ∧ s.held = some .record ∧
    s.g.startSinceOff = true ∧ ∀ s', Step fixed s s' → s'.disk.started = true := by
  have h := (launched fixed).step (Step.startRpc _ rfl)
  have h := h.step (Step.acquire _ (.start .explicit) (by decide) rfl)
  have h := h.step (Step.powerOff _ rfl rfl rfl)
  have h := h.step (Step.startCheck _ .explicit rfl rfl (by simp))
  have h := h.step (Step.startInfo _ .explicit rfl (by decide))
  have h := h.step (Step.startCommit _ .explicit true rfl rfl rfl)
  have h := h.step (Step.startAdopt _ .explicit rfl rfl)
  have h := h.step (Step.acquire _ .record (by decide) rfl)
  refine ⟨_, h, rfl, rfl, fun s' hs => ?_⟩
  cases hd : s'.disk.started
  · have := poweroff_respects_later_start good_fixed rfl h hs rfl hd
    simp [launchedState, State.init, addIf, unclaimed, Waiter.entry] at this
  · rfl

/-- The same report for a VM being removed queues no record. -/
theorem poweroff_while_removing_queues_nothing {s : State} (h : s.removal.isSome = true) :
    addIf (unclaimed s && fixed.poweroffSerialized) .record s.waiters = s.waiters := by
  cases hr : s.removal <;> simp_all [unclaimed, addIf]

/-! ## Rust tests -/

/-- `a_stop_queued_behind_a_removal_is_turned_away` (#1613): a stop that gets the lock after a
removal claimed the VM can only give up. -/
theorem stop_behind_removal : ∃ s, Reachable fixed s ∧ s.held = some (.stop .check) ∧
    ∀ s', Step fixed s s' → s'.held ≠ some (.stop .setFalse) := by
  have h := (launched fixed).step (Step.stopRpc _ rfl)
  have h := h.step (Step.removeRpc _ rfl rfl rfl)
  have h := h.step (Step.acquire _ .stop (by decide) rfl)
  refine ⟨_, h, rfl, fun s' hs => ?_⟩
  cases hs <;> simp_all [launchedState, State.init, Waiter.entry, State.release, State.released,
    Disk.empty, State.lockFree, removalHolds, RmPc.holds]
  all_goals cases (‹Waiter›) <;> simp_all [Waiter.entry]

/-- `an_automatic_restart_does_not_outlive_the_stop_it_raced`: a restart decided before a stop
reaches the lock after it, rereads `started` and gives up. -/
theorem restart_behind_stop : ∃ s, Reachable fixed s ∧ s.held = some (.start .auto .check) ∧
    s.g.stopAcked = true ∧ ∀ s', Step fixed s s' → s'.held ≠ some (.start .auto .info) := by
  have h := (launched fixed).step (Step.exit _ rfl)
  have h := h.step (Step.tick _ rfl rfl rfl rfl)
  have h := h.step (Step.stopRpc _ rfl)
  have h := h.step (Step.acquire _ .stop (by decide) rfl)
  have h := h.step (Step.stopCheck _ rfl rfl)
  have h := h.step (Step.stopSetFalse _ rfl rfl)
  have h := h.step (Step.stopProc _ rfl)
  have h := h.step (Step.stopDone _ true rfl)
  have h := h.step (Step.acquire _ (.start .auto) (by decide) rfl)
  refine ⟨_, h, rfl, rfl, fun s' hs => ?_⟩
  cases hs <;> simp_all [launchedState, State.init, Waiter.entry, State.release, State.released,
    Disk.empty, State.lockFree, removalHolds, RmPc.holds]
  all_goals cases (‹Waiter›) <;> simp_all [Waiter.entry]

/-- `a_start_on_a_running_vm_keeps_its_env_window` (#1614). -/
theorem adopt_keeps_window : ∃ s, Reachable fixed s ∧ s.held = none ∧ s.envWindow = true ∧
    s.disk.started = true := by
  have h := (launched fixed).step (Step.startRpc _ rfl)
  have h := h.step (Step.acquire _ (.start .explicit) (by decide) rfl)
  have h := h.step (Step.startCheck _ .explicit rfl rfl (by simp))
  have h := h.step (Step.startInfo _ .explicit rfl (by decide))
  have h := h.step (Step.startCommit _ .explicit true rfl rfl rfl)
  exact ⟨_, h.step (Step.startAdopt _ .explicit rfl rfl), rfl, rfl, rfl⟩

/-- `started_is_not_written_into_a_removed_workdir` (#1612): a stop queued behind a removal that
deleted the workdir cannot write `.state`. -/
theorem stop_after_removal : ∃ s, Reachable fixed s ∧ s.held = some (.stop .setFalse) ∧
    s.disk.dir = false ∧ ∀ s', Step fixed s s' → s'.held ≠ some (.stop .stopProc) := by
  have h := (launched fixed).step (Step.stopRpc _ rfl)
  have h := h.step (Step.removeRpc _ rfl rfl rfl)
  have h := h.step (Step.rmMarker _ _ _ rfl)
  have h := h.step (Step.rmAcquire _ _ _ rfl rfl)
  have h := h.step (Step.rmStop _ _ _ rfl)
  have h := h.step (Step.exit _ rfl)
  have h := h.step (Step.rmExitForget _ _ _ rfl (by decide) rfl)
  have h := h.step (Step.rmReleaseDel _ _ _ true rfl rfl rfl)
  have h := h.step (Step.rmDeleteAll _ _ _ rfl)
  have h := h.step (Step.rmFinish _ _ _ rfl)
  have h := h.step (Step.acquire _ .stop (by decide) rfl)
  have h := h.step (Step.stopCheck _ rfl rfl)
  refine ⟨_, h, rfl, rfl, fun s' hs => ?_⟩
  cases hs <;> simp_all [launchedState, State.init, Waiter.entry, State.release, State.released,
    Disk.empty, State.lockFree, removalHolds, RmPc.holds]
  all_goals cases (‹Waiter›) <;> simp_all [Waiter.entry]

end DstackFormal.Vmm.Traces
