\* SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
\* SPDX-License-Identifier: Apache-2.0

------------------------------ MODULE EnvUpdate ------------------------------
(***************************************************************************)
(* Environment re-encryption at boot (dstack-util unseal_env_vars) and the *)
(* VMM's once-per-boot update window (vmm app.rs update_sealed_env and the *)
(* boot.progress handler).                                                 *)
(*                                                                         *)
(* An env value records which owner write it carries, the key epoch it is  *)
(* encrypted to, and who stored it. The VMM opens the window when it       *)
(* launches the VM, recording the stored env; the first update closes it   *)
(* and is applied only over that env; boot progress reaching application   *)
(* code also closes it. Owner updates (UpdateVm) can happen at any time.   *)
(*                                                                         *)
(* Lossy lets either host notification, or the answer to the guest's      *)
(* update, be lost. With FailClosed (#1546) the guest starts applications *)
(* only once the host answered its update, retrying or stopping the boot  *)
(* otherwise; without it, an unanswered update is only logged.            *)
(***************************************************************************)
EXTENDS Naturals

CONSTANTS MaxEpoch, MaxOwnerWrites, Lossy, FailClosed

None == [owner |-> 0, epoch |-> 0, by |-> "none"]

VARIABLES
    current,     \* current key epoch
    store,       \* env stored by the VMM
    ownerWrites, \* number of owner updates so far
    window,      \* env recorded when the window opened, or None when closed
    vm,          \* guest step
    seen         \* env the guest read at boot

vars == <<current, store, ownerWrites, window, vm, seen>>

Init ==
    /\ current = 0
    /\ store = [owner |-> 0, epoch |-> 0, by |-> "owner"]
    /\ ownerWrites = 0
    /\ window = None
    /\ vm = "off"
    /\ seen = None

\* The VMM applies an update from the guest: once per boot, only over the
\* env the boot started with.
Deliver(env, empty) ==
    /\ window' = None
    /\ store' = IF window # None /\ ~empty /\ store = window THEN env ELSE store

Launch ==
    /\ vm = "off"
    /\ vm' = "booting"
    /\ window' = store
    /\ seen' = store
    /\ UNCHANGED <<current, store, ownerWrites>>

\* Re-encrypt to the current epoch if needed and send it, empty otherwise.
\* An unanswered update, whether lost on the way or after the VMM applied
\* it, is retried under FailClosed; the boot may also stop (Stop).
GuestPush ==
    /\ vm = "booting"
    /\ LET env == [owner |-> seen.owner, epoch |-> current, by |-> "guest"]
           empty == seen.epoch = current
           unanswered == IF FailClosed THEN "booting" ELSE "pushed"
       IN \/ Deliver(env, empty) /\ vm' = "pushed"
          \/ Lossy /\ Deliver(env, empty) /\ vm' = unanswered
          \/ Lossy /\ UNCHANGED <<store, window>> /\ vm' = unanswered
    /\ UNCHANGED <<current, ownerWrites, seen>>

\* boot.progress "init-script": application code starts after this.
Progress ==
    /\ vm = "pushed"
    /\ vm' = "app"
    /\ \/ window' = None
       \/ Lossy /\ UNCHANGED window
    /\ UNCHANGED <<current, store, ownerWrites, seen>>

\* Application code calls the host API with an env of its choosing.
AppUpdate ==
    /\ vm = "app"
    /\ Deliver([owner |-> seen.owner, epoch |-> current, by |-> "app"], FALSE)
    /\ UNCHANGED <<current, ownerWrites, vm, seen>>

OwnerUpdate ==
    /\ ownerWrites < MaxOwnerWrites
    /\ ownerWrites' = ownerWrites + 1
    /\ store' = [owner |-> ownerWrites + 1, epoch |-> current, by |-> "owner"]
    /\ UNCHANGED <<current, window, vm, seen>>

Stop ==
    /\ vm # "off"
    /\ vm' = "off"
    /\ window' = None
    /\ UNCHANGED <<current, store, ownerWrites, seen>>

Rotate ==
    /\ vm = "off" /\ current < MaxEpoch
    /\ current' = current + 1
    /\ UNCHANGED <<store, ownerWrites, window, vm, seen>>

Next == Launch \/ GuestPush \/ Progress \/ AppUpdate \/ OwnerUpdate \/ Stop \/ Rotate

Spec == Init /\ [][Next]_vars

-----------------------------------------------------------------------------
\* The latest owner update is never replaced by an older one.
OwnerUpdateKept == store.owner = ownerWrites

\* Application code never replaces the env.
NoAppEnv == store.by # "app"
=============================================================================
