\* SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
\* SPDX-License-Identifier: Apache-2.0

---------------------------- MODULE DiskMigration ----------------------------
(***************************************************************************)
(* Data disk setup and LUKS key migration across KMS key epochs, as        *)
(* implemented by dstack-util (system_setup.rs: setup_data_disk,           *)
(* luks_setup, open_encrypted_volume; system_setup/luks.rs:                *)
(* sync_luks_epochs).                                                      *)
(*                                                                         *)
(* A key epoch abstracts the (root, app) epoch pair: the disk key differs  *)
(* per epoch and the KMS serves every epoch up to the current one. A boot  *)
(* fetches its keys once, so it targets the epoch current at its start;    *)
(* the KMS may rotate at any time.                                         *)
(*                                                                         *)
(* The header has two keyslots and a token recording a keyslot and its     *)
(* epoch. Each cryptsetup command on the device (luksFormat, luksAddKey,   *)
(* luksKillSlot, token import, config --label) is atomic: it writes a new  *)
(* keyslot area before the header copies, each synced, and an outdated     *)
(* copy is repaired from the newer one on the next load. A crash can stop  *)
(* the boot between any two commands.                                      *)
(***************************************************************************)
EXTENDS Integers

CONSTANTS MaxEpoch

Slots == {0, 1}
NoKey == -1
NoToken == [slot |-> -1, epoch |-> -1]
Tokens == {NoToken} \cup [slot: Slots, epoch: 0..MaxEpoch]

VARIABLES
    current,  \* current key epoch on chain
    target,   \* epoch whose keys this boot fetched
    luks,     \* the device holds a LUKS header
    slots,    \* keyslots: Slots -> key epoch or NoKey
    token,    \* the dstack-kms token
    init,     \* the header carries the initializing label
    pc,       \* boot step
    oldSlot,  \* sync_luks_epochs: the recorded keyslot being migrated from
    slot,     \* sync_luks_epochs: the keyslot holding the target key
    hasData   \* applications have written data to the volume

vars == <<current, target, luks, slots, token, init, pc, oldSlot, slot, hasData>>
boot == <<target, oldSlot, slot>>

Keyslots == {s \in Slots: slots[s] # NoKey}
StoredEpoch == IF token = NoToken THEN 0 ELSE token.epoch
\* unlocked_keyslot: the first keyslot the target key opens.
Unlocked == {s \in Slots: slots[s] = target}
First(S) == IF 0 \in S THEN 0 ELSE 1

Init ==
    /\ current \in 0..MaxEpoch
    /\ target = 0
    /\ luks = FALSE
    /\ slots = [s \in Slots |-> NoKey]
    /\ token = NoToken
    /\ init = FALSE
    /\ pc = "off"
    /\ oldSlot = 0 /\ slot = 0
    /\ hasData = FALSE

Rotate ==
    /\ current < MaxEpoch
    /\ current' = current + 1
    /\ UNCHANGED <<target, luks, slots, token, init, pc, oldSlot, slot, hasData>>

\* setup_data_disk: an initialized disk is opened; an interrupted
\* initialization or a blank disk is formatted.
Boot ==
    /\ pc = "off"
    /\ target' = current
    /\ pc' = IF luks /\ ~init THEN "sync" ELSE "format"
    /\ UNCHANGED <<current, luks, slots, token, init, oldSlot, slot, hasData>>

\* luks_setup: luksFormat with the initializing label, key in keyslot 0.
Format ==
    /\ pc = "format"
    /\ luks' = TRUE /\ init' = TRUE
    /\ slots' = [s \in Slots |-> IF s = 0 THEN target ELSE NoKey]
    /\ token' = NoToken
    /\ pc' = IF target > 0 THEN "formatToken" ELSE "sync"
    /\ UNCHANGED <<current, target, oldSlot, slot, hasData>>

FormatToken ==
    /\ pc = "formatToken"
    /\ token' = [slot |-> 0, epoch |-> target]
    /\ pc' = "sync"
    /\ UNCHANGED <<current, target, luks, slots, init, oldSlot, slot, hasData>>

\* sync_luks_epochs, entry.
Sync ==
    /\ pc = "sync"
    /\ LET old == IF token = NoToken THEN 0 ELSE token.slot IN
       CASE StoredEpoch > target -> pc' = "fail" /\ UNCHANGED <<oldSlot, slot>>
         [] Unlocked # {} -> pc' = "record" /\ slot' = First(Unlocked) /\ UNCHANGED oldSlot
         [] StoredEpoch = target -> pc' = "fail" /\ UNCHANGED <<oldSlot, slot>>
         \* The recorded keyslot must exist and open with the recorded epoch.
         [] old \notin Keyslots \/ slots[old] # StoredEpoch ->
              pc' = "fail" /\ UNCHANGED <<oldSlot, slot>>
         [] OTHER -> pc' = "dropStale" /\ oldSlot' = old /\ UNCHANGED slot
    /\ UNCHANGED <<current, target, luks, slots, token, init, hasData>>

\* Drop the keyslot whose epochs were never recorded, to make room.
DropStale ==
    /\ pc = "dropStale"
    /\ slots' = [s \in Slots |-> IF s = oldSlot THEN slots[s] ELSE NoKey]
    /\ pc' = "addKey"
    /\ UNCHANGED <<current, target, luks, token, init, oldSlot, slot, hasData>>

AddKey ==
    /\ pc = "addKey"
    /\ slots' = [slots EXCEPT ![1 - oldSlot] = target]
    /\ slot' = 1 - oldSlot
    /\ pc' = "record"
    /\ UNCHANGED <<current, target, luks, token, init, oldSlot, hasData>>

\* Record the target epoch for the keyslot that holds it; a legacy disk at
\* epoch 0 keeps no token.
Record ==
    /\ pc = "record"
    /\ LET legacy == target = 0 /\ token = NoToken IN
       token' = IF legacy THEN token ELSE [slot |-> slot, epoch |-> target]
    /\ pc' = "killOld"
    /\ UNCHANGED <<current, target, luks, slots, init, oldSlot, slot, hasData>>

KillOld ==
    /\ pc = "killOld"
    /\ slots' = [s \in Slots |-> IF s = slot THEN slots[s] ELSE NoKey]
    /\ pc' = "open"
    /\ UNCHANGED <<current, target, luks, token, init, oldSlot, slot, hasData>>

\* luksOpen with the target key, from the header loaded after the changes.
Open ==
    /\ pc = "open"
    /\ pc' = CASE slots[slot] # target -> "fail"
               [] init -> "mkfs"
               [] OTHER -> "running"
    /\ UNCHANGED <<current, target, luks, slots, token, init, oldSlot, slot, hasData>>

\* mkfs on the volume, then cryptsetup config --label= on the device.
Mkfs ==
    /\ pc = "mkfs"
    /\ init' = FALSE
    /\ pc' = "running"
    /\ UNCHANGED <<current, target, luks, slots, token, oldSlot, slot, hasData>>

WriteData ==
    /\ pc = "running" /\ ~hasData
    /\ hasData' = TRUE
    /\ UNCHANGED <<current, target, luks, slots, token, init, pc, oldSlot, slot>>

\* Shutdown, a crash at any step, or a restart after a failed boot.
Stop ==
    /\ pc # "off"
    /\ pc' = "off"
    /\ UNCHANGED <<current, target, luks, slots, token, init, oldSlot, slot, hasData>>

Next ==
    \/ Rotate \/ Boot \/ Format \/ FormatToken \/ Sync \/ DropStale \/ AddKey
    \/ Record \/ KillOld \/ Open \/ Mkfs \/ WriteData \/ Stop

Spec == Init /\ [][Next]_vars

-----------------------------------------------------------------------------
TypeOK ==
    /\ current \in 0..MaxEpoch /\ target \in 0..current
    /\ slots \in [Slots -> {NoKey} \cup (0..MaxEpoch)]
    /\ token \in Tokens

\* A boot never fails: a failed boot fails again on every retry.
NoBootFailure == pc # "fail"

\* Data, once written, stays under a key the KMS still serves.
DataRecoverable == hasData => (luks /\ \E s \in Keyslots: slots[s] <= current)

\* Reinitialization never runs over data.
NoFormatOverData == pc = "format" => ~hasData

\* A running disk is keyed by its boot's epoch alone, and records it.
RunningIsMigrated ==
    pc = "running" =>
        /\ Keyslots = {slot} /\ slots[slot] = target
        /\ IF token = NoToken THEN target = 0 ELSE token = [slot |-> slot, epoch |-> target]
=============================================================================
