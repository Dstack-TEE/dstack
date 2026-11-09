\* SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
\* SPDX-License-Identifier: Apache-2.0

---------------------------- MODULE DiskMigration ----------------------------
(***************************************************************************)
(* Data disk setup and LUKS keyslot migration across KMS key epochs, as    *)
(* implemented by dstack-util (system_setup.rs: setup_data_disk,           *)
(* luks_setup, open_encrypted_volume, migrate_disk_key).                   *)
(*                                                                         *)
(* A key epoch abstracts the (root, app) epoch pair: the disk key differs  *)
(* per epoch and the KMS serves every epoch up to the current one.         *)
(*                                                                         *)
(* cryptsetup behaviour, measured with cryptsetup 2.7.0 (see README):      *)
(* - luksChangeKey moves keyslot 0 to the other keyslot area and           *)
(*   overwrites the old one;                                               *)
(* - luksHeaderRestore writes both header copies and the keyslot areas in  *)
(*   one 16 MiB write, which a crash can leave partly on disk;             *)
(* - loading a header whose copies differ rewrites the older copy from     *)
(*   the newer one (higher seqid).                                         *)
(*                                                                         *)
(* FixRestore = FALSE models the implementation. FixRestore = TRUE models  *)
(* the proposed fix: luksChangeKey runs on the device,                     *)
(* whose writes are ordered (new area, primary, secondary, old area, each  *)
(* synced; measured with strace), then imports the token. A crash between  *)
(* the two leaves a key newer than the token, possibly of an epoch older   *)
(* than the current one, so the boot tries every epoch from the recorded   *)
(* one to the current one.                                                 *)
(***************************************************************************)
EXTENDS Integers

CONSTANTS MaxEpoch, FixRestore

Areas == {"A", "B"}
Other(a) == IF a = "A" THEN "B" ELSE "A"
NoKey == -1   \* an area holding no usable keyslot
NoToken == -1 \* a header without the dstack-kms token

Headers == [area: Areas, key: 0..MaxEpoch, token: {NoToken} \cup (0..MaxEpoch),
            seq: 0..64, init: BOOLEAN]

VARIABLES
    current,  \* current key epoch on chain
    luks,     \* the device holds a LUKS header
    hp, hs,   \* primary and secondary header copies on the device
    darea,    \* keyslot areas on the device: Areas -> key epoch or NoKey
    copy,     \* in-memory (tmpfs) header copy used for the boot
    carea,    \* keyslot areas of the in-memory copy
    pc,       \* boot step
    hasData   \* applications have written data to the volume

vars == <<current, luks, hp, hs, darea, copy, carea, pc, hasData>>

Newer(h1, h2) == IF h1.seq >= h2.seq THEN h1 ELSE h2
Effective == Newer(hp, hs)
StoredEpoch(h) == IF h.token = NoToken THEN 0 ELSE h.token
\* luksOpen succeeds with the key of epoch e on header h and areas ar.
Opens(h, ar, e) == h.key = e /\ ar[h.area] = e

Init ==
    /\ current \in 0..MaxEpoch
    /\ luks = FALSE
    /\ hp = [area |-> "A", key |-> 0, token |-> NoToken, seq |-> 0, init |-> FALSE]
    /\ hs = hp
    /\ darea = [a \in Areas |-> NoKey]
    /\ copy = hp
    /\ carea = darea
    /\ pc = "off"
    /\ hasData = FALSE

\* The KMS rotates while all CVMs are stopped (runbook step 2).
Rotate ==
    /\ pc = "off" /\ current < MaxEpoch
    /\ current' = current + 1
    /\ UNCHANGED <<luks, hp, hs, darea, copy, carea, pc, hasData>>

Boot ==
    /\ pc = "off"
    /\ pc' = IF luks THEN "backup" ELSE "format"
    /\ UNCHANGED <<current, luks, hp, hs, darea, copy, carea, hasData>>

\* luks_setup: luksFormat with the initializing label. No data exists yet.
Format ==
    /\ pc = "format"
    /\ LET h == [area |-> "A", key |-> current, token |-> NoToken,
                 seq |-> 1, init |-> TRUE]
       IN /\ hp' = h /\ hs' = h
    /\ darea' = [a \in Areas |-> IF a = "A" THEN current ELSE NoKey]
    /\ luks' = TRUE
    /\ pc' = IF current > 0 THEN "token" ELSE "backup"
    /\ UNCHANGED <<current, copy, carea, hasData>>

\* write_luks_epochs on the device; cryptsetup updates the header safely.
WriteToken ==
    /\ pc = "token"
    /\ LET h == [Effective EXCEPT !.token = current, !.seq = @ + 1]
       IN /\ hp' = h /\ hs' = h
    /\ pc' = "backup"
    /\ UNCHANGED <<current, luks, darea, copy, carea, hasData>>

\* open_encrypted_volume: luksHeaderBackup (which repairs an outdated copy),
\* validate the copy and compare its epoch with the current one.
Backup ==
    /\ pc = "backup"
    /\ hp' = Effective /\ hs' = Effective
    /\ copy' = Effective /\ carea' = darea
    /\ LET stored == StoredEpoch(Effective) IN
       pc' = CASE stored > current -> "fail"
               [] stored # current -> "rekey"
               [] OTHER -> "open"
    /\ UNCHANGED <<current, luks, darea, hasData>>

\* migrate_disk_key: luksChangeKey with the historical key on the copy, then
\* record the new epoch in its token.
Rekey ==
    /\ pc = "rekey" /\ ~FixRestore
    /\ LET old == StoredEpoch(copy) IN
       IF Opens(copy, carea, old)
       THEN /\ copy' = [area |-> Other(copy.area), key |-> current, token |-> current,
                        seq |-> copy.seq + 2, init |-> copy.init]
            /\ carea' = [a \in Areas |-> IF a = copy.area THEN NoKey ELSE current]
            /\ pc' = "restore"
       ELSE /\ pc' = "fail"
            /\ UNCHANGED <<copy, carea>>
    /\ UNCHANGED <<current, luks, hp, hs, darea, hasData>>

Regions == {"primary", "secondary", "newArea", "oldArea"}
Written(r, w) == r \in w
ApplyWrite(w) ==
    /\ hp' = IF Written("primary", w) THEN copy ELSE hp
    /\ hs' = IF Written("secondary", w) THEN copy ELSE hs
    /\ darea' = [a \in Areas |->
                   IF a = copy.area
                   THEN IF Written("newArea", w) THEN carea[a] ELSE darea[a]
                   ELSE IF Written("oldArea", w) THEN carea[a] ELSE darea[a]]

\* luksHeaderRestore: one write of all regions; a crash leaves any subset.
Restore ==
    /\ pc = "restore"
    /\ \E w \in SUBSET Regions:
         /\ ApplyWrite(w)
         /\ pc' = IF w = Regions THEN "open" ELSE "off"
    /\ UNCHANGED <<current, luks, copy, carea, hasData>>

\* Fix: luksChangeKey on the device with the key of the first epoch from
\* the recorded one that opens it; only the token is left if that is the
\* current one.
RekeyInPlace ==
    /\ pc = "rekey" /\ FixRestore
    /\ LET keys == {e \in StoredEpoch(Effective)..current: Opens(Effective, darea, e)} IN
       CASE keys = {} -> pc' = "fail" /\ UNCHANGED copy
         [] current \in keys -> pc' = "token" /\ UNCHANGED copy
         [] OTHER ->
              /\ copy' = [Effective EXCEPT !.area = Other(@), !.key = current, !.seq = @ + 2]
              /\ pc' = "newArea"
    /\ UNCHANGED <<current, luks, hp, hs, darea, carea, hasData>>

ChangeNewArea ==
    /\ pc = "newArea"
    /\ darea' = [darea EXCEPT ![copy.area] = current]
    /\ pc' = "primary"
    /\ UNCHANGED <<current, luks, hp, hs, copy, carea, hasData>>
ChangePrimary == pc = "primary" /\ hp' = copy /\ pc' = "secondary"
                 /\ UNCHANGED <<current, luks, hs, darea, copy, carea, hasData>>
ChangeSecondary == pc = "secondary" /\ hs' = copy /\ pc' = "wipeOld"
                   /\ UNCHANGED <<current, luks, hp, darea, copy, carea, hasData>>
WipeOld ==
    /\ pc = "wipeOld"
    /\ darea' = [darea EXCEPT ![Other(copy.area)] = NoKey]
    /\ pc' = "token"
    /\ UNCHANGED <<current, luks, hp, hs, copy, carea, hasData>>

\* luksOpen --header <in-memory copy>: the keyslot is read from the copy.
Open ==
    /\ pc = "open"
    /\ pc' = IF ~Opens(copy, carea, current) THEN "fail"
             ELSE IF copy.init THEN "mkfs" ELSE "running"
    /\ UNCHANGED <<current, luks, hp, hs, darea, copy, carea, hasData>>

\* mkfs on the volume, then cryptsetup config --label= on the device.
Mkfs ==
    /\ pc = "mkfs"
    /\ LET h == [Effective EXCEPT !.init = FALSE, !.seq = @ + 1]
       IN /\ hp' = h /\ hs' = h
    /\ pc' = "running"
    /\ UNCHANGED <<current, luks, darea, copy, carea, hasData>>

WriteData ==
    /\ pc = "running" /\ ~hasData
    /\ hasData' = TRUE
    /\ UNCHANGED <<current, luks, hp, hs, darea, copy, carea, pc>>

\* Shutdown, a crash at any step, or a restart after a failed boot; the
\* in-memory copy is lost.
Stop ==
    /\ pc # "off"
    /\ pc' = "off"
    /\ UNCHANGED <<current, luks, hp, hs, darea, copy, carea, hasData>>

Next ==
    \/ Rotate \/ Boot \/ Format \/ WriteToken \/ Backup \/ Rekey
    \/ Restore \/ RekeyInPlace \/ ChangeNewArea \/ ChangePrimary \/ ChangeSecondary \/ WipeOld
    \/ Open \/ Mkfs \/ WriteData \/ Stop

Spec == Init /\ [][Next]_vars

-----------------------------------------------------------------------------
TypeOK ==
    /\ current \in 0..MaxEpoch
    /\ hp \in Headers /\ hs \in Headers /\ copy \in Headers
    /\ darea \in [Areas -> {NoKey} \cup (0..MaxEpoch)]

\* A boot never fails: a failed boot fails again on every retry.
NoBootFailure == pc # "fail"

\* Keys a boot tries; the KMS keeps serving every epoch up to the current one.
BootKeys == IF FixRestore THEN StoredEpoch(Effective)..current ELSE {StoredEpoch(Effective)}

\* Data, once written, can always be opened by the next boot.
DataRecoverable == hasData => \E e \in BootKeys: Opens(Effective, darea, e)

\* Reinitialization never runs over data.
NoFormatOverData == pc \in {"format", "mkfs"} => ~hasData
=============================================================================
