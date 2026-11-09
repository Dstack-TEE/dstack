\* SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
\* SPDX-License-Identifier: Apache-2.0

----------------------------- MODULE KmsRotation -----------------------------
(***************************************************************************)
(* KMS root epochs: the DstackKms registry, KMS keyrings, onboarding and   *)
(* key release, as implemented by the contract and dstack-kms              *)
(* (main_service.rs servable_epoch/authorized_epoch, onboard_service.rs    *)
(* ensure_handover_registered).                                            *)
(*                                                                         *)
(* A root is an opaque fresh value; a keyring is the sequence of roots of  *)
(* epochs 0..latest. A node serves the current epoch when its keyring      *)
(* holds it and the chain hash over epochs 0..current matches the          *)
(* registry, which is equality of the prefixes.                            *)
(*                                                                         *)
(* The owner registers whatever a generating node attests (the evidence    *)
(* binds the epoch and keys, not the earlier roots) and activates an epoch *)
(* once some node can serve it. Operators may wipe a node to re-onboard.   *)
(***************************************************************************)
EXTENDS Naturals, Sequences, TLC

CONSTANTS Nodes, MaxRoots

VARIABLES
    reg,      \* registered roots, epoch e at index e + 1
    cur,      \* current epoch
    kr,       \* keyring of each node; <<>> before bootstrap or onboarding
    fresh,    \* next fresh root
    released  \* <<epoch, root>> pairs whose derived keys were released

vars == <<reg, cur, kr, fresh, released>>

Prefix(s, n) == SubSeq(s, 1, n)
Latest(n) == Len(kr[n]) - 1

\* servable_epoch: the keyring holds the current epoch with its chain hash.
Serves(n) == Len(reg) > 0 /\ Len(kr[n]) > cur /\ Prefix(kr[n], cur + 1) = Prefix(reg, cur + 1)

Init ==
    /\ reg = <<>> /\ cur = 0 /\ kr = [n \in Nodes |-> <<>>]
    /\ fresh = 1 /\ released = {}

Bootstrap(n) ==
    /\ kr[n] = <<>> /\ fresh <= MaxRoots
    /\ kr' = [kr EXCEPT ![n] = <<fresh>>]
    /\ fresh' = fresh + 1
    /\ UNCHANGED <<reg, cur, released>>

\* Handover from src: src passes its kms_export_keys self-check (it serves
\* the current epoch), the recipient's kms_import_keys check at the highest
\* exported epoch (registered), and ensure_handover_registered (the keyring
\* serves the current epoch; a rotation holds nothing beyond it).
CanHandOver(src, rotate) ==
    /\ Serves(src)
    /\ Latest(src) < Len(reg)
    /\ rotate => Latest(src) = cur

Join(dst, src) ==
    /\ kr[dst] = <<>> /\ CanHandOver(src, FALSE)
    /\ kr' = [kr EXCEPT ![dst] = kr[src]]
    /\ UNCHANGED <<reg, cur, fresh, released>>

RotationJoin(dst, src) ==
    /\ kr[dst] = <<>> /\ CanHandOver(src, TRUE) /\ fresh <= MaxRoots
    /\ kr' = [kr EXCEPT ![dst] = Append(kr[src], fresh)]
    /\ fresh' = fresh + 1
    /\ UNCHANGED <<reg, cur, released>>

\* registerRootEpoch with the keys node n generated for the next epoch.
Register(n) ==
    /\ Len(kr[n]) = Len(reg) + 1
    /\ reg' = Append(reg, kr[n][Len(reg) + 1])
    /\ UNCHANGED <<cur, kr, fresh, released>>

Activate ==
    /\ Len(reg) > cur + 1
    /\ \E n \in Nodes: Len(kr[n]) > cur + 1 /\ Prefix(kr[n], cur + 2) = Prefix(reg, cur + 2)
    /\ cur' = cur + 1
    /\ UNCHANGED <<reg, kr, fresh, released>>

Pop ==
    /\ Len(reg) > cur + 1
    /\ reg' = SubSeq(reg, 1, Len(reg) - 1)
    /\ UNCHANGED <<cur, kr, fresh, released>>

Wipe(n) ==
    /\ kr[n] # <<>>
    /\ kr' = [kr EXCEPT ![n] = <<>>]
    /\ UNCHANGED <<reg, cur, fresh, released>>

\* GetAppKey for epoch e <= current, current or historical.
Release(n, e) ==
    /\ Serves(n) /\ e <= cur
    /\ released' = released \cup {<<e, kr[n][e + 1]>>}
    /\ UNCHANGED <<reg, cur, kr, fresh>>

Next ==
    \/ Activate \/ Pop
    \/ \E n \in Nodes: Bootstrap(n) \/ Register(n) \/ Wipe(n) \/ \E e \in 0..cur: Release(n, e)
    \/ \E d, s \in Nodes: d # s /\ (Join(d, s) \/ RotationJoin(d, s))

Spec == Init /\ [][Next]_vars

Symmetry == Permutations(Nodes)

-----------------------------------------------------------------------------
\* Keys are only ever released from the registered root of their epoch, so
\* no two roots are ever used for one epoch.
ReleasedFromRegisteredRoots ==
    \A r \in released: r[1] <= cur /\ reg[r[1] + 1] = r[2]

Agrees(k) == \A e \in 1..Len(k): e <= Len(reg) => k[e] = reg[e]

\* An ordinary handover only passes on roots the registry agrees with, so a
\* recipient can serve every registered epoch it received once activated.
HandoverAgreesWithRegistry == [][\A d, s \in Nodes: Join(d, s) => Agrees(kr[s])]_vars
=============================================================================
