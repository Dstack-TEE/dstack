\* SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
\* SPDX-License-Identifier: Apache-2.0

----------------------------- MODULE EpochPolicy -----------------------------
(***************************************************************************)
(* Epoch-scoped policy of DstackKms and DstackApp, and key release decided *)
(* on the selected rows.                                                   *)
(*                                                                         *)
(* Root side (DstackKms): one row of allowed values (OS images; KMS MRs   *)
(* and devices alike) per root epoch, written by *AtEpoch(s) over a range *)
(* of registered rows. A pending epoch can be popped and registered again, *)
(* with the same or other keys. Rows are keyed by registration            *)
(* (RootEpoch.registration); KeyByChainHash = TRUE models the earlier     *)
(* contract, which keyed them by chain hash.                               *)
(*                                                                         *)
(* App side (DstackApp): one row of allowed compose hashes per app epoch,  *)
(* written over a range up to the next epoch. An app policy predating app  *)
(* epochs (v0.5.x, v0.6.0) has only its flat mapping, which is row 0, and  *)
(* epoch-less setters writing it; DstackKms authorizes it through          *)
(* isAppAllowed for app epoch 0 only. Its owner may upgrade it at any      *)
(* time, keeping the mapping as row 0. LegacyIgnoresAppEpoch = TRUE drops  *)
(* the app epoch 0 check of that fallback.                                 *)
(***************************************************************************)
EXTENDS Naturals, Sequences

CONSTANTS Values, Keys, MaxEpoch, MaxRegistrations, KeyByChainHash,
          Composes, MaxAppEpoch, LegacyIgnoresAppEpoch

VARIABLES
    keys,        \* keys of the registered root epochs, epoch e at index e + 1
    regs,        \* registration of each registered root epoch
    nextReg,     \* registrations so far
    cur,         \* current root epoch
    rows,        \* <<row key, value>> pairs allowed
    revoked,     \* values removed from every registered row, not added since
    legacy,      \* the app policy predates app epochs
    appCur,      \* current app epoch
    appRows,     \* <<app epoch, compose hash>> pairs allowed
    appRevoked,  \* compose hashes removed from every app row, not added since
    leaked,      \* a key released for a revoked value or compose hash
    mismatched   \* an app key released for an app epoch whose row disallows it

vars == <<keys, regs, nextReg, cur, rows, revoked, legacy, appCur, appRows,
          appRevoked, leaked, mismatched>>
rootVars == <<keys, regs, nextReg, cur, rows, revoked>>
appVars == <<legacy, appCur, appRows, appRevoked>>
ghostVars == <<leaked, mismatched>>

Latest == Len(keys) - 1
RowKey(ks, rs, e) == IF KeyByChainHash THEN SubSeq(ks, 1, e + 1) ELSE <<rs[e + 1]>>
Row(e) == {v \in Values: <<RowKey(keys, regs, e), v>> \in rows}
AppRow(a) == {c \in Composes: <<a, c>> \in appRows}

Init ==
    /\ \E k \in Keys: keys = <<k>>
    /\ regs = <<0>> /\ nextReg = 1 /\ cur = 0
    /\ rows = {} /\ revoked = {}
    /\ legacy \in BOOLEAN /\ appCur = 0 /\ appRows = {} /\ appRevoked = {}
    /\ leaked = {} /\ mismatched = FALSE

\* ---- DstackKms ----
Register(k) ==
    /\ Latest < MaxEpoch /\ nextReg < MaxRegistrations
    /\ keys' = Append(keys, k)
    /\ regs' = Append(regs, nextReg)
    /\ nextReg' = nextReg + 1
    /\ UNCHANGED <<cur, rows, revoked, appVars, ghostVars>>

Activate ==
    /\ cur < Latest
    /\ cur' = cur + 1
    /\ UNCHANGED <<keys, regs, nextReg, rows, revoked, appVars, ghostVars>>

Pop ==
    /\ Latest > cur
    /\ keys' = SubSeq(keys, 1, Latest)
    /\ regs' = SubSeq(regs, 1, Latest)
    /\ UNCHANGED <<nextReg, cur, rows, revoked, appVars, ghostVars>>

\* add*AtEpochs / remove*AtEpochs(from, to, v); *AtEpoch is from = to.
Write(from, to, v, allowed) ==
    /\ from <= to /\ to <= Latest
    /\ LET written == {<<RowKey(keys, regs, e), v>>: e \in from..to}
       IN rows' = IF allowed THEN rows \cup written ELSE rows \ written
    /\ revoked' = IF allowed THEN revoked \ {v}
                  ELSE IF from = 0 /\ to = Latest THEN revoked \cup {v}
                  ELSE revoked
    /\ UNCHANGED <<keys, regs, nextReg, cur, appVars, ghostVars>>

\* ---- DstackApp ----
AppWrite(from, to, c, allowed) ==
    /\ ~legacy /\ from <= to /\ to <= appCur + 1
    /\ LET written == {<<a, c>>: a \in from..to}
       IN appRows' = IF allowed THEN appRows \cup written ELSE appRows \ written
    /\ appRevoked' = IF allowed THEN appRevoked \ {c}
                     ELSE IF from = 0 /\ to = appCur + 1 THEN appRevoked \cup {c}
                     ELSE appRevoked
    /\ UNCHANGED <<rootVars, legacy, appCur, ghostVars>>

\* The epoch-less setters of a legacy policy write its only row.
LegacyWrite(c, allowed) ==
    /\ legacy
    /\ appRows' = IF allowed THEN appRows \cup {<<0, c>>} ELSE appRows \ {<<0, c>>}
    /\ appRevoked' = IF allowed THEN appRevoked \ {c} ELSE appRevoked \cup {c}
    /\ UNCHANGED <<rootVars, legacy, appCur, ghostVars>>

Upgrade ==
    /\ legacy /\ legacy' = FALSE
    /\ UNCHANGED <<rootVars, appCur, appRows, appRevoked, ghostVars>>

Advance ==
    /\ ~legacy /\ appCur < MaxAppEpoch
    /\ appCur' = appCur + 1
    /\ UNCHANGED <<rootVars, legacy, appRows, appRevoked, ghostVars>>

\* ---- Key release ----
\* kms_serve releases keys of the current epoch at most; the key handover
\* may carry a registered pending one.
KmsRelease(op, e, v) ==
    /\ e <= (IF op = "kms_export_keys" THEN Latest ELSE cur)
    /\ v \in Row(e)
    /\ leaked' = IF v \in revoked THEN leaked \cup {<<"root", e, v>>} ELSE leaked
    /\ UNCHANGED <<rootVars, appVars, mismatched>>

\* app_get_key for root epoch e <= current and app epoch a. A legacy policy
\* is asked through isAppAllowed, which reads its only row.
AppRelease(e, a, v, c) ==
    /\ e <= cur /\ v \in Row(e)
    /\ IF legacy
         THEN (a = 0 \/ LegacyIgnoresAppEpoch) /\ c \in AppRow(0)
         ELSE a <= appCur /\ c \in AppRow(a)
    /\ leaked' = leaked \cup (IF v \in revoked THEN {<<"root", e, v>>} ELSE {})
                        \cup (IF c \in appRevoked THEN {<<"app", a, c>>} ELSE {})
    /\ mismatched' = (mismatched \/ c \notin AppRow(a))
    /\ UNCHANGED <<rootVars, appVars>>

Next ==
    \/ Activate \/ Pop \/ Upgrade \/ Advance
    \/ \E k \in Keys: Register(k)
    \/ \E from, to \in 0..MaxEpoch, v \in Values, allowed \in BOOLEAN: Write(from, to, v, allowed)
    \/ \E from, to \in 0..MaxAppEpoch + 1, c \in Composes, allowed \in BOOLEAN: AppWrite(from, to, c, allowed)
    \/ \E c \in Composes, allowed \in BOOLEAN: LegacyWrite(c, allowed)
    \/ \E op \in {"kms_serve", "kms_export_keys"}, e \in 0..MaxEpoch, v \in Values: KmsRelease(op, e, v)
    \/ \E e \in 0..MaxEpoch, a \in 0..MaxAppEpoch, v \in Values, c \in Composes: AppRelease(e, a, v, c)

Spec == Init /\ [][Next]_vars

-----------------------------------------------------------------------------
TypeOK == cur <= Latest /\ Latest <= MaxEpoch /\ Len(regs) = Len(keys) /\ appCur <= MaxAppEpoch
          /\ (legacy => appCur = 0)

\* A value or compose hash removed from every row gets no key of any root or
\* app epoch, for any operation, until it is added again; including through a
\* root epoch popped and registered again, and across the upgrade of a legacy
\* app policy.
RevocationIsTotal == leaked = {}

\* An app key of app epoch a is released only when row a allows the compose
\* hash; for a legacy policy, only app epoch 0, its flat mapping.
AppKeyMatchesSelectedRow == ~mismatched

\* A root epoch registration starts with an empty row, whatever its keys.
RegistrationStartsEmpty ==
    [][Len(keys') > Len(keys) =>
        \A v \in Values: <<RowKey(keys', regs', Latest + 1), v>> \notin rows']_vars
=============================================================================
