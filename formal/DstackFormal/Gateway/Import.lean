-- SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
--
-- SPDX-License-Identifier: Apache-2.0

/-!
# KV instance import (`dstack/gateway/src/kv/import.rs`)

Models `accept_instances_at` and `validate_instance`: the boundary that filters replicated
`inst/` records before they reach the routing table and `wg.conf`.

Tracks origin/next at 13d952749f, including #1604 (`ce8f54312a`): a record carrying this node's
key or any gateway key in the replicated `node/` info is rejected `LostConflict` on every node,
before the IP and key checks. #1615 (WireGuard key proof of possession, not merged) is modeled
only abstractly, as the hypothesis of `accepted_legit`.

The records are sorted by `(reg_time, instance_id)` (`ordered.sort_by`, modeled with core
`List.mergeSort`) and folded once, left to right, keeping a table of claimed IPs and claimed
public keys. A record is rejected `Unusable` when `validate_instance` fails, `LostConflict` when
its key belongs to a gateway or its IP or key is already claimed, and otherwise accepted.

Proven:
* `accept_ip_injective`, `accept_key_injective`: no two accepted records share an IP or a key.
* `accept_partition`: accepted ids ++ rejected ids is a permutation of
  undecodable ids ++ decoded ids (each input id is reported exactly once).
* `accept_classified`: every decoded record is accepted (valid, no gateway key), or rejected
  `Unusable` and invalid, or rejected `LostConflict`, valid, and either carrying a gateway key or
  beaten by an accepted record that is strictly older in `(reg_time, id)` and conflicts with it
  on IP or key.
* `accept_no_gateway_key`: no accepted record carries any gateway's key.
* `accept_perm_invariant`: the result does not depend on input order.
* `accept_congr`: two nodes whose validators and gateway-key checks agree on every record accept
  the same set; `isGatewayKey_agree`: with equal KV contents the gateway-key checks agree once
  each node's own key has replicated (`own_key_unpublished_diverges` is the window before);
  `validator_disagreement_flips_winner` shows why routability must agree too (`IpAlloc.lean`).
* Key squatting: `squatting_without_proof` (an attacker registering a victim's key wins once the
  victim's record is recycled); `accepted_legit` and `key_binding_stable` under the hypothesis
  that every record in the KV was submitted by its key's holder (proof of possession enforced on
  every node, i.e. `global/wg_key_proof_config` requires it everywhere and did before any such
  record was written; #1615 checks the proof only at registration and does not store it).

Assumptions / modeling gap:
* Ids, app ids, IPs and keys are `Nat`; Rust compares ids as `String`s. Any strict total order
  works the same way; `Nat` stands for it.
* `validate_id`, `validate_wg_public_key` and `WgConfig::is_routable_client_ip` are abstract
  node-local predicates (`WgView`); base64 decoding and IPv4 arithmetic are not modeled.
* Decoded ids are unique (they are `BTreeMap` keys); this is a theorem hypothesis.
* Error messages and logging are not modeled.
-/

namespace DstackFormal.Gateway.Import

/-- `kv::InstanceRecord`, restricted to the fields `accept_instances_at` reads. -/
structure Record where
  id : Nat
  appId : Nat
  ip : Nat
  publicKey : Nat
  regTime : Nat
deriving DecidableEq, Repr

/-- `kv::import::Rejection`. -/
inductive Rejection where
  | unusable
  | lostConflict
deriving DecidableEq, Repr

/-- The node-local parts of `WgConfig` that `validate_instance` consults. -/
structure WgView where
  gatewayKey : Nat
  idOk : Nat → Bool
  keyOk : Nat → Bool
  routable : Nat → Bool

/-- `kv::MAX_CLOCK_DRIFT_SECS`. -/
def maxClockDriftSecs : Nat := 300

/-- `validate_instance`: the same checks, in the same order. -/
def validateInstance (wg : WgView) (now : Nat) (r : Record) : Bool :=
  wg.idOk r.id && wg.idOk r.appId && wg.keyOk r.publicKey && wg.routable r.ip && decide (r.regTime ≤ now + maxClockDriftSecs)

/-- `claimed_ips.get(&ip)` on the `HashMap<Ipv4Addr, String>` modeled as an association list. -/
def owner (ip : Nat) : List (Nat × Nat) → Option Nat
  | [] => none
  | (i, o) :: rest => if i = ip then some o else owner ip rest

/-- Loop state of `accept_instances_at`. -/
structure Acc where
  instances : List Record
  rejected : List (Nat × Rejection)
  claimedIps : List (Nat × Nat)
  claimedKeys : List Nat
deriving DecidableEq, Repr

/-- `rejected.push(RejectedInstance { .. })` followed by `continue`. -/
def Acc.reject (acc : Acc) (id : Nat) (k : Rejection) : Acc :=
  { acc with rejected := acc.rejected ++ [(id, k)] }

/-- The three inserts at the end of the loop body. -/
def Acc.accept (acc : Acc) (r : Record) : Acc :=
  { acc with
    instances := r :: acc.instances
    claimedIps := (r.ip, r.id) :: acc.claimedIps
    claimedKeys := r.publicKey :: acc.claimedKeys }

/-- `data.public_key == wg.public_key || gateway_keys.contains(&data.public_key)`, where
`gatewayKeys` is `KvStore::gateway_wg_public_keys` (the keys in replicated `node/` info). -/
def isGatewayKey (wg : WgView) (gatewayKeys : List Nat) (r : Record) : Bool :=
  r.publicKey == wg.gatewayKey || gatewayKeys.contains r.publicKey

/-- One iteration of the `for (instance_id, data) in ordered` loop. -/
def step (valid gw : Record → Bool) (acc : Acc) (r : Record) : Acc :=
  if valid r = false then acc.reject r.id .unusable
  else if gw r then acc.reject r.id .lostConflict
  else if (owner r.ip acc.claimedIps).isSome then acc.reject r.id .lostConflict
  else if r.publicKey ∈ acc.claimedKeys then acc.reject r.id .lostConflict
  else acc.accept r

/-- The comparator passed to `ordered.sort_by`: `reg_time`, then instance id. -/
def recLe (a b : Record) : Bool :=
  decide (a.regTime < b.regTime ∨ (a.regTime = b.regTime ∧ a.id ≤ b.id))

/-- The strict order the sort induces on records with distinct ids: "registered earlier". -/
def Older (a b : Record) : Prop :=
  a.regTime < b.regTime ∨ (a.regTime = b.regTime ∧ a.id < b.id)

/-- The initial loop state: every undecodable record is already rejected as `Unusable`. -/
def initAcc (undecodable : List Nat) : Acc :=
  { instances := [], rejected := undecodable.map (·, .unusable), claimedIps := [],
    claimedKeys := [] }

/-- `accept_instances_at`. -/
def acceptInstancesAt (wg : WgView) (gatewayKeys : List Nat) (now : Nat) (decoded : List Record)
    (undecodable : List Nat) : Acc :=
  (decoded.mergeSort recLe).foldl (step (validateInstance wg now) (isGatewayKey wg gatewayKeys))
    (initAcc undecodable)

/-- Two records conflict when they claim the same IP or the same key. -/
def Conflicts (w r : Record) : Prop := w.ip = r.ip ∨ w.publicKey = r.publicKey

/-- How one processed record ended up. -/
def Classified (valid gw : Record → Bool) (before : Record → Record → Prop) (acc : Acc)
    (r : Record) : Prop :=
  (r ∈ acc.instances ∧ valid r = true ∧ gw r = false) ∨
  ((r.id, Rejection.unusable) ∈ acc.rejected ∧ valid r = false) ∨
  ((r.id, Rejection.lostConflict) ∈ acc.rejected ∧ valid r = true ∧
    (gw r = true ∨ ∃ w ∈ acc.instances, w ≠ r ∧ Conflicts w r ∧ before w r))

/-- Loop invariant after processing `seen`. -/
structure Inv (valid gw : Record → Bool) (before : Record → Record → Prop) (u : List Nat)
    (acc : Acc) (seen : List Record) : Prop where
  ips : acc.claimedIps = acc.instances.map (fun r => (r.ip, r.id))
  keys : acc.claimedKeys = acc.instances.map (·.publicKey)
  distinct : acc.instances.Pairwise (fun a b => a.ip ≠ b.ip ∧ a.publicKey ≠ b.publicKey)
  sound : ∀ r ∈ acc.instances, r ∈ seen ∧ valid r = true ∧ gw r = false
  perm : (acc.instances.map (·.id) ++ acc.rejected.map (·.1)).Perm (u ++ seen.map (·.id))
  classified : ∀ r ∈ seen, Classified valid gw before acc r

theorem owner_map_eq_none {ip : Nat} :
    ∀ l : List Record, owner ip (l.map (fun r => (r.ip, r.id))) = none ↔ ∀ r ∈ l, r.ip ≠ ip
  | [] => by simp [owner]
  | a :: l => by
    have ih := owner_map_eq_none (ip := ip) l
    by_cases h : a.ip = ip <;> simp [owner, h, ih]

theorem classified_reject {valid gw before acc r} (id : Nat) (k : Rejection)
    (h : Classified valid gw before acc r) : Classified valid gw before (acc.reject id k) r := by
  rcases h with h | h | ⟨h1, h2, hrest⟩
  · exact Or.inl h
  · exact Or.inr (Or.inl ⟨by simp [Acc.reject, h.1], h.2⟩)
  · exact Or.inr (Or.inr ⟨by simp [Acc.reject, h1], h2, hrest⟩)

theorem classified_accept {valid gw before acc r} (x : Record)
    (h : Classified valid gw before acc r) : Classified valid gw before (acc.accept x) r := by
  rcases h with h | h | ⟨h1, h2, hg | ⟨w, hw, hrest⟩⟩
  · exact Or.inl ⟨by simp [Acc.accept, h.1], h.2⟩
  · exact Or.inr (Or.inl h)
  · exact Or.inr (Or.inr ⟨h1, h2, Or.inl hg⟩)
  · exact Or.inr (Or.inr ⟨h1, h2, Or.inr ⟨w, by simp [Acc.accept, hw], hrest⟩⟩)

theorem inv_step {valid gw before u acc seen} (r : Record)
    (hi : Inv valid gw before u acc seen)
    (hb : ∀ w ∈ seen, before w r) (hfresh : ∀ w ∈ seen, w ≠ r) :
    Inv valid gw before u (step valid gw acc r) (seen ++ [r]) := by
  have permRej : ∀ k, ((acc.reject r.id k).instances.map (·.id) ++
      (acc.reject r.id k).rejected.map (·.1)).Perm (u ++ (seen ++ [r]).map (·.id)) := by
    intro k
    have := hi.perm.append_right [r.id]
    simpa [Acc.reject, List.append_assoc] using this
  have rejInv : ∀ k, (k = .unusable → valid r = false) →
      (k = .lostConflict → valid r = true ∧
        (gw r = true ∨ ∃ w ∈ acc.instances, w ≠ r ∧ Conflicts w r)) →
      Inv valid gw before u (acc.reject r.id k) (seen ++ [r]) := by
    intro k hk1 hk2
    refine ⟨hi.ips, hi.keys, hi.distinct, ?_, permRej k, ?_⟩
    · intro x hx
      have := hi.sound x hx
      exact ⟨List.mem_append_left _ this.1, this.2⟩
    · intro x hx
      rcases List.mem_append.mp hx with hx | hx
      · exact classified_reject _ _ (hi.classified x hx)
      · have hxr : x = r := by simpa using hx
        subst hxr
        cases k with
        | unusable => exact Or.inr (Or.inl ⟨by simp [Acc.reject], hk1 rfl⟩)
        | lostConflict =>
          obtain ⟨hv, hg | ⟨w, hw, hne, hc⟩⟩ := hk2 rfl
          · exact Or.inr (Or.inr ⟨by simp [Acc.reject], hv, Or.inl hg⟩)
          · exact Or.inr (Or.inr ⟨by simp [Acc.reject], hv, Or.inr ⟨w, hw, hne, hc,
              hb w (hi.sound w hw).1⟩⟩)
  unfold step
  by_cases hv : valid r = false
  · rw [hv]
    simp only [↓reduceIte]
    exact rejInv _ (fun _ => hv) (fun h => nomatch h)
  have hv' : valid r = true := by simpa using hv
  rw [hv']
  simp only [Bool.true_eq_false, ↓reduceIte]
  by_cases hg : gw r = true
  · rw [hg]
    simp only [↓reduceIte]
    exact rejInv _ (fun h => nomatch h) (fun _ => ⟨hv', Or.inl hg⟩)
  have hg' : gw r = false := by simpa using hg
  rw [hg']
  simp only [Bool.false_eq_true, ↓reduceIte]
  by_cases hip : (owner r.ip acc.claimedIps).isSome
  · rw [hip]
    simp only [↓reduceIte]
    refine rejInv _ (fun h => nomatch h) (fun _ => ⟨hv', ?_⟩)
    rw [hi.ips] at hip
    have : ¬ ∀ w ∈ acc.instances, w.ip ≠ r.ip := by
      intro hall
      rw [(owner_map_eq_none _).mpr hall] at hip
      exact absurd hip (by simp)
    obtain ⟨w, hw, hwip⟩ : ∃ w ∈ acc.instances, w.ip = r.ip := by
      apply Classical.byContradiction
      intro hn
      exact this (fun w hw he => hn ⟨w, hw, he⟩)
    exact Or.inr ⟨w, hw, fun h => hfresh w (hi.sound w hw).1 h, Or.inl hwip⟩
  have hip' : (owner r.ip acc.claimedIps).isSome = false := by simpa using hip
  rw [hip']
  simp only [Bool.false_eq_true, ↓reduceIte]
  by_cases hkey : r.publicKey ∈ acc.claimedKeys
  · simp only [hkey, ↓reduceIte]
    refine rejInv _ (fun h => nomatch h) (fun _ => ⟨hv', ?_⟩)
    rw [hi.keys] at hkey
    obtain ⟨w, hw, hwk⟩ := List.mem_map.mp hkey
    exact Or.inr ⟨w, hw, fun h => hfresh w (hi.sound w hw).1 h, Or.inr hwk⟩
  simp only [hkey, ↓reduceIte]
  have hipNone : ∀ w ∈ acc.instances, w.ip ≠ r.ip := by
    apply (owner_map_eq_none _).mp
    rw [← hi.ips]
    simpa using hip
  have hkeyNone : ∀ w ∈ acc.instances, w.publicKey ≠ r.publicKey := by
    intro w hw he
    exact hkey (hi.keys ▸ List.mem_map.mpr ⟨w, hw, he⟩)
  refine ⟨by simp [Acc.accept, hi.ips], by simp [Acc.accept, hi.keys], ?_, ?_, ?_, ?_⟩
  · simp only [Acc.accept, List.pairwise_cons]
    exact ⟨fun w hw => ⟨fun h => hipNone w hw h.symm, fun h => hkeyNone w hw h.symm⟩,
      hi.distinct⟩
  · intro x hx
    simp only [Acc.accept, List.mem_cons] at hx
    rcases hx with rfl | hx
    · exact ⟨by simp, hv', hg'⟩
    · have := hi.sound x hx
      exact ⟨List.mem_append_left _ this.1, this.2⟩
  · have h1 := (hi.perm.cons r.id).trans (List.perm_append_singleton r.id _).symm
    simpa [Acc.accept, List.append_assoc] using h1
  · intro x hx
    rcases List.mem_append.mp hx with hx | hx
    · exact classified_accept _ (hi.classified x hx)
    · have hxr : x = r := by simpa using hx
      subst hxr
      exact Or.inl ⟨by simp [Acc.accept], hv', hg'⟩

theorem inv_run {valid gw before u} :
    ∀ (l seen : List Record) (acc : Acc), Inv valid gw before u acc seen →
      (∀ w ∈ seen, ∀ r ∈ l, before w r) → l.Pairwise before →
      (∀ w ∈ seen, ∀ r ∈ l, w ≠ r) → l.Nodup →
      Inv valid gw before u (l.foldl (step valid gw) acc) (seen ++ l)
  | [], seen, acc, hi, _, _, _, _ => by simpa using hi
  | r :: l, seen, acc, hi, hb, hp, hf, hn => by
    rw [List.pairwise_cons] at hp
    rw [List.nodup_cons] at hn
    have hi' := inv_step r hi (fun w hw => hb w hw r (by simp))
      (fun w hw => hf w hw r (by simp))
    have := inv_run l (seen ++ [r]) _ hi'
      (by
        intro w hw x hx
        rcases List.mem_append.mp hw with hw | hw
        · exact hb w hw x (by simp [hx])
        · have : w = r := by simpa using hw
          subst this; exact hp.1 x hx)
      hp.2
      (by
        intro w hw x hx
        rcases List.mem_append.mp hw with hw | hw
        · exact hf w hw x (by simp [hx])
        · have : w = r := by simpa using hw
          subst this; exact fun h => hn.1 (h ▸ hx))
      hn.2
    simpa using this

theorem inv_init (valid gw before) (u : List Nat) : Inv valid gw before u (initAcc u) [] := by
  refine ⟨rfl, rfl, List.Pairwise.nil, by simp [initAcc], ?_, by simp⟩
  simp [initAcc, Function.comp_def]

theorem recLe_trans (a b c : Record) : recLe a b = true → recLe b c = true → recLe a c = true := by
  simp only [recLe, decide_eq_true_eq]; omega

theorem recLe_total (a b : Record) : (recLe a b || recLe b a) = true := by
  simp only [recLe, Bool.or_eq_true, decide_eq_true_eq]; omega

theorem eq_of_id_eq {l : List Record} (hn : (l.map (·.id)).Nodup) :
    ∀ {a b}, a ∈ l → b ∈ l → a.id = b.id → a = b := by
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

theorem sorted_nodup_ids {l : List Record} (hn : (l.map (·.id)).Nodup) :
    ((l.mergeSort recLe).map (·.id)).Nodup :=
  (((List.mergeSort_perm l recLe).map (·.id)).nodup_iff).mpr hn

theorem sorted_older {l : List Record} (hn : (l.map (·.id)).Nodup) :
    (l.mergeSort recLe).Pairwise Older := by
  have hs := List.pairwise_mergeSort recLe_trans recLe_total l
  have hd : (l.mergeSort recLe).Pairwise (fun a b => a.id ≠ b.id) :=
    List.pairwise_map.mp (sorted_nodup_ids hn)
  refine (hs.and hd).imp ?_
  intro a b ⟨h1, h2⟩
  simp only [recLe, decide_eq_true_eq] at h1
  unfold Older; omega

theorem sorted_nodup {l : List Record} (hn : (l.map (·.id)).Nodup) :
    (l.mergeSort recLe).Nodup :=
  (List.pairwise_map.mp (sorted_nodup_ids hn)).imp (fun h he => h (congrArg Record.id he))

theorem accept_inv (wg : WgView) (gk : List Nat) (now : Nat) (decoded : List Record) (u : List Nat)
    (hn : (decoded.map (·.id)).Nodup) :
    Inv (validateInstance wg now) (isGatewayKey wg gk) Older u
      (acceptInstancesAt wg gk now decoded u) (decoded.mergeSort recLe) := by
  have := inv_run (valid := validateInstance wg now) (gw := isGatewayKey wg gk) (before := Older)
    (u := u) (decoded.mergeSort recLe) [] (initAcc u) (inv_init _ _ _ u) (by simp) (sorted_older hn)
    (by simp) (sorted_nodup hn)
  simpa [acceptInstancesAt] using this

theorem pairwise_inj {α β : Type} {f : α → β} :
    ∀ {l : List α}, l.Pairwise (fun a b => f a ≠ f b) →
      ∀ {a b}, a ∈ l → b ∈ l → f a = f b → a = b
  | [], _, _, _, ha, _, _ => by simp at ha
  | x :: l, h, a, b, ha, hb, he => by
    rw [List.pairwise_cons] at h
    simp only [List.mem_cons] at ha hb
    rcases ha with rfl | ha <;> rcases hb with rfl | hb
    · rfl
    · exact absurd he (h.1 b hb)
    · exact absurd he.symm (h.1 a ha)
    · exact pairwise_inj h.2 ha hb he

/-- No two accepted instances share a WireGuard IP. -/
theorem accept_ip_injective (wg : WgView) (gk : List Nat) (now : Nat) (decoded : List Record) (u : List Nat)
    (hn : (decoded.map (·.id)).Nodup) {a b : Record}
    (ha : a ∈ (acceptInstancesAt wg gk now decoded u).instances)
    (hb : b ∈ (acceptInstancesAt wg gk now decoded u).instances) (h : a.ip = b.ip) : a = b :=
  pairwise_inj ((accept_inv wg gk now decoded u hn).distinct.imp (fun h => h.1)) ha hb h

/-- No two accepted instances share a WireGuard public key. -/
theorem accept_key_injective (wg : WgView) (gk : List Nat) (now : Nat) (decoded : List Record) (u : List Nat)
    (hn : (decoded.map (·.id)).Nodup) {a b : Record}
    (ha : a ∈ (acceptInstancesAt wg gk now decoded u).instances)
    (hb : b ∈ (acceptInstancesAt wg gk now decoded u).instances)
    (h : a.publicKey = b.publicKey) : a = b :=
  pairwise_inj ((accept_inv wg gk now decoded u hn).distinct.imp (fun h => h.2)) ha hb h

/-- Every accepted instance is a decoded record that passed `validate_instance` and carries no
gateway node's key. -/
theorem accept_sound (wg : WgView) (gk : List Nat) (now : Nat) (decoded : List Record) (u : List Nat)
    (hn : (decoded.map (·.id)).Nodup) :
    ∀ r ∈ (acceptInstancesAt wg gk now decoded u).instances,
      r ∈ decoded ∧ validateInstance wg now r = true ∧ isGatewayKey wg gk r = false := by
  intro r hr
  have := (accept_inv wg gk now decoded u hn).sound r hr
  exact ⟨List.mem_mergeSort.mp this.1, this.2⟩

/-- Accepted and rejected ids together are exactly the input ids, each once. -/
theorem accept_partition (wg : WgView) (gk : List Nat) (now : Nat) (decoded : List Record) (u : List Nat)
    (hn : (decoded.map (·.id)).Nodup) :
    let acc := acceptInstancesAt wg gk now decoded u
    (acc.instances.map (·.id) ++ acc.rejected.map (·.1)).Perm (u ++ decoded.map (·.id)) :=
  (accept_inv wg gk now decoded u hn).perm.trans
    (((List.mergeSort_perm decoded recLe).map (·.id)).append_left u)

/-- Every decoded record is accepted, rejected as unusable because it is invalid, or rejected
because an accepted, strictly older record already holds its IP or key. -/
theorem accept_classified (wg : WgView) (gk : List Nat) (now : Nat) (decoded : List Record) (u : List Nat)
    (hn : (decoded.map (·.id)).Nodup) :
    ∀ r ∈ decoded,
      Classified (validateInstance wg now) (isGatewayKey wg gk) Older
        (acceptInstancesAt wg gk now decoded u) r :=
  fun r hr => (accept_inv wg gk now decoded u hn).classified r (List.mem_mergeSort.mpr hr)

/-- A record that passed validation and carries no gateway key is either accepted or loses to an
older accepted one. -/
theorem valid_loser_has_older_winner (wg : WgView) (gk : List Nat) (now : Nat) (decoded : List Record)
    (u : List Nat) (hn : (decoded.map (·.id)).Nodup) (r : Record) (hr : r ∈ decoded)
    (hv : validateInstance wg now r = true) (hg : isGatewayKey wg gk r = false)
    (hna : r ∉ (acceptInstancesAt wg gk now decoded u).instances) :
    ∃ w ∈ (acceptInstancesAt wg gk now decoded u).instances, Conflicts w r ∧ Older w r := by
  rcases accept_classified wg gk now decoded u hn r hr with h | h | ⟨_, _, hg' | ⟨w, hw, _, hc, ho⟩⟩
  · exact absurd h.1 hna
  · rw [hv] at h; exact absurd h.2 (by decide)
  · rw [hg] at hg'; exact absurd hg' (by decide)
  · exact ⟨w, hw, hc, ho⟩

theorem mergeSort_perm_eq {l₁ l₂ : List Record} (h : l₁.Perm l₂)
    (hn : (l₁.map (·.id)).Nodup) : l₁.mergeSort recLe = l₂.mergeSort recLe := by
  apply List.Perm.eq_of_pairwise (le := fun a b => recLe a b = true)
  · intro a b ha hb hab hba
    simp only [recLe, decide_eq_true_eq] at hab hba
    exact eq_of_id_eq hn (List.mem_mergeSort.mp ha)
      (h.symm.subset (List.mem_mergeSort.mp hb)) (by omega)
  · exact List.pairwise_mergeSort recLe_trans recLe_total l₁
  · exact List.pairwise_mergeSort recLe_trans recLe_total l₂
  · exact (List.mergeSort_perm l₁ recLe).trans (h.trans (List.mergeSort_perm l₂ recLe).symm)

/-- Iteration order of the decoded records does not matter. -/
theorem accept_perm_invariant (wg : WgView) (gk : List Nat) (now : Nat) {d₁ d₂ : List Record} (u : List Nat)
    (h : d₁.Perm d₂) (hn : (d₁.map (·.id)).Nodup) :
    acceptInstancesAt wg gk now d₁ u = acceptInstancesAt wg gk now d₂ u := by
  unfold acceptInstancesAt
  rw [mergeSort_perm_eq h hn]

theorem run_congr {v₁ v₂ g₁ g₂ : Record → Bool} :
    ∀ (l : List Record) (acc : Acc), (∀ r ∈ l, v₁ r = v₂ r ∧ g₁ r = g₂ r) →
      l.foldl (step v₁ g₁) acc = l.foldl (step v₂ g₂) acc
  | [], _, _ => rfl
  | r :: l, acc, h => by
    simp only [List.foldl_cons]
    have : step v₁ g₁ acc r = step v₂ g₂ acc r := by
      unfold step; rw [(h r (by simp)).1, (h r (by simp)).2]
    rw [this]
    exact run_congr l _ (fun x hx => h x (by simp [hx]))

/-- Nodes whose validators and gateway-key checks agree on every record in the KV accept the same
instances and report the same rejections, regardless of their own iteration order. -/
theorem accept_congr {wg₁ wg₂ : WgView} {gk₁ gk₂ : List Nat} {now₁ now₂ : Nat}
    {d₁ d₂ : List Record} (u : List Nat) (h : d₁.Perm d₂) (hn : (d₁.map (·.id)).Nodup)
    (hagree : ∀ r ∈ d₁, validateInstance wg₁ now₁ r = validateInstance wg₂ now₂ r)
    (hgw : ∀ r ∈ d₁, isGatewayKey wg₁ gk₁ r = isGatewayKey wg₂ gk₂ r) :
    acceptInstancesAt wg₁ gk₁ now₁ d₁ u = acceptInstancesAt wg₂ gk₂ now₂ d₂ u := by
  rw [← accept_perm_invariant wg₂ gk₂ now₂ u h hn]
  exact run_congr _ _ (fun r hr =>
    ⟨hagree r (List.mem_mergeSort.mp hr), hgw r (List.mem_mergeSort.mp hr)⟩)

/-- With equal KV contents every node reads the same `gateway_keys`; once a node's own key is
among them (its `node/` info has replicated), the own-key test adds nothing, so all such nodes
judge every record's key the same way. -/
theorem isGatewayKey_agree {wg₁ wg₂ : WgView} {gk : List Nat} (h₁ : wg₁.gatewayKey ∈ gk)
    (h₂ : wg₂.gatewayKey ∈ gk) (r : Record) : isGatewayKey wg₁ gk r = isGatewayKey wg₂ gk r := by
  unfold isGatewayKey
  by_cases hk : r.publicKey ∈ gk
  · simp [hk]
  · have e₁ : r.publicKey ≠ wg₁.gatewayKey := fun he => hk (he ▸ h₁)
    have e₂ : r.publicKey ≠ wg₂.gatewayKey := fun he => hk (he ▸ h₂)
    have b₁ : (r.publicKey == wg₁.gatewayKey) = false := by simpa using e₁
    have b₂ : (r.publicKey == wg₂.gatewayKey) = false := by simpa using e₂
    simp [hk, b₁, b₂]

/-! ## Mirrors of Rust unit tests -/

/-- A view in which everything is well formed and `7` is the gateway's own key. -/
def testWg : WgView :=
  { gatewayKey := 7, idOk := fun _ => true, keyOk := fun k => k != 0,
    routable := fun ip => ip ≥ 16 && ip < 255 }

def testNow : Nat := 1700000000

def inst (id ip key reg : Nat) : Record :=
  { id, appId := 1, ip, publicKey := key, regTime := reg }

def ids (acc : Acc) : List Nat := acc.instances.map (·.id)

-- duplicate_ip_and_key_claims_resolve_to_the_older_registration (ids: new = 2, old = 1)
#guard ids (acceptInstancesAt testWg [] testNow [inst 2 20 9 300, inst 1 20 1 100] []) == [1]
#guard ids (acceptInstancesAt testWg [] testNow [inst 2 21 1 300, inst 1 20 1 100] []) == [1]
-- conflict_resolution_does_not_depend_on_iteration_order (a = 1, b = 2)
#guard ids (acceptInstancesAt testWg [] testNow [inst 1 20 1 100, inst 2 20 2 100] []) == [1]
#guard ids (acceptInstancesAt testWg [] testNow [inst 2 20 2 100, inst 1 20 1 100] []) == [1]
-- rejects_the_gateways_own_public_key
#guard ids (acceptInstancesAt testWg [] testNow [inst 1 20 7 100] []) == []
-- every_node_rejects_another_gateways_public_key (peer gateway key 8; steals = 1, good = 2)
#guard ids (acceptInstancesAt testWg [8] testNow [inst 1 20 8 100, inst 2 21 1 200] []) == [2]
#guard (acceptInstancesAt testWg [8] testNow [inst 1 20 8 100, inst 2 21 1 200] []).rejected ==
  [(1, .lostConflict)]
-- rejects_registrations_dated_into_the_future (future = 1, skewed = 2)
#guard ids (acceptInstancesAt testWg [] testNow
  [inst 1 20 1 (testNow + maxClockDriftSecs + 1), inst 2 21 2 (testNow + maxClockDriftSecs)] [])
  == [2]
-- a_conflict_loser_is_dropped_but_an_unusable_record_keeps_its_instance
-- (loser = 1, winner = 2, malformed = 3, undecodable = 4)
#guard (acceptInstancesAt testWg [] testNow [inst 1 20 9 300, inst 2 20 1 100, inst 3 30 0 100] [4]
  ).rejected == [(4, .unusable), (3, .unusable), (1, .lostConflict)]

/-! ## Validators that disagree can flip the winner -/

/-- Node A considers IP `20` its own gateway address; node B does not. (`routable` is the one
node-local input left after #1604; `IpAlloc.PoolsClear` is what keeps it consistent.) -/
def wgA : WgView := { testWg with routable := fun ip => ip != 20 }
def wgB : WgView := testWg

/-- An older record that only node A refuses, and a newer one holding a different IP but the same
key. Node A keeps the newer record; node B keeps the older one. Cross-node agreement therefore
requires every node to judge every replicated record the same way (see `IpAlloc.lean`). -/
theorem validator_disagreement_flips_winner :
    ids ([inst 1 20 5 100, inst 2 21 5 200].foldl (step (validateInstance wgA testNow) (fun _ => false))
        (initAcc [])) = [2] ∧
    ids ([inst 1 20 5 100, inst 2 21 5 200].foldl (step (validateInstance wgB testNow) (fun _ => false))
        (initAcc [])) = [1] ∧
    [inst 1 20 5 100, inst 2 21 5 200].mergeSort recLe = [inst 1 20 5 100, inst 2 21 5 200] := by
  refine ⟨by decide, by decide, List.mergeSort_of_pairwise (by decide)⟩

/-! ## Gateway keys -/

/-- No accepted instance carries this node's key or any gateway key in the KV. -/
theorem accept_no_gateway_key (wg : WgView) (gk : List Nat) (now : Nat) (decoded : List Record)
    (u : List Nat) (hn : (decoded.map (·.id)).Nodup) :
    ∀ r ∈ (acceptInstancesAt wg gk now decoded u).instances,
      r.publicKey ≠ wg.gatewayKey ∧ r.publicKey ∉ gk := by
  intro r hr
  have := (accept_sound wg gk now decoded u hn r hr).2.2
  simp only [isGatewayKey, Bool.or_eq_false_iff, beq_eq_false_iff_ne, ne_eq] at this
  refine ⟨this.1, fun hm => ?_⟩
  have : gk.contains r.publicKey = true := List.contains_iff_mem.mpr hm
  simp_all

/-- The residual window: a node whose own `node/` info has not replicated yet refuses a record
carrying its key while the others accept it. `isGatewayKey_agree` needs every judging node's key
in the replicated set. -/
theorem own_key_unpublished_diverges :
    ids (acceptInstancesAt testWg [] testNow [inst 1 20 7 100] []) = [] ∧
    ids (acceptInstancesAt { testWg with gatewayKey := 8 } [] testNow [inst 1 20 7 100] []) =
      [1] := by
  refine ⟨?_, ?_⟩ <;>
  · unfold acceptInstancesAt
    rw [List.mergeSort_of_pairwise (by decide)]
    decide

/-! ## Key squatting and proof of possession

Records carry no proof; an attacker who registers another CVM's (public) WireGuard key gets a
record that loses to the victim's older one, and wins as soon as the victim's record is gone.
`owner r` is the CVM that submitted record `r`, `holder k` the CVM holding the private key of `k`.
-/

/-- A record submitted by the holder of its key's private key. -/
def Legit (owner : Record → Nat) (holder : Nat → Nat) (r : Record) : Prop :=
  holder r.publicKey = owner r

/-- Without proofs: victim `1` (key 5, registered at 100), attacker `2` claiming key 5 at 200.
While both records exist the victim wins; once the victim's record is recycled, the attacker's
record is accepted carrying the victim's key. -/
theorem squatting_without_proof :
    let owner : Record → Nat := (·.id)
    let holder : Nat → Nat := fun _ => 1
    let victim := inst 1 20 5 100
    let attacker := inst 2 21 5 200
    ids (acceptInstancesAt testWg [] testNow [victim, attacker] []) = [1] ∧
    (acceptInstancesAt testWg [] testNow [attacker] []).instances = [attacker] ∧
    ¬ Legit owner holder attacker := by
  refine ⟨?_, ?_, by simp [Legit, inst]⟩
  · unfold acceptInstancesAt
    rw [List.mergeSort_of_pairwise (by decide)]
    decide
  · unfold acceptInstancesAt
    rw [List.mergeSort_of_pairwise (by decide)]
    decide

/-- With proof of possession enforced on every registration that reached the KV (the policy
`global/wg_key_proof_config` requires it on every node, from before any such record was
written), every accepted record was submitted by its key's holder. -/
theorem accepted_legit (owner : Record → Nat) (holder : Nat → Nat) (wg : WgView) (gk : List Nat)
    (now : Nat) (kv : List Record) (u : List Nat) (hn : (kv.map (·.id)).Nodup)
    (hpop : ∀ r ∈ kv, Legit owner holder r) :
    ∀ r ∈ (acceptInstancesAt wg gk now kv u).instances, Legit owner holder r :=
  fun r hr => hpop r (accept_sound wg gk now kv u hn r hr).1

/-- Consequently the CVM routed under a key never changes across KV contents (before and after a
recycle, on any node): the accepted records for one key have the same owner. -/
theorem key_binding_stable (owner : Record → Nat) (holder : Nat → Nat)
    {wg₁ wg₂ : WgView} {gk₁ gk₂ : List Nat} {now₁ now₂ : Nat} {kv₁ kv₂ : List Record}
    {u₁ u₂ : List Nat} (hn₁ : (kv₁.map (·.id)).Nodup) (hn₂ : (kv₂.map (·.id)).Nodup)
    (hpop₁ : ∀ r ∈ kv₁, Legit owner holder r) (hpop₂ : ∀ r ∈ kv₂, Legit owner holder r)
    {r₁ r₂ : Record} (h₁ : r₁ ∈ (acceptInstancesAt wg₁ gk₁ now₁ kv₁ u₁).instances)
    (h₂ : r₂ ∈ (acceptInstancesAt wg₂ gk₂ now₂ kv₂ u₂).instances)
    (hk : r₁.publicKey = r₂.publicKey) : owner r₁ = owner r₂ := by
  rw [← accepted_legit owner holder _ _ _ _ _ hn₁ hpop₁ r₁ h₁,
    ← accepted_legit owner holder _ _ _ _ _ hn₂ hpop₂ r₂ h₂, hk]

end DstackFormal.Gateway.Import
