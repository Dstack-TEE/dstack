-- SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
--
-- SPDX-License-Identifier: Apache-2.0

/-!
# KV instance import (`dstack/gateway/src/kv/import.rs`)

Models `accept_instances_at` and `validate_instance`: the boundary that filters replicated
`inst/` records before they reach the routing table and `wg.conf`.

The records are sorted by `(reg_time, instance_id)` (`ordered.sort_by`, modeled with core
`List.mergeSort`) and folded once, left to right, keeping a table of claimed IPs and claimed
public keys. A record is rejected `Unusable` when `validate_instance` fails, `LostConflict` when
its IP or key is already claimed, and otherwise accepted.

Proven:
* `accept_ip_injective`, `accept_key_injective`: no two accepted records share an IP or a key.
* `accept_partition`: accepted ids ++ rejected ids is a permutation of
  undecodable ids ++ decoded ids (each input id is reported exactly once).
* `accept_classified`: every decoded record is accepted (and valid), or rejected `Unusable` and
  invalid, or rejected `LostConflict`, valid, and beaten by an accepted record that is strictly
  older in `(reg_time, id)` and conflicts with it on IP or key.
* `accept_perm_invariant`: the result does not depend on input order.
* `accept_congr`: two nodes whose validators agree on every record of the KV accept the same set;
  `validator_disagreement_flips_winner` shows agreement is needed.

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
  wg.idOk r.id && wg.idOk r.appId && wg.keyOk r.publicKey && r.publicKey != wg.gatewayKey &&
    wg.routable r.ip && decide (r.regTime ≤ now + maxClockDriftSecs)

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

/-- One iteration of the `for (instance_id, data) in ordered` loop. -/
def step (valid : Record → Bool) (acc : Acc) (r : Record) : Acc :=
  if valid r = false then acc.reject r.id .unusable
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
def acceptInstancesAt (wg : WgView) (now : Nat) (decoded : List Record)
    (undecodable : List Nat) : Acc :=
  (decoded.mergeSort recLe).foldl (step (validateInstance wg now)) (initAcc undecodable)

/-- Two records conflict when they claim the same IP or the same key. -/
def Conflicts (w r : Record) : Prop := w.ip = r.ip ∨ w.publicKey = r.publicKey

/-- How one processed record ended up. -/
def Classified (valid : Record → Bool) (before : Record → Record → Prop) (acc : Acc)
    (r : Record) : Prop :=
  (r ∈ acc.instances ∧ valid r = true) ∨
  ((r.id, Rejection.unusable) ∈ acc.rejected ∧ valid r = false) ∨
  ((r.id, Rejection.lostConflict) ∈ acc.rejected ∧ valid r = true ∧
    ∃ w ∈ acc.instances, w ≠ r ∧ Conflicts w r ∧ before w r)

/-- Loop invariant after processing `seen`. -/
structure Inv (valid : Record → Bool) (before : Record → Record → Prop) (u : List Nat)
    (acc : Acc) (seen : List Record) : Prop where
  ips : acc.claimedIps = acc.instances.map (fun r => (r.ip, r.id))
  keys : acc.claimedKeys = acc.instances.map (·.publicKey)
  distinct : acc.instances.Pairwise (fun a b => a.ip ≠ b.ip ∧ a.publicKey ≠ b.publicKey)
  sound : ∀ r ∈ acc.instances, r ∈ seen ∧ valid r = true
  perm : (acc.instances.map (·.id) ++ acc.rejected.map (·.1)).Perm (u ++ seen.map (·.id))
  classified : ∀ r ∈ seen, Classified valid before acc r

theorem owner_map_eq_none {ip : Nat} :
    ∀ l : List Record, owner ip (l.map (fun r => (r.ip, r.id))) = none ↔ ∀ r ∈ l, r.ip ≠ ip
  | [] => by simp [owner]
  | a :: l => by
    have ih := owner_map_eq_none (ip := ip) l
    by_cases h : a.ip = ip <;> simp [owner, h, ih]

theorem classified_reject {valid before acc r} (id : Nat) (k : Rejection)
    (h : Classified valid before acc r) : Classified valid before (acc.reject id k) r := by
  rcases h with h | h | ⟨h1, h2, w, hw⟩
  · exact Or.inl h
  · exact Or.inr (Or.inl ⟨by simp [Acc.reject, h.1], h.2⟩)
  · exact Or.inr (Or.inr ⟨by simp [Acc.reject, h1], h2, w, hw⟩)

theorem classified_accept {valid before acc r} (x : Record)
    (h : Classified valid before acc r) : Classified valid before (acc.accept x) r := by
  rcases h with h | h | ⟨h1, h2, w, hw, hrest⟩
  · exact Or.inl ⟨by simp [Acc.accept, h.1], h.2⟩
  · exact Or.inr (Or.inl h)
  · exact Or.inr (Or.inr ⟨h1, h2, w, by simp [Acc.accept, hw], hrest⟩)

theorem inv_step {valid before u acc seen} (r : Record) (hi : Inv valid before u acc seen)
    (hb : ∀ w ∈ seen, before w r) (hfresh : ∀ w ∈ seen, w ≠ r) :
    Inv valid before u (step valid acc r) (seen ++ [r]) := by
  have permRej : ∀ k, ((acc.reject r.id k).instances.map (·.id) ++
      (acc.reject r.id k).rejected.map (·.1)).Perm (u ++ (seen ++ [r]).map (·.id)) := by
    intro k
    have := hi.perm.append_right [r.id]
    simpa [Acc.reject, List.append_assoc] using this
  have rejInv : ∀ k, (k = .unusable → valid r = false) →
      (k = .lostConflict → valid r = true ∧ ∃ w ∈ acc.instances, w ≠ r ∧ Conflicts w r) →
      Inv valid before u (acc.reject r.id k) (seen ++ [r]) := by
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
          obtain ⟨hv, w, hw, hne, hc⟩ := hk2 rfl
          exact Or.inr (Or.inr ⟨by simp [Acc.reject], hv, w, hw, hne, hc,
            hb w (hi.sound w hw).1⟩)
  unfold step
  by_cases hv : valid r = false
  · rw [hv]
    simp only [↓reduceIte]
    exact rejInv _ (fun _ => hv) (fun h => nomatch h)
  have hv' : valid r = true := by simpa using hv
  rw [hv']
  simp only [Bool.true_eq_false, ↓reduceIte]
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
    exact ⟨w, hw, fun h => hfresh w (hi.sound w hw).1 h, Or.inl hwip⟩
  have hip' : (owner r.ip acc.claimedIps).isSome = false := by simpa using hip
  rw [hip']
  simp only [Bool.false_eq_true, ↓reduceIte]
  by_cases hkey : r.publicKey ∈ acc.claimedKeys
  · simp only [hkey, ↓reduceIte]
    refine rejInv _ (fun h => nomatch h) (fun _ => ⟨hv', ?_⟩)
    rw [hi.keys] at hkey
    obtain ⟨w, hw, hwk⟩ := List.mem_map.mp hkey
    exact ⟨w, hw, fun h => hfresh w (hi.sound w hw).1 h, Or.inr hwk⟩
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
    · exact ⟨by simp, hv'⟩
    · have := hi.sound x hx
      exact ⟨List.mem_append_left _ this.1, this.2⟩
  · have h1 := (hi.perm.cons r.id).trans (List.perm_append_singleton r.id _).symm
    simpa [Acc.accept, List.append_assoc] using h1
  · intro x hx
    rcases List.mem_append.mp hx with hx | hx
    · exact classified_accept _ (hi.classified x hx)
    · have hxr : x = r := by simpa using hx
      subst hxr
      exact Or.inl ⟨by simp [Acc.accept], hv'⟩

theorem inv_run {valid before u} :
    ∀ (l seen : List Record) (acc : Acc), Inv valid before u acc seen →
      (∀ w ∈ seen, ∀ r ∈ l, before w r) → l.Pairwise before →
      (∀ w ∈ seen, ∀ r ∈ l, w ≠ r) → l.Nodup →
      Inv valid before u (l.foldl (step valid) acc) (seen ++ l)
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

theorem inv_init (valid before) (u : List Nat) : Inv valid before u (initAcc u) [] := by
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

theorem accept_inv (wg : WgView) (now : Nat) (decoded : List Record) (u : List Nat)
    (hn : (decoded.map (·.id)).Nodup) :
    Inv (validateInstance wg now) Older u (acceptInstancesAt wg now decoded u)
      (decoded.mergeSort recLe) := by
  have := inv_run (valid := validateInstance wg now) (before := Older) (u := u)
    (decoded.mergeSort recLe) [] (initAcc u) (inv_init _ _ u) (by simp) (sorted_older hn)
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
theorem accept_ip_injective (wg : WgView) (now : Nat) (decoded : List Record) (u : List Nat)
    (hn : (decoded.map (·.id)).Nodup) {a b : Record}
    (ha : a ∈ (acceptInstancesAt wg now decoded u).instances)
    (hb : b ∈ (acceptInstancesAt wg now decoded u).instances) (h : a.ip = b.ip) : a = b :=
  pairwise_inj ((accept_inv wg now decoded u hn).distinct.imp (fun h => h.1)) ha hb h

/-- No two accepted instances share a WireGuard public key. -/
theorem accept_key_injective (wg : WgView) (now : Nat) (decoded : List Record) (u : List Nat)
    (hn : (decoded.map (·.id)).Nodup) {a b : Record}
    (ha : a ∈ (acceptInstancesAt wg now decoded u).instances)
    (hb : b ∈ (acceptInstancesAt wg now decoded u).instances)
    (h : a.publicKey = b.publicKey) : a = b :=
  pairwise_inj ((accept_inv wg now decoded u hn).distinct.imp (fun h => h.2)) ha hb h

/-- Every accepted instance is a decoded record that passed `validate_instance`. -/
theorem accept_sound (wg : WgView) (now : Nat) (decoded : List Record) (u : List Nat)
    (hn : (decoded.map (·.id)).Nodup) :
    ∀ r ∈ (acceptInstancesAt wg now decoded u).instances,
      r ∈ decoded ∧ validateInstance wg now r = true := by
  intro r hr
  have := (accept_inv wg now decoded u hn).sound r hr
  exact ⟨List.mem_mergeSort.mp this.1, this.2⟩

/-- Accepted and rejected ids together are exactly the input ids, each once. -/
theorem accept_partition (wg : WgView) (now : Nat) (decoded : List Record) (u : List Nat)
    (hn : (decoded.map (·.id)).Nodup) :
    let acc := acceptInstancesAt wg now decoded u
    (acc.instances.map (·.id) ++ acc.rejected.map (·.1)).Perm (u ++ decoded.map (·.id)) :=
  (accept_inv wg now decoded u hn).perm.trans
    (((List.mergeSort_perm decoded recLe).map (·.id)).append_left u)

/-- Every decoded record is accepted, rejected as unusable because it is invalid, or rejected
because an accepted, strictly older record already holds its IP or key. -/
theorem accept_classified (wg : WgView) (now : Nat) (decoded : List Record) (u : List Nat)
    (hn : (decoded.map (·.id)).Nodup) :
    ∀ r ∈ decoded,
      Classified (validateInstance wg now) Older (acceptInstancesAt wg now decoded u) r :=
  fun r hr => (accept_inv wg now decoded u hn).classified r (List.mem_mergeSort.mpr hr)

/-- A record that passed validation is either accepted or loses to an older accepted one. -/
theorem valid_loser_has_older_winner (wg : WgView) (now : Nat) (decoded : List Record)
    (u : List Nat) (hn : (decoded.map (·.id)).Nodup) (r : Record) (hr : r ∈ decoded)
    (hv : validateInstance wg now r = true)
    (hna : r ∉ (acceptInstancesAt wg now decoded u).instances) :
    ∃ w ∈ (acceptInstancesAt wg now decoded u).instances, Conflicts w r ∧ Older w r := by
  rcases accept_classified wg now decoded u hn r hr with h | h | ⟨_, _, w, hw, _, hc, ho⟩
  · exact absurd h.1 hna
  · rw [hv] at h; exact absurd h.2 (by decide)
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
theorem accept_perm_invariant (wg : WgView) (now : Nat) {d₁ d₂ : List Record} (u : List Nat)
    (h : d₁.Perm d₂) (hn : (d₁.map (·.id)).Nodup) :
    acceptInstancesAt wg now d₁ u = acceptInstancesAt wg now d₂ u := by
  unfold acceptInstancesAt
  rw [mergeSort_perm_eq h hn]

theorem run_congr {v₁ v₂ : Record → Bool} :
    ∀ (l : List Record) (acc : Acc), (∀ r ∈ l, v₁ r = v₂ r) →
      l.foldl (step v₁) acc = l.foldl (step v₂) acc
  | [], _, _ => rfl
  | r :: l, acc, h => by
    simp only [List.foldl_cons]
    have : step v₁ acc r = step v₂ acc r := by unfold step; rw [h r (by simp)]
    rw [this]
    exact run_congr l _ (fun x hx => h x (by simp [hx]))

/-- Nodes whose validators agree on every record in the KV accept the same instances and report
the same rejections, regardless of their own iteration order. -/
theorem accept_congr {wg₁ wg₂ : WgView} {now₁ now₂ : Nat} {d₁ d₂ : List Record} (u : List Nat)
    (h : d₁.Perm d₂) (hn : (d₁.map (·.id)).Nodup)
    (hagree : ∀ r ∈ d₁, validateInstance wg₁ now₁ r = validateInstance wg₂ now₂ r) :
    acceptInstancesAt wg₁ now₁ d₁ u = acceptInstancesAt wg₂ now₂ d₂ u := by
  rw [← accept_perm_invariant wg₂ now₂ u h hn]
  exact run_congr _ _ (fun r hr => hagree r (List.mem_mergeSort.mp hr))

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
#guard ids (acceptInstancesAt testWg testNow [inst 2 20 9 300, inst 1 20 1 100] []) == [1]
#guard ids (acceptInstancesAt testWg testNow [inst 2 21 1 300, inst 1 20 1 100] []) == [1]
-- conflict_resolution_does_not_depend_on_iteration_order (a = 1, b = 2)
#guard ids (acceptInstancesAt testWg testNow [inst 1 20 1 100, inst 2 20 2 100] []) == [1]
#guard ids (acceptInstancesAt testWg testNow [inst 2 20 2 100, inst 1 20 1 100] []) == [1]
-- rejects_the_gateways_own_public_key
#guard ids (acceptInstancesAt testWg testNow [inst 1 20 7 100] []) == []
-- rejects_registrations_dated_into_the_future (future = 1, skewed = 2)
#guard ids (acceptInstancesAt testWg testNow
  [inst 1 20 1 (testNow + maxClockDriftSecs + 1), inst 2 21 2 (testNow + maxClockDriftSecs)] [])
  == [2]
-- a_conflict_loser_is_dropped_but_an_unusable_record_keeps_its_instance
-- (loser = 1, winner = 2, malformed = 3, undecodable = 4)
#guard (acceptInstancesAt testWg testNow [inst 1 20 9 300, inst 2 20 1 100, inst 3 30 0 100] [4]
  ).rejected == [(4, .unusable), (3, .unusable), (1, .lostConflict)]

/-! ## Validators that disagree can flip the winner -/

/-- Node A considers IP `20` its own gateway address; node B does not. -/
def wgA : WgView := { testWg with routable := fun ip => ip != 20 }
def wgB : WgView := testWg

/-- An older record that only node A refuses, and a newer one holding a different IP but the same
key. Node A keeps the newer record; node B keeps the older one. Cross-node agreement therefore
requires every node to judge every replicated record the same way (see `IpAlloc.lean`). -/
theorem validator_disagreement_flips_winner :
    ids ([inst 1 20 5 100, inst 2 21 5 200].foldl (step (validateInstance wgA testNow))
        (initAcc [])) = [2] ∧
    ids ([inst 1 20 5 100, inst 2 21 5 200].foldl (step (validateInstance wgB testNow))
        (initAcc [])) = [1] ∧
    [inst 1 20 5 100, inst 2 21 5 200].mergeSort recLe = [inst 1 20 5 100, inst 2 21 5 200] := by
  refine ⟨by decide, by decide, List.mergeSort_of_pairwise (by decide)⟩

end DstackFormal.Gateway.Import
