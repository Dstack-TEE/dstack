-- SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
--
-- SPDX-License-Identifier: Apache-2.0

import DstackFormal.Gateway.Import

/-!
# WireGuard client IP allocation (`dstack/gateway/src/main_service.rs`, `config.rs`)

Models `ProxyState::alloc_ip`, `ProxyState::valid_ip` (= `WgConfig::is_valid_client_ip`),
`ProxyState::release_ip`, `WgConfig::is_routable_client_ip`, and the paths that change
`allocated_addresses`: first registration and the rebuild branch of `new_client_by_id`,
`forget_instance`, and the per-record step of `reload_instances_from_kv_store`.

Tracks origin/next at 13d952749f: #1605 (`fc1405c0b5`, `release_ip` frees an address only if no
other instance holds it), #1604 (`ce8f54312a`, gateway keys are rejected on every node, see
`Import.lean`), and #1606 (`435ea8550a`), which only logs a warning when a peer gateway's address
lies in this node's pool: `PoolsClear` below stays an assumption, nothing enforces it.

Proven:
* `allocIp_some`: a returned IP is a host of the pool, valid, previously unallocated, and is the
  only addition to `allocated_addresses`; `allocIp_first` it is the first such host.
* `allocIp_none_iff`: `None` exactly when every valid host is already allocated.
* `reachable_held`, `alloc_never_live`: across any sequence of registrations, rebuilds,
  `forget_instance` calls and KV reloads (which may give two live instances one address, as for
  a conflict loser kept through its grace period), every valid address a live instance holds
  stays allocated, so `alloc_ip` never hands out an address in use. `shared_ip_not_reissued`
  replays the trace that reissued a live address before #1605.
* Cross node: under `PoolsClear` (an operator assumption that `config.rs::validate` does not
  check, since it only sees one node), an IP valid on any node is routable on every node
  (`valid_on_some_node_routable_everywhere`); with disjoint pools two nodes never allocate the
  same IP (`disjoint_pools_distinct_ips`). `cluster_accepts_same_set` combines this with
  `Import.accept_congr`: nodes with equal KV contents accept the same instance set, provided
  every record's IP was allocated by some node, every node's own key has replicated into the
  gateway key set, and every `reg_time` is within every node's drift horizon. Records carrying a
  gateway key, the judging node's own included, no longer need to be excluded by hypothesis.

Modeling gap: IPv4 addresses are `Nat`; an `Ipv4Net` is an inclusive range; the IPv4 special
classes (`is_unspecified`, `is_loopback`, `is_multicast`, `is_broadcast`) are one shared
predicate; `client_ip_range.hosts()` is an arbitrary list; the reload step takes any address
(what `accept_instances` lets through is in `Import.lean`).
-/

namespace DstackFormal.Gateway.IpAlloc

/-- `ipnet::Ipv4Net`, as the inclusive address range it `contains`. -/
structure Net where
  lo : Nat
  hi : Nat
deriving DecidableEq, Repr

def Net.contains (n : Net) (ip : Nat) : Bool := decide (n.lo ≤ ip ∧ ip ≤ n.hi)

/-- The address fields of `config::WgConfig`. -/
structure WgNet where
  addr : Nat
  broadcast : Nat
  reserved : List Net
  clientRange : Net
deriving DecidableEq, Repr

/-- `WgConfig::is_routable_client_ip`; `special` is the IPv4 unspecified/loopback/multicast/
broadcast classification. -/
def routable (special : Nat → Bool) (w : WgNet) (ip : Nat) : Bool :=
  !special ip && ip != w.addr && ip != w.broadcast && !(w.reserved.any (·.contains ip))

/-- `WgConfig::is_valid_client_ip` (= `ProxyState::valid_ip`). -/
def validClient (special : Nat → Bool) (w : WgNet) (ip : Nat) : Bool :=
  w.clientRange.contains ip && routable special w ip

/-- `ProxyState::alloc_ip`: first valid host not in `allocated_addresses`, inserted on success. -/
def allocIp (valid : Nat → Bool) (allocated : List Nat) : List Nat → Option Nat × List Nat
  | [] => (none, allocated)
  | ip :: rest =>
    if !valid ip then allocIp valid allocated rest
    else if ip ∈ allocated then allocIp valid allocated rest
    else (some ip, ip :: allocated)

theorem allocIp_some {valid : Nat → Bool} {allocated : List Nat} :
    ∀ {hosts : List Nat} {ip : Nat} {a' : List Nat}, allocIp valid allocated hosts = (some ip, a') →
      ip ∈ hosts ∧ valid ip = true ∧ ip ∉ allocated ∧ a' = ip :: allocated
  | [], _, _, h => by simp [allocIp] at h
  | x :: rest, ip, a', h => by
    unfold allocIp at h
    by_cases hv : valid x = true
    · by_cases hm : x ∈ allocated
      · simp only [hv, hm, Bool.not_true, Bool.false_eq_true, ↓reduceIte] at h
        have := allocIp_some h
        exact ⟨List.mem_cons_of_mem _ this.1, this.2⟩
      · simp only [hv, hm, Bool.not_true, Bool.false_eq_true, ↓reduceIte, Prod.mk.injEq,
          Option.some.injEq] at h
        obtain ⟨rfl, rfl⟩ := h
        exact ⟨by simp, hv, hm, rfl⟩
    · simp only [hv, Bool.not_false, ↓reduceIte] at h
      · have := allocIp_some h
        exact ⟨List.mem_cons_of_mem _ this.1, this.2⟩

theorem allocIp_none_iff {valid : Nat → Bool} {allocated : List Nat} :
    ∀ {hosts : List Nat}, (allocIp valid allocated hosts).1 = none ↔
      ∀ ip ∈ hosts, valid ip = true → ip ∈ allocated
  | [] => by simp [allocIp]
  | x :: rest => by
    have ih := allocIp_none_iff (valid := valid) (allocated := allocated) (hosts := rest)
    unfold allocIp
    by_cases hv : valid x = true
    · by_cases hm : x ∈ allocated
      · simp only [hv, hm, Bool.not_true, Bool.false_eq_true, ↓reduceIte, ih, List.mem_cons,
          forall_eq_or_imp, true_implies, true_and]
      · simp only [hv, hm, Bool.not_true, Bool.false_eq_true, ↓reduceIte, reduceCtorEq,
          List.mem_cons, forall_eq_or_imp, true_implies, false_and]
    · simp only [hv, Bool.not_false, ↓reduceIte, ih, List.mem_cons, forall_eq_or_imp,
        Bool.false_eq_true, false_implies, true_and]

theorem allocIp_none_state {valid : Nat → Bool} {allocated : List Nat} :
    ∀ {hosts : List Nat}, (allocIp valid allocated hosts).1 = none →
      (allocIp valid allocated hosts).2 = allocated
  | [] => by simp [allocIp]
  | x :: rest => by
    unfold allocIp
    by_cases hv : valid x = true
    · by_cases hm : x ∈ allocated
      · simp only [hv, hm, Bool.not_true, Bool.false_eq_true, ↓reduceIte]
        exact allocIp_none_state
      · simp [hv, hm]
    · simp only [hv, Bool.not_false, ↓reduceIte]
      exact allocIp_none_state

/-- First fit: every host before the returned one is invalid or taken. -/
theorem allocIp_first {valid : Nat → Bool} {allocated : List Nat} :
    ∀ {hosts : List Nat} {ip : Nat} {a' : List Nat}, allocIp valid allocated hosts = (some ip, a') →
      ∃ pre post, hosts = pre ++ ip :: post ∧ ∀ x ∈ pre, valid x = true → x ∈ allocated
  | [], _, _, h => by simp [allocIp] at h
  | x :: rest, ip, a', h => by
    unfold allocIp at h
    by_cases hv : valid x = true
    · by_cases hm : x ∈ allocated
      · simp only [hv, hm, Bool.not_true, Bool.false_eq_true, ↓reduceIte] at h
        obtain ⟨pre, post, he, hp⟩ := allocIp_first h
        refine ⟨x :: pre, post, by simp [he], ?_⟩
        intro y hy hvy
        simp only [List.mem_cons] at hy
        rcases hy with rfl | hy
        · exact hm
        · exact hp y hy hvy
      · simp only [hv, hm, Bool.not_true, Bool.false_eq_true, ↓reduceIte, Prod.mk.injEq,
          Option.some.injEq] at h
        obtain ⟨rfl, rfl⟩ := h
        exact ⟨[], rest, rfl, by simp⟩
    · simp only [hv, Bool.not_false, ↓reduceIte] at h
      obtain ⟨pre, post, he, hp⟩ := allocIp_first h
      refine ⟨x :: pre, post, by simp [he], ?_⟩
      intro y hy hvy
      simp only [List.mem_cons] at hy
      rcases hy with rfl | hy
      · exact absurd hvy hv
      · exact hp y hy hvy

-- alloc_ip skips the reserved range and an address already taken
#guard (allocIp (validClient (fun _ => false) ⟨1, 255, [⟨0, 15⟩], ⟨0, 255⟩⟩) [16]
  (List.range' 1 254)).1 == some 17

/-! ## Local allocation state -/

/-- The parts of `ProxyStateMut` allocation touches: `instances` as `(id, ip)` and
`allocated_addresses`. -/
structure Local where
  instances : List (Nat × Nat)
  allocated : List Nat
deriving DecidableEq, Repr

def lookupIp (id : Nat) : List (Nat × Nat) → Option Nat
  | [] => none
  | (i, ip) :: rest => if i = id then some ip else lookupIp id rest

/-- `instances.insert(id, ..)` with address `ip`. -/
def setInst (l : List (Nat × Nat)) (id ip : Nat) : List (Nat × Nat) :=
  (id, ip) :: l.filter (·.1 ≠ id)

/-- `ProxyState::release_ip`: return `ip` to the pool unless an instance other than `id` holds
it. -/
def Local.releaseIp (s : Local) (ip id : Nat) : Local :=
  if s.instances.any (fun x => decide (x.1 ≠ id) && x.2 == ip) then s
  else { s with allocated := s.allocated.filter (· ≠ ip) }

/-- First registration in `new_client_by_id`: `alloc_ip` then `add_instance`. -/
def Local.register (valid : Nat → Bool) (hosts : List Nat) (s : Local) (id : Nat) : Local :=
  match allocIp valid s.allocated hosts with
  | (some ip, a') => { instances := setInst s.instances id ip, allocated := a' }
  | (none, _) => s

/-- The rebuild branch of `new_client_by_id`: an existing instance whose IP is no longer valid
releases it and is given a new one; if the pool is exhausted the call fails after the release. -/
def Local.rebuild (valid : Nat → Bool) (hosts : List Nat) (s : Local) (id : Nat) : Local :=
  match lookupIp id s.instances with
  | none => s
  | some old =>
    if valid old then s
    else
      let s := s.releaseIp old id
      match allocIp valid s.allocated hosts with
      | (some ip, a') => { instances := setInst s.instances id ip, allocated := a' }
      | (none, _) => s

/-- `forget_instance`: drop the record, then `release_ip`. -/
def Local.forget (s : Local) (id : Nat) : Local :=
  match lookupIp id s.instances with
  | some ip => ({ s with instances := s.instances.filter (·.1 ≠ id) }).releaseIp ip id
  | none => s

/-- `reload_instances_from_kv_store` for one accepted record: release the old address if it
changed, insert the record's address into `allocated_addresses`, store the instance. The address
may be one a local instance already holds (a conflict loser in its grace period). -/
def Local.reload (s : Local) (id ip : Nat) : Local :=
  let s := match lookupIp id s.instances with
    | some old => if old ≠ ip then s.releaseIp old id else s
    | none => s
  { instances := setInst s.instances id ip, allocated := ip :: s.allocated }

inductive LEv where
  | register (id : Nat)
  | rebuild (id : Nat)
  | forget (id : Nat)
  | reload (id ip : Nat)

def Local.apply (valid : Nat → Bool) (hosts : List Nat) (s : Local) : LEv → Local
  | .register id => s.register valid hosts id
  | .rebuild id => s.rebuild valid hosts id
  | .forget id => s.forget id
  | .reload id ip => s.reload id ip

inductive Reachable (valid : Nat → Bool) (hosts : List Nat) : Local → Prop
  | init : Reachable valid hosts ⟨[], []⟩
  | step (s : Local) (e : LEv) : Reachable valid hosts s →
      Reachable valid hosts (s.apply valid hosts e)

/-- Every valid address a live instance holds is allocated. -/
def Held (valid : Nat → Bool) (s : Local) : Prop :=
  ∀ x ∈ s.instances, valid x.2 = true → x.2 ∈ s.allocated

theorem releaseIp_instances (s : Local) (ip id : Nat) :
    (s.releaseIp ip id).instances = s.instances := by
  unfold Local.releaseIp; split <;> rfl

theorem releaseIp_keeps {s : Local} {ip id : Nat} {x : Nat × Nat} (hx : x ∈ s.instances)
    (ha : x.2 ∈ s.allocated) (hne : x.1 ≠ id ∨ x.2 ≠ ip) : x.2 ∈ (s.releaseIp ip id).allocated := by
  unfold Local.releaseIp
  split
  · exact ha
  · rename_i hnone
    simp only [List.mem_filter, decide_eq_true_eq]
    refine ⟨ha, fun he => ?_⟩
    rcases hne with hne | hne
    · apply hnone
      exact List.any_eq_true.mpr ⟨x, hx, by simp [hne, he]⟩
    · exact hne he

theorem mem_setInst {l : List (Nat × Nat)} {id ip : Nat} {x : Nat × Nat}
    (h : x ∈ setInst l id ip) : x = (id, ip) ∨ (x ∈ l ∧ x.1 ≠ id) := by
  simp only [setInst, List.mem_cons, List.mem_filter, decide_eq_true_eq] at h
  exact h

theorem reachable_held {valid : Nat → Bool} {hosts : List Nat} {s : Local}
    (h : Reachable valid hosts s) : Held valid s := by
  induction h with
  | init => intro x hx; simp at hx
  | step s e _ ih =>
    cases e with
    | register id =>
      simp only [Local.apply, Local.register]
      split
      · rename_i ip a' heq
        obtain ⟨_, _, _, rfl⟩ := allocIp_some heq
        intro x hx hv
        rcases mem_setInst hx with rfl | ⟨hx, _⟩
        · simp
        · exact List.mem_cons_of_mem _ (ih x hx hv)
      · exact ih
    | rebuild id =>
      simp only [Local.apply, Local.rebuild]
      split
      · exact ih
      · rename_i old hold
        split
        · exact ih
        · rename_i hinv
          have hrel : Held valid (s.releaseIp old id) := by
            intro x hx hv
            rw [releaseIp_instances] at hx
            by_cases hxo : x.1 = id ∧ x.2 = old
            · rw [hxo.2] at hv; exact absurd hv hinv
            · exact releaseIp_keeps hx (ih x hx hv) (by omega)
          split
          · rename_i ip a' heq
            obtain ⟨_, _, _, rfl⟩ := allocIp_some heq
            intro x hx hv
            rcases mem_setInst hx with rfl | ⟨hx, _⟩
            · simp
            · exact List.mem_cons_of_mem _ (hrel x hx hv)
          · exact hrel
    | forget id =>
      simp only [Local.apply, Local.forget]
      split
      · rename_i ip _
        intro x hx hv
        rw [releaseIp_instances] at hx
        simp only [List.mem_filter, decide_eq_true_eq] at hx
        exact releaseIp_keeps (s := { s with instances := s.instances.filter (·.1 ≠ id) })
          (by simp [hx.1, hx.2]) (ih x hx.1 hv) (Or.inl hx.2)
      · exact ih
    | reload id ip =>
      simp only [Local.apply, Local.reload]
      have hpre : ∀ t : Local, t.instances = s.instances →
          (∀ x ∈ t.instances, x.1 ≠ id → valid x.2 = true → x.2 ∈ t.allocated) →
          Held valid { instances := setInst t.instances id ip, allocated := ip :: t.allocated } := by
        intro t _ ht x hx hv
        rcases mem_setInst hx with rfl | ⟨hx, hne⟩
        · simp
        · exact List.mem_cons_of_mem _ (ht x hx hne hv)
      split
      · split
        · apply hpre _ (releaseIp_instances _ _ _)
          intro x hx hne hv
          rw [releaseIp_instances] at hx
          exact releaseIp_keeps hx (ih x hx hv) (Or.inl hne)
        · exact hpre _ rfl (fun x hx _ hv => ih x hx hv)
      · exact hpre _ rfl (fun x hx _ hv => ih x hx hv)

/-- `alloc_ip` never hands out an address a live instance holds, including addresses shared by a
winner and a conflict loser during the loser's grace period. -/
theorem alloc_never_live {valid : Nat → Bool} {hosts : List Nat} {s : Local}
    (h : Reachable valid hosts s) {ip : Nat} {a' : List Nat}
    (ha : allocIp valid s.allocated hosts = (some ip, a')) :
    ip ∈ hosts ∧ valid ip = true ∧ ∀ x ∈ s.instances, x.2 ≠ ip := by
  obtain ⟨hh, hv, hfree, _⟩ := allocIp_some ha
  refine ⟨hh, hv, fun x hx he => hfree ?_⟩
  rw [← he] at hv ⊢
  exact reachable_held h x hx hv

/-- The pre-#1605 failure: winner and loser share address 20; forgetting one no longer frees the
address, so the next registration gets 21. -/
theorem shared_ip_not_reissued :
    let s := [LEv.reload 1 20, .reload 2 20, .forget 1, .register 3].foldl
      (Local.apply (fun _ => true) [20, 21]) ⟨[], []⟩
    (2, 20) ∈ s.instances ∧ (3, 21) ∈ s.instances := by
  decide

/-! ## Cross node -/

/-- Operator assumption: no node's `client_ip_range` contains any node's own address, broadcast
address, or reserved net. `config.rs::validate` checks one node at a time and cannot see it. -/
def PoolsClear (nodes : List WgNet) : Prop :=
  ∀ m ∈ nodes, ∀ n ∈ nodes, ∀ ip, m.clientRange.contains ip = true →
    ip ≠ n.addr ∧ ip ≠ n.broadcast ∧ ∀ net ∈ n.reserved, net.contains ip = false

/-- Operator assumption: the nodes' `client_ip_range`s are pairwise disjoint. -/
def PoolsDisjoint (nodes : List WgNet) : Prop :=
  ∀ m ∈ nodes, ∀ n ∈ nodes, m ≠ n → ∀ ip,
    ¬ (m.clientRange.contains ip = true ∧ n.clientRange.contains ip = true)

theorem valid_on_some_node_routable_everywhere {special : Nat → Bool} {nodes : List WgNet}
    (hc : PoolsClear nodes) {m n : WgNet} (hm : m ∈ nodes) (hn : n ∈ nodes) {ip : Nat}
    (hv : validClient special m ip = true) : routable special n ip = true := by
  simp only [validClient, Bool.and_eq_true] at hv
  obtain ⟨h1, h2, h3⟩ := hc m hm n hn ip hv.1
  simp only [routable, Bool.and_eq_true, Bool.not_eq_true', bne_iff_ne, ne_eq,
    List.any_eq_false] at hv ⊢
  exact ⟨⟨⟨hv.2.1.1.1, h1⟩, h2⟩, fun net hnet => by simp [h3 net hnet]⟩

theorem disjoint_pools_distinct_ips {special : Nat → Bool} {nodes : List WgNet}
    (hd : PoolsDisjoint nodes) {m n : WgNet} (hm : m ∈ nodes) (hn : n ∈ nodes) (hmn : m ≠ n)
    {ip₁ ip₂ : Nat} (h₁ : validClient special m ip₁ = true)
    (h₂ : validClient special n ip₂ = true) : ip₁ ≠ ip₂ := by
  rintro rfl
  simp only [validClient, Bool.and_eq_true] at h₁ h₂
  exact hd m hm n hn hmn ip₁ ⟨h₁.1, h₂.1⟩

/-- A gateway node: its address config, WireGuard key, and wall clock. -/
structure GwNode where
  net : WgNet
  key : Nat
  now : Nat

/-- The `Import.WgView` a node judges replicated records by. -/
def GwNode.view (special : Nat → Bool) (idOk keyOk : Nat → Bool) (g : GwNode) :
    Import.WgView :=
  { gatewayKey := g.key, idOk, keyOk, routable := routable special g.net }

/-- Nodes with equal KV contents (records and replicated gateway keys `gk`) accept the same
instances, provided every record's IP was handed out by some node's `alloc_ip` (so it is valid
there), every node's own key is among `gk` (its `node/` info has replicated), and every record's
`reg_time` is within every node's drift horizon. A record carrying any node's key, including the
judging node's own, is rejected on all of them alike. -/
theorem cluster_accepts_same_set {special : Nat → Bool} {idOk keyOk : Nat → Bool}
    {nodes : List GwNode} (hc : PoolsClear (nodes.map (·.net))) {a b : GwNode}
    (ha : a ∈ nodes) (hb : b ∈ nodes) (gk : List Nat) (kv : List Import.Record)
    (undecodable : List Nat) (hn : (kv.map (·.id)).Nodup)
    (hip : ∀ r ∈ kv, ∃ m ∈ nodes, validClient special m.net r.ip = true)
    (hown : ∀ g ∈ nodes, g.key ∈ gk)
    (htime : ∀ r ∈ kv, ∀ g ∈ nodes, r.regTime ≤ g.now + Import.maxClockDriftSecs) :
    Import.acceptInstancesAt (a.view special idOk keyOk) gk a.now kv undecodable =
      Import.acceptInstancesAt (b.view special idOk keyOk) gk b.now kv undecodable := by
  apply Import.accept_congr undecodable (List.Perm.refl kv) hn
  · intro r hr
    obtain ⟨m, hm, hv⟩ := hip r hr
    have hmn : m.net ∈ nodes.map (·.net) := List.mem_map_of_mem hm
    have ra := valid_on_some_node_routable_everywhere hc hmn (List.mem_map_of_mem ha) hv
    have rb := valid_on_some_node_routable_everywhere hc hmn (List.mem_map_of_mem hb) hv
    have ta := htime r hr a ha
    have tb := htime r hr b hb
    simp only [Import.validateInstance, GwNode.view, ra, rb, decide_true, ta, tb, Bool.and_true]
  · intro r _
    exact Import.isGatewayKey_agree (hown a ha) (hown b hb) r

-- every_node_rejects_another_gateways_public_key, seen from both nodes: node A (key 100) and
-- node B (key 200) both refuse a record carrying B's key.
#guard [(100 : Nat), 200].all fun k =>
  (Import.acceptInstancesAt
    ((⟨⟨1, 255, [⟨0, 15⟩], ⟨16, 127⟩⟩, k, 0⟩ : GwNode).view (fun _ => false) (fun _ => true)
      (fun _ => true)) [100, 200] 0 [⟨1, 1, 20, 200, 0⟩] []).instances.isEmpty

end DstackFormal.Gateway.IpAlloc
