-- SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
--
-- SPDX-License-Identifier: Apache-2.0

import DstackFormal.Gateway.Import

/-!
# WireGuard client IP allocation (`dstack/gateway/src/main_service.rs`, `config.rs`)

Models `ProxyState::alloc_ip` and `ProxyState::valid_ip` (= `WgConfig::is_valid_client_ip`),
`WgConfig::is_routable_client_ip`, the registration path's use of `alloc_ip` +
`add_instance`, and `ProxyState::forget_instance`.

Proven:
* `allocIp_some`: a returned IP is a host of the pool, valid, previously unallocated, and is the
  only addition to `allocated_addresses`; `allocIp_first` it is the first such host.
* `allocIp_none_iff`: `None` exactly when every valid host is already allocated.
* `reachable_inv`, `register_fresh_ip`: across any sequence of registrations and
  `forget_instance` calls, live instances hold distinct allocated IPs and a newly allocated IP
  is never a live instance's. `forget_shared_ip_reissues_live_ip` shows the distinctness part of
  the invariant is load-bearing: `forget_instance` frees the IP unconditionally.
* Cross node: under `PoolsClear` (an operator assumption that `config.rs::validate` does not
  check, since it only sees one node), an IP valid on any node is routable on every node
  (`valid_on_some_node_routable_everywhere`); with disjoint pools two nodes never allocate the
  same IP (`disjoint_pools_distinct_ips`). `cluster_accepts_same_set` combines this with
  `Import.accept_congr`: nodes with equal KV contents accept the same instance set, provided
  every record's IP was allocated by some node, its key is no gateway's key, and its `reg_time`
  is within every node's drift horizon.
* `gateway_key_record_diverges`: a record whose key equals node B's gateway key (any CVM can
  register with node A using B's public key) is accepted on A and refused on B.

Modeling gap: IPv4 addresses are `Nat`; an `Ipv4Net` is an inclusive range; the IPv4 special
classes (`is_unspecified`, `is_loopback`, `is_multicast`, `is_broadcast`) are one shared
predicate; `client_ip_range.hosts()` is an arbitrary list. The rebuild branch of
`new_client_by_id` (an existing instance with an invalid IP) and the KV reload path, which inserts
imported IPs into `allocated_addresses` directly, are not modeled.
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

/-- First registration in `new_client_by_id`: `alloc_ip` then `add_instance`. -/
def Local.register (valid : Nat → Bool) (hosts : List Nat) (s : Local) (id : Nat) : Local :=
  match allocIp valid s.allocated hosts with
  | (some ip, a') => { instances := (id, ip) :: s.instances, allocated := a' }
  | (none, _) => s

def lookupIp (id : Nat) : List (Nat × Nat) → Option Nat
  | [] => none
  | (i, ip) :: rest => if i = id then some ip else lookupIp id rest

/-- `forget_instance`: drop the record and free its IP. -/
def Local.forget (s : Local) (id : Nat) : Local :=
  match lookupIp id s.instances with
  | some ip =>
    { instances := s.instances.filter (·.1 ≠ id), allocated := s.allocated.filter (· ≠ ip) }
  | none => s

inductive LEv where
  | register (id : Nat)
  | forget (id : Nat)

def Local.apply (valid : Nat → Bool) (hosts : List Nat) (s : Local) : LEv → Local
  | .register id => s.register valid hosts id
  | .forget id => s.forget id

inductive Reachable (valid : Nat → Bool) (hosts : List Nat) : Local → Prop
  | init : Reachable valid hosts ⟨[], []⟩
  | step (s : Local) (e : LEv) : Reachable valid hosts s →
      Reachable valid hosts (s.apply valid hosts e)

structure LInv (valid : Nat → Bool) (s : Local) : Prop where
  distinct : (s.instances.map (·.2)).Nodup
  allocated : ∀ x ∈ s.instances, x.2 ∈ s.allocated
  valid : ∀ x ∈ s.instances, valid x.2 = true

theorem lookupIp_mem : ∀ {l : List (Nat × Nat)} {id ip : Nat}, lookupIp id l = some ip →
    (id, ip) ∈ l
  | [], _, _, h => by simp [lookupIp] at h
  | (i, p) :: rest, id, ip, h => by
    unfold lookupIp at h
    by_cases hi : i = id
    · simp only [hi, ↓reduceIte, Option.some.injEq] at h
      subst h; subst hi; simp
    · simp only [hi, ↓reduceIte] at h
      exact List.mem_cons_of_mem _ (lookupIp_mem h)

theorem nodup_filter_snd {p : Nat × Nat → Bool} :
    ∀ {l : List (Nat × Nat)}, (l.map (·.2)).Nodup → ((l.filter p).map (·.2)).Nodup
  | [], _ => by simp
  | x :: l, h => by
    simp only [List.map_cons, List.nodup_cons, List.mem_map] at h
    by_cases hp : p x = true
    · simp only [List.filter_cons, hp, ↓reduceIte, List.map_cons, List.nodup_cons, List.mem_map,
        List.mem_filter]
      exact ⟨fun ⟨a, ha, he⟩ => h.1 ⟨a, ha.1, he⟩, nodup_filter_snd h.2⟩
    · simp only [List.filter_cons, hp, Bool.false_eq_true, ↓reduceIte]
      exact nodup_filter_snd h.2

theorem eq_of_snd_eq {l : List (Nat × Nat)} (hn : (l.map (·.2)).Nodup) :
    ∀ {a b}, a ∈ l → b ∈ l → a.2 = b.2 → a = b := by
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

theorem reachable_inv {valid : Nat → Bool} {hosts : List Nat} {s : Local}
    (h : Reachable valid hosts s) : LInv valid s := by
  induction h with
  | init => exact ⟨by simp, by simp, by simp⟩
  | step s e _ ih =>
    cases e with
    | register id =>
      simp only [Local.apply, Local.register]
      split
      · rename_i ip a' heq
        obtain ⟨_, hv, hfree, rfl⟩ := allocIp_some heq
        refine ⟨?_, ?_, ?_⟩
        · simp only [List.map_cons, List.nodup_cons, List.mem_map]
          refine ⟨?_, ih.distinct⟩
          rintro ⟨x, hx, he⟩
          exact hfree (he ▸ ih.allocated x hx)
        · intro x hx
          simp only [List.mem_cons] at hx
          rcases hx with rfl | hx
          · simp
          · exact List.mem_cons_of_mem _ (ih.allocated x hx)
        · intro x hx
          simp only [List.mem_cons] at hx
          rcases hx with rfl | hx
          · exact hv
          · exact ih.valid x hx
      · exact ih
    | forget id =>
      simp only [Local.apply, Local.forget]
      split
      · rename_i ip heq
        have hmem := lookupIp_mem heq
        refine ⟨nodup_filter_snd ih.distinct, ?_, ?_⟩
        · intro x hx
          simp only [List.mem_filter, decide_eq_true_eq] at hx ⊢
          refine ⟨ih.allocated x hx.1, ?_⟩
          intro he
          have := eq_of_snd_eq ih.distinct hx.1 hmem he
          exact hx.2 (by rw [this])
        · intro x hx
          simp only [List.mem_filter] at hx
          exact ih.valid x hx.1
      · exact ih

/-- A registration's new IP is valid, in the pool, and held by no live instance. -/
theorem register_fresh_ip {valid : Nat → Bool} {hosts : List Nat} {s : Local}
    (h : Reachable valid hosts s) {ip : Nat} {a' : List Nat}
    (ha : allocIp valid s.allocated hosts = (some ip, a')) :
    ip ∈ hosts ∧ valid ip = true ∧ ∀ x ∈ s.instances, x.2 ≠ ip := by
  obtain ⟨hh, hv, hfree, _⟩ := allocIp_some ha
  exact ⟨hh, hv, fun x hx he => hfree (he ▸ (reachable_inv h).allocated x hx)⟩

/-- Live instances on one node never share an IP. -/
theorem live_ips_distinct {valid : Nat → Bool} {hosts : List Nat} {s : Local}
    (h : Reachable valid hosts s) : (s.instances.map (·.2)).Nodup :=
  (reachable_inv h).distinct

/-- If two live instances ever share an IP (e.g. through a path outside this model),
`forget_instance` of one frees the address the other still uses, and the next registration is
handed it. -/
theorem forget_shared_ip_reissues_live_ip :
    let s : Local := ⟨[(1, 20), (2, 20)], [20]⟩
    let s' := (s.forget 1).register (fun _ => true) [20] 3
    (2, 20) ∈ s'.instances ∧ (3, 20) ∈ s'.instances := by
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

/-- Nodes with equal KV contents accept the same instances, provided every record's IP was handed
out by some node's `alloc_ip` (so it is valid there), its key is no node's gateway key, and its
`reg_time` is within every node's drift horizon. -/
theorem cluster_accepts_same_set {special : Nat → Bool} {idOk keyOk : Nat → Bool}
    {nodes : List GwNode} (hc : PoolsClear (nodes.map (·.net))) {a b : GwNode}
    (ha : a ∈ nodes) (hb : b ∈ nodes) (kv : List Import.Record) (undecodable : List Nat)
    (hn : (kv.map (·.id)).Nodup)
    (hip : ∀ r ∈ kv, ∃ m ∈ nodes, validClient special m.net r.ip = true)
    (hkey : ∀ r ∈ kv, ∀ g ∈ nodes, r.publicKey ≠ g.key)
    (htime : ∀ r ∈ kv, ∀ g ∈ nodes, r.regTime ≤ g.now + Import.maxClockDriftSecs) :
    Import.acceptInstancesAt (a.view special idOk keyOk) a.now kv undecodable =
      Import.acceptInstancesAt (b.view special idOk keyOk) b.now kv undecodable := by
  apply Import.accept_congr undecodable (List.Perm.refl kv) hn
  intro r hr
  obtain ⟨m, hm, hv⟩ := hip r hr
  have hmn : m.net ∈ nodes.map (·.net) := List.mem_map_of_mem hm
  have ra := valid_on_some_node_routable_everywhere hc hmn (List.mem_map_of_mem ha) hv
  have rb := valid_on_some_node_routable_everywhere hc hmn (List.mem_map_of_mem hb) hv
  have ka : (r.publicKey != a.key) = true := by simp [hkey r hr a ha]
  have kb : (r.publicKey != b.key) = true := by simp [hkey r hr b hb]
  have ta := htime r hr a ha
  have tb := htime r hr b hb
  simp only [Import.validateInstance, GwNode.view, ra, rb, ka, kb, decide_true, ta, tb,
    Bool.and_true]

/-- A CVM registering with node A under node B's public WireGuard key passes A's checks and fails
B's: the nodes then disagree on the record. -/
theorem gateway_key_record_diverges :
    let a : GwNode := ⟨⟨1, 255, [⟨0, 15⟩], ⟨16, 127⟩⟩, 100, 0⟩
    let b : GwNode := ⟨⟨129, 255, [⟨128, 143⟩], ⟨144, 254⟩⟩, 200, 0⟩
    let r : Import.Record := ⟨1, 1, 20, 200, 0⟩
    Import.validateInstance (a.view (fun _ => false) (fun _ => true) (fun _ => true)) 0 r = true ∧
    Import.validateInstance (b.view (fun _ => false) (fun _ => true) (fun _ => true)) 0 r = false := by
  decide

end DstackFormal.Gateway.IpAlloc
