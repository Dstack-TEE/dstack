-- SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
--
-- SPDX-License-Identifier: Apache-2.0

/-!
# Per-instance port policy (`dstack/gateway/src/proxy/port_policy.rs`)

Models `is_port_allowed`, `filter_allowed_addresses`, `should_send_pp` and
`parse_info_port_policy`, together with `ProxyState::instance_port_policy` (admin override wins
over the instance-reported policy) and `ProxyState::update_instance_port_policy`
(`main_service.rs`).

Proven:
* `known_unknown_policy_denied`: a registered instance with neither an override nor a reported
  policy is denied (`PolicyUnknown`) on every port, and a fetch is queued.
* `unregistered_bypasses`: an id that is not a registered instance is allowed (the documented
  `localhost` bypass).
* `restrict_allows_exactly_listed`, `open_allows_all`: with an effective policy, restrict mode
  allows exactly the listed ports; otherwise every port.
* `admin_override_decides`: an override, when present, alone decides.
* `filter_ok_spec`: a successful filter returns a nonempty sublist of the candidates that contains
  exactly the allowed ones; `filter_err_iff` it fails exactly when no candidate is allowed.
* `parse_listed_iff`, `parse_pp_last_wins`: the parsed policy keeps `restrict_mode`, lists exactly
  the declared ports, and a duplicated port keeps its last flag (`BTreeMap` collect).
* `legacy_ends_open`: a CVM with an empty `tcb_info` ends up with an open policy once the lazy
  fetch lands, so fail-closed is transient for legacy CVMs (documented design).
* `send_pp_sound`: a PROXY header is sent only for a listed port whose flag is set.

Modeling gap: JSON parsing of `tcb_info` / `app_compose` is abstracted into the shape `TcbInfo`;
the channel send and background fetch are modeled as a returned flag; ports are `Nat`.
-/

namespace DstackFormal.Gateway.PortPolicy

/-- `kv::PortPolicy`: `ports: BTreeMap<u16, PortFlags>` as an association list with unique keys. -/
structure Policy where
  ports : List (Nat × Bool)
  restrictMode : Bool
deriving DecidableEq, Repr

/-- `PortPolicy::default()`. -/
def Policy.default : Policy := ⟨[], false⟩

/-- The fields of `InstanceInfo` the lookup reads. -/
structure Instance where
  id : Nat
  portPolicy : Option Policy
  adminPortPolicy : Option Policy
deriving DecidableEq, Repr

/-- `state.instances.get(id)`. -/
def find (st : List Instance) (id : Nat) : Option Instance := st.find? (·.id == id)

/-- `ProxyState::instance_port_policy`: admin override, else the reported policy. -/
def instancePortPolicy (st : List Instance) (id : Nat) : Option Policy :=
  (find st id).bind fun i => i.adminPortPolicy.or i.portPolicy

/-- `BTreeMap::contains_key` on the association list. -/
def lookup (port : Nat) : List (Nat × Bool) → Option Bool
  | [] => none
  | (p, f) :: rest => if p = port then some f else lookup port rest

inductive DenyReason where
  | portNotAllowed
  | policyUnknown
deriving DecidableEq, Repr

/-- `is_port_allowed`: the decision, and whether an id was sent to `port_policy_tx`. -/
def isPortAllowed (st : List Instance) (id port : Nat) : Except DenyReason Unit × Bool :=
  match instancePortPolicy st id with
  | none => if (find st id).isNone then (.ok (), false) else (.error .policyUnknown, true)
  | some policy =>
    if !policy.restrictMode then (.ok (), false)
    else if (lookup port policy.ports).isSome then (.ok (), false)
    else (.error .portNotAllowed, false)

def allowed (st : List Instance) (id port : Nat) : Bool :=
  match (isPortAllowed st id port).1 with
  | .ok () => true
  | .error _ => false

/-- `filter_allowed_addresses` over the candidates' instance ids. -/
def filterAllowed (st : List Instance) (addrs : List Nat) (port : Nat) : Except String (List Nat) :=
  if addrs.length = 0 then .error "empty selection"
  else
    let out := addrs.filter (allowed st · port)
    if out.isEmpty then .error "port denied by app port policy" else .ok out

/-- `should_send_pp`. -/
def shouldSendPp (st : List Instance) (id port : Nat) : Bool :=
  ((instancePortPolicy st id).bind fun p => lookup port p.ports).getD false

/-- The shapes `parse_info_port_policy` distinguishes in `tcb_info`. -/
inductive TcbInfo where
  | empty
  | invalidJson
  | missingAppCompose
  | invalidAppCompose
  /-- `app_compose.port_policy`: declared `(port, pp)` entries and `restrict_mode`. -/
  | appCompose (ports : List (Nat × Bool)) (restrictMode : Bool)
deriving DecidableEq, Repr

inductive FetchError where
  | permanent
  | transient
deriving DecidableEq, Repr

/-- `BTreeMap::insert`. -/
def insert (port : Nat) (f : Bool) : List (Nat × Bool) → List (Nat × Bool)
  | [] => [(port, f)]
  | (p, g) :: rest => if p = port then (p, f) :: rest else (p, g) :: insert port f rest

/-- `.into_iter().map(..).collect::<BTreeMap<_, _>>()`: later entries overwrite earlier ones. -/
def collect (l : List (Nat × Bool)) : List (Nat × Bool) :=
  l.foldl (fun m e => insert e.1 e.2 m) []

/-- `parse_info_port_policy`. -/
def parseInfoPortPolicy : TcbInfo → Except FetchError Policy
  | .empty => .ok Policy.default
  | .invalidJson => .error .permanent
  | .missingAppCompose => .error .permanent
  | .invalidAppCompose => .error .permanent
  | .appCompose ports restrict => .ok ⟨collect ports, restrict⟩

/-- `ProxyState::update_instance_port_policy`. -/
def updatePolicy (st : List Instance) (id : Nat) (p : Policy) : List Instance :=
  st.map fun i => if i.id = id then { i with portPolicy := some p } else i

theorem known_unknown_policy_denied {st : List Instance} {id : Nat} {i : Instance}
    (hf : find st id = some i) (hr : i.portPolicy = none) (ha : i.adminPortPolicy = none)
    (port : Nat) : isPortAllowed st id port = (.error .policyUnknown, true) := by
  simp [isPortAllowed, instancePortPolicy, hf, hr, ha]

theorem unregistered_bypasses {st : List Instance} {id : Nat} (hf : find st id = none)
    (port : Nat) : isPortAllowed st id port = (.ok (), false) := by
  simp [isPortAllowed, instancePortPolicy, hf]

theorem restrict_allows_exactly_listed {st : List Instance} {id : Nat} {p : Policy}
    (he : instancePortPolicy st id = some p) (hr : p.restrictMode = true) (port : Nat) :
    allowed st id port = true ↔ (lookup port p.ports).isSome = true := by
  unfold allowed isPortAllowed
  rw [he]
  by_cases hl : (lookup port p.ports).isSome = true <;> simp [hr, hl]

theorem open_allows_all {st : List Instance} {id : Nat} {p : Policy}
    (he : instancePortPolicy st id = some p) (hr : p.restrictMode = false) (port : Nat) :
    allowed st id port = true := by
  simp [allowed, isPortAllowed, he, hr]

theorem admin_override_decides {st : List Instance} {id : Nat} {i : Instance} {a : Policy}
    (hf : find st id = some i) (ha : i.adminPortPolicy = some a) :
    instancePortPolicy st id = some a := by
  simp [instancePortPolicy, hf, ha]

theorem filter_ok_spec {st : List Instance} {addrs out : List Nat} {port : Nat}
    (h : filterAllowed st addrs port = .ok out) :
    out.Sublist addrs ∧ out ≠ [] ∧ ∀ a, a ∈ out ↔ a ∈ addrs ∧ allowed st a port = true := by
  unfold filterAllowed at h
  by_cases h0 : addrs.length = 0
  · simp [h0] at h
  · simp only [h0, ↓reduceIte] at h
    by_cases he : (addrs.filter (allowed st · port)).isEmpty = true
    · simp [he] at h
    · simp only [he, Bool.false_eq_true, ↓reduceIte, Except.ok.injEq] at h
      subst h
      refine ⟨List.filter_sublist, ?_, fun a => List.mem_filter⟩
      intro hn
      simp [hn] at he

theorem filter_err_iff {st : List Instance} {addrs : List Nat} {port : Nat} :
    (∃ e, filterAllowed st addrs port = .error e) ↔ ∀ a ∈ addrs, allowed st a port = false := by
  unfold filterAllowed
  by_cases h0 : addrs.length = 0
  · have : addrs = [] := List.eq_nil_of_length_eq_zero h0
    simp [this]
  · simp only [h0, ↓reduceIte]
    by_cases he : (addrs.filter (allowed st · port)).isEmpty = true
    · simp only [he, ↓reduceIte, Except.error.injEq, exists_eq', true_iff]
      simpa [List.isEmpty_iff, List.filter_eq_nil_iff] using he
    · simp only [he, Bool.false_eq_true, ↓reduceIte, reduceCtorEq, exists_false, false_iff]
      intro hall
      apply he
      simpa [List.isEmpty_iff, List.filter_eq_nil_iff] using hall

theorem lookup_insert (port q : Nat) (f : Bool) :
    ∀ m : List (Nat × Bool), lookup q (insert port f m) = if port = q then some f else lookup q m
  | [] => by simp [insert, lookup]
  | (p, g) :: rest => by
    by_cases hp : p = port
    · subst hp
      by_cases hq : p = q <;> simp [insert, lookup, hq]
    · have ih := lookup_insert port q f rest
      by_cases hq : p = q
      · subst hq; simp [insert, lookup, hp, Ne.symm hp]
      · simp [insert, lookup, hp, hq, ih]

/-- Lookup in the collected map reads the last declaration of the port. -/
def lastFlag (q : Nat) (l : List (Nat × Bool)) : Option Bool :=
  l.foldl (fun acc e => if e.1 = q then some e.2 else acc) none

theorem lookup_collect_aux (q : Nat) :
    ∀ (l : List (Nat × Bool)) (m : List (Nat × Bool)),
      lookup q (l.foldl (fun m e => insert e.1 e.2 m) m) =
        l.foldl (fun acc e => if e.1 = q then some e.2 else acc) (lookup q m)
  | [], _ => rfl
  | e :: l, m => by
    simp only [List.foldl_cons]
    rw [lookup_collect_aux q l, lookup_insert]

theorem parse_pp_last_wins {ports : List (Nat × Bool)} {restrict : Bool} {p : Policy}
    (h : parseInfoPortPolicy (.appCompose ports restrict) = .ok p) (q : Nat) :
    lookup q p.ports = lastFlag q ports ∧ p.restrictMode = restrict := by
  simp only [parseInfoPortPolicy, Except.ok.injEq] at h
  subst h
  exact ⟨by simpa [collect, lastFlag, lookup] using lookup_collect_aux q ports [], rfl⟩

theorem lastFlag_isSome_aux (q : Nat) :
    ∀ (l : List (Nat × Bool)) (acc : Option Bool),
      (l.foldl (fun acc e => if e.1 = q then some e.2 else acc) acc).isSome =
        (acc.isSome || l.any (·.1 == q))
  | [], acc => by simp
  | e :: l, acc => by
    simp only [List.foldl_cons, List.any_cons]
    rw [lastFlag_isSome_aux q l]
    by_cases he : e.1 = q
    · simp [he]
    · have : (e.1 == q) = false := by simp [he]
      simp [he, this]

theorem parse_listed_iff {ports : List (Nat × Bool)} {restrict : Bool} {p : Policy}
    (h : parseInfoPortPolicy (.appCompose ports restrict) = .ok p) (q : Nat) :
    (lookup q p.ports).isSome = true ↔ q ∈ ports.map (·.1) := by
  rw [(parse_pp_last_wins h q).1, lastFlag, lastFlag_isSome_aux]
  simp [List.mem_map]

theorem find_update {st : List Instance} {id : Nat} {i : Instance} (hf : find st id = some i)
    (p : Policy) : find (updatePolicy st id p) id = some { i with portPolicy := some p } := by
  induction st with
  | nil => simp [find] at hf
  | cons x rest ih =>
    by_cases hx : x.id = id
    · simp only [find, List.find?_cons, hx, beq_self_eq_true] at hf
      simp only [Option.some.injEq] at hf
      subst hf
      simp [updatePolicy, find, hx]
    · have hx' : (x.id == id) = false := by simp [hx]
      simp only [find, List.find?_cons, hx'] at hf
      have := ih hf
      simp only [find, updatePolicy] at this
      simp [updatePolicy, find, hx, this]

/-- A legacy CVM (empty `tcb_info`, no override) is open on every port once the fetch lands. -/
theorem legacy_ends_open {st : List Instance} {id : Nat} {i : Instance} (hf : find st id = some i)
    (ha : i.adminPortPolicy = none) {p : Policy} (hp : parseInfoPortPolicy .empty = .ok p)
    (port : Nat) : allowed (updatePolicy st id p) id port = true := by
  simp only [parseInfoPortPolicy, Except.ok.injEq] at hp
  subst hp
  apply open_allows_all (p := Policy.default) _ rfl
  simp [instancePortPolicy, find_update hf, ha]

theorem send_pp_sound {st : List Instance} {id port : Nat} (h : shouldSendPp st id port = true) :
    ∃ p, instancePortPolicy st id = some p ∧ lookup port p.ports = some true := by
  unfold shouldSendPp at h
  cases hp : instancePortPolicy st id with
  | none => simp [hp] at h
  | some p =>
    refine ⟨p, rfl, ?_⟩
    cases hl : lookup port p.ports with
    | none => simp [hp, hl] at h
    | some b => simp [hp, hl] at h; simp [h]

-- legacy_empty_info_uses_bounded_open_compatibility_policy
example : parseInfoPortPolicy .empty = .ok ⟨[], false⟩ := rfl
-- reported_policy_wins_and_preserves_proxy_protocol_flags
example : parseInfoPortPolicy (.appCompose [(443, true), (8080, false)] true) =
    .ok ⟨[(443, true), (8080, false)], true⟩ := rfl
-- malformed_or_missing_compose_is_permanent_failure
example : ∀ t ∈ [TcbInfo.invalidJson, .missingAppCompose, .invalidAppCompose],
    parseInfoPortPolicy t = .error .permanent := by
  intro t ht
  simp only [List.mem_cons, List.not_mem_nil, or_false] at ht
  rcases ht with rfl | rfl | rfl <;> rfl

end DstackFormal.Gateway.PortPolicy
