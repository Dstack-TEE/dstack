-- SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
--
-- SPDX-License-Identifier: Apache-2.0

/-!
# SNI certificate resolution (`dstack/gateway/src/cert_store.rs`)

Models `CertStore::resolve_cert`, `CertStoreBuilder::add_cert`, and `CertResolver::update_cert`
(clone the installed store, add, swap only on success). Hostnames are `List Char`.

Proven:
* `exact_beats_wildcard`: an exact entry is returned whatever the wildcard table holds.
* `resolve_wildcard_iff`: without an exact entry, an SNI resolves to `c` iff it is
  `label ++ "." ++ parent` with `label` free of dots and the wildcard for `parent` being `c`.
* `nested_subdomain_misses`: `a.b.d` never resolves through the wildcard registered for `d`;
  `base_domain_misses`: neither does `d` itself.
* `built_exact_empty`: every store reachable from `CertStore::new` through `update_cert` has an
  empty `exact_certs`, so the exact branch of `resolve_cert` is dead code in this crate.
* `update_cert_err_keeps_store`, `update_cert_ok_spec`: a failed update leaves the installed
  store unchanged; a successful one replaces only `domain`'s wildcard entry, and only for a
  record whose `not_after` and whose chain's expiry are both in the future.
* `empty_label_resolves`: `resolve_cert` itself accepts an empty first label (`".d"` gets `d`'s
  wildcard); excluding it relies on rustls validating the SNI as a DNS name.

Modeling gap: certificates and keys are opaque values; PEM/X.509 parsing is the input
`certNotAfter : Option Nat` and `parseOk : Bool`; the clock is a parameter; `HashMap` is an
association list (insert replaces); case folding of SNI is not modeled.
-/

namespace DstackFormal.Gateway.CertStore

abbrev Name := List Char

/-- `HashMap::get` on an association list. -/
def get {κ : Type} (k : Name) : List (Name × κ) → Option κ
  | [] => none
  | (n, v) :: rest => if n = k then some v else get k rest

/-- `HashMap::insert`: replace the entry for `k`, or add one. -/
def put {κ : Type} (k : Name) (v : κ) : List (Name × κ) → List (Name × κ)
  | [] => [(k, v)]
  | (n, w) :: rest => if n = k then (k, v) :: rest else (n, w) :: put k v rest

/-- `str::split_once('.')`. -/
def splitOnce : Name → Option (Name × Name)
  | [] => none
  | x :: xs => if x = '.' then some ([], xs) else (splitOnce xs).map fun p => (x :: p.1, p.2)

/-- `CertStore`. `κ` stands for `Arc<CertifiedKey>`, `δ` for `CertData`. -/
structure Store (κ δ : Type) where
  exact : List (Name × κ)
  wildcard : List (Name × κ)
  certData : List (Name × δ)

/-- `CertStore::new`. -/
def Store.new {κ δ : Type} : Store κ δ := ⟨[], [], []⟩

/-- `CertStore::resolve_cert`. -/
def Store.resolve {κ δ : Type} (s : Store κ δ) (sni : Name) : Option κ :=
  match get sni s.exact with
  | some c => some c
  | none =>
    match splitOnce sni with
    | some (_, parent) => get parent s.wildcard
    | none => none

/-- What `add_cert` learns from a `CertData`: its replicated `not_after`, the chain's expiry
(`get_cert_expiry`), and whether `parse_certified_key` succeeds with key `key`. -/
structure Data (κ : Type) where
  notAfter : Nat
  certNotAfter : Option Nat
  parsed : Option κ

inductive AddError where
  | recordExpired
  | noExpiry
  | certExpired
  | parse
deriving DecidableEq, Repr

/-- `CertStoreBuilder::add_cert` at wall-clock `now`. -/
def Store.addCert {κ δ : Type} (s : Store κ δ) (now : Nat) (domain : Name) (d : Data κ)
    (raw : δ) : Except AddError (Store κ δ) :=
  if d.notAfter ≤ now then .error .recordExpired
  else match d.certNotAfter with
    | none => .error .noExpiry
    | some exp =>
      if exp ≤ now then .error .certExpired
      else match d.parsed with
        | none => .error .parse
        | some key =>
          .ok { s with wildcard := put domain key s.wildcard, certData := put domain raw s.certData }

/-- `CertResolver::update_cert`: the installed store after the call. -/
def Store.updateCert {κ δ : Type} (s : Store κ δ) (now : Nat) (domain : Name) (d : Data κ)
    (raw : δ) : Store κ δ :=
  match s.addCert now domain d raw with
  | .ok s' => s'
  | .error _ => s

theorem exact_beats_wildcard {κ δ : Type} {s : Store κ δ} {sni : Name} {c : κ}
    (h : get sni s.exact = some c) : s.resolve sni = some c := by
  simp [Store.resolve, h]

theorem splitOnce_spec : ∀ {sni l p : Name}, splitOnce sni = some (l, p) ↔
    sni = l ++ '.' :: p ∧ '.' ∉ l
  | [], l, p => by simp [splitOnce]
  | x :: xs, l, p => by
    by_cases hx : x = '.'
    · subst hx
      simp only [splitOnce, ↓reduceIte, Option.some.injEq, Prod.mk.injEq]
      constructor
      · rintro ⟨rfl, rfl⟩; simp
      · rintro ⟨he, hl⟩
        cases l with
        | nil => simp at he; exact ⟨rfl, he⟩
        | cons y ys => simp at he hl; exact absurd he.1.symm (fun h => hl.1 h.symm)
    · simp only [splitOnce, hx, ↓reduceIte]
      constructor
      · intro h
        obtain ⟨⟨l', p'⟩, h1, h2⟩ := Option.map_eq_some_iff.mp h
        simp only [Prod.mk.injEq] at h2
        obtain ⟨rfl, rfl⟩ := h2
        have := (splitOnce_spec (sni := xs)).mp h1
        refine ⟨by simp [this.1], ?_⟩
        simp only [List.mem_cons, not_or]
        exact ⟨fun h => hx h.symm, this.2⟩
      · rintro ⟨he, hl⟩
        cases l with
        | nil => simp at he; exact absurd he.1 hx
        | cons y ys =>
          simp only [List.cons_append, List.cons.injEq] at he
          obtain ⟨rfl, rfl⟩ := he
          simp only [List.mem_cons, not_or] at hl
          have := (splitOnce_spec (sni := ys ++ '.' :: p) (l := ys) (p := p)).mpr ⟨rfl, hl.2⟩
          simp [this]

theorem resolve_wildcard_iff {κ δ : Type} {s : Store κ δ} {sni : Name} {c : κ}
    (h : get sni s.exact = none) :
    s.resolve sni = some c ↔
      ∃ label parent, sni = label ++ '.' :: parent ∧ '.' ∉ label ∧ get parent s.wildcard = some c := by
  unfold Store.resolve
  rw [h]
  simp only
  cases hs : splitOnce sni with
  | none =>
    simp only [reduceCtorEq, false_iff]
    rintro ⟨l, p, he, hl, _⟩
    have := (splitOnce_spec (sni := sni) (l := l) (p := p)).mpr ⟨he, hl⟩
    rw [hs] at this; simp at this
  | some lp =>
    obtain ⟨l, p⟩ := lp
    have hlp := splitOnce_spec.mp hs
    simp only
    constructor
    · intro hg; exact ⟨l, p, hlp.1, hlp.2, hg⟩
    · rintro ⟨l', p', he, hl', hg⟩
      have := (splitOnce_spec (sni := sni) (l := l') (p := p')).mpr ⟨he, hl'⟩
      rw [hs] at this
      simp only [Option.some.injEq, Prod.mk.injEq] at this
      rw [this.2]; exact hg

/-- When `d` is the only wildcard registered, `a.b.d` does not resolve. -/
theorem nested_subdomain_misses {κ δ : Type} {s : Store κ δ} {a b d : Name}
    (ha : '.' ∉ a) (hex : get (a ++ '.' :: b ++ '.' :: d) s.exact = none)
    (hw : ∀ n, get n s.wildcard ≠ none → n = d) :
    s.resolve (a ++ '.' :: b ++ '.' :: d) = none := by
  cases hr : s.resolve (a ++ '.' :: b ++ '.' :: d) with
  | none => rfl
  | some c =>
    obtain ⟨l, p, he, hl, hg⟩ := (resolve_wildcard_iff hex).mp hr
    have hsplit₁ := (splitOnce_spec (sni := a ++ '.' :: b ++ '.' :: d) (l := a)
      (p := b ++ '.' :: d)).mpr ⟨by simp, ha⟩
    have hsplit₂ := (splitOnce_spec (sni := a ++ '.' :: b ++ '.' :: d) (l := l) (p := p)).mpr
      ⟨he, hl⟩
    rw [hsplit₁] at hsplit₂
    simp only [Option.some.injEq, Prod.mk.injEq] at hsplit₂
    have hpd := hw p (by rw [hg]; simp)
    rw [← hsplit₂.2] at hpd
    have := congrArg List.length hpd
    simp at this; omega

/-- When `d` is the only wildcard registered, `d` itself does not resolve. -/
theorem base_domain_misses {κ δ : Type} {s : Store κ δ} {d : Name}
    (hex : get d s.exact = none) (hw : ∀ n, get n s.wildcard ≠ none → n = d) :
    s.resolve d = none := by
  cases hr : s.resolve d with
  | none => rfl
  | some c =>
    obtain ⟨l, p, he, _, hg⟩ := (resolve_wildcard_iff hex).mp hr
    have hpd := hw p (by rw [hg]; simp)
    subst hpd
    have := congrArg List.length he
    simp at this; omega

theorem addCert_exact {κ δ : Type} {s s' : Store κ δ} {now : Nat} {domain : Name} {d : Data κ}
    {raw : δ} (h : s.addCert now domain d raw = .ok s') : s'.exact = s.exact := by
  unfold Store.addCert at h
  split at h
  · simp at h
  · split at h
    · simp at h
    · split at h
      · simp at h
      · split at h
        · simp at h
        · simp only [Except.ok.injEq] at h; subst h; rfl

theorem updateCert_exact {κ δ : Type} (s : Store κ δ) (now : Nat) (domain : Name) (d : Data κ)
    (raw : δ) : (s.updateCert now domain d raw).exact = s.exact := by
  unfold Store.updateCert
  split
  · rename_i s' h; exact addCert_exact h
  · rfl

/-- Stores built by `CertResolver` (start empty, change only through `update_cert`). -/
inductive Built {κ δ : Type} : Store κ δ → Prop
  | new : Built Store.new
  | update (s : Store κ δ) (now : Nat) (domain : Name) (d : Data κ) (raw : δ) :
      Built s → Built (s.updateCert now domain d raw)

theorem built_exact_empty {κ δ : Type} {s : Store κ δ} (h : Built s) : s.exact = [] := by
  induction h with
  | new => rfl
  | update s now domain d raw _ ih => rw [updateCert_exact, ih]

theorem update_cert_err_keeps_store {κ δ : Type} {s : Store κ δ} {now : Nat} {domain : Name}
    {d : Data κ} {raw : δ} {e : AddError} (h : s.addCert now domain d raw = .error e) :
    s.updateCert now domain d raw = s := by
  simp [Store.updateCert, h]

theorem get_put {κ : Type} (k q : Name) (v : κ) :
    ∀ m : List (Name × κ), get q (put k v m) = if k = q then some v else get q m
  | [] => by simp [put, get]
  | (n, w) :: rest => by
    by_cases hn : n = k
    · subst hn
      by_cases hq : n = q <;> simp [put, get, hq]
    · have ih := get_put k q v rest
      by_cases hq : n = q
      · subst hq; simp [put, get, hn, Ne.symm hn]
      · simp [put, get, hn, hq, ih]

theorem update_cert_ok_spec {κ δ : Type} {s s' : Store κ δ} {now : Nat} {domain : Name}
    {d : Data κ} {raw : δ} (h : s.addCert now domain d raw = .ok s') :
    now < d.notAfter ∧ (∃ exp, d.certNotAfter = some exp ∧ now < exp) ∧
    (∃ key, d.parsed = some key ∧ get domain s'.wildcard = some key) ∧
    (∀ n, n ≠ domain → get n s'.wildcard = get n s.wildcard) := by
  unfold Store.addCert at h
  by_cases h1 : d.notAfter ≤ now
  · simp [h1] at h
  · simp only [h1, ↓reduceIte] at h
    cases h2 : d.certNotAfter with
    | none => simp [h2] at h
    | some exp =>
      simp only [h2] at h
      by_cases h3 : exp ≤ now
      · simp [h3] at h
      · simp only [h3, ↓reduceIte] at h
        cases h4 : d.parsed with
        | none => simp [h4] at h
        | some key =>
          simp only [h4, Except.ok.injEq] at h
          subst h
          refine ⟨by omega, ⟨exp, rfl, by omega⟩, ⟨key, rfl, by simp [get_put]⟩, ?_⟩
          intro n hn
          simp [get_put, Ne.symm hn]

theorem empty_label_resolves {κ δ : Type} {s : Store κ δ} {d : Name} {c : κ}
    (hex : get ('.' :: d) s.exact = none) (hw : get d s.wildcard = some c) :
    s.resolve ('.' :: d) = some c :=
  (resolve_wildcard_iff hex).mpr ⟨[], d, rfl, by simp, hw⟩

/-! ## Mirrors of Rust unit tests -/

def testStore : Store Nat Unit :=
  Store.new.updateCert 100 "example.com".toList ⟨200, some 300, some 1⟩ ()

-- test_cert_store_builder / test_cert_store_wildcard
#guard testStore.resolve "test.example.com".toList == some 1
#guard testStore.resolve "foo.example.com".toList == some 1
#guard testStore.resolve "example.com".toList == none
#guard testStore.resolve "example.org".toList == none
#guard testStore.resolve "sub.foo.example.com".toList == none
-- an_expired_chain_is_rejected_however_the_record_dates_it
#guard (Store.new.updateCert 100 "example.com".toList ⟨200, some 50, some (1 : Nat)⟩ ()
  : Store Nat Unit).wildcard.isEmpty
-- expired_update_retains_previous_certificate
#guard (testStore.updateCert 100 "example.com".toList ⟨50, some 300, some 2⟩ ()).resolve
  "app.example.com".toList == some 1

end DstackFormal.Gateway.CertStore
