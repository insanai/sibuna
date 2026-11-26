/-
  SID 0036, host wildcards and the PROXY address families. Core Lean 4, no libraries.

  Three parts carry the design.

  1. A host pattern is an exact name or a wildcard `*.SUFFIX`. A wildcard matches a host
     that ends in `.SUFFIX` after at least one more character, so it never matches the
     suffix itself, and the match always begins at a label boundary (invariants 1 and 2).

  2. One pattern covers another when it matches every host the other matches. A route
     covers another when its hosts cover every host of the other and its path prefix
     covers the other's prefix. Under the first-match rule a covered route is never
     chosen, and neither is a request that only a covered pattern of a route would
     bring to it. This is why the configuration refuses both (invariant 4).

  3. A PROXY version 2 header names both addresses in one family. Addresses are first
     made canonical (an IPv4-mapped IPv6 address becomes IPv4). Two IPv4 addresses are
     written as IPv4, any other pair as IPv6 with IPv4 mapped. The encoding is total and
     keeps the address (invariants 6 and 7).

  Hosts are lower-case lists of characters; the implementation folds ASCII case before it
  compares, and strips a port and a trailing dot from the request host.
-/

/-! ## Host patterns -/

abbrev Host := List Char

/-- A host pattern of a route or of an SNI rule. `wild s` is written `*.s`. -/
inductive Pat where
  | exact (name : Host)
  | wild (suffix : Host)

/-- `h` lies under the domain `s`: one or more characters, a dot, then `s`. -/
def Under (s h : Host) : Prop := ∃ p : Host, p ≠ [] ∧ h = p ++ '.' :: s

/-- Whether pattern `a` matches host `h`. -/
def Pat.Matches : Pat → Host → Prop
  | .exact e, h => h = e
  | .wild s, h => Under s h

/-- A wildcard never matches its own suffix: `*.example.org` leaves `example.org` out. -/
theorem wild_not_apex (s : Host) : ¬ (Pat.wild s).Matches s := by
  intro ⟨p, hp, h⟩
  have hl := congrArg List.length h
  simp at hl
  cases p with
  | nil => exact hp rfl
  | cons _ _ => simp at hl; omega

/-- The match begins at a label boundary: a host that is `x` followed by the suffix,
    where `x` does not end in a dot, is not under the suffix. So `*.example.org` does not
    match `badexample.org`. -/
theorem wild_label_boundary (x s : Host) (hx : x.getLast? ≠ some '.') :
    ¬ (Pat.wild s).Matches (x ++ s) := by
  intro ⟨p, _, h⟩
  have h' : x ++ s = (p ++ ['.']) ++ s := by simp [h]
  have hx' : x = p ++ ['.'] := List.append_cancel_right h'
  apply hx
  simp [hx']

/-- What the implementation computes: the host is longer than `.s` and ends with it. -/
def matchesWild (s h : Host) : Bool :=
  decide (s.length + 1 < h.length) && ('.' :: s).isSuffixOf h

/-- The computation decides `Under`. -/
theorem matchesWild_iff (s h : Host) : matchesWild s h = true ↔ Under s h := by
  simp only [matchesWild, Bool.and_eq_true, decide_eq_true_eq, List.isSuffixOf_iff_suffix]
  constructor
  · intro ⟨hlen, ⟨p, hp⟩⟩
    refine ⟨p, ?_, hp.symm⟩
    intro hnil
    subst hnil
    have := congrArg List.length hp
    simp at this
    omega
  · intro ⟨p, hp, h⟩
    refine ⟨?_, ⟨p, h.symm⟩⟩
    subst h
    cases p with
    | nil => exact absurd rfl hp
    | cons _ _ => simp; omega

/-! ## Coverage -/

/-- Whether pattern `a` covers pattern `b`, as the configuration check computes it. -/
def Pat.Covers : Pat → Pat → Prop
  | .exact e, .exact f => e = f
  | .exact _, .wild _ => False
  | .wild s, .exact f => Under s f
  | .wild s, .wild t => t = s ∨ Under s t

theorem under_trans {s t h : Host} : Under s t → Under t h → Under s h := by
  intro ⟨p, hp, ht⟩ ⟨q, hq, hh⟩
  refine ⟨q ++ '.' :: p, by simp, ?_⟩
  subst ht
  subst hh
  simp

/-- Coverage is sound: a covering pattern matches every host the covered one matches. -/
theorem covers_sound (a b : Pat) (h : Host) : a.Covers b → b.Matches h → a.Matches h := by
  cases a with
  | exact e =>
    cases b with
    | exact f => intro hc hm; simp [Pat.Covers] at hc; simp [Pat.Matches] at *; rw [hm, hc]
    | wild t => intro hc; exact absurd hc (by simp [Pat.Covers])
  | wild s =>
    cases b with
    | exact f => intro hc hm; simp [Pat.Matches] at hm; subst hm; exact hc
    | wild t =>
      intro hc hm
      rcases hc with ht | ht
      · subst ht; exact hm
      · exact under_trans ht hm

/-! ## Paths -/

/-- A path lies under a prefix: it starts with the prefix, and the prefix ends in `/`
    or the rest is empty or begins with `/` or `?`. So `/public` covers `/public/x` and
    not `/public-admin`. -/
def UnderPath (pre path : List Char) : Prop :=
  ∃ rest, path = pre ++ rest ∧
    (pre.getLast? = some '/' ∨ rest = [] ∨ ∃ c r, rest = c :: r ∧ (c = '/' ∨ c = '?'))

/-- A prefix covers every path under a prefix that is itself under it. -/
theorem underPath_trans (p q x : List Char) :
    UnderPath p q → UnderPath q x → UnderPath p x := by
  intro ⟨r, hq, hr⟩ ⟨r', hx, hr'⟩
  refine ⟨r ++ r', by simp [hx, hq], ?_⟩
  rcases hr with hp | hnil | ⟨c, t, hct, hc⟩
  · exact Or.inl hp
  · subst hnil
    simp at hq
    subst hq
    rcases hr' with hp | hnil' | ⟨c, t, hct, hc⟩
    · exact Or.inl hp
    · exact Or.inr (Or.inl (by simp [hnil']))
    · exact Or.inr (Or.inr ⟨c, t, by simp [hct], hc⟩)
  · exact Or.inr (Or.inr ⟨c, t ++ r', by simp [hct], hc⟩)

/-! ## Routes and the first match -/

/-- A route: a list of host patterns or none (any host), and a path prefix or none. -/
structure Route where
  hosts : Option (List Pat)
  path : Option (List Char)

def HostOk : Option (List Pat) → Host → Prop
  | none, _ => True
  | some ps, h => ∃ p ∈ ps, p.Matches h

def PathOk : Option (List Char) → List Char → Prop
  | none, _ => True
  | some p, x => UnderPath p x

def Route.Matches (r : Route) (h : Host) (x : List Char) : Prop :=
  HostOk r.hosts h ∧ PathOk r.path x

def HostsCover : Option (List Pat) → Option (List Pat) → Prop
  | none, _ => True
  | some _, none => False
  | some as, some bs => ∀ b ∈ bs, ∃ a ∈ as, a.Covers b

def PathCover : Option (List Char) → Option (List Char) → Prop
  | none, _ => True
  | some _, none => False
  | some p, some q => UnderPath p q

def Route.Covers (a b : Route) : Prop := HostsCover a.hosts b.hosts ∧ PathCover a.path b.path

theorem hostsCover_sound (a b : Option (List Pat)) (h : Host) :
    HostsCover a b → HostOk b h → HostOk a h := by
  cases a with
  | none => intro _ _; trivial
  | some as =>
    cases b with
    | none => intro hc; exact absurd hc (by simp [HostsCover])
    | some bs =>
      intro hc ⟨pb, hb, hm⟩
      obtain ⟨pa, ha, hcov⟩ := hc pb hb
      exact ⟨pa, ha, covers_sound pa pb h hcov hm⟩

theorem pathCover_sound (a b : Option (List Char)) (x : List Char) :
    PathCover a b → PathOk b x → PathOk a x := by
  cases a with
  | none => intro _ _; trivial
  | some p =>
    cases b with
    | none => intro hc; exact absurd hc (by simp [PathCover])
    | some q => intro hc hm; exact underPath_trans p q x hc hm

/-- Route coverage is sound. -/
theorem route_covers_sound (a b : Route) (h : Host) (x : List Char) :
    a.Covers b → b.Matches h x → a.Matches h x := by
  intro ⟨hh, hp⟩ ⟨mh, mp⟩
  exact ⟨hostsCover_sound _ _ h hh mh, pathCover_sound _ _ x hp mp⟩

/-- The first-match rule: route `j` serves the request when it matches and no earlier
    route does. -/
def Chosen (rs : List Route) (h : Host) (x : List Char) (j : Nat) : Prop :=
  ∃ b, rs[j]? = some b ∧ b.Matches h x ∧ ∀ k a, k < j → rs[k]? = some a → ¬ a.Matches h x

/-- A route that an earlier route covers is never chosen, whatever the request. -/
theorem covered_never_chosen (rs : List Route) (i j : Nat) (a b : Route)
    (hij : i < j) (ha : rs[i]? = some a) (hb : rs[j]? = some b) (hc : a.Covers b)
    (h : Host) (x : List Char) : ¬ Chosen rs h x j := by
  intro ⟨b', hb', hm, hfirst⟩
  rw [hb] at hb'
  cases hb'
  exact hfirst i a hij ha (route_covers_sound a b h x hc hm)

/-! ## PROXY address families -/

/-- An address: IPv4 as a 32-bit number, IPv6 as a 128-bit number. -/
inductive Addr where
  | v4 (n : Nat)
  | v6 (n : Nat)

/-- The base of the IPv4-mapped block `::ffff:0:0/96`. -/
def mappedBase : Nat := 0xffff * 4294967296

/-- An IPv4-mapped IPv6 address becomes IPv4; every other address stays. -/
def canonical : Addr → Addr
  | .v4 n => .v4 n
  | .v6 n => if n / 4294967296 = 0xffff then .v4 (n % 4294967296) else .v6 n

/-- The IPv6 form of an address. -/
def asV6 : Addr → Nat
  | .v4 n => mappedBase + n
  | .v6 n => n

/-- The address block of a version 2 header: one family for both addresses. -/
inductive Block where
  | inet (src dst : Nat)
  | inet6 (src dst : Nat)

/-- The encoding: canonical addresses, IPv4 when both are IPv4, else IPv6 for both.
    It is a total function, so a header can always be written. -/
def encode (src dst : Addr) : Block :=
  match canonical src, canonical dst with
  | .v4 s, .v4 d => .inet s d
  | s, d => .inet6 (asV6 s) (asV6 d)

/-- Reading an address back from a block, as a receiver that maps IPv4 does. -/
def decodeSrc : Block → Addr
  | .inet s _ => .v4 s
  | .inet6 s _ => canonical (.v6 s)

def decodeDst : Block → Addr
  | .inet _ d => .v4 d
  | .inet6 _ d => canonical (.v6 d)

def Valid : Addr → Prop
  | .v4 n => n < 4294967296
  | .v6 _ => True

theorem canonical_idem (a : Addr) (hv : Valid a) : canonical (canonical a) = canonical a := by
  cases a with
  | v4 n => rfl
  | v6 n =>
    by_cases h : n / 4294967296 = 0xffff
    · simp only [canonical, h, if_true]
    · simp only [canonical, h, if_false]

theorem canonical_v6_of_v4 (n : Nat) (hn : n < 4294967296) :
    canonical (.v6 (mappedBase + n)) = .v4 n := by
  simp only [canonical, mappedBase]
  have h1 : (0xffff * 4294967296 + n) / 4294967296 = 0xffff := by omega
  have h2 : (0xffff * 4294967296 + n) % 4294967296 = n := by omega
  simp [h1, h2]

theorem canonical_valid (a : Addr) (hv : Valid a) : Valid (canonical a) := by
  cases a with
  | v4 n => exact hv
  | v6 n =>
    simp only [canonical]
    split
    · simp [Valid]; omega
    · trivial

theorem decode_asV6 (a : Addr) (hv : Valid a) (hc : canonical a = a) :
    canonical (.v6 (asV6 a)) = a := by
  cases a with
  | v4 n => exact canonical_v6_of_v4 n hv
  | v6 n => simp only [asV6]; exact hc

/-- The header keeps both addresses up to the IPv4 mapping: a receiver reads back the
    canonical source and destination. -/
theorem encode_keeps (src dst : Addr) (hs : Valid src) (hd : Valid dst) :
    decodeSrc (encode src dst) = canonical src ∧ decodeDst (encode src dst) = canonical dst := by
  have vs := canonical_valid src hs
  have vd := canonical_valid dst hd
  have is := canonical_idem src hs
  have id := canonical_idem dst hd
  unfold encode
  generalize canonical src = s at vs is
  generalize canonical dst = d at vd id
  cases s <;> cases d <;>
    simp [decodeSrc, decodeDst, decode_asV6, *]

/-- Every IPv4 pair gives an IPv4 block, whichever form each address arrives in: the
    client of a PROXY header as IPv4 and the listener of a dual-stack socket as
    IPv4-mapped IPv6, both mapped, or both plain. -/
theorem ipv4_pairs_stay_ipv4 (src dst : Addr) (s d : Nat)
    (hs : canonical src = .v4 s) (hd : canonical dst = .v4 d) :
    encode src dst = .inet s d := by
  unfold encode
  rw [hs, hd]

/-! ## A hidden pattern -/

/-- The hosts of a route cover one pattern: a route without hosts covers every pattern. -/
def HostsCoverPat : Option (List Pat) → Pat → Prop
  | none, _ => True
  | some as, b => ∃ a ∈ as, a.Covers b

/-- A pattern of route `j` that an earlier route covers, with a prefix that covers the
    prefix of `j`, never brings a request to `j`: every request whose host it matches
    is taken by the earlier route or one before it. -/
theorem hidden_pattern_never_chosen (rs : List Route) (i j : Nat) (a b : Route) (pb : Pat)
    (hij : i < j) (ha : rs[i]? = some a) (hb : rs[j]? = some b)
    (hcov : HostsCoverPat a.hosts pb) (hpath : PathCover a.path b.path)
    (h : Host) (x : List Char) (hm : pb.Matches h) (hx : PathOk b.path x) :
    ¬ Chosen rs h x j := by
  intro ⟨b', hb', _, hfirst⟩
  rw [hb] at hb'
  cases hb'
  apply hfirst i a hij ha
  refine ⟨?_, pathCover_sound _ _ x hpath hx⟩
  cases hh : a.hosts with
  | none => simp [HostOk]
  | some as =>
    rw [hh] at hcov
    obtain ⟨pa, hpa, hc⟩ := hcov
    exact ⟨pa, hpa, covers_sound pa pb h hc hm⟩
