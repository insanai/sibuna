/-
  Admission under attack (SID 0034).

  We prove five things about the admission of TCP connections and UDP datagrams.

  1. Caps. A permit is taken only when the node, the frontend and the client address
     are each below their cap, and a release gives one permit back. Then in every
     reachable state, whatever the order of takes and releases from any number of
     accept threads, the node, each frontend and each address hold at most their caps.
  2. Pressure has hysteresis. It switches on at a load of at least `on` and off at a
     load of at most `off`, with `off < on`. A constant load switches it at most once,
     and between a switch on and the next switch off the load fell by at least
     `on - off`.
  3. Under pressure a known client is never refused for being new, and the new clients
     admitted over `n` ticks are at most `burst + rate * n`.
  4. The two classes of a UDP frontend. A datagram of a confirmed mapping may take the
     last token; any other datagram only a token above the reserve. A flood of other
     datagrams never takes the tokens below the reserve, so confirmed mappings keep at
     least `min tokens reserve` datagrams in every tick.
  5. Strikes. A client is banned only after more than `strikes` refusals in one window,
     so a client that stays within its limits is never banned automatically.

  Checked with Lean 4 core, no libraries: `lean admission-under-attack.lean`.
-/

/-! ## 1. Caps -/

/-- A live permit: the frontend and the client address that hold it. -/
structure Permit where
  frontend : Nat
  address : Nat
  deriving DecidableEq

/-- The caps: of the node, of each frontend, of each address on a frontend. -/
structure Caps where
  node : Nat
  frontend : Nat
  address : Nat

/-- The permits a frontend holds. -/
def onFrontend (f : Nat) (live : List Permit) : Nat :=
  (live.filter (fun p => p.frontend == f)).length

/-- The permits an address holds on a frontend. -/
def ofAddress (f a : Nat) (live : List Permit) : Nat :=
  (live.filter (fun p => p.frontend == f && p.address == a)).length

/-- Whether a take of `(f, a)` is allowed: every count is below its cap. -/
def allowed (c : Caps) (live : List Permit) (f a : Nat) : Bool :=
  live.length < c.node && onFrontend f live < c.frontend && ofAddress f a live < c.address

/-- One step of any accept thread: a take, which may be refused, or a release. -/
inductive Op where
  | take (f a : Nat)
  | release (p : Permit)

/-- The effect of one step on the live permits. -/
def step (c : Caps) (live : List Permit) : Op → List Permit
  | .take f a => if allowed c live f a then ⟨f, a⟩ :: live else live
  | .release p => live.erase p

/-- Every count is within its cap. -/
def WithinCaps (c : Caps) (live : List Permit) : Prop :=
  live.length ≤ c.node ∧ (∀ f, onFrontend f live ≤ c.frontend) ∧
    (∀ f a, ofAddress f a live ≤ c.address)

theorem filter_erase_le (q : Permit → Bool) (live : List Permit) (p : Permit) :
    ((live.erase p).filter q).length ≤ (live.filter q).length := by
  induction live with
  | nil => simp
  | cons x rest ih =>
    by_cases h : x = p
    · subst h
      simp only [List.erase_cons_head]
      by_cases hq : q x = true
      · simp [List.filter_cons, hq]
      · simp [List.filter_cons, hq]
    · have : (x :: rest).erase p = x :: rest.erase p := by
        simp [List.erase_cons, beq_iff_eq, h]
      rw [this]
      by_cases hq : q x = true
      · simp [List.filter_cons, hq]; omega
      · simp [List.filter_cons, hq]; omega

theorem length_erase_le (live : List Permit) (p : Permit) :
    (live.erase p).length ≤ live.length := by
  induction live with
  | nil => simp
  | cons x rest ih =>
    by_cases h : x = p
    · subst h; simp
    · have : (x :: rest).erase p = x :: rest.erase p := by
        simp [List.erase_cons, beq_iff_eq, h]
      rw [this]; simp; omega

/-- A take keeps every count within its cap. -/
theorem take_within (c : Caps) (live : List Permit) (f a : Nat)
    (h : WithinCaps c live) : WithinCaps c (step c live (.take f a)) := by
  unfold step
  by_cases ha : allowed c live f a = true
  · simp only [ha, if_true]
    simp only [allowed, Bool.and_eq_true, decide_eq_true_eq] at ha
    obtain ⟨⟨hn, hf⟩, hadr⟩ := ha
    obtain ⟨_, hF, hA⟩ := h
    refine ⟨by simp; omega, ?_, ?_⟩
    · intro g
      unfold onFrontend
      by_cases hg : f = g
      · subst hg
        simp [List.filter_cons]
        unfold onFrontend at hf; omega
      · have : ((⟨f, a⟩ : Permit).frontend == g) = false := by simp [hg]
        simp [List.filter_cons, this]
        exact hF g
    · intro g b
      unfold ofAddress
      by_cases hg : f = g ∧ a = b
      · obtain ⟨rfl, rfl⟩ := hg
        simp [List.filter_cons]
        unfold ofAddress at hadr; omega
      · have : (((⟨f, a⟩ : Permit).frontend == g) && ((⟨f, a⟩ : Permit).address == b))
            = false := by
          simp only [Bool.and_eq_false_iff, beq_eq_false_iff_ne, ne_eq]
          by_cases hfg : f = g
          · exact Or.inr (fun hab => hg ⟨hfg, hab⟩)
          · exact Or.inl hfg
        simp [List.filter_cons, this]
        exact hA g b
  · have : allowed c live f a = false := by simpa using ha
    simp only [this]
    exact h

/-- A release keeps every count within its cap. -/
theorem release_within (c : Caps) (live : List Permit) (p : Permit)
    (h : WithinCaps c live) : WithinCaps c (step c live (.release p)) := by
  obtain ⟨hn, hF, hA⟩ := h
  refine ⟨Nat.le_trans (length_erase_le live p) hn, ?_, ?_⟩
  · intro f
    exact Nat.le_trans (filter_erase_le _ live p) (hF f)
  · intro f a
    exact Nat.le_trans (filter_erase_le _ live p) (hA f a)

/-- Running steps in order. -/
def run (c : Caps) (live : List Permit) : List Op → List Permit
  | [] => live
  | op :: rest => run c (step c live op) rest

/-- 1. Every interleaving of takes and releases stays within the caps. The list of
    steps is any order in which the accept threads took the lock. -/
theorem caps_hold (c : Caps) (ops : List Op) :
    ∀ live, WithinCaps c live → WithinCaps c (run c live ops) := by
  induction ops with
  | nil => intro live h; exact h
  | cons op rest ih =>
    intro live h
    apply ih
    cases op with
    | take f a => exact take_within c live f a h
    | release p => exact release_within c live p h

/-- The empty node is within its caps, so every reachable state is. -/
theorem reachable_within (c : Caps) (ops : List Op) : WithinCaps c (run c [] ops) :=
  caps_hold c ops [] ⟨by simp, by intro f; simp [onFrontend], by intro f a; simp [ofAddress]⟩

/-! ## 2. Pressure with hysteresis -/

/-- The next pressure state for a load. -/
def next (on off load : Nat) (pressed : Bool) : Bool :=
  if pressed then !(load ≤ off) else load ≥ on

/-- A constant load reaches a fixed state after one step. -/
theorem constant_load_settles (on off load : Nat) (hgap : off < on) (p : Bool) :
    next on off load (next on off load p) = next on off load p := by
  cases p <;> by_cases h1 : load ≤ off <;> by_cases h2 : load ≥ on <;>
    simp [next, h1, h2] <;> omega

/-- A switch on happens at a load of at least `on`. -/
theorem switch_on_load (on off load : Nat) (h : next on off load false = true) :
    load ≥ on := by
  simpa [next] using h

/-- A switch off happens at a load of at most `off`. -/
theorem switch_off_load (on off load : Nat) (h : next on off load true = false) :
    load ≤ off := by
  simpa [next] using h

/-- 2. Between a switch on at load `l₁` and a switch off at load `l₂`, the load fell by
    at least `on - off`. -/
theorem hysteresis (on off l₁ l₂ : Nat) (hgap : off < on)
    (hon : next on off l₁ false = true) (hoff : next on off l₂ true = false) :
    l₁ - l₂ ≥ on - off := by
  have := switch_on_load on off l₁ hon
  have := switch_off_load on off l₂ hoff
  omega

/-! ## 3. Admission under pressure -/

/-- A token bucket: tokens, and the burst it holds at most. -/
structure Bucket where
  tokens : Nat
  burst : Nat

/-- One arrival under pressure: a known client passes and takes nothing; a new client
    passes only with a token. Returns whether it passed. -/
def arrive (b : Bucket) (known : Bool) : Bool × Bucket :=
  if known then (true, b)
  else if b.tokens > 0 then (true, { b with tokens := b.tokens - 1 }) else (false, b)

/-- 3a. A known client is never refused under pressure. -/
theorem known_pass (b : Bucket) : (arrive b true).1 = true := rfl

/-- The new clients admitted by a run of arrivals. -/
def admitted : Bucket → List Bool → Nat
  | _, [] => 0
  | b, k :: rest =>
    let r := arrive b k
    (if r.1 && !k then 1 else 0) + admitted r.2 rest

/-- Within one tick, the new clients admitted are at most the tokens. -/
theorem admitted_le_tokens (arrivals : List Bool) :
    ∀ b : Bucket, admitted b arrivals ≤ b.tokens := by
  induction arrivals with
  | nil => intro b; simp [admitted]
  | cons k rest ih =>
    intro b
    simp only [admitted, arrive]
    cases k with
    | true => simp; exact ih b
    | false =>
      by_cases ht : b.tokens > 0
      · simp [ht]
        have := ih { b with tokens := b.tokens - 1 }
        simp at this; omega
      · simp [ht]
        exact ih b

/-- A refill at the start of a tick: `rate` tokens, capped at the burst. -/
def refill (rate : Nat) (b : Bucket) : Bucket :=
  { b with tokens := min b.burst (b.tokens + rate) }

/-- What a run of ticks leaves: each tick refills, then takes the admitted. -/
def tickRun (rate : Nat) : Bucket → List (List Bool) → Nat
  | _, [] => 0
  | b, tick :: rest =>
    let b' := refill rate b
    let n := admitted b' tick
    n + tickRun rate { b' with tokens := b'.tokens - n } rest

/-- 3b. Over `n` ticks at most `tokens + rate * n` new clients pass. -/
theorem new_bounded (rate : Nat) (ticks : List (List Bool)) :
    ∀ b : Bucket, tickRun rate b ticks ≤ b.tokens + rate * ticks.length := by
  induction ticks with
  | nil => intro b; simp [tickRun]
  | cons tick rest ih =>
    intro b
    simp only [tickRun, List.length_cons]
    have h1 := admitted_le_tokens tick (refill rate b)
    have h2 := ih { refill rate b with tokens := (refill rate b).tokens - admitted (refill rate b) tick }
    have h3 : (refill rate b).tokens ≤ b.tokens + rate := by
      simp [refill]; omega
    simp at h2
    rw [Nat.mul_succ]
    omega

/-! ## 4. Two classes of datagrams -/

/-- One datagram: of a confirmed mapping or not. Returns whether it passed. -/
def datagram (reserve : Nat) (tokens : Nat) (confirmed : Bool) : Bool × Nat :=
  if confirmed then
    if tokens > 0 then (true, tokens - 1) else (false, tokens)
  else if tokens > reserve then (true, tokens - 1) else (false, tokens)

/-- The tokens left after a run of datagrams. -/
def left (reserve : Nat) : Nat → List Bool → Nat
  | t, [] => t
  | t, d :: rest => left reserve (datagram reserve t d).2 rest

/-- 4a. A flood of datagrams that are not confirmed never takes the tokens below
    `min tokens reserve`. -/
theorem flood_keeps_reserve (reserve : Nat) (flood : List Bool)
    (hflood : ∀ d ∈ flood, d = false) :
    ∀ t, left reserve t flood ≥ min t reserve := by
  induction flood with
  | nil => intro t; simp [left]; omega
  | cons d rest ih =>
    intro t
    have hd : d = false := hflood d (List.mem_cons_self ..)
    have hrest : ∀ d ∈ rest, d = false := fun d h => hflood d (List.mem_cons_of_mem _ h)
    subst hd
    simp only [left, datagram]
    by_cases ht : t > reserve
    · simp [ht]
      have := ih hrest (t - 1)
      omega
    · simp [ht]
      exact ih hrest t

/-- The confirmed datagrams that pass from `t` tokens. -/
def confirmedPass (t : Nat) : Nat → Nat
  | 0 => 0
  | n + 1 => if t > 0 then 1 + confirmedPass (t - 1) n else 0

theorem confirmedPass_eq (t n : Nat) : confirmedPass t n = min t n := by
  induction n generalizing t with
  | zero => simp [confirmedPass]
  | succ n ih =>
    simp only [confirmedPass]
    by_cases ht : t > 0
    · simp [ht, ih]; omega
    · simp [ht]; omega

/-- 4b. After any flood of other datagrams, `n` confirmed datagrams in the same tick
    pass at least `min (min tokens reserve) n` times. -/
theorem confirmed_keep_share (reserve t n : Nat) (flood : List Bool)
    (hflood : ∀ d ∈ flood, d = false) :
    confirmedPass (left reserve t flood) n ≥ min (min t reserve) n := by
  rw [confirmedPass_eq]
  have := flood_keeps_reserve reserve flood hflood t
  omega

/-! ## 5. Strikes -/

/-- A client is banned when its refusals in a window exceed `strikes`. -/
def banned (strikes refusals : Nat) : Bool := refusals > strikes

/-- 5. A client with at most `strikes` refusals in the window is not banned. -/
theorem within_limits_not_banned (strikes refusals : Nat) (h : refusals ≤ strikes) :
    banned strikes refusals = false := by
  simp [banned]; omega
