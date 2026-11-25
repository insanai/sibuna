/-
  Plugin tiers (SID 0030).

  Part 1 is the failure rule. An invocation of a hook ends with a verdict or
  with a failure. We define the outcome of one invocation and of a chain of
  hooks, and we prove that a chain with a failing authorization hook never
  admits, that a telemetry hook never changes an outcome, and that fuel bounds
  the steps of an invocation.

  Part 2 is the circuit breaker of the agent tier. We define its state machine
  and prove that an open breaker refuses every call before its time, that it
  opens after exactly `limit` failures in a row, that one success closes it,
  and that at most one probe is out at a time.

  Checked with Lean 4 core, no libraries: `lean plugin-tiers.lean`.
-/

/-! ## Part 1: the failure rule -/

/-- What a hook may answer. -/
inductive Verdict where
  | admit
  | deny
  | challenge
  deriving DecidableEq, Repr

/-- The stage a hook is attached to. -/
inductive Stage where
  | connection
  | request
  | telemetry
  deriving DecidableEq, Repr

/-- The written choice `on_failure`. `deny` is the default. -/
inductive OnFailure where
  | deny
  | admit
  deriving DecidableEq, Repr

/-- How an invocation ended: with a verdict, or with a timeout, an overload,
    a trap or an unreachable agent. The rule treats the four failures alike. -/
inductive Result where
  | verdict (v : Verdict)
  | failed
  deriving DecidableEq, Repr

/-- The outcome of one invocation. -/
def outcome (s : Stage) (f : OnFailure) (r : Result) : Verdict :=
  match s, r, f with
  | Stage.telemetry, _, _ => Verdict.admit
  | _, Result.verdict v, _ => v
  | _, Result.failed, OnFailure.deny => Verdict.deny
  | _, Result.failed, OnFailure.admit => Verdict.admit

/-- A hook is an authorization hook when it decides and fails closed. -/
def authorizes (s : Stage) (f : OnFailure) : Prop :=
  s ≠ Stage.telemetry ∧ f = OnFailure.deny

/-- A failing authorization hook denies. -/
theorem authorization_fails_closed (s : Stage) (f : OnFailure)
    (h : authorizes s f) : outcome s f Result.failed = Verdict.deny := by
  obtain ⟨hs, hf⟩ := h
  subst hf
  cases s <;> simp_all [outcome]

/-- Only the written choice `admit` turns a failure into an admission. -/
theorem failure_admits_only_by_choice (s : Stage) (f : OnFailure)
    (hs : s ≠ Stage.telemetry) (h : outcome s f Result.failed = Verdict.admit) :
    f = OnFailure.admit := by
  cases s <;> cases f <;> simp_all [outcome]

/-- A verdict of a deciding hook is its outcome: the rule never overrides it. -/
theorem verdict_is_kept (s : Stage) (f : OnFailure) (v : Verdict)
    (hs : s ≠ Stage.telemetry) : outcome s f (Result.verdict v) = v := by
  cases s <;> simp_all [outcome]

/-- A telemetry hook admits whatever it does. -/
theorem telemetry_changes_nothing (f : OnFailure) (r : Result) :
    outcome Stage.telemetry f r = Verdict.admit := by
  simp [outcome]

/-- A chain runs its hooks in order. The first outcome that is not an
    admission ends it. Each entry is the outcome of one hook. -/
def chain : List Verdict → Verdict
  | [] => Verdict.admit
  | Verdict.admit :: rest => chain rest
  | v :: _ => v

/-- A chain admits exactly when every hook of it admits. -/
theorem chain_admits_iff (vs : List Verdict) :
    chain vs = Verdict.admit ↔ ∀ v ∈ vs, v = Verdict.admit := by
  induction vs with
  | nil => simp [chain]
  | cons v rest ih =>
    cases v <;> simp [chain, ih]

/-- The theorem of the record: a chain that holds a failing authorization
    hook does not admit, whatever the hooks before and after it answer. -/
theorem failing_authorization_blocks_chain (s : Stage) (f : OnFailure)
    (h : authorizes s f) (before after : List Verdict) :
    chain (before ++ outcome s f Result.failed :: after) ≠ Verdict.admit := by
  intro hc
  have hall := (chain_admits_iff _).mp hc
  have hmem : outcome s f Result.failed ∈ before ++ outcome s f Result.failed :: after := by
    simp
  have := hall _ hmem
  rw [authorization_fails_closed s f h] at this
  cases this

/-- Adding a telemetry hook to a request leaves the verdict of its chain. -/
theorem telemetry_leaves_chain (vs : List Verdict) (f : OnFailure) (r : Result) :
    chain (vs ++ [outcome Stage.telemetry f r]) = chain vs := by
  rw [telemetry_changes_nothing]
  induction vs with
  | nil => simp [chain]
  | cons v rest ih => cases v <;> simp [chain, ih]

/-- Fuel. One step of the interpreter spends at least one unit, and an
    invocation stops when no unit is left. `run fuel costs` is the number of
    steps taken over a program whose steps cost `costs`. -/
def run : Nat → List Nat → Nat
  | _, [] => 0
  | fuel, c :: rest =>
    let cost := c + 1
    if cost ≤ fuel then 1 + run (fuel - cost) rest else 0

/-- An invocation takes at most as many steps as it has fuel. -/
theorem steps_bounded_by_fuel (fuel : Nat) (costs : List Nat) : run fuel costs ≤ fuel := by
  induction costs generalizing fuel with
  | nil => simp [run]
  | cons c rest ih =>
    simp only [run]
    split
    · have := ih (fuel - (c + 1)); omega
    · omega

/-! ## Part 2: the circuit breaker -/

/-- The breaker of one thread for one agent. `failures` counts failures in a
    row while closed. `openUntil` is the time before which calls are refused;
    it is meaningful when `isOpen`. `probing` says that one call is out to
    test the agent. -/
structure Breaker where
  failures : Nat
  isOpen : Bool
  openUntil : Nat
  probing : Bool
  deriving DecidableEq, Repr

/-- The breaker at start: closed, no failure seen. -/
def Breaker.closed : Breaker :=
  { failures := 0, isOpen := false, openUntil := 0, probing := false }

/-- Asks to make a call at time `now`. Returns the new state and whether the
    call may go out. -/
def Breaker.allow (b : Breaker) (now : Nat) : Breaker × Bool :=
  if !b.isOpen then (b, true)
  else if b.probing then (b, false)
  else if now < b.openUntil then (b, false)
  else ({ b with probing := true }, true)

/-- Records the end of a call that went out. `limit` is the number of
    failures in a row that opens the breaker, `hold` how long it stays open. -/
def Breaker.record (b : Breaker) (ok : Bool) (now limit hold : Nat) : Breaker :=
  if ok then Breaker.closed
  else if b.isOpen then { b with openUntil := now + hold, probing := false }
  else if b.failures + 1 ≥ limit then
    { failures := 0, isOpen := true, openUntil := now + hold, probing := false }
  else { b with failures := b.failures + 1 }

/-- An open breaker refuses every call before its time. -/
theorem open_refuses (b : Breaker) (now : Nat) (ho : b.isOpen = true)
    (ht : now < b.openUntil) : (b.allow now).2 = false := by
  unfold Breaker.allow
  simp only [ho, Bool.not_true, Bool.false_eq_true, if_false, ht, if_true]
  split <;> rfl

/-- A refused call leaves the breaker as it was. -/
theorem refusal_keeps_state (b : Breaker) (now : Nat)
    (h : (b.allow now).2 = false) : (b.allow now).1 = b := by
  unfold Breaker.allow at *
  split
  · simp_all
  · split
    · rfl
    · split
      · rfl
      · simp_all

/-- A closed breaker lets every call out. -/
theorem closed_allows (b : Breaker) (now : Nat) (hc : b.isOpen = false) :
    (b.allow now).2 = true := by
  simp [Breaker.allow, hc]

/-- While a probe is out, no second call goes out. -/
theorem one_probe_at_a_time (b : Breaker) (now later : Nat) (ho : b.isOpen = true)
    (hp : b.probing = false) (ht : b.openUntil ≤ now) :
    ((b.allow now).1.allow later).2 = false := by
  have hnot : ¬ now < b.openUntil := Nat.not_lt.mpr ht
  simp [Breaker.allow, ho, hp, hnot]

/-- One success closes the breaker, whatever its state. -/
theorem success_closes (b : Breaker) (now limit hold : Nat) :
    b.record true now limit hold = Breaker.closed := by
  simp [Breaker.record]

/-- A failed probe reopens the breaker for the whole hold time. -/
theorem failed_probe_reopens (b : Breaker) (now limit hold : Nat) (ho : b.isOpen = true) :
    (b.record false now limit hold).isOpen = true ∧
    (b.record false now limit hold).openUntil = now + hold ∧
    (b.record false now limit hold).probing = false := by
  simp [Breaker.record, ho]

/-- Applies `n` failures in a row to a breaker, all at time `now`. -/
def failTimes (b : Breaker) (now limit hold : Nat) : Nat → Breaker
  | 0 => b
  | n + 1 => (failTimes b now limit hold n).record false now limit hold

/-- Fewer than `limit` failures in a row leave a closed breaker closed, and
    it has counted them. -/
theorem stays_closed_below_limit (now limit hold n : Nat) (h : n < limit) :
    failTimes Breaker.closed now limit hold n =
      { failures := n, isOpen := false, openUntil := 0, probing := false } := by
  induction n with
  | zero => rfl
  | succ k ih =>
    have hk : k < limit := by omega
    simp only [failTimes, ih hk, Breaker.record]
    have : ¬ (k + 1 ≥ limit) := by omega
    simp [this]

/-- The breaker opens at exactly `limit` failures in a row. -/
theorem opens_at_limit (now limit hold : Nat) (hl : 0 < limit) :
    (failTimes Breaker.closed now limit hold limit).isOpen = true ∧
    (failTimes Breaker.closed now limit hold limit).openUntil = now + hold := by
  obtain ⟨k, rfl⟩ : ∃ k, limit = k + 1 := ⟨limit - 1, by omega⟩
  have hk : k < k + 1 := by omega
  simp only [failTimes, stays_closed_below_limit now (k + 1) hold k hk, Breaker.record]
  simp

/-- A success between failures restarts the count: the breaker opens only on
    failures in a row. -/
theorem success_resets_count (b : Breaker) (now limit hold : Nat) (h : 1 < limit) :
    ((b.record true now limit hold).record false now limit hold).isOpen = false := by
  have : ¬ (1 ≥ limit) := by omega
  simp [Breaker.record, Breaker.closed, this]

/-- After the hold time an open breaker lets one call out, the probe. -/
theorem probe_after_hold (b : Breaker) (now : Nat) (ho : b.isOpen = true)
    (hp : b.probing = false) (ht : b.openUntil ≤ now) :
    (b.allow now).2 = true ∧ (b.allow now).1.probing = true := by
  have hnot : ¬ now < b.openUntil := Nat.not_lt.mpr ht
  simp [Breaker.allow, ho, hp, hnot]
