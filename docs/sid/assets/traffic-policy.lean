/-
  Traffic management (SID 0019): the four rules that bound what a pool does.

  1. Failover ends, tries at most `retries` other servers, and never tries a
     server twice.
  2. The weight of a server in its slow start is at least one unit, never above
     its configured weight, and never decreases with time.
  3. A sticky server is chosen only when it is eligible. Otherwise the choice is
     the normal one.
  4. Passive health counts below its limit, and never leaves a pool with
     available servers without a candidate.

  Checked with Lean 4 core, no libraries: `lean traffic-policy.lean`.
-/

/-! ## Failover -/

/-- The servers one request tries. `pick` is the scheduler: it sees the servers
    tried so far and offers another, or none. `retries` is the budget. A server
    that was tried already ends the request, as does no offer. -/
def failover (pick : List Nat → Option Nat) : Nat → List Nat → List Nat
  | 0, tried => tried
  | retries + 1, tried =>
    match pick tried with
    | some server =>
      if server ∈ tried then tried else failover pick retries (server :: tried)
    | none => tried

/-- Failover is a total function of its budget, so it ends. It tries at most
    `retries` servers beyond those it started with. -/
theorem failover_is_bounded (pick : List Nat → Option Nat) (retries : Nat)
    (tried : List Nat) :
    (failover pick retries tried).length ≤ tried.length + retries := by
  induction retries generalizing tried with
  | zero => simp [failover]
  | succ n ih =>
    unfold failover
    split
    next server _ =>
      split
      · omega
      · have h := ih (server :: tried)
        simp [List.length_cons] at h
        omega
    next => omega

/-- No server is tried twice, whatever the scheduler offers. -/
theorem failover_tries_no_server_twice (pick : List Nat → Option Nat)
    (retries : Nat) (tried : List Nat) (h : tried.Nodup) :
    (failover pick retries tried).Nodup := by
  induction retries generalizing tried with
  | zero => simpa [failover] using h
  | succ n ih =>
    unfold failover
    split
    next server _ =>
      split
      · exact h
      next fresh => exact ih (server :: tried) (List.nodup_cons.mpr ⟨fresh, h⟩)
    next => exact h

/-- Without a budget the request stays on its first server. -/
theorem no_retries_no_failover (pick : List Nat → Option Nat) (tried : List Nat) :
    failover pick 0 tried = tried := by
  simp [failover]

/-! ## Slow start -/

/-- The weight of a server of configured weight `weight`, `elapsed` after it
    entered service, with a ramp of `ramp`, in units of 1/256. -/
def rampWeight (weight elapsed ramp : Nat) : Nat :=
  if ramp ≤ elapsed then 256 * weight else max 1 (256 * weight * elapsed / ramp)

theorem ramp_weight_is_full_after_the_ramp (weight elapsed ramp : Nat)
    (h : ramp ≤ elapsed) : rampWeight weight elapsed ramp = 256 * weight := by
  simp [rampWeight, h]

/-- A ramping server always has some weight, so it is never starved. -/
theorem ramp_weight_is_positive (weight elapsed ramp : Nat) (h : 1 ≤ weight) :
    1 ≤ rampWeight weight elapsed ramp := by
  unfold rampWeight
  split
  · omega
  · exact Nat.le_max_left _ _

/-- A ramping server never has more than its configured weight. -/
theorem ramp_weight_is_bounded (weight elapsed ramp : Nat) (h : 1 ≤ weight) :
    rampWeight weight elapsed ramp ≤ 256 * weight := by
  unfold rampWeight
  split
  · exact Nat.le_refl _
  next early =>
    have part : 256 * weight * elapsed / ramp ≤ 256 * weight := by
      apply Nat.div_le_of_le_mul
      rw [Nat.mul_comm ramp]
      exact Nat.mul_le_mul_left _ (by omega)
    exact Nat.max_le.mpr ⟨by omega, part⟩

/-- The weight never decreases as time passes. -/
theorem ramp_weight_is_monotone (weight earlier later ramp : Nat) (h : 1 ≤ weight)
    (order : earlier ≤ later) :
    rampWeight weight earlier ramp ≤ rampWeight weight later ramp := by
  by_cases done : ramp ≤ later
  · rw [ramp_weight_is_full_after_the_ramp weight later ramp done]
    exact ramp_weight_is_bounded weight earlier ramp h
  · have early : ¬ ramp ≤ earlier := by omega
    simp only [rampWeight, done, early, if_false]
    have part : 256 * weight * earlier / ramp ≤ 256 * weight * later / ramp :=
      (Nat.le_div_iff_mul_le (by omega)).mpr
        (Nat.le_trans (Nat.div_mul_le_self _ _) (Nat.mul_le_mul_left _ order))
    exact Nat.max_le.mpr
      ⟨Nat.le_max_left _ _, Nat.le_trans part (Nat.le_max_right _ _)⟩

/-! ## Sticky sessions -/

/-- The server of a request: its sticky server when that is eligible, else the
    choice of the scheduler. -/
def choose (eligible : Nat → Bool) (sticky normal : Option Nat) : Option Nat :=
  match sticky with
  | some server => if eligible server then some server else normal
  | none => normal

/-- Whatever is chosen is eligible, given that the scheduler chooses so. A
    cookie or an address therefore never sends a request to a server that is
    down, full, ejected or already tried. -/
theorem chosen_is_eligible (eligible : Nat → Bool) (sticky normal : Option Nat)
    (sound : ∀ server, normal = some server → eligible server = true)
    (server : Nat) (h : choose eligible sticky normal = some server) :
    eligible server = true := by
  unfold choose at h
  split at h
  next held =>
    split at h
    next up => cases h; exact up
    next => exact sound server h
  next => exact sound server h

theorem eligible_sticky_server_is_chosen (eligible : Nat → Bool) (server : Nat)
    (normal : Option Nat) (up : eligible server = true) :
    choose eligible (some server) normal = some server := by
  simp [choose, up]

/-- A sticky server that is not eligible gives way to normal selection. -/
theorem ineligible_sticky_server_gives_way (eligible : Nat → Bool) (server : Nat)
    (normal : Option Nat) (down : eligible server = false) :
    choose eligible (some server) normal = normal := by
  simp [choose, down]

/-! ## Passive health -/

/-- One step of the failure count of a server: the count after an outcome, and
    whether the server is ejected now. -/
def step (limit count : Nat) (failed : Bool) : Nat × Bool :=
  if failed then
    if limit ≤ count + 1 then (0, true) else (count + 1, false)
  else (0, false)

/-- The count stays below the limit, so one more failure is always decisive at
    `limit - 1`. -/
theorem count_stays_below_the_limit (limit count : Nat) (failed : Bool)
    (h : 1 ≤ limit) : (step limit count failed).1 < limit := by
  unfold step
  split
  · split
    · exact h
    · simp; omega
  · exact h

/-- A success forgets every earlier failure: only consecutive failures eject. -/
theorem success_clears_the_count (limit count : Nat) :
    step limit count false = (0, false) := by
  simp [step]

/-- The failure that reaches the limit ejects, and no earlier one does. -/
theorem ejects_exactly_at_the_limit (limit count : Nat) :
    (step limit count true).2 = true ↔ limit ≤ count + 1 := by
  unfold step
  by_cases h : limit ≤ count + 1 <;> simp [h]

/-- The servers a request may use: `(server, ejected)` pairs of the available
    servers. Ejected servers are left out only while another remains. -/
def candidates (available : List (Nat × Bool)) : List (Nat × Bool) :=
  if available.any (fun s => !s.2) then available.filter (fun s => !s.2)
  else available

/-- Passive health alone never empties a pool: a pool whose servers are all
    ejected still serves. -/
theorem ejection_never_empties_a_pool (available : List (Nat × Bool))
    (h : available ≠ []) : candidates available ≠ [] := by
  unfold candidates
  split
  next some =>
    intro empty
    rw [List.any_eq_true] at some
    obtain ⟨s, here, fit⟩ := some
    have : s ∈ available.filter (fun s => !s.2) := List.mem_filter.mpr ⟨here, fit⟩
    rw [empty] at this
    exact absurd this (List.not_mem_nil)
  next => exact h

/-- No ejected server is a candidate while a server that is not ejected is
    available. -/
theorem ejected_servers_wait (available : List (Nat × Bool))
    (spare : available.any (fun s => !s.2) = true) (s : Nat × Bool)
    (h : s ∈ candidates available) : s.2 = false := by
  simp only [candidates, spare, if_true] at h
  have := (List.mem_filter.mp h).2
  simpa using this
