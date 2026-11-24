/-!
# Formal Models of the Event-Driven HTTP Workers (SID 0016)

Models for the worker design of SID 0016, checked with Lean 4.19.0.

1. Record table: a readiness key names an index and a generation. A key issued for a record never names a later record at the same index.
2. Timer wheel: an entry fires no earlier than its deadline when the deadline lies inside the wheel, and no entry waits longer than one turn of the wheel.
3. Backpressure: a side is read only below the high-water mark, so the bytes held for the other side stay below a fixed bound.
4. Upload relay: a body with a declared length forwards exactly that many bytes, in any pieces.
5. Assignment: giving each new connection to a least loaded worker keeps the workers within one connection of each other while no connection closes.
6. Round budget: one event causes a bounded number of rounds, so a worker returns to its poller.

The kernel, socket readiness, the HTTP grammar, generation wrap-around after `2^30` reuses of one index, and Rust memory safety are outside these models. The HTTP grammar is covered by the differential tests of `sibuna-net`.
-/

namespace SibunaWorkers

/-! ## Part A: Record table with generations -/

section Slab

/-- One slot: its generation and whether it holds a record. -/
structure Slot where
  generation : Nat
  occupied : Bool

/-- Vacating a slot increases its generation. -/
def Slot.vacate (s : Slot) : Slot := { generation := s.generation + 1, occupied := false }

/-- Filling a vacant slot keeps its generation. -/
def Slot.fill (s : Slot) : Slot := { s with occupied := true }

/-- A key matches when the slot is occupied and the generations agree. -/
def Slot.answers (s : Slot) (key : Nat) : Bool := s.occupied && s.generation == key

/-- The operations a worker applies to one slot. -/
inductive Op where
  | vacate
  | fill

def Slot.apply (s : Slot) : Op → Slot
  | .vacate => s.vacate
  | .fill => s.fill

def Slot.run (s : Slot) : List Op → Slot
  | [] => s
  | op :: ops => (s.apply op).run ops

/-- Generations never decrease. -/
theorem generation_monotone (s : Slot) (ops : List Op) :
    s.generation ≤ (s.run ops).generation := by
  induction ops generalizing s with
  | nil => exact Nat.le_refl _
  | cons op ops ih =>
    have step : s.generation ≤ (s.apply op).generation := by
      cases op <;> simp [Slot.apply, Slot.vacate, Slot.fill]
    exact Nat.le_trans step (ih (s.apply op))

/-- A key issued for a record does not answer after that record was removed, whatever
happens to the slot afterwards. This is why a stale readiness event finds no record. -/
theorem stale_key_never_answers (s : Slot) (ops : List Op) :
    ((s.vacate).run ops).answers s.generation = false := by
  have h := generation_monotone s.vacate ops
  simp [Slot.vacate] at h
  unfold Slot.answers
  have : ((s.vacate).run ops).generation ≠ s.generation := by
    simp [Slot.vacate]; omega
  simp [this]

end Slab

/-! ## Part B: Timer wheel -/

section Wheel

/-- The second an entry is filed under: the deadline rounded up to a whole second and
clamped to the next `slots - 1` seconds after the last turned one. -/
def armSecond (turned slots wanted : Nat) : Nat :=
  max (turned + 1) (min wanted (turned + slots - 1))

/-- An entry is never filed under a second that has already turned, so it will fire. -/
theorem arm_after_turned (turned slots wanted : Nat) :
    turned < armSecond turned slots wanted := by
  unfold armSecond; omega

/-- An entry fires within one turn of the wheel, so no slot is passed twice before it. -/
theorem arm_within_one_turn (turned slots wanted : Nat) (h : 2 ≤ slots) :
    armSecond turned slots wanted < turned + slots := by
  unfold armSecond; omega

/-- Two distinct seconds inside one turn fall into distinct slots: an entry filed under
second `s` fires when second `s` turns, not earlier. -/
theorem slot_is_unique_within_a_turn (turned slots a b : Nat)
    (ha : turned < a) (ha' : a < turned + slots)
    (hb : turned < b) (hb' : b < turned + slots)
    (hmod : a % slots = b % slots) : a = b := by
  have ea := Nat.div_add_mod a slots
  have eb := Nat.div_add_mod b slots
  rcases Nat.lt_trichotomy (a / slots) (b / slots) with hlt | heq | hgt
  · -- Equal residues and a smaller quotient put `b` a whole turn after `a`.
    have h := Nat.mul_le_mul_left slots (Nat.succ_le_of_lt hlt)
    rw [Nat.mul_succ] at h
    omega
  · rw [← ea, ← eb, heq, hmod]
  · have h := Nat.mul_le_mul_left slots (Nat.succ_le_of_lt hgt)
    rw [Nat.mul_succ] at h
    omega

/-- A deadline inside the wheel is not fired early: the filed second is at least the
deadline rounded up. -/
theorem arm_not_early (turned slots wanted : Nat) (h : wanted ≤ turned + slots - 1) :
    wanted ≤ armSecond turned slots wanted := by
  unfold armSecond; omega

/-- A deadline beyond the wheel fires early, at the last slot, and the worker arms it
again. Each such round brings the entry `slots - 1` seconds closer. -/
theorem far_deadline_makes_progress (turned slots wanted : Nat) (h : 2 ≤ slots)
    (far : turned + slots - 1 < wanted) :
    armSecond turned slots wanted = turned + slots - 1 := by
  unfold armSecond; omega

end Wheel

/-! ## Part C: Backpressure -/

section Backpressure

/-- One step of a relay direction: read at most `block` bytes when the backlog is below
`high`, or write some of the backlog. `grow` is the framing a read may add. -/
inductive Step where
  | read (bytes : Nat)
  | write (bytes : Nat)

def relayStep (high block grow backlog : Nat) : Step → Nat
  | .read bytes => if backlog < high then backlog + min bytes block + grow else backlog
  | .write bytes => backlog - min bytes backlog

def relayRun (high block grow : Nat) : Nat → List Step → Nat
  | backlog, [] => backlog
  | backlog, s :: ss => relayRun high block grow (relayStep high block grow backlog s) ss

/-- The bytes held for a slow peer never reach `high + block + grow`, whatever the fast
peer sends and however slowly the slow peer reads. -/
theorem backlog_bounded (high block grow : Nat) (steps : List Step) (backlog : Nat)
    (h : backlog < high + block + grow) :
    relayRun high block grow backlog steps < high + block + grow := by
  induction steps generalizing backlog with
  | nil => exact h
  | cons s ss ih =>
    apply ih
    cases s with
    | read bytes =>
      simp only [relayStep]
      split <;> omega
    | write bytes =>
      simp only [relayStep]; omega

end Backpressure

/-! ## Part D: Upload relay with a declared length -/

section Upload

/-- Feeding `offered` bytes to a body with `left` bytes to go: the count forwarded and
the count still to go. -/
def feedLength (left offered : Nat) : Nat × Nat :=
  (min left offered, left - min left offered)

/-- Total bytes forwarded over a sequence of offers. -/
def forwarded : Nat → List Nat → Nat
  | _, [] => 0
  | left, o :: os => (feedLength left o).1 + forwarded (feedLength left o).2 os

def remaining : Nat → List Nat → Nat
  | left, [] => left
  | left, o :: os => remaining (feedLength left o).2 os

/-- Forwarded plus remaining is the declared length: no byte is lost or invented, and
bytes beyond the body are never forwarded as body. -/
theorem upload_conserves (left : Nat) (offers : List Nat) :
    forwarded left offers + remaining left offers = left := by
  induction offers generalizing left with
  | nil => simp [forwarded, remaining]
  | cons o os ih =>
    simp only [forwarded, remaining]
    have := ih (feedLength left o).2
    simp only [feedLength] at *
    omega

/-- The relay never forwards more than the declared length. -/
theorem upload_never_exceeds (left : Nat) (offers : List Nat) :
    forwarded left offers ≤ left := by
  have := upload_conserves left offers; omega

end Upload

/-! ## Part E: Assignment to the least loaded worker -/

section Assignment

/-- Every load lies in `[low, low + 1]`. -/
def Balanced (loads : List Nat) (low : Nat) : Prop :=
  ∀ x ∈ loads, low ≤ x ∧ x ≤ low + 1

/-- Adds one connection to the first worker whose load is `low`. -/
def assign : List Nat → Nat → List Nat
  | [], _ => []
  | x :: xs, low => if x = low then (x + 1) :: xs else x :: assign xs low

/-- Giving a connection to a worker at the minimum keeps every worker within one
connection of the minimum. With per-core workers this spreads accepted connections
evenly over the processors. -/
theorem assign_keeps_balance (loads : List Nat) (low : Nat) (h : Balanced loads low) :
    Balanced (assign loads low) low := by
  induction loads with
  | nil => intro x hx; simp [assign] at hx
  | cons y ys ih =>
    have hy := h y (by simp)
    have hys : Balanced ys low := fun x hx => h x (List.mem_cons_of_mem y hx)
    intro x hx
    simp only [assign] at hx
    split at hx
    · simp at hx
      cases hx with
      | inl e => omega
      | inr m => exact hys x m
    · simp at hx
      cases hx with
      | inl e => omega
      | inr m => exact ih hys x m

end Assignment

/-! ## Part F: Round budget -/

section Rounds

/-- A connection asks for another round or rests. The worker grants at most `budget`. -/
def rounds : Nat → List Bool → Nat
  | 0, _ => 0
  | _, [] => 0
  | budget + 1, again :: rest => 1 + (if again then rounds budget rest else 0)

/-- One event causes at most `budget` rounds, however often the connection asks for
more. A connection with endless work therefore yields to the others. -/
theorem rounds_bounded (budget : Nat) (asks : List Bool) : rounds budget asks ≤ budget := by
  induction budget generalizing asks with
  | zero => simp [rounds]
  | succ n ih =>
    cases asks with
    | nil => simp [rounds]
    | cons a rest =>
      simp only [rounds]
      split
      · have := ih rest; omega
      · omega

end Rounds

end SibunaWorkers
