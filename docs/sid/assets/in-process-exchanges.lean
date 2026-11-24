/-
  In-process exchanges (SID 0017): the two bounded structures of the path.

  1. The decision is shown a bounded prefix of the request body, and the server
     receives the whole body in order.
  2. The idle pool of server connections never exceeds its capacity, and a
     connection taken from it is no longer in it.

  Checked with Lean 4 core, no libraries: `lean in-process-exchanges.lean`.
-/

/-- What the decision is shown of a body: at most `budget` bytes from its start. -/
def shown (budget : Nat) (body : List α) : List α := body.take budget

/-- What follows the shown part on the way to the server. -/
def rest (budget : Nat) (body : List α) : List α := body.drop budget

theorem shown_is_bounded (budget : Nat) (body : List α) :
    (shown budget body).length ≤ budget := by
  simp [shown, List.length_take]
  exact Nat.min_le_left _ _

/-- The server receives the shown part and then the rest: the body, unchanged. -/
theorem server_receives_the_body (budget : Nat) (body : List α) :
    shown budget body ++ rest budget body = body := by
  simp [shown, rest]

/-- A body within the budget is shown whole, so the decision is complete. -/
theorem short_body_is_shown_whole (budget : Nat) (body : List α)
    (h : body.length ≤ budget) : shown budget body = body := by
  simp [shown, List.take_of_length_le h]

/-- Returning a connection: it is kept only below the capacity. -/
def give (capacity : Nat) (pool : List α) (c : α) : List α :=
  if pool.length < capacity then c :: pool else pool

/-- Taking a connection: the most recent one, and the pool without it. -/
def take : List α → Option (α × List α)
  | [] => none
  | c :: pool => some (c, pool)

theorem give_keeps_the_bound (capacity : Nat) (pool : List α) (c : α)
    (h : pool.length ≤ capacity) : (give capacity pool c).length ≤ capacity := by
  unfold give
  split
  · simp; omega
  · exact h

theorem take_shrinks (pool pool' : List α) (c : α)
    (h : take pool = some (c, pool')) : pool'.length + 1 = pool.length := by
  cases pool with
  | nil => simp [take] at h
  | cons d tail =>
    simp [take] at h
    simp [← h.2]

/-- Give then take returns the same connection and the same pool: one owner at a time. -/
theorem give_then_take (capacity : Nat) (pool : List α) (c : α)
    (h : pool.length < capacity) : take (give capacity pool c) = some (c, pool) := by
  simp [give, h, take]
