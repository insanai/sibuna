/-
  Edge observability and client identity (SID 0020): the two algorithms of the record.

  1. The access log queue is bounded. Every offered entry is written, still queued, or
     counted as dropped, and exactly one of the three.
  2. The walk over the forwarded entries finds the client. Entries to the left of the
     client, which the client may have written itself, never change the result.

  Checked with Lean 4 core, no libraries: `lean edge-observability.lean`.
-/

/-- The counts of the access log: lines written, entries queued, entries dropped. -/
structure Log where
  written : Nat
  queued : Nat
  dropped : Nat

/-- A request path offers an entry, or the writer thread takes one and writes it. -/
inductive Step where
  | offer
  | write

/-- One step. An offer to a full queue is dropped: the request path never waits. -/
def step (capacity : Nat) (log : Log) : Step → Log
  | .offer =>
    if log.queued < capacity then { log with queued := log.queued + 1 }
    else { log with dropped := log.dropped + 1 }
  | .write =>
    if 0 < log.queued then { log with queued := log.queued - 1, written := log.written + 1 }
    else log

/-- Every entry the log has ever been offered. -/
def Log.total (log : Log) : Nat := log.written + log.queued + log.dropped

/-- The offers among some steps. -/
def offers : List Step → Nat
  | [] => 0
  | .offer :: rest => offers rest + 1
  | .write :: rest => offers rest

/-- The log after some steps, in order. -/
def run (capacity : Nat) (log : Log) : List Step → Log
  | [] => log
  | s :: rest => run capacity (step capacity log s) rest

theorem step_keeps_the_bound (capacity : Nat) (log : Log) (s : Step)
    (h : log.queued ≤ capacity) : (step capacity log s).queued ≤ capacity := by
  cases s with
  | offer =>
    by_cases hq : log.queued < capacity
    · simp [step, hq] <;> omega
    · simp [step, hq] <;> omega
  | write =>
    by_cases hq : 0 < log.queued
    · simp [step, hq] <;> omega
    · simp [step, hq] <;> omega

theorem offer_adds_one (capacity : Nat) (log : Log) :
    (step capacity log .offer).total = log.total + 1 := by
  by_cases hq : log.queued < capacity
  · simp [step, hq, Log.total] <;> omega
  · simp [step, hq, Log.total] <;> omega

theorem write_adds_none (capacity : Nat) (log : Log) :
    (step capacity log .write).total = log.total := by
  by_cases hq : 0 < log.queued
  · simp [step, hq, Log.total] <;> omega
  · simp [step, hq, Log.total] <;> omega

/-- The queue never holds more than its capacity. -/
theorem run_keeps_the_bound (capacity : Nat) (steps : List Step) :
    ∀ log : Log, log.queued ≤ capacity → (run capacity log steps).queued ≤ capacity := by
  induction steps with
  | nil => intro log h; exact h
  | cons s rest ih =>
    intro log h
    exact ih _ (step_keeps_the_bound capacity log s h)

/-- Written, queued and dropped account for every offer: no entry is lost or doubled. -/
theorem run_accounts_for_every_offer (capacity : Nat) (steps : List Step) :
    ∀ log : Log, (run capacity log steps).total = log.total + offers steps := by
  induction steps with
  | nil => intro log; simp [run, offers]
  | cons s rest ih =>
    intro log
    cases s with
    | offer =>
      simp only [run, offers]
      rw [ih, offer_adds_one]
      omega
    | write =>
      simp only [run, offers]
      rw [ih, write_adds_none]

/-- An offer below the capacity is never dropped. -/
theorem room_means_no_drop (capacity : Nat) (log : Log) (h : log.queued < capacity) :
    (step capacity log .offer).dropped = log.dropped := by
  simp [step, h]

/-- The walk over the forwarded entries, from the right. `last` is the entry seen before.
    The client is the first entry that is not a trusted proxy, or the leftmost entry
    when all are. -/
def walk (trusted : α → Bool) : Option α → List α → Option α
  | last, [] => last
  | _, entry :: rest => if trusted entry then walk trusted (some entry) rest else some entry

/-- The client of a request whose entries, from the right, are `entries`. -/
def client (trusted : α → Bool) (entries : List α) : Option α := walk trusted none entries

/-- Proxies we trust appended `proxies` (seen from the right) after the client `c`.
    Whatever stands to the left of `c` in the field, the walk answers `c`. -/
theorem forged_entries_are_never_read (trusted : α → Bool) (proxies forged : List α)
    (c : α) (hp : ∀ p, p ∈ proxies → trusted p = true) (hc : trusted c = false) :
    ∀ last : Option α, walk trusted last (proxies ++ c :: forged) = some c := by
  induction proxies with
  | nil => intro last; simp [walk, hc]
  | cons p rest ih =>
    intro last
    have hpt : trusted p = true := hp p (by simp)
    have hrest : ∀ q, q ∈ rest → trusted q = true := fun q hq => hp q (by simp [hq])
    simp [walk, hpt, ih hrest]

/-- The same statement for a whole field: two fields that agree from the client to the
    right name the same client. -/
theorem client_ignores_the_left (trusted : α → Bool) (proxies forged forged' : List α)
    (c : α) (hp : ∀ p, p ∈ proxies → trusted p = true) (hc : trusted c = false) :
    client trusted (proxies ++ c :: forged) = client trusted (proxies ++ c :: forged') := by
  unfold client
  rw [forged_entries_are_never_read trusted proxies forged c hp hc,
    forged_entries_are_never_read trusted proxies forged' c hp hc]

/-- With a seen entry the walk always answers: a trusted peer with a field has a client. -/
theorem walk_answers (trusted : α → Bool) (entries : List α) :
    ∀ e : α, (walk trusted (some e) entries).isSome = true := by
  induction entries with
  | nil => intro e; simp [walk]
  | cons x rest ih =>
    intro e
    simp only [walk]
    split
    · exact ih x
    · rfl
