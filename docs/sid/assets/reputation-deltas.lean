/-
  Reputation by deltas (SID 0033).

  A node holds a state: for each key an entry or nothing. A change carries the whole
  new state of one key. We prove four things.

  1. Replaying a log ends in the state that the last change of each key gave, whatever
     the start held for the keys the log changes.
  2. A full load that reads rows while writers continue, followed by the log after the
     counter read first, ends in the same state as replaying the whole log.
  3. An overlay over a base answers as one set, a change into the overlay is a change of
     that set, and a merge changes no answer.
  4. Stamps taken from a counter that writers hold until they commit are exactly
     1, 2, ..., m in the snapshot of any reader: a reader never meets a gap.

  And the arithmetic of the bound: with K * K >= n, a merge of n + K copies spread over
  K changes costs at most K + 1 copies per change.

  Checked with Lean 4 core, no libraries: `lean reputation-deltas.lean`.
-/

/-- A state: the entry of each key, or nothing. -/
def State (κ v : Type) := κ → Option v

/-- A change: one key and its whole new state. -/
abbrev Change (κ v : Type) := κ × Option v

variable {κ v : Type} [DecidableEq κ]

/-- Applying a change sets one key. -/
def apply (s : State κ v) (c : Change κ v) : State κ v :=
  fun j => if j = c.1 then c.2 else s j

/-- Replaying a log applies its changes in order. -/
def replay (s : State κ v) : List (Change κ v) → State κ v
  | [] => s
  | c :: rest => replay (apply s c) rest

/-- The last change of key `k` in a log, if the log changes `k`. -/
def lastFor (k : κ) : List (Change κ v) → Option (Option v)
  | [] => none
  | c :: rest =>
    match lastFor k rest with
    | some w => some w
    | none => if k = c.1 then some c.2 else none

/-- The step of `lastFor`, as an equation. -/
theorem lastFor_cons (k : κ) (c : Change κ v) (rest : List (Change κ v)) :
    lastFor k (c :: rest) =
      (match lastFor k rest with
       | some w => some w
       | none => if k = c.1 then some c.2 else none) := rfl

/-- 1. After a replay, a key holds its last change, or what it held before. -/
theorem replay_key (log : List (Change κ v)) :
    ∀ (s : State κ v) (k : κ), replay s log k = (lastFor k log).getD (s k) := by
  induction log with
  | nil => intro s k; rfl
  | cons c rest ih =>
    intro s k
    show replay (apply s c) rest k = _
    rw [ih (apply s c) k, lastFor_cons]
    cases h : lastFor k rest with
    | some w => rfl
    | none =>
      show (apply s c) k = _
      unfold apply
      by_cases hk : k = c.1
      · simp [hk]
      · simp [hk]

/-- A key that a log never changes is not changed by any of its prefixes. -/
theorem lastFor_take_none (k : κ) (log : List (Change κ v)) :
    ∀ n, lastFor k log = none → lastFor k (log.take n) = none := by
  induction log with
  | nil => intro n _; cases n <;> rfl
  | cons c rest ih =>
    intro n h
    cases n with
    | zero => rfl
    | succ n =>
      rw [lastFor_cons] at h
      cases hr : lastFor k rest with
      | some w => rw [hr] at h; cases h
      | none =>
        rw [hr] at h
        have hk : ¬ k = c.1 := by
          intro e; simp [e] at h
        show lastFor k (c :: rest.take n) = none
        rw [lastFor_cons, ih n hr]
        simp [hk]

/-- 2. A full load. The rows of key `k` were read after some prefix of the log, of a
    length `pick k` of its own. Replaying the whole log over those rows gives the same
    state as replaying it over the state the counter was read at. -/
theorem load_then_replay (s0 : State κ v) (log : List (Change κ v)) (pick : κ → Nat) :
    replay (fun k => replay s0 (log.take (pick k)) k) log = replay s0 log := by
  funext k
  rw [replay_key log _ k, replay_key log s0 k, replay_key (log.take (pick k)) s0 k]
  cases h : lastFor k log with
  | some w => rfl
  | none =>
    show (lastFor k (log.take (pick k))).getD (s0 k) = s0 k
    rw [lastFor_take_none k log (pick k) h]
    rfl

/-- An overlay: for each key no say, a removal (`some none`) or an entry. -/
def Overlay (κ v : Type) := κ → Option (Option v)

/-- What an overlay over a base answers. -/
def view (base : State κ v) (ov : Overlay κ v) : State κ v :=
  fun k => match ov k with
    | some x => x
    | none => base k

/-- A change written into the overlay. -/
def note (ov : Overlay κ v) (c : Change κ v) : Overlay κ v :=
  fun j => if j = c.1 then some c.2 else ov j

/-- The empty overlay. -/
def empty : Overlay κ v := fun _ => none

/-- A merge: the base that the overlay and base answer as. -/
def merge (base : State κ v) (ov : Overlay κ v) : State κ v := view base ov

/-- 3a. Noting a change in the overlay is applying it to the set. -/
theorem view_note (base : State κ v) (ov : Overlay κ v) (c : Change κ v) :
    view base (note ov c) = apply (view base ov) c := by
  funext k
  unfold view note apply
  by_cases hk : k = c.1
  · simp [hk]
  · simp [hk]

omit [DecidableEq κ] in
/-- 3b. A merge followed by an empty overlay changes no answer. -/
theorem merge_keeps_answers (base : State κ v) (ov : Overlay κ v) :
    view (merge base ov) empty = view base ov := by
  funext k; rfl

/-- Noting a whole log. -/
def noteAll (ov : Overlay κ v) : List (Change κ v) → Overlay κ v
  | [] => ov
  | c :: rest => noteAll (note ov c) rest

/-- 3c. Noting a log in the overlay is replaying it on the set. -/
theorem view_noteAll (base : State κ v) (log : List (Change κ v)) :
    ∀ ov, view base (noteAll ov log) = replay (view base ov) log := by
  induction log with
  | nil => intro ov; rfl
  | cons c rest ih =>
    intro ov
    show view base (noteAll (note ov c) rest) = replay (apply (view base ov) c) rest
    rw [ih (note ov c), view_note]

/-- The stamps of transactions that took the counter in turn, from `start`, where the
    transaction at position i made `ns[i]` changes. -/
def stamps (start : Nat) : List Nat → List Nat
  | [] => []
  | n :: rest => List.range' start n ++ stamps (start + n) rest

/-- `List.range'` splits at any point. -/
theorem range'_split (s m n : Nat) : List.range' s m ++ List.range' (s + m) n = List.range' s (m + n) := by
  induction m generalizing s with
  | zero => simp
  | succ m ih =>
    simp only [List.range'_succ, List.cons_append]
    have h : s + (m + 1) = (s + 1) + m := by omega
    rw [h, ih (s + 1)]
    have h2 : m + 1 + n = (m + n) + 1 := by omega
    rw [h2, List.range'_succ]

/-- 4. The transactions commit in the order they took the counter, so a reader's
    snapshot holds the first `j` of them. Their stamps are exactly the run from `start`
    with no gap, whatever each transaction wrote. -/
theorem stamps_have_no_gap (ns : List Nat) :
    ∀ start, stamps start ns = List.range' start ns.sum := by
  induction ns with
  | nil => intro start; rfl
  | cons n rest ih =>
    intro start
    show List.range' start n ++ stamps (start + n) rest = List.range' start (n :: rest).sum
    rw [ih (start + n), range'_split]
    simp [List.sum_cons]

/-- Any prefix of the commits is a run with no gap too. -/
theorem snapshot_has_no_gap (ns : List Nat) (j : Nat) (start : Nat) :
    stamps start (ns.take j) = List.range' start (ns.take j).sum :=
  stamps_have_no_gap (ns.take j) start

/-- The bound: with K * K >= n, a merge of n + K copies is at most K + 1 copies for
    each of the K changes it follows. -/
theorem merge_cost (n K : Nat) (h : n ≤ K * K) : n + K ≤ K * (K + 1) := by
  rw [Nat.mul_succ]
  exact Nat.add_le_add_right h K
