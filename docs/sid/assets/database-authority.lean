/-
  A database as the authority for the topology (SID 0028).

  The store is the list of committed documents. Revision `n` is the `n`th
  document, counted from one, and the head is the length of the list. A commit
  names the head that it expects. A node holds the number and the document of
  the revision that it serves, and takes a new one only when its check passes.

  We prove that a commit on a stale head changes nothing, that a commit adds one
  revision and keeps all earlier ones, that of two commits on one head the second
  fails, that a rollback restores a document as a new revision, and that a node
  keeps its snapshot through an unavailable database and a refused revision,
  serves only checked documents, and reaches the head after one successful look.

  Checked with Lean 4 core, no libraries: `lean database-authority.lean`.
-/

namespace Authority

/-- The committed documents, oldest first. -/
structure Store (α : Type) where
  history : List α

/-- The number of the newest revision, 0 when nothing is committed. -/
def Store.head (s : Store α) : Nat := s.history.length

/-- The document of revision `n`. Revisions are numbered from one. -/
def Store.read (s : Store α) (n : Nat) : Option α :=
  match n with
  | 0 => none
  | k + 1 => s.history[k]?

/-- A commit conditioned on the head that the writer expects. -/
def commit (s : Store α) (expected : Nat) (doc : α) : Option (Store α) :=
  if expected = s.head then some ⟨s.history ++ [doc]⟩ else none

/-- A stale expected head commits nothing. -/
theorem commit_conflict (s : Store α) (expected : Nat) (doc : α)
    (stale : expected ≠ s.head) : commit s expected doc = none := by
  simp [commit, stale]

/-- A commit that succeeds expected the head. -/
theorem commit_expected {s s' : Store α} {expected : Nat} {doc : α}
    (done : commit s expected doc = some s') : expected = s.head := by
  unfold commit at done
  by_cases same : expected = s.head
  · exact same
  · simp [same] at done

/-- The store after a commit that succeeds. -/
theorem commit_result {s s' : Store α} {expected : Nat} {doc : α}
    (done : commit s expected doc = some s') : s' = ⟨s.history ++ [doc]⟩ := by
  unfold commit at done
  by_cases same : expected = s.head
  · simp [same] at done; exact done.symm
  · simp [same] at done

/-- A commit adds exactly one revision. -/
theorem commit_head {s s' : Store α} {expected : Nat} {doc : α}
    (done : commit s expected doc = some s') : s'.head = s.head + 1 := by
  rw [commit_result done]; simp [Store.head]

/-- A commit keeps every earlier revision as it was. -/
theorem commit_keeps {s s' : Store α} {expected : Nat} {doc : α}
    (done : commit s expected doc = some s') (n : Nat) (old : n ≤ s.head) :
    s'.read n = s.read n := by
  rw [commit_result done]
  cases n with
  | zero => rfl
  | succ k =>
    have inside : k < s.history.length := by
      simp [Store.head] at old; omega
    simp [Store.read, List.getElem?_append_left inside]

/-- The new head holds the committed document. -/
theorem commit_reads_new {s s' : Store α} {expected : Nat} {doc : α}
    (done : commit s expected doc = some s') : s'.read s'.head = some doc := by
  rw [commit_result done]
  simp [Store.read, Store.head]

/-- Two writers expect the same head. After the first commits, the second fails. -/
theorem second_commit_conflicts {s s' : Store α} {expected : Nat} {first second : α}
    (done : commit s expected first = some s') : commit s' expected second = none := by
  have at_head := commit_expected done
  have grew := commit_head done
  apply commit_conflict
  omega

/-- Every number from one to the head has a document: there is no gap. -/
theorem read_complete (s : Store α) (n : Nat) (positive : 0 < n) (within : n ≤ s.head) :
    (s.read n).isSome = true := by
  cases n with
  | zero => omega
  | succ k =>
    have inside : k < s.history.length := by
      simp [Store.head] at within; omega
    simp [Store.read, List.getElem?_eq_getElem inside]

/-- No number above the head has a document. -/
theorem read_beyond (s : Store α) (n : Nat) (beyond : s.head < n) : s.read n = none := by
  cases n with
  | zero => rfl
  | succ k =>
    have outside : s.history.length ≤ k := by
      simp [Store.head] at beyond; omega
    simp [Store.read, List.getElem?_eq_none outside]

/-- A rollback commits the document of an earlier revision as a new revision. -/
def rollback (s : Store α) (expected target : Nat) : Option (Store α) :=
  match s.read target with
  | none => none
  | some doc => commit s expected doc

/-- After a rollback the head holds the document of the restored revision. -/
theorem rollback_restores {s s' : Store α} {expected target : Nat}
    (done : rollback s expected target = some s') : s'.read s'.head = s.read target := by
  unfold rollback at done
  cases found : s.read target with
  | none => simp [found] at done
  | some doc =>
    simp [found] at done
    exact commit_reads_new done

/-- A rollback keeps the history: the revisions that it leaves behind still read. -/
theorem rollback_keeps {s s' : Store α} {expected target : Nat}
    (done : rollback s expected target = some s') (n : Nat) (old : n ≤ s.head) :
    s'.read n = s.read n := by
  unfold rollback at done
  cases found : s.read target with
  | none => simp [found] at done
  | some doc =>
    simp [found] at done
    exact commit_keeps done n old

/-- What a node serves: the number of a revision and its document. -/
structure Node (α : Type) where
  applied : Nat
  snapshot : Option α

/-- What a look at the database gives. -/
inductive Answer (α : Type) where
  | unavailable : Answer α
  | revision : Nat → α → Answer α

/-- One look. The node takes the revision only when its own check passes. -/
def step (valid : α → Bool) (node : Node α) : Answer α → Node α
  | .unavailable => node
  | .revision n doc => if valid doc then ⟨n, some doc⟩ else node

/-- What a reachable database answers: the head, whole. -/
def poll (s : Store α) : Answer α :=
  match s.read s.head with
  | none => .unavailable
  | some doc => .revision s.head doc

/-- An unavailable database changes nothing on the node. -/
theorem step_unavailable (valid : α → Bool) (node : Node α) :
    step valid node .unavailable = node := rfl

/-- A revision that fails the check changes nothing on the node. -/
theorem step_invalid (valid : α → Bool) (node : Node α) (n : Nat) (doc : α)
    (bad : valid doc = false) : step valid node (.revision n doc) = node := by
  simp [step, bad]

/-- The node serves nothing, or a document that passed its check. -/
def Checked (valid : α → Bool) (node : Node α) : Prop :=
  ∀ doc, node.snapshot = some doc → valid doc = true

/-- Whatever the database answers, the node serves only checked documents. -/
theorem step_serves_valid (valid : α → Bool) (node : Node α) (answer : Answer α)
    (before : Checked valid node) : Checked valid (step valid node answer) := by
  cases answer with
  | unavailable => exact before
  | revision n doc =>
    by_cases good : valid doc = true
    · intro held holds
      simp [step, good] at holds
      rw [← holds]; exact good
    · have bad : valid doc = false := by simpa using good
      rw [step_invalid valid node n doc bad]; exact before

/-- The node serves nothing yet, or the revision of the store that it names. -/
def Agrees (s : Store α) (node : Node α) : Prop :=
  (node.applied = 0 ∧ node.snapshot = none) ∨
    (0 < node.applied ∧ node.applied ≤ s.head ∧ s.read node.applied = node.snapshot)

/-- A look at the store keeps the node in agreement with it. -/
theorem step_agrees (valid : α → Bool) (s : Store α) (node : Node α)
    (before : Agrees s node) : Agrees s (step valid node (poll s)) := by
  unfold poll
  cases found : s.read s.head with
  | none => exact before
  | some doc =>
    by_cases good : valid doc = true
    · have positive : 0 < s.head := by
        cases at_head : s.head with
        | zero => rw [at_head] at found; simp [Store.read] at found
        | succ k => omega
      simp only [step, good, if_true]
      exact Or.inr ⟨positive, Nat.le_refl _, found⟩
    · have bad : valid doc = false := by simpa using good
      rw [step_invalid valid node s.head doc bad]; exact before

/-- A commit by somebody else keeps the node in agreement: its revision did not change. -/
theorem commit_agrees {s s' : Store α} {expected : Nat} {doc : α} (node : Node α)
    (done : commit s expected doc = some s') (before : Agrees s node) : Agrees s' node := by
  cases before with
  | inl nothing => exact Or.inl nothing
  | inr serving =>
    have grew := commit_head done
    refine Or.inr ⟨serving.1, by omega, ?_⟩
    rw [commit_keeps done node.applied serving.2.1]; exact serving.2.2

/-- A node in agreement never names a revision above the head. -/
theorem applied_le_head (s : Store α) (node : Node α) (agrees : Agrees s node) :
    node.applied ≤ s.head := by
  cases agrees with
  | inl nothing => omega
  | inr serving => exact serving.2.1

/-- One look at a head that checks brings the node to the head. A notification that
    was lost therefore costs one period of the poll and no more. -/
theorem poll_converges (valid : α → Bool) (s : Store α) (node : Node α) (doc : α)
    (at_head : s.read s.head = some doc) (good : valid doc = true) :
    (step valid node (poll s)).applied = s.head ∧
      (step valid node (poll s)).snapshot = some doc := by
  simp [poll, at_head, step, good]

/-- The revision that a node reports never goes back. -/
theorem applied_monotone (valid : α → Bool) (s : Store α) (node : Node α)
    (agrees : Agrees s node) : node.applied ≤ (step valid node (poll s)).applied := by
  unfold poll
  cases found : s.read s.head with
  | none => exact Nat.le_refl _
  | some doc =>
    by_cases good : valid doc = true
    · simp only [step, good, if_true]
      exact applied_le_head s node agrees
    · have bad : valid doc = false := by simpa using good
      rw [step_invalid valid node s.head doc bad]; exact Nat.le_refl _

end Authority
