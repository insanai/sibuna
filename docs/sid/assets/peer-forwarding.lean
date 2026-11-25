/-
  Peer forwarding (SID 0026).

  Every client has one owner among the nodes that a node sees alive: the node with
  the largest score. A node that receives a flow of another node's client hands it
  to the owner, and a handed flow is served where it lands.

  We prove:

  * the rule of a node never forwards a flow that was forwarded, so a flow takes at
    most one extra hop and is always served, whatever each node believes;
  * a node that holds state for a flow serves it;
  * a node that sees no eligible peer serves every flow itself;
  * two nodes with the same view name the same owner;
  * the owner survives the loss of any other node, and a node that joins either
    becomes the owner or changes nothing;
  * the function that the code runs, a scan that keeps the best node so far,
    returns exactly that owner;
  * a header is accepted only for the node, the start and the connection it was
    made for.

  Checked with Lean 4 core, no libraries: `lean peer-forwarding.lean`.
-/

/-! ## The rule of one node -/

/-- What a node does with a flow. -/
inductive Action where
  | serve
  | forward (to : Nat)
  deriving DecidableEq, Repr

/-- The rule. `self` is the node, `owner` the owner it computed, `forwarded` whether
the flow came from a peer, `held` whether the node holds state for it. -/
def route (self owner : Nat) (forwarded held : Bool) : Action :=
  if forwarded then .serve
  else if held then .serve
  else if owner = self then .serve
  else .forward owner

/-- Invariant 1: a flow from a peer is served, whatever the node thinks of the owner. -/
theorem forwarded_is_served (self owner : Nat) (held : Bool) :
    route self owner true held = .serve := by
  simp [route]

/-- Invariant 5: a node that holds state for a flow serves it. -/
theorem held_is_served (self owner : Nat) (forwarded : Bool) :
    route self owner forwarded true = .serve := by
  cases forwarded <;> simp [route]

/-- A node never forwards to itself. -/
theorem never_to_self (self owner : Nat) (forwarded held : Bool) :
    route self owner forwarded held ≠ .forward self := by
  unfold route
  split
  · simp
  · split
    · simp
    · split
      · simp
      · intro h
        injection h with h
        contradiction

/-! ## The path of a flow through the cluster

`view n` is the owner that node `n` computes: the nodes need not agree. `held n`
says whether node `n` holds state for the flow. -/

/-- The nodes that handle a flow that first arrives at `first`, in order. The flow
is marked as forwarded after the first node. -/
def path (view : Nat → Nat) (held : Nat → Bool) (first : Nat) : List Nat :=
  match route first (view first) false (held first) with
  | .serve => [first]
  | .forward next =>
    match route next (view next) true (held next) with
    | .serve => [first, next]
    | .forward _ => [first, next, next]

/-- Invariant 1 for the whole cluster: no flow visits more than two nodes, for any
views, also views that contradict each other. There is no loop. -/
theorem one_hop (view : Nat → Nat) (held : Nat → Bool) (first : Nat) :
    (path view held first).length ≤ 2 := by
  unfold path
  split
  · simp
  · rename_i next _
    rw [forwarded_is_served]
    simp

/-- Invariant 2: the last node of the path serves the flow. A flow is never dropped
by the rule. -/
theorem served_at_the_end (view : Nat → Nat) (held : Nat → Bool) (first : Nat) :
    path view held first = [first] ∨ ∃ next, path view held first = [first, next] := by
  unfold path
  split
  · exact Or.inl rfl
  · rename_i next _
    rw [forwarded_is_served]
    exact Or.inr ⟨next, rfl⟩

/-- A flow that arrives at its owner, as that node sees it, stays there. -/
theorem owner_serves (view : Nat → Nat) (held : Nat → Bool) (n : Nat) (h : view n = n) :
    path view held n = [n] := by
  simp [path, route, h]

/-! ## The owner

`score` is the score of each node for one client. `live` is the view of one node.
Scores of distinct nodes differ: the code breaks the rare tie by the roster order,
which is a score of its own. -/

/-- `o` is the owner in `nodes` under the view `live`: it is alive and no other
live node scores higher. -/
def IsOwner (score : Nat → Nat) (live : Nat → Bool) (nodes : List Nat) (o : Nat) : Prop :=
  o ∈ nodes ∧ live o = true ∧ ∀ n, n ∈ nodes → live n = true → score n ≤ score o

/-- Invariant 3: with scores that differ, two owners under one view are one node.
Two nodes that see the same peers alive forward to the same place. -/
theorem owner_unique (score : Nat → Nat) (live : Nat → Bool) (nodes : List Nat)
    (distinct : ∀ a b, score a = score b → a = b) (a b : Nat)
    (ha : IsOwner score live nodes a) (hb : IsOwner score live nodes b) : a = b := by
  have h1 := ha.2.2 b hb.1 hb.2.1
  have h2 := hb.2.2 a ha.1 ha.2.1
  exact distinct a b (Nat.le_antisymm h2 h1)

/-- Invariant 4, a node leaves: the owner stays the owner when any other node is
no longer seen alive. -/
theorem owner_survives_loss (score : Nat → Nat) (live live' : Nat → Bool) (nodes : List Nat)
    (o : Nat) (h : IsOwner score live nodes o)
    (fewer : ∀ n, live' n = true → live n = true) (kept : live' o = true) :
    IsOwner score live' nodes o :=
  ⟨h.1, kept, fun n hn hl => h.2.2 n hn (fewer n hl)⟩

/-- Invariant 4, a node joins: when `j` becomes alive, the new owner is `j` or the
old owner. No client moves between two nodes that did not change. -/
theorem owner_after_join (score : Nat → Nat) (live live' : Nat → Bool) (nodes : List Nat)
    (distinct : ∀ a b, score a = score b → a = b)
    (o o' j : Nat) (h : IsOwner score live nodes o) (h' : IsOwner score live' nodes o')
    (grown : ∀ n, live' n = true → live n = true ∨ n = j)
    (kept : ∀ n, live n = true → live' n = true) : o' = j ∨ o' = o := by
  cases grown o' h'.2.1 with
  | inr hj => exact Or.inl hj
  | inl hlive =>
    have h1 := h.2.2 o' h'.1 hlive
    have h2 := h'.2.2 o h.1 (kept o h.2.1)
    exact Or.inr (distinct o' o (Nat.le_antisymm h1 h2))

/-! ## The scan that the code runs -/

/-- Keeps the best live node so far. A later node replaces it only with a strictly
larger score, so an earlier node wins a tie. -/
def step (score : Nat → Nat) (live : Nat → Bool) (best : Option Nat) (n : Nat) : Option Nat :=
  if live n then
    match best with
    | none => some n
    | some b => if score b < score n then some n else some b
  else best

/-- The owner as the code computes it: one pass over the roster. -/
def scan (score : Nat → Nat) (live : Nat → Bool) (nodes : List Nat) : Option Nat :=
  nodes.foldl (step score live) none

/-- What the scan holds: a live node seen so far that no live node seen so far beats. -/
def Best (score : Nat → Nat) (live : Nat → Bool) (seen : List Nat) : Option Nat → Prop
  | none => ∀ n, n ∈ seen → live n = false
  | some b => IsOwner score live seen b

theorem step_keeps_best (score : Nat → Nat) (live : Nat → Bool) (seen : List Nat)
    (best : Option Nat) (n : Nat) (h : Best score live seen best) :
    Best score live (seen ++ [n]) (step score live best n) := by
  unfold step
  cases hl : live n with
  | false =>
    simp only [Bool.false_eq_true, if_false]
    cases best with
    | none =>
      intro m hm
      rcases List.mem_append.mp hm with hm | hm
      · exact h m hm
      · rw [List.mem_singleton.mp hm]; exact hl
    | some b =>
      refine ⟨List.mem_append_left _ h.1, h.2.1, ?_⟩
      intro m hm hlm
      rcases List.mem_append.mp hm with hm | hm
      · exact h.2.2 m hm hlm
      · rw [List.mem_singleton.mp hm, hl] at hlm; cases hlm
  | true =>
    simp only [if_true]
    cases best with
    | none =>
      refine ⟨List.mem_append_right _ (List.mem_singleton.mpr rfl), hl, ?_⟩
      intro m hm hlm
      rcases List.mem_append.mp hm with hm | hm
      · rw [h m hm] at hlm; cases hlm
      · rw [List.mem_singleton.mp hm]; exact Nat.le_refl _
    | some b =>
      by_cases hlt : score b < score n
      · simp only [hlt, if_true]
        refine ⟨List.mem_append_right _ (List.mem_singleton.mpr rfl), hl, ?_⟩
        intro m hm hlm
        rcases List.mem_append.mp hm with hm | hm
        · exact Nat.le_trans (h.2.2 m hm hlm) (Nat.le_of_lt hlt)
        · rw [List.mem_singleton.mp hm]; exact Nat.le_refl _
      · simp only [hlt, if_false]
        refine ⟨List.mem_append_left _ h.1, h.2.1, ?_⟩
        intro m hm hlm
        rcases List.mem_append.mp hm with hm | hm
        · exact h.2.2 m hm hlm
        · rw [List.mem_singleton.mp hm]; exact Nat.le_of_not_lt hlt

theorem foldl_keeps_best (score : Nat → Nat) (live : Nat → Bool) (rest : List Nat) :
    ∀ (seen : List Nat) (best : Option Nat), Best score live seen best →
      Best score live (seen ++ rest) (rest.foldl (step score live) best) := by
  induction rest with
  | nil => intro seen best h; simpa using h
  | cons n rest ih =>
    intro seen best h
    have h' := ih (seen ++ [n]) _ (step_keeps_best score live seen best n h)
    simpa [List.append_assoc] using h'

/-- The scan returns the owner. -/
theorem scan_is_owner (score : Nat → Nat) (live : Nat → Bool) (nodes : List Nat) (o : Nat)
    (h : scan score live nodes = some o) : IsOwner score live nodes o := by
  have hb := foldl_keeps_best score live nodes [] none (by intro n hn; cases hn)
  unfold scan at h
  rw [h] at hb
  simpa using hb

/-- The scan finds no owner only when no node is alive. The node itself is always
alive in its own view, so the code always has an owner: invariant 2. -/
theorem scan_none_means_none_alive (score : Nat → Nat) (live : Nat → Bool) (nodes : List Nat)
    (h : scan score live nodes = none) : ∀ n, n ∈ nodes → live n = false := by
  have hb := foldl_keeps_best score live nodes [] none (by intro n hn; cases hn)
  unfold scan at h
  rw [h] at hb
  simpa using hb

/-- A node that sees only itself alive owns every client: it forwards nothing. -/
theorem alone_owns_all (score : Nat → Nat) (live : Nat → Bool) (nodes : List Nat)
    (self o : Nat) (only : ∀ n, live n = true → n = self)
    (h : scan score live nodes = some o) : o = self :=
  only o (scan_is_owner score live nodes o h).2.1

/-! ## What a header is bound to -/

/-- The fields of a header that the tag covers, beside the client. `sender` and
`receiver` are the addresses of the connection, `epoch` the start of the receiver. -/
structure Binding where
  sender : Nat
  receiver : Nat
  epoch : Nat
  deriving DecidableEq

/-- A node accepts a header whose binding is its own view of the connection. The
tag makes the binding unforgeable; that part is the hash, outside this model. -/
def accepts (mine : Binding) (header : Binding) : Bool := decide (mine = header)

/-- A header made for one start of a node is refused after the node restarts. -/
theorem refused_after_restart (mine header : Binding) (h : mine.epoch ≠ header.epoch) :
    accepts mine header = false := by
  simp only [accepts, decide_eq_false_iff_not]
  intro heq
  exact h (by rw [heq])

/-- A header made for one connection is refused on another. -/
theorem refused_on_another_connection (mine header : Binding)
    (h : mine.sender ≠ header.sender ∨ mine.receiver ≠ header.receiver) :
    accepts mine header = false := by
  simp only [accepts, decide_eq_false_iff_not]
  intro heq
  cases h with
  | inl h => exact h (by rw [heq])
  | inr h => exact h (by rw [heq])
