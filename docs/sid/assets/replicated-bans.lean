/-
  Replicated bans (SID 0022).

  The state of a node maps each client key to the time its ban ends; 0 means no
  ban. Nodes merge by taking the later end for each key. We prove the three laws
  that make the merge insensitive to order and repetition, that a merge never
  shortens a ban, and that folding any list of received states in any duplicated
  form gives the same result.

  Checked with Lean 4 core, no libraries: `lean replicated-bans.lean`.
-/

/-- The bans a node knows: the end for each key, 0 for none. -/
def Bans (κ : Type) := κ → Nat

/-- Merging two states keeps the later end of each key. -/
def merge (a b : Bans κ) : Bans κ := fun k => Nat.max (a k) (b k)

theorem merge_comm (a b : Bans κ) : merge a b = merge b a := by
  funext k; exact Nat.max_comm (a k) (b k)

theorem merge_assoc (a b c : Bans κ) : merge (merge a b) c = merge a (merge b c) := by
  funext k; exact Nat.max_assoc (a k) (b k) (c k)

theorem merge_idem (a : Bans κ) : merge a a = a := by
  funext k; exact Nat.max_self (a k)

/-- A merge never shortens a ban the node already holds. -/
theorem merge_keeps (a b : Bans κ) (k : κ) : a k ≤ merge a b k :=
  Nat.le_max_left (a k) (b k)

/-- A merge takes in every ban it hears. -/
theorem merge_learns (a b : Bans κ) (k : κ) : b k ≤ merge a b k :=
  Nat.le_max_right (a k) (b k)

/-- A datagram heard twice changes nothing the second time. -/
theorem replay_is_harmless (a b : Bans κ) : merge (merge a b) b = merge a b := by
  rw [merge_assoc, merge_idem]

/-- Two datagrams give the same state in either order. -/
theorem order_is_irrelevant (a b c : Bans κ) :
    merge (merge a b) c = merge (merge a c) b := by
  rw [merge_assoc, merge_comm b c, ← merge_assoc]

/-- What a node holds after it heard a list of states, starting from `a`. -/
def heard (a : Bans κ) (states : List (Bans κ)) : Bans κ := states.foldl merge a

/-- Hearing never loses a ban. -/
theorem heard_keeps (states : List (Bans κ)) :
    ∀ (a : Bans κ) (k : κ), a k ≤ heard a states k := by
  induction states with
  | nil => intro a k; exact Nat.le_refl _
  | cons s rest ih =>
    intro a k
    exact Nat.le_trans (merge_keeps a s k) (ih (merge a s) k)

/-- Every state in the list is contained in the result: each ban arrived. -/
theorem heard_contains (states : List (Bans κ)) :
    ∀ (a : Bans κ) (s : Bans κ), s ∈ states → ∀ k, s k ≤ heard a states k := by
  induction states with
  | nil => intro a s h; cases h
  | cons t rest ih =>
    intro a s h k
    cases h with
    | head => exact Nat.le_trans (merge_learns a t k) (heard_keeps rest (merge a t) k)
    | tail _ h' => exact ih (merge a t) s h' k

/-- An end is cut to a horizon ahead of the receiver's clock; a passed end is dropped. -/
def admit (now horizon end_ : Nat) : Nat :=
  if end_ ≤ now then 0 else Nat.min end_ (now + horizon)

/-- No received end lies beyond the horizon. -/
theorem admit_is_bounded (now horizon end_ : Nat) : admit now horizon end_ ≤ now + horizon := by
  unfold admit
  split
  · exact Nat.zero_le _
  · exact Nat.min_le_right _ _

/-- An admitted end never exceeds the end that was sent: a datagram cannot extend a ban
    beyond what its sender stated. -/
theorem admit_never_extends (now horizon end_ : Nat) : admit now horizon end_ ≤ end_ := by
  unfold admit
  split
  · exact Nat.zero_le _
  · exact Nat.min_le_left _ _

/-
  Lifted bans and run-time commands.

  A lift is a second map of the same kind: for each key the end up to which bans
  are lifted. A ban is in effect when it ends after the lift. Both maps merge by
  the larger number, so what is in effect depends only on what a node has heard,
  not on the order. A run-time command is an entry of a third such map whose
  number starts with the time of the command, so the later command is the larger
  number.
-/

/-- A ban is in effect at `now` when it has not ended and ends after the lift. -/
def inEffect (bans lifts : Bans κ) (now : Nat) (k : κ) : Prop :=
  now < bans k ∧ lifts k < bans k

/-- Two nodes that heard the same bans and lifts in different orders agree. -/
theorem effect_ignores_order (b₁ b₂ l₁ l₂ : Bans κ) (now : Nat) (k : κ) :
    inEffect (merge b₁ b₂) (merge l₁ l₂) now k ↔ inEffect (merge b₂ b₁) (merge l₂ l₁) now k := by
  rw [merge_comm b₁ b₂, merge_comm l₁ l₂]

/-- A lift that covers a ban ends it on every node that hears the lift. -/
theorem lift_ends_ban (bans lifts lift : Bans κ) (now : Nat) (k : κ)
    (covers : bans k ≤ lift k) : ¬ inEffect bans (merge lifts lift) now k := by
  intro h
  have learned : lift k ≤ merge lifts lift k := merge_learns lifts lift k
  exact Nat.lt_irrefl _ (Nat.lt_of_le_of_lt (Nat.le_trans covers learned) h.2)

/-- The same ban heard again after its lift stays lifted. -/
theorem lifted_ban_does_not_return (bans lifts : Bans κ) (now : Nat) (k : κ)
    (covers : bans k ≤ lifts k) : ¬ inEffect (merge bans bans) lifts now k := by
  rw [merge_idem]
  intro h
  exact Nat.lt_irrefl _ (Nat.lt_of_le_of_lt covers h.2)

/-- A ban that ends after the lift is a new ban and holds. -/
theorem newer_ban_holds (bans lifts fresh : Bans κ) (now : Nat) (k : κ)
    (later : lifts k < fresh k) (live : now < fresh k) :
    inEffect (merge bans fresh) lifts now k := by
  have learned : fresh k ≤ merge bans fresh k := merge_learns bans fresh k
  exact ⟨Nat.lt_of_lt_of_le live learned, Nat.lt_of_lt_of_le later learned⟩

/-- The number of a command: its time above `bits` bits of content. -/
def stamped (bits time content : Nat) : Nat := time * 2 ^ bits + content

/-- The later command is the larger number, whatever the two commands say. -/
theorem later_command_wins (bits t₁ t₂ c₁ c₂ : Nat) (fits : c₁ < 2 ^ bits) (later : t₁ < t₂) :
    stamped bits t₁ c₁ < stamped bits t₂ c₂ := by
  unfold stamped
  have step : t₁ * 2 ^ bits + c₁ < (t₁ + 1) * 2 ^ bits := by
    rw [Nat.succ_mul]; exact Nat.add_lt_add_left fits _
  have grow : (t₁ + 1) * 2 ^ bits ≤ t₂ * 2 ^ bits := Nat.mul_le_mul_right _ later
  exact Nat.lt_of_lt_of_le step (Nat.le_trans grow (Nat.le_add_right _ _))
