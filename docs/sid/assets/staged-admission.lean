/-
  Staged admission at the socket edge (SID 0032).

  Three small models.

  1. The decision of a TLS passthrough inspection. Every class of metadata has
     exactly one outcome: refuse, or forward to one pool.
  2. The inspected prefix. The edge moves bytes of the client stream into a buffer
     of bounded size. A forwarded connection gives the origin the buffer and then
     the rest of the stream, which is the stream itself. Of several connect
     attempts only the one that succeeds receives the buffer.
  3. The reply bound of a UDP mapping. Until the client address is validated the
     mapping sends at most three times the bytes it received.

  Checked with Lean 4 core, no libraries: `lean staged-admission.lean`.
-/

/-! ## 1. The decision is total -/

/-- What the inspection saw when it ended. -/
inductive Metadata where
  | visible | absent | encrypted | incomplete | invalid

/-- What a frontend configures for a class. A pool is named by a number. -/
inductive Action where
  | rules | deny | backend (pool : Nat)

/-- What happens to the connection. -/
inductive Outcome where
  | refuse | forward (pool : Nat)
  deriving DecidableEq

/-- The configured fallback: one action for each class that is not visible. -/
structure Fallback where
  absent : Action
  encrypted : Action
  incomplete : Action
  invalid : Action

/-- The action of a class. Visible metadata always goes to the rules. -/
def Fallback.action (f : Fallback) : Metadata → Action
  | .visible => .rules
  | .absent => f.absent
  | .encrypted => f.encrypted
  | .incomplete => f.incomplete
  | .invalid => f.invalid

/-- The decision. `rules` is what the rule list answers for this connection. -/
def outcomeOf (f : Fallback) (rules : Outcome) (m : Metadata) : Outcome :=
  match f.action m with
  | .rules => rules
  | .deny => .refuse
  | .backend pool => .forward pool

/-- Every class ends in a refusal or in exactly one pool. -/
theorem decision_total (f : Fallback) (rules : Outcome) (m : Metadata) :
    outcomeOf f rules m = .refuse ∨ ∃ pool, outcomeOf f rules m = .forward pool := by
  cases h : outcomeOf f rules m with
  | refuse => exact Or.inl rfl
  | forward pool => exact Or.inr ⟨pool, rfl⟩

/-- A configuration is accepted only when the classes without a ClientHello do not
    ask for the rules. -/
def Fallback.accepted (f : Fallback) : Prop :=
  f.incomplete ≠ .rules ∧ f.invalid ≠ .rules

/-- Without a ClientHello the rules are never consulted: the outcome does not depend
    on what they would answer. -/
theorem no_hello_ignores_rules (f : Fallback) (ok : f.accepted) (a b : Outcome) :
    outcomeOf f a .incomplete = outcomeOf f b .incomplete ∧
    outcomeOf f a .invalid = outcomeOf f b .invalid := by
  obtain ⟨hi, hv⟩ := ok
  constructor
  · unfold outcomeOf Fallback.action
    cases h : f.incomplete with
    | rules => exact absurd h hi
    | deny => rfl
    | backend p => rfl
  · unfold outcomeOf Fallback.action
    cases h : f.invalid with
    | rules => exact absurd h hv
    | deny => rfl
    | backend p => rfl

/-- A denied class is refused whatever the rules say. -/
theorem deny_refuses (f : Fallback) (rules : Outcome) (m : Metadata)
    (h : f.action m = .deny) : outcomeOf f rules m = .refuse := by
  unfold outcomeOf; rw [h]

/-- The defaults: the behaviour before SID 0032. -/
def defaults : Fallback :=
  { absent := .rules, encrypted := .rules, incomplete := .deny, invalid := .deny }

theorem defaults_accepted : defaults.accepted := by
  constructor <;> intro h <;> cases h

/-! ## 2. The prefix is bounded and replayed exactly once -/

/-- An inspection in progress: the bytes the edge holds, and the bytes of the client
    stream that are still in the socket. -/
structure Inspection (α : Type) where
  held : List α
  waiting : List α

/-- One read of at most `n` bytes, never beyond the bound `limit`. -/
def Inspection.read (s : Inspection α) (limit n : Nat) : Inspection α :=
  let take := Nat.min n (limit - s.held.length)
  { held := s.held ++ s.waiting.take take, waiting := s.waiting.drop take }

/-- A read moves bytes and neither loses, repeats nor reorders one. -/
theorem read_keeps_stream (s : Inspection α) (limit n : Nat) :
    (s.read limit n).held ++ (s.read limit n).waiting = s.held ++ s.waiting := by
  simp [Inspection.read, List.append_assoc, List.take_append_drop]

/-- A read never exceeds the bound. -/
theorem read_bounded (s : Inspection α) (limit n : Nat) (h : s.held.length ≤ limit) :
    (s.read limit n).held.length ≤ limit := by
  simp only [Inspection.read, List.length_append, List.length_take]
  have h1 : Nat.min n (limit - s.held.length) ≤ limit - s.held.length :=
    Nat.min_le_right _ _
  have h2 : min (Nat.min n (limit - s.held.length)) s.waiting.length
      ≤ Nat.min n (limit - s.held.length) := Nat.min_le_left _ _
  omega

/-- Any number of reads, of any sizes. -/
def Inspection.reads (s : Inspection α) (limit : Nat) : List Nat → Inspection α
  | [] => s
  | n :: rest => (s.read limit n).reads limit rest

theorem reads_keep_stream (limit : Nat) (sizes : List Nat) :
    ∀ s : Inspection α, (s.reads limit sizes).held ++ (s.reads limit sizes).waiting
      = s.held ++ s.waiting := by
  induction sizes with
  | nil => intro s; rfl
  | cons n rest ih =>
    intro s
    simp only [Inspection.reads]
    rw [ih, read_keeps_stream]

theorem reads_bounded (limit : Nat) (sizes : List Nat) :
    ∀ s : Inspection α, s.held.length ≤ limit → (s.reads limit sizes).held.length ≤ limit := by
  induction sizes with
  | nil => intro s h; exact h
  | cons n rest ih =>
    intro s h
    exact ih _ (read_bounded s limit n h)

/-- What a forwarded connection gives its origin: the replay, then the relay of what
    was still in the socket. -/
def Inspection.toOrigin (s : Inspection α) : List α := s.held ++ s.waiting

/-- Whatever the edge read, a forwarded origin sees the client stream itself, and the
    edge never held more than the bound. -/
theorem forwarded_origin_sees_the_stream (stream : List α) (limit : Nat) (sizes : List Nat) :
    ((Inspection.mk [] stream).reads limit sizes).toOrigin = stream ∧
    ((Inspection.mk [] stream).reads limit sizes).held.length ≤ limit := by
  constructor
  · simp [Inspection.toOrigin, reads_keep_stream]
  · exact reads_bounded limit sizes _ (Nat.zero_le _)

/-- What each connect attempt receives. `true` is an attempt that connected. The edge
    stops at the first one, and a failed attempt receives nothing. -/
def deliveries (held : List α) : List Bool → List (List α)
  | [] => []
  | true :: _ => [held]
  | false :: rest => [] :: deliveries held rest

/-- All bytes that reached any origin, in order. -/
def delivered (held : List α) (attempts : List Bool) : List α :=
  (deliveries held attempts).foldr (· ++ ·) []

/-- With a successful attempt the origins received the prefix exactly once in total.
    Without one they received nothing. -/
theorem replay_exactly_once (held : List α) (attempts : List Bool) :
    delivered held attempts = if attempts.any id then held else [] := by
  induction attempts with
  | nil => rfl
  | cons a rest ih =>
    cases a with
    | true => simp [delivered, deliveries]
    | false =>
      have step : delivered held (false :: rest) = delivered held rest := by
        simp [delivered, deliveries]
      rw [step, ih]; simp

/-! ## 3. The reply bound before validation -/

/-- What a mapping saw: a datagram of the client, or a reply of the origin. -/
inductive Datagram where
  | request (bytes : Nat)
  | reply (bytes : Nat)

/-- The account of an unvalidated mapping. -/
structure Account where
  received : Nat
  sent : Nat
  credit : Nat

/-- A request earns three times its size, up to a ceiling. A reply is sent only
    within the credit, and is dropped otherwise. -/
def Account.step (cap : Nat) (a : Account) : Datagram → Account
  | .request n =>
    { a with received := a.received + n, credit := Nat.min (a.credit + 3 * n) cap }
  | .reply n =>
    if n ≤ a.credit then { a with sent := a.sent + n, credit := a.credit - n } else a

/-- The invariant: what was sent and what may still be sent is within three times
    what was received. -/
def Account.sound (a : Account) : Prop := a.sent + a.credit ≤ 3 * a.received

theorem step_sound (cap : Nat) (a : Account) (d : Datagram) (h : a.sound) :
    (a.step cap d).sound := by
  unfold Account.sound at *
  cases d with
  | request n =>
    simp only [Account.step]
    have : Nat.min (a.credit + 3 * n) cap ≤ a.credit + 3 * n := Nat.min_le_left _ _
    omega
  | reply n =>
    simp only [Account.step]
    split
    · simp only; omega
    · exact h

/-- Any trace of an unvalidated mapping sends at most three times what it received. -/
theorem unvalidated_replies_bounded (cap : Nat) (trace : List Datagram) :
    ∀ a : Account, a.sound → (trace.foldl (Account.step cap) a).sent
      ≤ 3 * (trace.foldl (Account.step cap) a).received := by
  induction trace with
  | nil => intro a h; unfold Account.sound at h; simp only [List.foldl]; omega
  | cons d rest ih => intro a h; exact ih _ (step_sound cap a d h)

/-- A new mapping starts sound. -/
theorem new_mapping_sound : (Account.mk 0 0 0).sound := by
  unfold Account.sound; simp
