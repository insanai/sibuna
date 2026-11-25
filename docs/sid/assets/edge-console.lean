/-
  The operator console of the edge (SID 0031).

  Three small models, one for each rule that the console must keep.

  1. Admission. The management listener counts its connections in three
     classes. Browser and peer streams have a quota each, and a part of the
     slots is reserved for ordinary HTTP requests. We prove that the quotas
     hold after every step and that streams never take the reserve: while
     fewer HTTP requests are served than the reserve holds, the next HTTP
     request is admitted.

  2. Membership. A peer stream belongs to a configured member. Removing a
     member closes its stream, and no later step opens one for it again
     unless the member is configured again.

  3. Commands. The console runs a command only for an authenticated and
     authorised caller, only when the command is on its list, and then by
     the step of the admin socket. We prove that the console reaches no
     state that the admin socket cannot reach.

  Checked with Lean 4 core, no libraries: `lean edge-console.lean`.
-/

/-! ## 1. Admission -/

/-- The limits of the listener. -/
structure Capacity where
  slots : Nat
  reserve : Nat
  browsers : Nat
  peers : Nat

/-- A capacity is valid when the streams fit the slots outside the reserve. -/
def Capacity.valid (c : Capacity) : Prop := c.browsers + c.peers + c.reserve ≤ c.slots

/-- The connections admitted now, by class. -/
structure Admitted where
  http : Nat
  browsers : Nat
  peers : Nat

def Admitted.total (a : Admitted) : Nat := a.http + a.browsers + a.peers

inductive Class where
  | http
  | browser
  | peer

/-- Admits one connection, or leaves the state as it is. -/
def acquire (c : Capacity) (a : Admitted) : Class → Admitted
  | .http => if a.total < c.slots then { a with http := a.http + 1 } else a
  | .browser =>
    if a.total < c.slots ∧ a.browsers < c.browsers then { a with browsers := a.browsers + 1 }
    else a
  | .peer =>
    if a.total < c.slots ∧ a.peers < c.peers then { a with peers := a.peers + 1 } else a

/-- Releases one connection of a class. -/
def release (a : Admitted) : Class → Admitted
  | .http => { a with http := a.http - 1 }
  | .browser => { a with browsers := a.browsers - 1 }
  | .peer => { a with peers := a.peers - 1 }

/-- What must hold at every moment. -/
def Bounded (c : Capacity) (a : Admitted) : Prop :=
  a.total ≤ c.slots ∧ a.browsers ≤ c.browsers ∧ a.peers ≤ c.peers

theorem acquire_bounded (c : Capacity) (a : Admitted) (k : Class) (h : Bounded c a) :
    Bounded c (acquire c a k) := by
  obtain ⟨ht, hb, hp⟩ := h
  cases k with
  | http =>
    simp only [acquire]
    split
    · next hlt => exact ⟨by simp only [Admitted.total] at *; omega, hb, hp⟩
    · exact ⟨ht, hb, hp⟩
  | browser =>
    simp only [acquire]
    split
    · next hlt => exact ⟨by simp only [Admitted.total] at *; omega, by simp; omega, hp⟩
    · exact ⟨ht, hb, hp⟩
  | peer =>
    simp only [acquire]
    split
    · next hlt => exact ⟨by simp only [Admitted.total] at *; omega, hb, by simp; omega⟩
    · exact ⟨ht, hb, hp⟩

theorem release_bounded (c : Capacity) (a : Admitted) (k : Class) (h : Bounded c a) :
    Bounded c (release a k) := by
  obtain ⟨ht, hb, hp⟩ := h
  cases k <;> simp only [release, Bounded, Admitted.total] at * <;> omega

/-- The reserve: with a valid capacity, an HTTP request is admitted whenever fewer
    HTTP requests are served than the reserve holds, whatever the streams do. -/
theorem reserve_is_kept (c : Capacity) (a : Admitted) (hv : c.valid) (h : Bounded c a)
    (hr : a.http < c.reserve) : (acquire c a .http).http = a.http + 1 := by
  obtain ⟨_, hb, hp⟩ := h
  have : a.total < c.slots := by
    simp only [Admitted.total, Capacity.valid] at *; omega
  simp [acquire, this]

/-- A stream over its quota is refused, and the state does not change. -/
theorem full_class_is_refused (c : Capacity) (a : Admitted) (h : a.browsers = c.browsers) :
    acquire c a .browser = a := by
  simp [acquire, h]

/-! ## 2. Membership -/

/-- The configured members and the members that hold a stream. -/
structure Fleet where
  members : List Nat
  streams : List Nat

/-- Every stream belongs to a member. -/
def Fleet.sound (f : Fleet) : Prop := ∀ n, n ∈ f.streams → n ∈ f.members

/-- A member opens its one stream. Anyone else is refused. -/
def admit (f : Fleet) (n : Nat) : Fleet :=
  if n ∈ f.members ∧ n ∉ f.streams then { f with streams := n :: f.streams } else f

/-- Removing a member closes its stream. -/
def remove (f : Fleet) (n : Nat) : Fleet :=
  { members := f.members.filter (· ≠ n), streams := f.streams.filter (· ≠ n) }

/-- A stream ends. -/
def close (f : Fleet) (n : Nat) : Fleet :=
  { f with streams := f.streams.filter (· ≠ n) }

theorem admit_sound (f : Fleet) (n : Nat) (h : f.sound) : (admit f n).sound := by
  intro m hm
  unfold admit at hm ⊢
  split
  · next hc =>
    simp only [hc, and_self, ite_true] at hm
    rcases List.mem_cons.mp hm with rfl | hm
    · exact hc.1
    · exact h m hm
  · next hc =>
    simp only [hc, ite_false] at hm
    exact h m hm

theorem remove_sound (f : Fleet) (n : Nat) (h : f.sound) : (remove f n).sound := by
  intro m hm
  simp only [remove, List.mem_filter] at hm ⊢
  exact ⟨h m hm.1, hm.2⟩

theorem close_sound (f : Fleet) (n : Nat) (h : f.sound) : (close f n).sound := by
  intro m hm
  simp only [close, List.mem_filter] at hm
  exact h m hm.1

/-- After a removal the member holds no stream. -/
theorem remove_closes (f : Fleet) (n : Nat) : n ∉ (remove f n).streams := by
  simp [remove, List.mem_filter]

/-- After a removal the member is not configured. -/
theorem remove_forgets (f : Fleet) (n : Nat) : n ∉ (remove f n).members := by
  simp [remove, List.mem_filter]

/-- The steps that do not configure a member. -/
inductive Step where
  | admit (n : Nat)
  | remove (n : Nat)
  | close (n : Nat)

def step (f : Fleet) : Step → Fleet
  | .admit n => admit f n
  | .remove n => remove f n
  | .close n => close f n

/-- No step makes a member of a node that was none. -/
theorem step_adds_no_member (f : Fleet) (s : Step) (n : Nat) (h : n ∉ f.members) :
    n ∉ (step f s).members := by
  cases s with
  | admit m =>
    simp only [step, admit]
    split <;> exact h
  | remove m =>
    simp only [step, remove, List.mem_filter]
    exact fun hm => h hm.1
  | close m => exact h

theorem step_sound (f : Fleet) (s : Step) (h : f.sound) : (step f s).sound := by
  cases s with
  | admit n => exact admit_sound f n h
  | remove n => exact remove_sound f n h
  | close n => exact close_sound f n h

/-- A removed member stays without a stream through every later sequence of steps:
    a subsequent upgrade is refused. -/
theorem removed_stays_out (steps : List Step) :
    ∀ (f : Fleet) (n : Nat), f.sound → n ∉ f.members →
      n ∉ (steps.foldl step f).streams := by
  induction steps with
  | nil => intro f n hs hn hin; exact hn (hs n hin)
  | cons s rest ih =>
    intro f n hs hn
    exact ih (step f s) n (step_sound f s hs) (step_adds_no_member f s n hn)

/-- The statement of the record: remove a member, then run anything. It has no stream. -/
theorem removal_is_final (f : Fleet) (n : Nat) (steps : List Step) (h : f.sound) :
    n ∉ (steps.foldl step (remove f n)).streams :=
  removed_stays_out steps (remove f n) n (remove_sound f n h) (remove_forgets f n)

/-! ## 3. Commands -/

section Commands

variable {σ κ : Type}

/-- A request to the console: who asks, and what. -/
structure Request (κ : Type) where
  authenticated : Bool
  authorised : Bool
  command : κ

/-- The console runs the step of the admin socket, or nothing. `listed` is the list of
    commands the console offers. -/
def consoleStep (adminStep : σ → κ → σ) (listed : κ → Bool) (s : σ) (r : Request κ) : σ :=
  if r.authenticated && r.authorised && listed r.command then adminStep s r.command else s

/-- The states the admin socket can reach from `s`. -/
inductive Reach (adminStep : σ → κ → σ) : σ → σ → Prop where
  | here (s : σ) : Reach adminStep s s
  | more {s t : σ} (c : κ) : Reach adminStep s t → Reach adminStep s (adminStep t c)

/-- A request without authentication changes nothing. -/
theorem unauthenticated_changes_nothing (adminStep : σ → κ → σ) (listed : κ → Bool) (s : σ)
    (r : Request κ) (h : r.authenticated = false) : consoleStep adminStep listed s r = s := by
  simp [consoleStep, h]

/-- A command that is not on the list changes nothing. -/
theorem unlisted_changes_nothing (adminStep : σ → κ → σ) (listed : κ → Bool) (s : σ)
    (r : Request κ) (h : listed r.command = false) : consoleStep adminStep listed s r = s := by
  simp [consoleStep, h]

/-- No new power: whatever sequence of requests the console serves, the state it ends
    in is one that commands on the admin socket reach. -/
theorem console_adds_no_power (adminStep : σ → κ → σ) (listed : κ → Bool)
    (requests : List (Request κ)) :
    ∀ (s t : σ), Reach adminStep s t →
      Reach adminStep s (requests.foldl (consoleStep adminStep listed) t) := by
  induction requests with
  | nil => intro s t h; exact h
  | cons r rest ih =>
    intro s t h
    apply ih
    unfold consoleStep
    split
    · exact Reach.more r.command h
    · exact h

end Commands
