/-
  Upgrade handoff (SID 0029).

  An old process hands its listeners and its UDP mappings to a replacement. We
  model the cutover as a state machine of both processes and prove, for every
  reachable state:

  * at most one process reads the UDP sockets (`single_reader`);
  * a process accepts on the TCP listeners, unless the replacement died after
    it acknowledged the cutover (`always_an_acceptor`);
  * the old process stops accepting only after the acknowledgement was sent
    (`old_stops_only_after_done`);
  * the replacement reads nothing before it acknowledged (`new_reads_after_done`);
  * a replacement that died before the old process released leaves a step that
    returns the whole service to the old process (`failure_returns_service`).

  The model does not cover a crash of the old process, the loss of a datagram in
  a full socket buffer, or time: a deadline appears only as the step `die`,
  which is how the old process ends a silent replacement.

  Checked with Lean 4 core, no libraries: `lean upgrade-handoff.lean`.
-/

/-- Where the handoff stands, as the old process sees it. -/
inductive Phase where
  /-- No handoff, or one that was abandoned. -/
  | serving
  /-- The replacement holds the listeners. The old process changed nothing. -/
  | offered
  /-- READY was read: the old process stopped reading UDP. -/
  | frozen
  /-- The mappings and COMMIT were sent. -/
  | committed
  /-- DONE was read: the old process stopped accepting and drains. -/
  | released
  deriving DecidableEq

/-- Both processes at one instant. -/
structure State where
  phase : Phase
  /-- The old process accepts on the TCP listeners. -/
  oldAccepts : Bool
  /-- The old process reads the UDP listeners and the sockets of the mappings. -/
  oldReads : Bool
  /-- The replacement runs. -/
  newAlive : Bool
  newAccepts : Bool
  newReads : Bool
  /-- The replacement wrote DONE. The old process may not have read it yet. -/
  doneSent : Bool

/-- One daemon serves, and no replacement runs. -/
def start : State :=
  { phase := .serving, oldAccepts := true, oldReads := true,
    newAlive := false, newAccepts := false, newReads := false, doneSent := false }

/-- The steps of the two processes. A message is read after it was sent, and its
    sender may have died meanwhile, so reading a message does not ask that the
    sender lives. -/
inductive Step : State → State → Prop where
  /-- A replacement connects and is given the listeners. -/
  | offer (s : State) : s.phase = .serving →
      Step s { s with phase := .offered, newAlive := true, newAccepts := false,
                      newReads := false, doneSent := false }
  /-- The old process reads READY and stops reading UDP. -/
  | ready (s : State) : s.phase = .offered →
      Step s { s with phase := .frozen, oldReads := false }
  /-- The old process sends the mappings and COMMIT. -/
  | commit (s : State) : s.phase = .frozen →
      Step s { s with phase := .committed }
  /-- The replacement starts accepting, after COMMIT. -/
  | armTcp (s : State) : s.phase = .committed → s.newAlive = true →
      Step s { s with newAccepts := true }
  /-- The replacement writes DONE. It accepts already. -/
  | sendDone (s : State) : s.phase = .committed → s.newAlive = true →
      s.newAccepts = true → Step s { s with doneSent := true }
  /-- The replacement starts reading UDP, after it wrote DONE. -/
  | armUdp (s : State) : s.newAlive = true → s.doneSent = true →
      Step s { s with newReads := true }
  /-- The old process reads DONE and stops accepting. -/
  | release (s : State) : s.phase = .committed → s.doneSent = true →
      Step s { s with phase := .released, oldAccepts := false }
  /-- The replacement dies: by a fault of its own, or by the SIGKILL of the old
      process at the deadline. Its descriptors close. -/
  | die (s : State) :
      Step s { s with newAlive := false, newAccepts := false, newReads := false }
  /-- The old process finds the connection closed, which only a dead
      replacement gives, and takes the service back. -/
  | resume (s : State) : s.phase ≠ .released → s.newAlive = false →
      Step s { s with phase := .serving, oldReads := true }

/-- The states that the machine can reach from `start`. -/
inductive Reachable : State → Prop where
  | start : Reachable start
  | step {s t : State} : Reachable s → Step s t → Reachable t

/-- What every reachable state satisfies. The theorems below read it off. -/
structure Inv (s : State) : Prop where
  /-- The replacement reads only alive and after DONE. -/
  reads : s.newReads = true → s.newAlive = true ∧ s.doneSent = true
  /-- Once a live replacement wrote DONE, the old process does not read. -/
  quiet : s.newAlive = true → s.doneSent = true → s.oldReads = false
  /-- The old process accepts in every phase but the last. -/
  accepts : s.phase ≠ .released → s.oldAccepts = true
  /-- The last phase is entered on DONE only. -/
  acked : s.phase = .released → s.doneSent = true
  /-- A live replacement that wrote DONE accepts. -/
  armed : s.newAlive = true → s.doneSent = true → s.newAccepts = true
  /-- From READY on the old process does not read. -/
  frozen : s.phase = .frozen ∨ s.phase = .committed ∨ s.phase = .released →
    s.oldReads = false
  /-- Before READY the old process reads. -/
  serves : s.phase = .serving ∨ s.phase = .offered → s.oldReads = true

theorem inv_start : Inv start := by
  constructor <;> simp [start]

theorem inv_step {s t : State} (h : Inv s) (st : Step s t) : Inv t := by
  obtain ⟨reads, quiet, accepts, acked, armed, frozen, serves⟩ := h
  cases st with
  | offer hp => constructor <;> simp_all
  | ready hp => constructor <;> simp_all
  | commit hp => constructor <;> simp_all
  | armTcp hp ha => constructor <;> simp_all
  | sendDone hp ha hacc => constructor <;> simp_all
  | armUdp ha hd => constructor <;> simp_all
  | release hp hd => constructor <;> simp_all
  | die => constructor <;> simp_all
  | resume hp ha => constructor <;> simp_all

theorem inv_reachable {s : State} (r : Reachable s) : Inv s := by
  induction r with
  | start => exact inv_start
  | step _ st ih => exact inv_step ih st

/-- No instant with two readers of one UDP flow. -/
theorem single_reader {s : State} (r : Reachable s) :
    ¬ (s.oldReads = true ∧ s.newReads = true) := by
  intro ⟨ho, hn⟩
  have h := inv_reachable r
  have ⟨ha, hd⟩ := h.reads hn
  have := h.quiet ha hd
  simp_all

/-- No instant without an acceptor on a listener, except after the replacement
    acknowledged the cutover and then died. -/
theorem always_an_acceptor {s : State} (r : Reachable s) :
    s.oldAccepts = true ∨ s.newAccepts = true ∨
      (s.doneSent = true ∧ s.newAlive = false) := by
  have h := inv_reachable r
  by_cases hp : s.phase = .released
  · have hd := h.acked hp
    cases ha : s.newAlive with
    | true => exact Or.inr (Or.inl (h.armed ha hd))
    | false => exact Or.inr (Or.inr ⟨hd, rfl⟩)
  · exact Or.inl (h.accepts hp)

/-- The old process stops accepting only after DONE was written. -/
theorem old_stops_only_after_done {s : State} (r : Reachable s)
    (stopped : s.oldAccepts = false) : s.doneSent = true := by
  have h := inv_reachable r
  by_cases hp : s.phase = .released
  · exact h.acked hp
  · have := h.accepts hp
    simp_all

/-- The replacement reads no UDP socket before it wrote DONE. -/
theorem new_reads_after_done {s : State} (r : Reachable s)
    (reads : s.newReads = true) : s.doneSent = true :=
  ((inv_reachable r).reads reads).2

/-- The old process reads UDP whenever no handoff has passed READY. -/
theorem old_reads_before_ready {s : State} (r : Reachable s)
    (early : s.phase = .serving ∨ s.phase = .offered) : s.oldReads = true :=
  (inv_reachable r).serves early

/-- A replacement that is dead before the old process released leaves a step
    after which the old process accepts and reads again, in the first phase. -/
theorem failure_returns_service {s : State} (r : Reachable s)
    (dead : s.newAlive = false) (early : s.phase ≠ .released) :
    ∃ t, Step s t ∧ t.phase = .serving ∧ t.oldAccepts = true ∧ t.oldReads = true := by
  refine ⟨_, Step.resume s early dead, rfl, ?_, rfl⟩
  exact (inv_reachable r).accepts early

/-- After that step the state is one a fresh handoff can start from: a second
    replacement may connect. -/
theorem retry_is_possible {s : State} (dead : s.newAlive = false)
    (early : s.phase ≠ .released) :
    ∃ t u, Step s t ∧ Step t u ∧ u.phase = .offered ∧ u.newAlive = true :=
  ⟨_, _, Step.resume s early dead, Step.offer _ rfl, rfl, rfl⟩
