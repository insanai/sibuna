/-!
# Formal Model of Automatic HTTPS (SID 0021)

A model of the four algorithms of SID 0021, checked with Lean 4.19.0.

1. Order: a phase moves forward only, every step of a live order takes budget or ends it, and an order is over after a bounded number of steps whatever the authority answers.
2. Renewal: the renewal time of a certificate lies after its issue and strictly before its expiry.
3. Retry: the delay after a failure is at least the first delay, at most one day, and monotone in the number of consecutive failures.
4. Installing: a failed order leaves the served certificate unchanged, a served name keeps a certificate, and the expiry of a served certificate never decreases.

Times are natural numbers of seconds. The JSON documents, the signatures, the sockets and the files are outside the model. Tests cover them.
-/

namespace SibunaAcme

/-! ## Part A: The order -/

/-- The phases of one order, in the order of RFC 8555. -/
inductive Phase where
  | directory | nonce | account | newOrder | authorization | present | respond
  | pollAuthorization | finalize | pollOrder | download | done | failed
  deriving DecidableEq, Repr

/-- The position of a phase. `done` and `failed` are the last ones. -/
def rank : Phase → Nat
  | .directory => 0 | .nonce => 1 | .account => 2 | .newOrder => 3
  | .authorization => 4 | .present => 5 | .respond => 6 | .pollAuthorization => 7
  | .finalize => 8 | .pollOrder => 9 | .download => 10 | .done => 11 | .failed => 12

/-- The phase after a good answer. -/
def next : Phase → Phase
  | .directory => .nonce | .nonce => .account | .account => .newOrder
  | .newOrder => .authorization | .authorization => .present | .present => .respond
  | .respond => .pollAuthorization | .pollAuthorization => .finalize
  | .finalize => .pollOrder | .pollOrder => .download | .download => .done
  | .done => .done | .failed => .failed

/-- The phase after an authorization that is already valid. Elsewhere a skip is a good
answer. -/
def skipped : Phase → Phase
  | .authorization => .finalize
  | p => next p

/-- An order that sends nothing more. -/
def terminal (p : Phase) : Bool := p == .done || p == .failed

/-- A phase that may repeat its request: the two polls, and any request after `badNonce`. -/
def repeats (p : Phase) : Bool := !terminal p

/-- What the authority answered, as far as the machine cares. -/
inductive Reply where
  | good      -- the phase is complete
  | skip      -- the authorization is already valid: no challenge is needed
  | again     -- pending, processing or badNonce: repeat
  | bad       -- an error, an invalid object or a broken bound
  deriving DecidableEq, Repr

/-- An order: its phase and the requests it may still send. -/
structure Order where
  phase : Phase
  budget : Nat
  deriving Repr

/-- One answer of the authority. Every request takes one unit of budget. -/
def step (o : Order) (r : Reply) : Order :=
  if terminal o.phase then o
  else match o.budget with
    | 0 => { o with phase := .failed }
    | b + 1 =>
      match r with
      | .good => { phase := next o.phase, budget := b }
      | .skip => { phase := skipped o.phase, budget := b }
      | .again => { phase := o.phase, budget := b }
      | .bad => { phase := .failed, budget := b }

/-- The order after a sequence of answers. -/
def run (o : Order) : List Reply → Order
  | [] => o
  | r :: rs => run (step o r) rs

theorem rank_next (p : Phase) : rank p ≤ rank (next p) := by
  cases p <;> simp [rank, next]

theorem rank_skipped (p : Phase) : rank p ≤ rank (skipped p) := by
  cases p <;> simp [rank, skipped, next]

theorem rank_le_failed (p : Phase) : rank p ≤ rank .failed := by
  cases p <;> simp [rank]

/-- A step never moves a phase backwards. -/
theorem step_forward (o : Order) (r : Reply) : rank o.phase ≤ rank (step o r).phase := by
  unfold step
  split
  · exact Nat.le_refl _
  · split
    · exact rank_le_failed _
    · cases r
      · exact rank_next _
      · exact rank_skipped _
      · exact Nat.le_refl _
      · exact rank_le_failed _

/-- A terminal order stays as it is. -/
theorem step_terminal (o : Order) (r : Reply) (h : terminal o.phase = true) : step o r = o := by
  simp [step, h]

/-- Every step of a live order takes budget, or ends the order. -/
theorem step_spends (o : Order) (r : Reply) (h : terminal o.phase = false) :
    terminal (step o r).phase = true ∨ (step o r).budget + 1 = o.budget := by
  unfold step
  simp [h]
  split
  · left; rfl
  · rename_i b hb
    cases r <;> simp [hb]

/-- An order of budget `n` is over after `n + 1` answers, whatever they are. -/
theorem run_ends (replies : List Reply) :
    ∀ o : Order, o.budget < replies.length → terminal (run o replies).phase = true := by
  induction replies with
  | nil => intro o h; simp at h
  | cons r rs ih =>
    intro o h
    simp only [run]
    cases ht : terminal o.phase with
    | true =>
      rw [step_terminal o r ht]
      cases rs with
      | nil => simpa [run] using ht
      | cons r' rs' =>
        have keep : ∀ (l : List Reply), run o l = o := by
          intro l
          induction l with
          | nil => rfl
          | cons x xs ihx => simp [run, step_terminal o x ht, ihx]
        rw [keep]; exact ht
    | false =>
      rcases step_spends o r ht with hterm | hbudget
      · have keep : ∀ (l : List Reply), run (step o r) l = step o r := by
          intro l
          induction l with
          | nil => rfl
          | cons x xs ihx => simp [run, step_terminal (step o r) x hterm, ihx]
        rw [keep]; exact hterm
      · apply ih
        simp only [List.length_cons] at h
        omega

/-- `done` is entered from `download` by a good answer, and from nowhere else. -/
-- (A skip in `download` is a good answer.)
theorem done_from_download (o : Order) (r : Reply) (h : (step o r).phase = .done) :
    o.phase = .done ∨ (o.phase = .download ∧ (r = .good ∨ r = .skip)) := by
  unfold step at h
  split at h
  · left; exact h
  · rename_i live
    split at h
    · simp at h
    · cases r
      · right
        refine ⟨?_, Or.inl rfl⟩
        cases hp : o.phase <;> simp [hp, next, terminal] at h live ⊢
      · right
        refine ⟨?_, Or.inr rfl⟩
        cases hp : o.phase <;> simp [hp, next, skipped, terminal] at h live ⊢
      · left; exact h
      · simp at h

/-! ## Part B: The renewal time -/

/-- A certificate valid from `issued` to `expires` is renewed when a third of its life
remains. -/
def renewAt (issued expires : Nat) : Nat := issued + 2 * (expires - issued) / 3

/-- The renewal is due strictly before the expiry, and not before the issue. -/
theorem renew_in_life (issued expires : Nat) (h : issued < expires) :
    issued ≤ renewAt issued expires ∧ renewAt issued expires < expires := by
  unfold renewAt
  omega

/-- A certificate with no life is due at once. -/
theorem renew_degenerate (issued expires : Nat) (h : expires ≤ issued) :
    renewAt issued expires = issued := by
  unfold renewAt
  omega

/-! ## Part C: The retry delay -/

/-- The first delay, in seconds. -/
def base : Nat := 120

/-- The longest delay: one day. -/
def cap : Nat := 86400

/-- The delay after `failures` consecutive failures, counted from one. -/
def delay (failures : Nat) : Nat := min (base * 2 ^ (min (failures - 1) 10)) cap

theorem delay_bounded (n : Nat) : delay n ≤ cap := by
  unfold delay
  exact Nat.min_le_right _ _

theorem delay_at_least_base (n : Nat) : base ≤ delay n := by
  unfold delay
  have hpow : 1 ≤ 2 ^ (min (n - 1) 10) := Nat.one_le_two_pow
  have hbase : base ≤ base * 2 ^ (min (n - 1) 10) := Nat.le_mul_of_pos_right _ hpow
  have hcap : base ≤ cap := by decide
  exact Nat.le_min.mpr ⟨hbase, hcap⟩

/-- More failures never shorten the delay. -/
theorem delay_monotone (n m : Nat) (h : n ≤ m) : delay n ≤ delay m := by
  unfold delay
  have hexp : min (n - 1) 10 ≤ min (m - 1) 10 := by omega
  have hpow : 2 ^ (min (n - 1) 10) ≤ 2 ^ (min (m - 1) 10) :=
    Nat.pow_le_pow_right (by decide) hexp
  have hmul : base * 2 ^ (min (n - 1) 10) ≤ base * 2 ^ (min (m - 1) 10) :=
    Nat.mul_le_mul_left _ hpow
  exact Nat.le_min.mpr
    ⟨Nat.le_trans (Nat.min_le_left _ _) hmul, Nat.min_le_right _ _⟩

/-- The authority's `Retry-After` can lengthen the delay, up to one day. -/
def delayWith (failures retryAfter : Nat) : Nat := max (delay failures) (min retryAfter cap)

theorem delayWith_bounded (n r : Nat) : delayWith n r ≤ cap := by
  unfold delayWith
  exact Nat.max_le.mpr ⟨delay_bounded n, Nat.min_le_right _ _⟩

theorem delayWith_at_least_delay (n r : Nat) : delay n ≤ delayWith n r := by
  unfold delayWith
  exact Nat.le_max_left _ _

/-! ## Part D: Installing a certificate -/

/-- A certificate as the table sees it: its expiry, and whether it passed the checks
(it names the host, matches its key and is valid now). -/
structure Cert where
  expires : Nat
  sound : Bool
  deriving Repr

/-- How an order, or a look at the storage, ended. -/
inductive Outcome where
  | failed
  | issued (c : Cert)

/-- The certificate served after an outcome. A new certificate is installed when it is
sound and does not expire earlier than the served one. -/
def install (served : Option Cert) : Outcome → Option Cert
  | .failed => served
  | .issued c =>
    match served with
    | none => if c.sound then some c else none
    | some s => if c.sound && s.expires ≤ c.expires then some c else some s

/-- A failed order replaces nothing. -/
theorem failure_keeps (served : Option Cert) : install served .failed = served := rfl

/-- A served name never loses its certificate. -/
theorem served_stays (s : Cert) (o : Outcome) : (install (some s) o).isSome = true := by
  cases o with
  | failed => rfl
  | issued c =>
    simp only [install]
    split <;> rfl

/-- The expiry of the served certificate never decreases. -/
theorem expiry_monotone (s : Cert) (o : Outcome) :
    ∃ t, install (some s) o = some t ∧ s.expires ≤ t.expires := by
  cases o with
  | failed => exact ⟨s, rfl, Nat.le_refl _⟩
  | issued c =>
    simp only [install]
    split
    · rename_i h
      simp only [Bool.and_eq_true, decide_eq_true_eq] at h
      exact ⟨c, rfl, h.2⟩
    · exact ⟨s, rfl, Nat.le_refl _⟩

/-- Only a sound certificate is ever installed. -/
theorem installed_is_sound (served : Option Cert) (c t : Cert)
    (hs : ∀ s, served = some s → s.sound = true)
    (h : install served (.issued c) = some t) : t.sound = true := by
  cases served with
  | none =>
    simp only [install] at h
    split at h
    · rename_i hc
      cases h; exact hc
    · cases h
  | some s =>
    simp only [install] at h
    split at h
    · rename_i hc
      simp only [Bool.and_eq_true] at hc
      cases h; exact hc.1
    · have same := Option.some.inj h
      rw [← same]; exact hs s rfl

end SibunaAcme
