/-!
# Formal Model of Automatic HTTPS (SID 0021)

A model of the algorithms of SID 0021, checked with Lean 4.19.0.

1. Order: a phase moves forward only, every step of a live order takes budget or ends it, and an order is over after a bounded number of steps whatever the authority answers.
2. Renewal: the renewal time of a certificate lies after its issue and strictly before its expiry.
3. Retry: the delay after a failure is at least the first delay, at most one day, and monotone in the number of consecutive failures.
4. Installing: a failed order leaves the served certificate unchanged, a served name keeps a certificate, and the expiry of a served certificate never decreases.
5. Issuer: every name has one issuer, a public authority is never asked for an internal name or an address, and no name is refused when the frontend states no issuer.
6. Wildcard: `*.parent` covers a host of exactly one more label, neither the parent nor a deeper host, and an exact certificate wins over a wildcard, which wins over a file.
7. Propagation: the check of DNS-01 asks a bounded number of times, pauses no longer than the timeout in total, and succeeds when the record shows in time.

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

/-! ## Part E: The issuer of a name -/

/-- What an `auto` name is. -/
inductive NameKind where
  | publicName | internalName | address
  deriving DecidableEq, Repr

/-- `tls.issuer` of the frontend. -/
inductive Setting where
  | absent | acme | internal
  deriving DecidableEq, Repr

/-- Who issues, or the refusal of the configuration check. -/
inductive Issuer where
  | acme | localAuthority | refused
  deriving DecidableEq, Repr

/-- The choice of SID 0021. `publicDirectory` says that `global.acme.directory` is a public authority. -/
def choose (publicDirectory : Bool) : Setting → NameKind → Issuer
  | .internal, _ => .localAuthority
  | .acme, .address => .refused
  | .acme, .internalName => if publicDirectory then .refused else .acme
  | .acme, .publicName => .acme
  | .absent, .address => .localAuthority
  | .absent, .internalName => if publicDirectory then .localAuthority else .acme
  | .absent, .publicName => .acme

/-- Without a stated issuer no name is refused: `auto: ["localhost"]` works with no other setting. -/
theorem absent_never_refuses (d : Bool) (k : NameKind) : choose d .absent k ≠ .refused := by
  cases d <;> cases k <;> simp [choose]

/-- A public authority is never asked for an internal name or an address. -/
theorem public_authority_gets_public_names_only (s : Setting) (k : NameKind)
    (h : choose true s k = .acme) : k = .publicName := by
  cases s <;> cases k <;> simp [choose] at h <;> rfl

/-- No ACME authority is asked for an address, whatever the directory. -/
theorem address_never_ordered (d : Bool) (s : Setting) : choose d s .address ≠ .acme := by
  cases d <;> cases s <;> simp [choose]

/-- `issuer: "internal"` always means the local authority. -/
theorem internal_setting_is_local (d : Bool) (k : NameKind) :
    choose d .internal k = .localAuthority := by
  cases k <;> rfl

/-- A public name goes to the ACME authority unless the frontend says `internal`. -/
theorem public_name_is_ordered (d : Bool) (s : Setting) (h : s ≠ .internal) :
    choose d s .publicName = .acme := by
  cases s
  · rfl
  · rfl
  · exact absurd rfl h

/-! ## Part F: Wildcards -/

/-- A host name as its labels, the leftmost first. -/
abbrev Host := List String

/-- Whether the wildcard `*.parent` covers `host`: the host is one label and then the parent. -/
def covers (parent host : Host) : Bool :=
  match host with
  | [] => false
  | _ :: rest => decide (rest = parent)

/-- `*.example.org` covers `a.example.org`. -/
theorem covers_one_label (label : String) (parent : Host) :
    covers parent (label :: parent) = true := by
  simp [covers]

/-- `*.example.org` does not cover `example.org`. -/
theorem covers_not_parent (parent : Host) : covers parent parent = false := by
  cases parent with
  | nil => rfl
  | cons head tail =>
    simp only [covers, decide_eq_false_iff_not]
    intro same
    have lengths := congrArg List.length same
    simp at lengths

/-- `*.example.org` does not cover `a.b.example.org`. -/
theorem covers_not_two_labels (a b : String) (parent : Host) :
    covers parent (a :: b :: parent) = false := by
  simp only [covers, decide_eq_false_iff_not]
  intro same
  have lengths := congrArg List.length same
  simp at lengths

/-- A covered host has exactly one label more than the parent. -/
theorem covered_length (parent host : Host) (h : covers parent host = true) :
    host.length = parent.length + 1 := by
  cases host with
  | nil => simp [covers] at h
  | cons head rest =>
    simp only [covers, decide_eq_true_eq] at h
    simp [h]

/-- The certificate of a handshake: the automatic certificate of the exact name, else that of the wildcard, else the one from a file. -/
def selectCert (exact wildcard file : Option Cert) : Option Cert :=
  match exact, wildcard with
  | some c, _ => some c
  | none, some c => some c
  | none, none => file

/-- An exact automatic certificate wins. -/
theorem exact_wins (c : Cert) (wildcard file : Option Cert) :
    selectCert (some c) wildcard file = some c := rfl

/-- Without an exact one, the automatic wildcard wins over the file. -/
theorem wildcard_wins_over_file (c : Cert) (file : Option Cert) :
    selectCert none (some c) file = some c := rfl

/-- Without an automatic certificate the file decides, as before SID 0021. -/
theorem file_decides_otherwise (file : Option Cert) : selectCert none none file = file := rfl

/-! ## Part G: The propagation check of DNS-01 -/

/-- The rounds of the check: one at once, and one after each pause that fits into the timeout. -/
def rounds (timeout pause : Nat) : Nat := timeout / pause + 1

/-- Asks round after round. Returns whether the record showed, and the rounds that were asked. `visible n` says whether every server shows the record in round `n`. -/
def check (visible : Nat → Bool) : (fuel asked : Nat) → Bool × Nat
  | 0, asked => (false, asked)
  | fuel + 1, asked => if visible asked then (true, asked + 1) else check visible fuel (asked + 1)

/-- The check asks at most as many times as it has rounds. -/
theorem check_bounded (visible : Nat → Bool) (fuel asked : Nat) :
    (check visible fuel asked).2 ≤ asked + fuel := by
  induction fuel generalizing asked with
  | zero => simp [check]
  | succ n ih =>
    simp only [check]
    split
    · simp
    · have := ih (asked + 1)
      omega

/-- With the timeout of the configuration the check asks at most `timeout / pause + 1` times. -/
theorem check_asks_at_most (visible : Nat → Bool) (timeout pause : Nat) :
    (check visible (rounds timeout pause) 0).2 ≤ timeout / pause + 1 := by
  have := check_bounded visible (rounds timeout pause) 0
  simp only [rounds] at *
  omega

/-- The pauses between the rounds take no longer than the timeout in total. -/
theorem pauses_fit_the_timeout (timeout pause : Nat) :
    (rounds timeout pause - 1) * pause ≤ timeout := by
  simp only [rounds, Nat.add_sub_cancel]
  exact Nat.div_mul_le_self timeout pause

/-- A record that shows in a round the check reaches is found. -/
theorem check_finds (visible : Nat → Bool) (fuel asked n : Nat)
    (shown : visible n = true) (after : asked ≤ n) (inTime : n < asked + fuel) :
    (check visible fuel asked).1 = true := by
  induction fuel generalizing asked with
  | zero => omega
  | succ k ih =>
    simp only [check]
    split
    · rfl
    · rename_i hidden
      have differs : asked ≠ n := by
        intro same
        rw [same] at hidden
        exact hidden shown
      exact ih (asked + 1) (by omega) (by omega)

/-- A record that never shows fails the check: the authority is not asked to validate. -/
theorem check_fails_when_hidden (visible : Nat → Bool) (fuel asked : Nat)
    (hidden : ∀ n, visible n = false) : (check visible fuel asked).1 = false := by
  induction fuel generalizing asked with
  | zero => rfl
  | succ k ih =>
    simp only [check, hidden asked]
    exact ih (asked + 1)

/-! ## Part H: Issuance on demand -/

/-- The bucket of tokens: one new certificate takes one token. -/
structure Bucket where
  capacity : Nat
  tokens : Nat

/-- The bucket gains tokens with time, to at most its capacity. -/
def Bucket.refill (b : Bucket) (gained : Nat) : Bucket :=
  { b with tokens := min b.capacity (b.tokens + gained) }

/-- Takes one token. Returns whether there was one, and the bucket afterwards. -/
def Bucket.take (b : Bucket) : Bool × Bucket :=
  if b.tokens = 0 then (false, b) else (true, { b with tokens := b.tokens - 1 })

/-- One name asks for a token after the bucket gained `gained` tokens. -/
def Bucket.step (b : Bucket) (gained : Nat) : Bool × Bucket := (b.refill gained).take

/-- The orders that a run admits. Each element is the gain before one name asks. -/
def admitted : Bucket → List Nat → Nat
  | _, [] => 0
  | b, gained :: rest =>
    (if (b.step gained).1 then 1 else 0) + admitted (b.step gained).2 rest

/-- A refill never exceeds the capacity. -/
theorem refill_within (b : Bucket) (gained : Nat) : (b.refill gained).tokens ≤ b.capacity := by
  simp only [Bucket.refill]
  exact Nat.min_le_left _ _

/-- A take leaves the bucket within its capacity. -/
theorem take_within (b : Bucket) (h : b.tokens ≤ b.capacity) :
    b.take.2.tokens ≤ b.take.2.capacity := by
  unfold Bucket.take
  split
  · exact h
  · simp only
    omega

/-- An empty bucket admits nothing: the tokens never go below zero. -/
theorem empty_bucket_refuses (b : Bucket) (h : b.tokens = 0) : b.take.1 = false := by
  simp [Bucket.take, h]

/-- A step conserves tokens: what it admits and what it leaves is at most what the bucket had and gained. -/
theorem step_conserves (b : Bucket) (gained : Nat) :
    (if (b.step gained).1 then 1 else 0) + (b.step gained).2.tokens ≤ b.tokens + gained := by
  have within : (b.refill gained).tokens ≤ b.tokens + gained := by
    simp only [Bucket.refill]
    exact Nat.min_le_right _ _
  unfold Bucket.step Bucket.take
  split
  · simp only [Bool.false_eq_true, if_false]
    omega
  · simp only [if_true]
    omega

/-- Over any run the admitted orders are at most the tokens at its start plus the tokens gained. -/
theorem admitted_bounded (b : Bucket) (gains : List Nat) :
    admitted b gains ≤ b.tokens + gains.sum := by
  induction gains generalizing b with
  | nil => simp [admitted]
  | cons gained rest ih =>
    simp only [admitted, List.sum_cons]
    have step := step_conserves b gained
    have tail := ih (b.step gained).2
    omega

/-- A bucket that starts full admits at most its capacity plus the refills. -/
theorem full_bucket_admits_at_most (capacity : Nat) (gains : List Nat) :
    admitted { capacity := capacity, tokens := capacity } gains ≤ capacity + gains.sum :=
  admitted_bounded _ gains

/-- What the guards say about one name. The first four read memory, in the handshake. The last three take time, in the thread. -/
structure Guards where
  /-- A plain host name: no address, no wildcard, at most 253 bytes. -/
  hostName : Bool
  /-- A suffix of `allow` covers the name, or the file has no list. -/
  suffix : Bool
  /-- The name is not denied at the moment. -/
  notDenied : Bool
  /-- The held names and the queue have room. -/
  room : Bool
  /-- The storage has a fresh certificate. -/
  stored : Bool
  /-- The `ask` URL allows the name, or the file has no URL. -/
  asked : Bool
  /-- The bucket has a token. -/
  token : Bool

/-- What becomes of a name that a handshake asks for. -/
inductive Demand where
  | notQueued
  | denied
  | loaded
  | ordered
  deriving DecidableEq

/-- The decision. `guarded` says that the file has `ask` or `allow`. The daemon refuses a file without. -/
def decide (guarded : Bool) (g : Guards) : Demand :=
  if !(guarded && g.hostName && g.suffix && g.notDenied && g.room) then .notQueued
  else if g.stored then .loaded
  else if !(g.asked && g.token) then .denied
  else .ordered

/-- An order is placed only when the file has a guard and every guard passes. -/
theorem ordered_passed_every_guard (guarded : Bool) (g : Guards)
    (h : decide guarded g = .ordered) :
    guarded = true ∧ g.hostName = true ∧ g.suffix = true ∧ g.notDenied = true ∧ g.room = true
      ∧ g.asked = true ∧ g.token = true := by
  unfold decide at h
  cases guarded <;> cases hn : g.hostName <;> cases sf : g.suffix <;> cases nd : g.notDenied
    <;> cases rm : g.room <;> cases st : g.stored <;> cases ak : g.asked <;> cases tk : g.token
    <;> simp_all

/-- Without a guard in the file nothing is ordered and nothing is loaded. -/
theorem unguarded_orders_nothing (g : Guards) : decide false g = .notQueued := by
  simp [decide]

/-- A name that the `ask` URL refuses is never ordered. -/
theorem refused_by_ask_is_not_ordered (guarded : Bool) (g : Guards) (h : g.asked = false) :
    decide guarded g ≠ .ordered := by
  intro ordered
  have := ordered_passed_every_guard guarded g ordered
  simp_all

/-- A name without a token is never ordered. -/
theorem without_token_is_not_ordered (guarded : Bool) (g : Guards) (h : g.token = false) :
    decide guarded g ≠ .ordered := by
  intro ordered
  have := ordered_passed_every_guard guarded g ordered
  simp_all

/-- What happens to the tables of issuance on demand. -/
inductive TableEvent where
  /-- A handshake asks for a new name. -/
  | request
  /-- The thread holds a queued name. -/
  | hold
  /-- The thread denies a queued name. -/
  | deny
  /-- A held name is released. -/
  | release

/-- The tables as two counts: the held names and the queued names. -/
def tableStep (bound : Nat) (s : Nat × Nat) : TableEvent → Nat × Nat
  | .request => if s.1 + s.2 < bound then (s.1, s.2 + 1) else s
  | .hold => if s.2 = 0 then s else (s.1 + 1, s.2 - 1)
  | .deny => (s.1, s.2 - 1)
  | .release => (s.1 - 1, s.2)

/-- No event takes the held names and the queue together over the bound. -/
theorem table_step_within (bound : Nat) (s : Nat × Nat) (e : TableEvent)
    (h : s.1 + s.2 ≤ bound) : (tableStep bound s e).1 + (tableStep bound s e).2 ≤ bound := by
  cases e <;> simp only [tableStep]
  · split <;> first | omega | (simp at *; omega)
  · split <;> first | omega | (simp at *; omega)
  · omega
  · omega

/-- After any run of events the daemon holds at most `bound` names. -/
theorem table_within (bound : Nat) (events : List TableEvent) (s : Nat × Nat)
    (h : s.1 + s.2 ≤ bound) : (events.foldl (tableStep bound) s).1 ≤ bound := by
  induction events generalizing s with
  | nil =>
    simp only [List.foldl]
    omega
  | cons e rest ih =>
    simp only [List.foldl]
    exact ih (tableStep bound s e) (table_step_within bound s e h)

end SibunaAcme
