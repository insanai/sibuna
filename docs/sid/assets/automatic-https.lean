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
8. On demand: the token bucket never exceeds its capacity, the orders it admits are bounded, a name is ordered only after every guard, and the table of held names keeps its bound.
9. Authorities: one attempt asks the listed authorities in order, at most once each, stops at the first that issues, succeeds when one issues and fails when none does.
10. Renewal information: the pick lies in the window of the authority, the renewal time is at most four fifths of the lifetime and before the expiry, a window in the past is due at once, and a time inside our bounds is taken as it is.
11. Stapling: an OCSP response is stapled only inside its window and only when it says good, and the next question to the responder lies after now and inside the window.
12. Zone search: the search for the zone of a record at a DNS provider asks a bounded number of questions, fewer than the owner has labels, finds only a zone that the account has and that ends the owner, and finds the longest such zone.
13. Constraints: the empty list of the local root permits every name, a list permits exactly the names that an entry covers, a suffix covers at whole labels and never a shorter name, and a list of one kind of entry permits no name of the other kind.
14. Restart: the delay before the certificate thread starts again after a panic is at least five seconds, at most five minutes, and never shrinks.

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

/-! ## Part I: The authorities of one attempt -/

/-- One attempt asks `count` authorities in order, starting with the one at `first`.
`issues i` says whether the authority `i` issues. The result is the authority that
issued, if any, and the number of authorities that were asked. -/
def attempt (issues : Nat → Bool) : (count first : Nat) → Option Nat × Nat
  | 0, _ => (none, 0)
  | n + 1, i =>
    if issues i then (some i, 1)
    else ((attempt issues n (i + 1)).1, (attempt issues n (i + 1)).2 + 1)

/-- An attempt asks every authority at most once. -/
theorem attempt_asks_at_most (issues : Nat → Bool) (n i : Nat) :
    (attempt issues n i).2 ≤ n := by
  induction n generalizing i with
  | zero => exact Nat.le_refl 0
  | succ n ih =>
    simp only [attempt]
    split
    · show 1 ≤ n + 1
      omega
    · show (attempt issues n (i + 1)).2 + 1 ≤ n + 1
      have := ih (i + 1)
      omega

/-- The authority that issued is a listed one that issues. Every authority before it
failed, and the attempt stopped with it: nobody after it was asked. -/
theorem attempt_stops_at_the_first (issues : Nat → Bool) (n i k : Nat)
    (h : (attempt issues n i).1 = some k) :
    issues k = true ∧ i ≤ k ∧ k < i + n ∧ (∀ j, i ≤ j → j < k → issues j = false) ∧
      (attempt issues n i).2 = k - i + 1 := by
  induction n generalizing i with
  | zero => simp [attempt] at h
  | succ n ih =>
    simp only [attempt] at h ⊢
    by_cases hi : issues i = true
    · rw [if_pos hi] at h ⊢
      have hk : i = k := by simpa using h
      refine ⟨hk ▸ hi, by omega, by omega, ?_, ?_⟩
      · intro j h1 h2
        omega
      · show 1 = k - i + 1
        omega
    · rw [if_neg hi] at h ⊢
      have h' : (attempt issues n (i + 1)).1 = some k := h
      obtain ⟨a, b, c, d, e⟩ := ih (i + 1) h'
      refine ⟨a, by omega, by omega, ?_, ?_⟩
      · intro j h1 h2
        by_cases hj : j = i
        · rw [hj]
          simpa using hi
        · exact d j (by omega) h2
      · show (attempt issues n (i + 1)).2 + 1 = k - i + 1
        omega

/-- When no listed authority issues, the attempt fails after it asked all of them. -/
theorem attempt_fails_when_all_fail (issues : Nat → Bool) (n i : Nat)
    (h : ∀ j, i ≤ j → j < i + n → issues j = false) :
    attempt issues n i = (none, n) := by
  induction n generalizing i with
  | zero => rfl
  | succ n ih =>
    have hi : issues i = false := h i (Nat.le_refl _) (by omega)
    have rest := ih (i + 1) (fun j h1 h2 => h j (by omega) (by omega))
    simp [attempt, hi, rest]

/-- When a listed authority issues, the attempt succeeds. -/
theorem attempt_succeeds_when_one_issues (issues : Nat → Bool) (n i k : Nat)
    (h1 : i ≤ k) (h2 : k < i + n) (hk : issues k = true) :
    (attempt issues n i).1 ≠ none := by
  induction n generalizing i with
  | zero => omega
  | succ n ih =>
    by_cases hi : issues i = true
    · simp [attempt, hi]
    · have hne : k ≠ i := fun e => hi (e ▸ hk)
      simp only [attempt]
      rw [if_neg hi]
      exact ih (i + 1) (by omega) (by omega)

/-! ## Part J: Renewal information -/

/-- The time in the window `[s, e)` for a certificate whose serial hashes to `h`. -/
def pick (s e h : Nat) : Nat := if e ≤ s then s else s + h % (e - s)

/-- The pick lies in the window. -/
theorem pick_in_window (s e h : Nat) (hw : s < e) : s ≤ pick s e h ∧ pick s e h < e := by
  unfold pick
  rw [if_neg (by omega)]
  have := Nat.mod_lt h (show 0 < e - s by omega)
  omega

/-- The pick of an empty window is its start. -/
theorem pick_of_empty_window (s h : Nat) : pick s s h = s := by
  unfold pick
  rw [if_pos (Nat.le_refl s)]

/-- The latest renewal that an authority may ask for: four fifths of the lifetime. -/
def latest (b e : Nat) : Nat := b + (e - b) / 5 * 4

/-- The renewal time for a pick `p` and a floor `f`. -/
def ariRenew (b e p f : Nat) : Nat := min (max p f) (latest b e)

/-- The cap lies before the expiry. -/
theorem latest_before_expiry (b e : Nat) (h : b < e) : latest b e < e := by
  unfold latest
  omega

/-- No answer of the authority moves the renewal past the cap. -/
theorem ari_at_most_cap (b e p f : Nat) : ariRenew b e p f ≤ latest b e :=
  Nat.min_le_right _ _

/-- So no answer of the authority parks a certificate until it expires. -/
theorem ari_before_expiry (b e p f : Nat) (h : b < e) : ariRenew b e p f < e :=
  Nat.lt_of_le_of_lt (ari_at_most_cap b e p f) (latest_before_expiry b e h)

/-- A window in the past makes a loaded certificate, which has no floor, due at once. -/
theorem past_window_is_due (b e p now : Nat) (h : p ≤ now) : ariRenew b e p 0 ≤ now := by
  unfold ariRenew
  have : max p 0 = p := Nat.max_eq_left (Nat.zero_le p)
  rw [this]
  exact Nat.le_trans (Nat.min_le_left _ _) h

/-- A certificate that was just obtained is not renewed before its floor, unless the
cap comes first. -/
theorem ari_respects_the_floor (b e p f : Nat) (h : f ≤ latest b e) :
    f ≤ ariRenew b e p f := by
  unfold ariRenew
  exact Nat.le_min.mpr ⟨Nat.le_max_right p f, h⟩

/-- An authority that asks for a time inside our bounds gets it. -/
theorem ari_follows_the_authority (b e p f : Nat) (h1 : f ≤ p) (h2 : p ≤ latest b e) :
    ariRenew b e p f = p := by
  unfold ariRenew
  rw [Nat.max_eq_left h1]
  exact Nat.min_eq_left h2

/-! ## Part K: OCSP stapling -/

/-- What a responder says about a certificate. -/
inductive OcspStatus where
  | good | revoked | unknown
  deriving DecidableEq, Repr

/-- Whether an answer with the status `st` and the window `[t, n)` is stapled at `now`. -/
def staples (st : OcspStatus) (t n now : Nat) : Bool :=
  if st = .good ∧ t ≤ now ∧ now < n then true else false

/-- A response is stapled only inside its window. -/
theorem stapled_inside_window (st : OcspStatus) (t n now : Nat)
    (h : staples st t n now = true) : t ≤ now ∧ now < n := by
  unfold staples at h
  split at h
  · rename_i hc
    exact hc.2
  · contradiction

/-- Only a good answer is stapled. -/
theorem stapled_is_good (st : OcspStatus) (t n now : Nat)
    (h : staples st t n now = true) : st = .good := by
  unfold staples at h
  split at h
  · rename_i hc
    exact hc.1
  · contradiction

/-- A revoked answer never staples. -/
theorem revoked_never_staples (t n now : Nat) : staples .revoked t n now = false := by
  unfold staples
  rw [if_neg]
  intro hc
  exact absurd hc.1 (by decide)

/-- An answer that does not know the certificate never staples. -/
theorem unknown_never_staples (t n now : Nat) : staples .unknown t n now = false := by
  unfold staples
  rw [if_neg]
  intro hc
  exact absurd hc.1 (by decide)

/-- When the responder is asked again, for an answer with the window `[t, n)` taken at
`now`: at the middle of the window, or, once that has passed, at half of the time that
is left, and one second later at least. -/
def refreshAt (t n now : Nat) : Nat :=
  if now < t + (n - t) / 2 then t + (n - t) / 2
  else if (n - now) / 2 = 0 then now + 1 else now + (n - now) / 2

/-- The next question lies after now: the thread does not ask in a loop. -/
theorem refresh_after_now (t n now : Nat) : now < refreshAt t n now := by
  unfold refreshAt
  split
  · assumption
  · split <;> omega

/-- The next question lies inside the window of an answer that is stapled. -/
theorem refresh_within_window (t n now : Nat) (h1 : t ≤ now) (h2 : now < n) :
    refreshAt t n now ≤ n := by
  unfold refreshAt
  split
  · omega
  · split <;> omega

/-- With two seconds left, the next question comes before the window ends: a new
response can replace the stapled one in time. -/
theorem refresh_before_the_end (t n now : Nat) (h1 : t ≤ now) (h2 : now + 2 ≤ n) :
    refreshAt t n now < n := by
  unfold refreshAt
  split
  · omega
  · split <;> omega

/-! ## Part L: The zone of a record at a DNS provider -/

/-- The names that may be the zone of a record, the longest first: the owner and its
parents down to two labels, `limit` at most. A name is its labels, the leftmost first. -/
def zoneCandidates : Nat → List Nat → List (List Nat)
  | 0, _ => []
  | _ + 1, [] => []
  | _ + 1, [_] => []
  | k + 1, a :: b :: rest => (a :: b :: rest) :: zoneCandidates k (b :: rest)

/-- The first candidate that the account has. `has` is the answer of the provider. -/
def firstKnown (has : List Nat → Bool) : List (List Nat) → Option (List Nat)
  | [] => none
  | z :: rest => if has z then some z else firstKnown has rest

/-- The zone that the search finds for an owner. -/
def findZone (has : List Nat → Bool) (limit : Nat) (owner : List Nat) : Option (List Nat) :=
  firstKnown has (zoneCandidates limit owner)

/-- The search asks at most `limit` questions. -/
theorem zone_questions_bounded (k : Nat) (l : List Nat) : (zoneCandidates k l).length ≤ k := by
  induction k generalizing l with
  | zero => simp [zoneCandidates]
  | succ k ih =>
    match l with
    | [] => simp [zoneCandidates]
    | [_] => simp [zoneCandidates]
    | a :: b :: rest =>
      simp only [zoneCandidates, List.length_cons]
      have := ih (b :: rest)
      omega

/-- The search asks fewer questions than the owner has labels. -/
theorem zone_questions_below_labels (k : Nat) (l : List Nat) :
    (zoneCandidates k l).length + 1 ≤ l.length ∨ zoneCandidates k l = [] := by
  induction k generalizing l with
  | zero => right; simp [zoneCandidates]
  | succ k ih =>
    match l with
    | [] => right; simp [zoneCandidates]
    | [_] => right; simp [zoneCandidates]
    | a :: b :: rest =>
      left
      simp only [zoneCandidates, List.length_cons]
      cases ih (b :: rest) with
      | inl h => simp only [List.length_cons] at h; omega
      | inr h => rw [h]; simp

/-- Every candidate ends the owner, has two labels at least, and is no longer than it. -/
theorem zone_candidate_is_parent (k : Nat) (l z : List Nat) (h : z ∈ zoneCandidates k l) :
    z <:+ l ∧ 2 ≤ z.length ∧ z.length ≤ l.length := by
  induction k generalizing l with
  | zero => simp [zoneCandidates] at h
  | succ k ih =>
    match l with
    | [] => simp [zoneCandidates] at h
    | [_] => simp [zoneCandidates] at h
    | a :: b :: rest =>
      simp only [zoneCandidates, List.mem_cons] at h
      cases h with
      | inl h =>
        subst h
        exact ⟨List.suffix_refl _, by simp, Nat.le_refl _⟩
      | inr h =>
        have ⟨hs, h2, hl⟩ := ih (b :: rest) h
        refine ⟨List.IsSuffix.trans hs (List.suffix_cons a (b :: rest)), h2, ?_⟩
        simp only [List.length_cons] at hl ⊢
        omega

/-- A zone that the search finds is one that the provider has. -/
theorem first_known_is_known (has : List Nat → Bool) (cs : List (List Nat)) (z : List Nat)
    (h : firstKnown has cs = some z) : has z = true ∧ z ∈ cs := by
  induction cs with
  | nil => simp [firstKnown] at h
  | cons c rest ih =>
    simp only [firstKnown] at h
    split at h
    · rename_i hc
      have hz : c = z := Option.some.inj h
      subst hz
      exact ⟨hc, List.mem_cons_self⟩
    · have ⟨h1, h2⟩ := ih h
      exact ⟨h1, List.mem_cons_of_mem c h2⟩

/-- The zone that the search finds is in the account and ends the owner. -/
theorem found_zone_is_known_parent (has : List Nat → Bool) (k : Nat) (l z : List Nat)
    (h : findZone has k l = some z) : has z = true ∧ z <:+ l := by
  have ⟨h1, h2⟩ := first_known_is_known has _ z h
  exact ⟨h1, (zone_candidate_is_parent k l z h2).1⟩

/-- The longest zone wins: no candidate that the provider has is longer than the zone
that the search finds. A record of `a.b.example.org` goes into the zone `b.example.org`
when the account has it, and not into `example.org`. -/
theorem longest_zone_wins (has : List Nat → Bool) (k : Nat) (l z z' : List Nat)
    (h : findZone has k l = some z) (hm : z' ∈ zoneCandidates k l) (hk : has z' = true) :
    z'.length ≤ z.length := by
  unfold findZone at h
  induction k generalizing l with
  | zero => simp [zoneCandidates] at hm
  | succ k ih =>
    match l with
    | [] => simp [zoneCandidates] at hm
    | [_] => simp [zoneCandidates] at hm
    | a :: b :: rest =>
      simp only [zoneCandidates, List.mem_cons] at hm
      simp only [zoneCandidates, firstKnown] at h
      split at h
      · have hz : a :: b :: rest = z := Option.some.inj h
        subst hz
        cases hm with
        | inl hm => subst hm; exact Nat.le_refl _
        | inr hm =>
          have := (zone_candidate_is_parent k (b :: rest) z' hm).2.2
          simp only [List.length_cons] at this ⊢
          omega
      · rename_i hc
        cases hm with
        | inl hm => subst hm; exact absurd hk hc
        | inr hm => exact ih (b :: rest) h hm

/-- A search that finds nothing asked about zones that the account does not have. -/
theorem no_zone_means_none_known (has : List Nat → Bool) (cs : List (List Nat))
    (h : firstKnown has cs = none) : ∀ c ∈ cs, has c = false := by
  induction cs with
  | nil => intro c hc; simp at hc
  | cons c rest ih =>
    simp only [firstKnown] at h
    split at h
    · contradiction
    · rename_i hc
      intro c' hc'
      cases List.mem_cons.mp hc' with
      | inl e => subst e; simpa using hc
      | inr e => exact ih h c' e

/-- `_acme-challenge.a.example.org` in an account that has `example.org` (labels as
numbers: 0 the challenge label, 1 `a`, 2 `example`, 3 `org`). -/
example : findZone (fun z => z == [2, 3]) 8 [0, 1, 2, 3] = some [2, 3] := by decide

/-- A name of one label is never asked about: a provider has no zone `org`. -/
example : zoneCandidates 8 [3] = [] := by decide

/-! ## Part M: The name constraints of the local root -/

/-- Whether the suffix `s` covers the host `h`. Both are lists of labels from the
top-level label down: `a.corp.internal` is `[internal, corp, a]`, so a suffix of the
name is a prefix of the list, and it ends at a label by construction. -/
def under : List Nat → List Nat → Bool
  | [], _ => true
  | _ :: _, [] => false
  | s :: ss, h :: hs => s == h && under ss hs

/-- An entry of `internal.constraints`: a DNS suffix, or a range of addresses with its
first address and its size. An address is a number. A range of size `k` starts at a
multiple of `k`. -/
inductive Entry where
  | suffix (labels : List Nat)
  | range (base size : Nat)

/-- What a certificate names: a host, or an address. -/
inductive Named where
  | host (labels : List Nat)
  | address (a : Nat)

/-- Whether one entry covers a name. A suffix covers hosts only, a range addresses only. -/
def covered : Entry → Named → Bool
  | .suffix s, .host h => under s h
  | .range b k, .address a => a / k == b / k
  | _, _ => false

/-- Whether the root may sign for a name: the empty list permits all, else an entry
must cover the name. -/
def permits (list : List Entry) (n : Named) : Bool :=
  list.isEmpty || list.any (fun e => covered e n)

/-- The empty list permits every name. -/
theorem empty_list_permits_all (n : Named) : permits [] n = true := by
  simp [permits]

/-- With a list, a name is permitted exactly when an entry covers it. -/
theorem permitted_iff_covered (e : Entry) (list : List Entry) (n : Named) :
    permits (e :: list) n = true ↔ ∃ x, x ∈ e :: list ∧ covered x n = true := by
  simp [permits, List.any_eq_true]

/-- A suffix covers itself. -/
theorem under_self (s : List Nat) : under s s = true := by
  induction s with
  | nil => simp [under]
  | cons a t ih => simp [under, ih]

/-- A suffix covers every name below a name that it covers. -/
theorem under_below (s h t : List Nat) (c : under s h = true) : under s (h ++ t) = true := by
  induction s generalizing h with
  | nil => simp [under]
  | cons a ss ih =>
    cases h with
    | nil => simp [under] at c
    | cons b hs =>
      simp [under] at c
      simp [under, c.1, ih hs c.2]

/-- A covered host has at least the labels of the suffix: `internal` is not covered by
`corp.internal`. -/
theorem under_is_no_shorter (s h : List Nat) (c : under s h = true) : s.length ≤ h.length := by
  induction s generalizing h with
  | nil => simp
  | cons a ss ih =>
    cases h with
    | nil => simp [under] at c
    | cons b hs =>
      simp [under] at c
      have := ih hs c.2
      simp
      omega

/-- The cover compares whole labels: `evilcorp.internal` is not under `corp.internal`. -/
theorem under_compares_labels (a b : Nat) (ss hs : List Nat)
    (c : under (a :: ss) (b :: hs) = true) : a = b := by
  simp [under] at c
  exact c.1

/-- A list of suffixes only permits no address. -/
theorem suffixes_close_addresses (list : List Entry) (a : Nat) (e : Entry)
    (h : ∀ x, x ∈ e :: list → ∃ s, x = .suffix s) :
    permits (e :: list) (.address a) = false := by
  simp only [permits, List.isEmpty_cons, Bool.false_or]
  apply Bool.eq_false_iff.mpr
  intro c
  rw [List.any_eq_true] at c
  obtain ⟨x, hx, hc⟩ := c
  obtain ⟨s, rfl⟩ := h x hx
  simp [covered] at hc

/-- A list of ranges only permits no host. -/
theorem ranges_close_hosts (list : List Entry) (l : List Nat) (e : Entry)
    (h : ∀ x, x ∈ e :: list → ∃ b k, x = .range b k) :
    permits (e :: list) (.host l) = false := by
  simp only [permits, List.isEmpty_cons, Bool.false_or]
  apply Bool.eq_false_iff.mpr
  intro c
  rw [List.any_eq_true] at c
  obtain ⟨x, hx, hc⟩ := c
  obtain ⟨b, k, rfl⟩ := h x hx
  simp [covered] at hc

/-- A range covers its own first address. -/
theorem range_covers_its_base (b k : Nat) : covered (.range b k) (.address b) = true := by
  simp [covered]

/-- `a.corp.internal` (labels 1, 2, 3 from the top) under `corp.internal`: permitted.
`evilcorp.internal` (labels 1, 4) is not, and an address in 10/8 of a toy space is. -/
example : permits [.suffix [1, 2], .range 160 16] (.host [1, 2, 3]) = true := by decide
example : permits [.suffix [1, 2], .range 160 16] (.host [1, 4]) = false := by decide
example : permits [.suffix [1, 2], .range 160 16] (.address 171) = true := by decide
example : permits [.suffix [1, 2], .range 160 16] (.address 176) = false := by decide

/-! ## Part N: The restart of the certificate thread -/

/-- The seconds before the restart after the `n`-th panic in a row, from 1. -/
def restartDelay (n : Nat) : Nat :=
  min (5 * 2 ^ (min (n - 1) 16)) 300

/-- The delay is at least five seconds. -/
theorem restart_at_least_five (n : Nat) : 5 ≤ restartDelay n := by
  have h : 1 ≤ 2 ^ (min (n - 1) 16) := Nat.one_le_two_pow
  simp only [restartDelay]
  omega

/-- The delay is at most five minutes. -/
theorem restart_at_most_five_minutes (n : Nat) : restartDelay n ≤ 300 := by
  simp only [restartDelay]
  omega

/-- The delay never shrinks as the panics go on. -/
theorem restart_monotone (n m : Nat) (h : n ≤ m) : restartDelay n ≤ restartDelay m := by
  have e : min (n - 1) 16 ≤ min (m - 1) 16 := by omega
  have p : 2 ^ (min (n - 1) 16) ≤ 2 ^ (min (m - 1) 16) :=
    Nat.pow_le_pow_right (by decide) e
  simp only [restartDelay]
  omega

/-- The first delays: 5, 10, 20, 40, 80, 160, then 300. -/
example : (List.range 9).map (fun n => restartDelay (n + 1)) =
    [5, 10, 20, 40, 80, 160, 300, 300, 300] := by decide

end SibunaAcme
