/-
  SID 0035, post-quantum key exchange. Core Lean 4, no libraries.

  Two parts carry the design.

  1. The layout of a hybrid share and secret: the post-quantum half, then the classical
     half. Splitting by the known lengths gives back both halves, and a share of any other
     length is refused (invariants 1 and 4).

  2. The choice of a group by a TLS server: the first group in the client's list that the
     server supports and that is usable for the version. The hybrid group is never usable
     for TLS 1.2, and adding it to the server never changes the choice for a client that
     does not offer it (invariants 2 and 3).
-/

/-! ## Layout -/

/-- The lengths of a hybrid share: the post-quantum half and the classical half. -/
structure Layout where
  pq : Nat
  classical : Nat

/-- A share or secret: the post-quantum half first, as X25519MLKEM768 orders them. -/
def concat (pq classical : List Nat) : List Nat := pq ++ classical

/-- Splits a received share, refusing one of the wrong length. -/
def split (l : Layout) (share : List Nat) : Option (List Nat × List Nat) :=
  if share.length = l.pq + l.classical then
    some (share.take l.pq, share.drop l.pq)
  else
    none

/-- Splitting what `concat` built, with matching lengths, gives back both halves. -/
theorem split_concat (l : Layout) (pq classical : List Nat)
    (hp : pq.length = l.pq) (hc : classical.length = l.classical) :
    split l (concat pq classical) = some (pq, classical) := by
  have hlen : (concat pq classical).length = l.pq + l.classical := by
    simp [concat, hp, hc]
  simp only [split, hlen, if_true, concat]
  rw [← hp]
  simp [hc]

/-- A share of any other length is refused. -/
theorem split_wrong_length (l : Layout) (share : List Nat)
    (h : share.length ≠ l.pq + l.classical) : split l share = none := by
  simp [split, h]

/-- Whoever holds the combined secret holds each half: the post-quantum half is its
    prefix and the classical half its suffix. So learning the secret of a session means
    breaking both components, not one. -/
theorem secret_reveals_halves (pq classical : List Nat) :
    (concat pq classical).take pq.length = pq ∧
    (concat pq classical).drop pq.length = classical := by
  simp [concat]

/-! ## Selection -/

/-- The groups that matter here. -/
inductive Group where
  | hybrid
  | x25519
  | p256
  | p384
  deriving DecidableEq

inductive Version where
  | tls12
  | tls13
  deriving DecidableEq

/-- A key encapsulation has no place in TLS 1.2. -/
def usable : Group → Version → Bool
  | .hybrid, .tls12 => false
  | _, _ => true

/-- The server's choice: the first group of the client that the server supports and that
    is usable for the version, as rustls 0.23 chooses (`choose_suite_and_kx_group`). -/
def select (server : List Group) (v : Version) : List Group → Option Group
  | [] => none
  | g :: rest => if g ∈ server ∧ usable g v = true then some g else select server v rest

/-- The selected group is offered by the client, supported by the server and usable. -/
theorem selected_is_mutual (server client : List Group) (v : Version) (g : Group)
    (h : select server v client = some g) :
    g ∈ client ∧ g ∈ server ∧ usable g v = true := by
  induction client with
  | nil => simp [select] at h
  | cons c rest ih =>
    simp only [select] at h
    by_cases hc : c ∈ server ∧ usable c v = true
    · simp only [hc, and_self, if_true, Option.some.injEq] at h
      subst h
      exact ⟨List.mem_cons_self .., hc.1, hc.2⟩
    · simp only [hc, if_false] at h
      have := ih h
      exact ⟨List.mem_cons_of_mem _ this.1, this.2⟩

/-- The hybrid group is never selected for TLS 1.2. -/
theorem never_hybrid_on_tls12 (server client : List Group) :
    select server .tls12 client ≠ some .hybrid := by
  intro h
  have := (selected_is_mutual server client .tls12 .hybrid h).2.2
  simp [usable] at this

/-- For a client that does not offer the hybrid group, adding it to the server changes no
    selection: a classical client negotiates what it negotiated before. -/
theorem classical_client_unchanged (server client : List Group) (v : Version)
    (h : Group.hybrid ∉ client) :
    select (.hybrid :: server) v client = select server v client := by
  induction client with
  | nil => rfl
  | cons c rest ih =>
    have hc : c ≠ .hybrid := fun e => h (e ▸ List.mem_cons_self ..)
    have hr : Group.hybrid ∉ rest := fun m => h (List.mem_cons_of_mem _ m)
    have hmem : (c ∈ Group.hybrid :: server) = (c ∈ server) := by
      simp [List.mem_cons, hc]
    simp only [select, hmem, ih hr]

/-- A selection that succeeded still succeeds when the server adds a group. -/
theorem adding_keeps_success (server client : List Group) (v : Version) (extra : Group)
    (g : Group) (h : select server v client = some g) :
    ∃ g', select (extra :: server) v client = some g' := by
  induction client with
  | nil => simp [select] at h
  | cons c rest ih =>
    simp only [select] at h ⊢
    by_cases hc : c ∈ server ∧ usable c v = true
    · have : c ∈ extra :: server ∧ usable c v = true := ⟨List.mem_cons_of_mem _ hc.1, hc.2⟩
      exact ⟨c, by simp only [this, and_self, if_true]⟩
    · simp only [hc, if_false] at h
      by_cases hc' : c ∈ extra :: server ∧ usable c v = true
      · exact ⟨c, by simp only [hc', and_self, if_true]⟩
      · simp only [hc', if_false]
        exact ih h

/-- A TLS 1.3 client that lists the hybrid group first gets it from a server that has it. -/
theorem hybrid_first_wins (server rest : List Group) (h : Group.hybrid ∈ server) :
    select server .tls13 (.hybrid :: rest) = some .hybrid := by
  simp [select, h, usable]

/-! ## The classical component -/

/-- A client's started exchange: the hybrid key and its X25519 component. -/
structure Started where
  hybridKey : Nat
  classicalKey : Nat

/-- The key the client completes with, given the group the server picked. -/
def completeWith (s : Started) : Group → Option Nat
  | .hybrid => some s.hybridKey
  | .x25519 => some s.classicalKey
  | _ => none

/-- When the server picks X25519, the client completes with the X25519 key it already
    sent, so no HelloRetryRequest is needed. -/
theorem component_completes (s : Started) : completeWith s .x25519 = some s.classicalKey := rfl

/-- A server with only the classical groups picks X25519 from a browser-like client that
    lists the hybrid group first and X25519 second. -/
theorem classical_server_picks_component :
    select [.x25519, .p256, .p384] .tls13 [.hybrid, .x25519, .p256] = some .x25519 := by
  decide
