/-
  Shared affinity and fleet-wide caps (SID 0025).

  Part 1 models an entry of the sticky table as the pair of its end and its server,
  merged by the larger pair. We prove the three laws of the merge and that a newly
  learned choice wins over the choice it replaces on every node.

  Part 2 models the quota ledger. Node `i` keeps for each peer `j` the amount `g i j`
  it gave and the amount `h i j` it heard that `j` gave. We prove that the shares never
  sum to more than the bases, for any roster, as long as no node holds more than its
  giver sent; that giving, and hearing any datagram any number of times in any order,
  keep that condition; and the facts about a restarted node that the record uses.

  Checked with Lean 4 core, no libraries: `lean shared-affinity.lean`.
-/

/-! ## Part 1: the sticky table -/

/-- One entry: the Unix millisecond it ends and the server it names. -/
structure Entry where
  ends : Nat
  server : Nat
deriving DecidableEq

/-- The order of entries: by end, then by server. -/
def Entry.le (a b : Entry) : Prop :=
  a.ends < b.ends ∨ (a.ends = b.ends ∧ a.server ≤ b.server)

instance (a b : Entry) : Decidable (a.le b) := by unfold Entry.le; exact inferInstance

/-- Merging keeps the larger entry. -/
def Entry.merge (a b : Entry) : Entry := if a.le b then b else a

theorem Entry.merge_comm (a b : Entry) : a.merge b = b.merge a := by
  cases a with | mk ae as => cases b with | mk be bs =>
  by_cases h1 : Entry.le ⟨ae, as⟩ ⟨be, bs⟩ <;>
  by_cases h2 : Entry.le ⟨be, bs⟩ ⟨ae, as⟩ <;>
  simp only [Entry.merge, h1, h2, if_true, if_false] <;>
  simp only [Entry.le] at h1 h2 <;>
  first
    | rfl
    | (simp only [Entry.mk.injEq]; omega)

theorem Entry.merge_idem (a : Entry) : a.merge a = a := by
  simp [Entry.merge]

theorem Entry.merge_assoc (a b c : Entry) : (a.merge b).merge c = a.merge (b.merge c) := by
  cases a with | mk ae as => cases b with | mk be bs => cases c with | mk ce cs =>
  by_cases h1 : Entry.le ⟨ae, as⟩ ⟨be, bs⟩ <;>
  by_cases h2 : Entry.le ⟨be, bs⟩ ⟨ce, cs⟩ <;>
  by_cases h3 : Entry.le ⟨ae, as⟩ ⟨ce, cs⟩ <;>
  simp only [Entry.merge, h1, h2, h3, if_true, if_false] <;>
  simp only [Entry.le] at h1 h2 h3 <;>
  first
    | rfl
    | (simp only [Entry.mk.injEq]; omega)
    | omega

/-- A merge never loses an entry: the result is at least the entry the node held. -/
theorem Entry.merge_ge_left (a b : Entry) : a.le (a.merge b) := by
  cases a with | mk ae as => cases b with | mk be bs =>
  by_cases h : Entry.le ⟨ae, as⟩ ⟨be, bs⟩
  · simp only [Entry.merge, h, if_true]
  · simp only [Entry.merge, h, if_false]; exact Or.inr ⟨rfl, Nat.le_refl _⟩

/-- A datagram heard twice changes nothing the second time. -/
theorem Entry.replay_is_harmless (a b : Entry) : (a.merge b).merge b = a.merge b := by
  rw [Entry.merge_assoc, Entry.merge_idem]

/-- The entry a node writes when it places a client on another server than the table
    names: it ends at the later of `now + ttl` and one past the old end. -/
def learn (old : Entry) (now ttl server : Nat) : Entry :=
  ⟨Nat.max (now + ttl) (old.ends + 1), server⟩

/-- A learned choice replaces the old one on every node that merges it, whatever the
    servers are and whatever the clocks say. -/
theorem learn_wins (old : Entry) (now ttl server : Nat) :
    old.merge (learn old now ttl server) = learn old now ttl server := by
  cases old with | mk oe os =>
  have h : Entry.le ⟨oe, os⟩ (learn ⟨oe, os⟩ now ttl server) := by
    simp only [Entry.le, learn]
    left
    exact Nat.lt_of_lt_of_le (Nat.lt_succ_self oe) (Nat.le_max_right _ _)
  simp only [Entry.merge, h, if_true]

/-- A refresh by the node that holds the entry never moves the client: the server
    stays, and the end does not move back. -/
theorem refresh_keeps (old : Entry) (now ttl : Nat) (h : old.ends ≤ now + ttl) :
    old.merge ⟨now + ttl, old.server⟩ = ⟨now + ttl, old.server⟩ := by
  cases old with | mk oe os =>
  have : Entry.le ⟨oe, os⟩ ⟨now + ttl, os⟩ := by
    simp only [Entry.le]
    simp only at h
    omega
  simp only [Entry.merge, this, if_true]

/-- A received entry counts only while it has not ended and lies within the horizon. -/
def admits (now horizon ends : Nat) : Bool := now < ends && ends ≤ now + horizon

theorem admitted_is_bounded (now horizon ends : Nat) (h : admits now horizon ends = true) :
    ends ≤ now + horizon := by
  simp [admits] at h
  exact h.2

/-! ## Part 2: the quota ledger -/

/-- The sum of `f` over the nodes of a roster. -/
def total (nodes : List α) (f : α → Int) : Int :=
  match nodes with
  | [] => 0
  | x :: rest => f x + total rest f

theorem total_add (nodes : List α) (f g : α → Int) :
    total nodes (fun x => f x + g x) = total nodes f + total nodes g := by
  induction nodes with
  | nil => simp [total]
  | cons x rest ih => simp only [total, ih]; omega

theorem total_le (nodes : List α) (f g : α → Int) (h : ∀ x, f x ≤ g x) :
    total nodes f ≤ total nodes g := by
  induction nodes with
  | nil => simp [total]
  | cons x rest ih => simp only [total]; have := h x; omega

theorem total_congr (nodes : List α) (f g : α → Int) (h : ∀ x, f x = g x) :
    total nodes f = total nodes g := by
  have : f = g := funext h
  rw [this]

theorem total_zero (nodes : List α) : total nodes (fun _ => (0 : Int)) = 0 := by
  induction nodes with
  | nil => simp [total]
  | cons x rest ih => simp only [total, ih]; omega

/-- A double sum may be taken in either order. -/
theorem total_swap (ns : List α) (ms : List β) (f : α → β → Int) :
    total ns (fun i => total ms (fun j => f i j))
      = total ms (fun j => total ns (fun i => f i j)) := by
  induction ns with
  | nil => simp [total, total_zero]
  | cons x rest ih =>
    simp only [total, ih]
    rw [← total_add]

/-- The share of node `i`: its base, plus what it heard that each peer gave to it,
    minus what it gave to each peer. -/
def share (nodes : List α) (base : α → Int) (g h : α → α → Int) (i : α) : Int :=
  base i + total nodes (fun j => h i j) - total nodes (fun j => g i j)

/-- The condition of the ledger: a node holds for a peer no more than the peer gave. -/
def Sound (g h : α → α → Int) : Prop := ∀ i j, h j i ≤ g i j

/-- The cap. For every roster, the shares sum to at most the bases, which sum to the
    limit. Nothing is assumed about which datagrams arrived. -/
theorem shares_within_limit (nodes : List α) (base : α → Int) (g h : α → α → Int)
    (sound : Sound g h) :
    total nodes (share nodes base g h) ≤ total nodes base := by
  have split : total nodes (share nodes base g h)
      = total nodes base
        + total nodes (fun i => total nodes (fun j => h i j))
        - total nodes (fun i => total nodes (fun j => g i j)) := by
    unfold share
    have e1 := total_add nodes
      (fun i => base i + total nodes (fun j => h i j))
      (fun i => - total nodes (fun j => g i j))
    have e2 := total_add nodes base (fun i => total nodes (fun j => h i j))
    have e3 := total_add nodes
      (fun i => total nodes (fun j => g i j)) (fun i => - total nodes (fun j => g i j))
    have e4 : total nodes (fun i =>
        total nodes (fun j => g i j) + - total nodes (fun j => g i j)) = 0 := by
      rw [total_congr nodes _ (fun _ => (0 : Int)) (fun x => Int.add_right_neg _)]
      exact total_zero nodes
    have e5 : total nodes (fun i =>
        base i + total nodes (fun j => h i j) - total nodes (fun j => g i j))
        = total nodes (fun i =>
        base i + total nodes (fun j => h i j) + - total nodes (fun j => g i j)) :=
      total_congr nodes _ _ (fun x => by omega)
    rw [e5, e1, e2]
    omega
  have swapped := total_swap nodes nodes (fun i j => h i j)
  have bound : total nodes (fun j => total nodes (fun i => h i j))
      ≤ total nodes (fun j => total nodes (fun i => g j i)) :=
    total_le nodes _ _ (fun j => total_le nodes _ _ (fun i => sound j i))
  rw [split, swapped]
  omega

/-- Node `i` gives `d` to node `j`: only its own count of what it gave grows. -/
def give [DecidableEq α] (g : α → α → Int) (i j : α) (d : Int) : α → α → Int :=
  fun a b => if a = i ∧ b = j then g a b + d else g a b

/-- Node `j` hears the number `v` from node `i` and keeps the larger. -/
def hear [DecidableEq α] (h : α → α → Int) (j i : α) (v : Int) : α → α → Int :=
  fun a b => if a = j ∧ b = i then max (h a b) v else h a b

theorem give_keeps_sound [DecidableEq α] (g h : α → α → Int) (i j : α) (d : Int)
    (positive : 0 ≤ d) (sound : Sound g h) : Sound (give g i j d) h := by
  intro a b
  have := sound a b
  unfold give
  split <;> omega

/-- Any number that the giver ever sent is at most what it has given now. So hearing
    it keeps the ledger sound: late, twice, or out of order. -/
theorem hear_keeps_sound [DecidableEq α] (g h : α → α → Int) (i j : α) (v : Int)
    (sent : v ≤ g i j) (sound : Sound g h) : Sound g (hear h j i v) := by
  intro a b
  have := sound a b
  unfold hear
  split
  · rename_i same
    obtain ⟨hb, ha⟩ := same
    subst hb; subst ha
    omega
  · exact this

/-- One event between two nodes of a cluster that no node restarts in. -/
inductive Event (α : Type) where
  | gave (i j : α) (d : Nat)
  | heard (j i : α) (v : Int)

/-- The ledgers after one event. A number is heard only when the giver sent it. -/
def step [DecidableEq α] (s : (α → α → Int) × (α → α → Int)) (e : Event α) :
    (α → α → Int) × (α → α → Int) :=
  match e with
  | .gave i j d => (give s.1 i j d, s.2)
  | .heard j i v => if v ≤ s.1 i j then (s.1, hear s.2 j i v) else s

/-- The cap holds after every list of gifts and of datagrams heard in any order and
    any number of times, from any sound state. -/
theorem cap_holds_on_every_trace [DecidableEq α] (nodes : List α) (base : α → Int)
    (events : List (Event α)) :
    ∀ (s : (α → α → Int) × (α → α → Int)), Sound s.1 s.2 →
      total nodes (share nodes base (events.foldl step s).1 (events.foldl step s).2)
        ≤ total nodes base := by
  induction events with
  | nil => intro s sound; exact shares_within_limit nodes base s.1 s.2 sound
  | cons e rest ih =>
    intro s sound
    apply ih
    cases e with
    | gave i j d =>
      exact give_keeps_sound s.1 s.2 i j d (Int.ofNat_nonneg d) sound
    | heard j i v =>
      simp only [step]
      split
      · rename_i sent; exact hear_keeps_sound s.1 s.2 i j v sent sound
      · exact sound

/-- A gift leaves the flows of the giver within its share when it comes from the part
    that no flow uses. -/
theorem gift_from_free_share (share used d : Int) (free : d ≤ share - used) :
    used ≤ share - d := by omega

/-! ### A node that restarted

  `out` is the net amount a node gave to a peer and `pos` its positive part. The rule
  of the record is that the positive parts of one node sum to at most its base. -/

/-- The positive part. -/
def pos (x : Int) : Int := max x 0

/-- What a node counts for one peer while it is not synchronised with every peer:
    for a peer it is synchronised with, the net amount it received when that is
    positive; for the others nothing. `net` is given minus heard. -/
def counted (synced : Bool) (net : Int) : Int := if synced then pos (-net) else 0

/-- For each peer, what the node counts is at most what it really holds for that peer,
    plus the positive part of what it gave. -/
theorem counted_term (synced : Bool) (net : Int) : counted synced net + net ≤ pos net := by
  unfold counted pos
  cases synced <;> simp <;> omega

/-- The share that a restarted node counts never exceeds its true share, as long as
    it gave no more than its base in all. `net j` is its true net gift to peer `j`,
    which it does not know for the peers it is not synchronised with. -/
theorem restarted_share_is_safe (peers : List α) (base : Int) (net : α → Int)
    (synced : α → Bool) (rule : total peers (fun j => pos (net j)) ≤ base) :
    total peers (fun j => counted (synced j) (net j))
      ≤ base - total peers net := by
  have term := total_le peers (fun j => counted (synced j) (net j) + net j)
    (fun j => pos (net j)) (fun j => counted_term (synced j) (net j))
  rw [total_add] at term
  omega

/-- When the last peer is synchronised the node counts its true share. That share
    covers every flow it admitted before, because it covers all that it counted. -/
theorem full_share_covers_counted (peers : List α) (base : Int) (net : α → Int)
    (rule : total peers (fun j => pos (net j)) ≤ base) :
    total peers (fun j => pos (-(net j))) ≤ base - total peers net :=
  restarted_share_is_safe peers base net (fun _ => true) rule

/-- Taking over the ledger of a peer that kept it. The node gave `gave` and heard
    `got` before it restarted. The peer holds `kept ≤ gave` of the gifts and has given
    `given ≥ got`. The net gift that the node takes over is at most the true one, so
    the rule on its gifts still holds. -/
theorem takeover_keeps_rule (gave got kept given : Int) (h1 : kept ≤ gave) (h2 : got ≤ given) :
    pos (kept - given) ≤ pos (gave - got) := by
  unfold pos; omega

/-- Two nodes that both restarted start their pair at zero. Without the rule this
    would be unsound. Four nodes with base 100: `j` gives 100 to `i`, `i` gives 100
    to each of `k` and `l`, then `i` and `j` restart. Forgetting the pair returns
    100 to `j`, while `k` and `l` hold 200 each: 500 in all. The rule forbids the
    second gift of `i`, since its positive net gifts would sum to 200. -/
example : ¬ (pos (100 : Int) + pos 100 + pos (-100) ≤ 100) := by decide

/-- With the rule, a node whose pair with a restarted peer is forgotten still has a
    true share of at least zero: what it gave to the others came from its base. -/
theorem forgotten_pair_is_safe (base others : Int) (rule : others ≤ base) : 0 ≤ base - others := by
  omega
