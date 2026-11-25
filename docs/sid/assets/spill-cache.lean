/-
  The mapped spill cache (SID 0027).

  Three parts of the design are modelled.

  1. Admission into a bucket of four slots. A bucket is a list of keys and `est`
     gives the estimated frequency of a key. We prove that a bucket never grows
     past four, that a rejected offer changes nothing, that a displaced entry has
     the smallest estimate and a smaller one than the candidate, and that a key
     seen once cannot displace an entry that was seen.
  2. The validation of a slot. `sum` stands for the checksum. We prove that a
     reader gets a value only from a slot that passes every check, so a torn,
     expired or far-future slot yields nothing.
  3. The age of a slot from a write counter of 32 bits. We prove that the age is
     exact across a wrap of the counter.

  The sketch itself, the file system and the memory model are outside the model.

  Checked with Lean 4 core, no libraries: `lean spill-cache.lean`.
-/

/-! ## Admission -/

/-- The slots of a bucket. -/
def ways : Nat := 4

/-- The key of the smallest estimate, the first among equals. -/
def minKey (est : Nat → Nat) : List Nat → Option Nat
  | [] => none
  | x :: xs =>
    match minKey est xs with
    | none => some x
    | some m => if est x ≤ est m then some x else some m

theorem minKey_mem (est : Nat → Nat) :
    ∀ (b : List Nat) (v : Nat), minKey est b = some v → v ∈ b := by
  intro b
  induction b with
  | nil => intro v h; simp [minKey] at h
  | cons x xs ih =>
    intro v h
    unfold minKey at h
    cases hm : minKey est xs with
    | none => simp [hm] at h; simp [h]
    | some m =>
      simp [hm] at h
      by_cases hx : est x ≤ est m
      · simp [hx] at h; simp [h]
      · simp [hx] at h; subst h; exact List.mem_cons_of_mem x (ih m hm)

theorem minKey_least (est : Nat → Nat) :
    ∀ (b : List Nat) (v : Nat), minKey est b = some v → ∀ x, x ∈ b → est v ≤ est x := by
  intro b
  induction b with
  | nil => intro v h; simp [minKey] at h
  | cons y ys ih =>
    intro v h x hx
    unfold minKey at h
    cases hm : minKey est ys with
    | none =>
      simp [hm] at h; subst h
      cases ys with
      | nil => simp at hx; subst hx; exact Nat.le_refl _
      | cons z zs =>
        unfold minKey at hm
        cases hz : minKey est zs with
        | none => simp [hz] at hm
        | some w => simp [hz] at hm; by_cases c : est z ≤ est w <;> simp [c] at hm
    | some m =>
      simp [hm] at h
      have least := ih m hm
      rcases List.mem_cons.mp hx with hxy | hxs
      · subst hxy
        by_cases c : est x ≤ est m
        · simp [c] at h; subst h; exact Nat.le_refl _
        · simp [c] at h; subst h; omega
      · have hmx := least x hxs
        by_cases c : est y ≤ est m
        · simp [c] at h; subst h; omega
        · simp [c] at h; subst h; exact hmx

theorem minKey_some (est : Nat → Nat) (x : Nat) (xs : List Nat) :
    ∃ v, minKey est (x :: xs) = some v := by
  unfold minKey
  cases minKey est xs with
  | none => exact ⟨x, rfl⟩
  | some m => by_cases c : est x ≤ est m <;> simp [c]

/-- Writes `k` over the first slot that holds `v`. -/
def overwrite (v k : Nat) : List Nat → List Nat
  | [] => []
  | x :: xs => if x = v then k :: xs else x :: overwrite v k xs

theorem overwrite_length (v k : Nat) : ∀ b : List Nat, (overwrite v k b).length = b.length := by
  intro b
  induction b with
  | nil => rfl
  | cons x xs ih => unfold overwrite; by_cases c : x = v <;> simp [c, ih]

/-- An entry other than the victim stays in the bucket. -/
theorem overwrite_keeps (v k x : Nat) (hx : x ≠ v) :
    ∀ b : List Nat, x ∈ b → x ∈ overwrite v k b := by
  intro b
  induction b with
  | nil => intro h; simp at h
  | cons y ys ih =>
    intro h
    unfold overwrite
    by_cases c : y = v
    · simp [c]
      rcases List.mem_cons.mp h with e | e
      · exact absurd (e.trans c) hx
      · exact Or.inr e
    · simp [c]
      rcases List.mem_cons.mp h with e | e
      · exact Or.inl e
      · exact Or.inr (ih e)

/-- What an offer did. -/
inductive Outcome where
  | updated
  | stored
  | replaced (victim : Nat)
  | rejected
  deriving DecidableEq

/-- Offers the key `k` to the bucket `b`. -/
def offer (est : Nat → Nat) (b : List Nat) (k : Nat) : List Nat × Outcome :=
  if k ∈ b then (b, .updated)
  else if b.length < ways then (k :: b, .stored)
  else
    match minKey est b with
    | none => (b, .rejected)
    | some v => if est v < est k then (overwrite v k b, .replaced v) else (b, .rejected)

/-- A bucket never holds more than four entries. -/
theorem offer_bounded (est : Nat → Nat) (b : List Nat) (k : Nat) (h : b.length ≤ ways) :
    (offer est b k).1.length ≤ ways := by
  unfold offer
  by_cases hk : k ∈ b
  · simp [hk, h]
  · by_cases hl : b.length < ways
    · simp [hk, hl]; omega
    · simp only [hk, hl, if_false]
      cases minKey est b with
      | none => exact h
      | some v =>
        by_cases c : est v < est k
        · simp [c, overwrite_length]; exact h
        · simp [c]; exact h

/-- A rejected offer leaves the bucket as it was. -/
theorem rejected_unchanged (est : Nat → Nat) (b : List Nat) (k : Nat)
    (h : (offer est b k).2 = .rejected) : (offer est b k).1 = b := by
  unfold offer at h ⊢
  by_cases hk : k ∈ b
  · simp [hk]
  · by_cases hl : b.length < ways
    · simp [hk, hl] at h
    · simp only [hk, hl, if_false] at h ⊢
      cases hm : minKey est b with
      | none => rfl
      | some v =>
        by_cases c : est v < est k
        · simp [hm, c] at h
        · simp [c]

/-- A displaced entry was in the bucket, had the smallest estimate there, and a
    smaller estimate than the candidate. -/
theorem replaced_is_least (est : Nat → Nat) (b : List Nat) (k v : Nat)
    (h : (offer est b k).2 = .replaced v) :
    v ∈ b ∧ est v < est k ∧ ∀ x, x ∈ b → est v ≤ est x := by
  unfold offer at h
  by_cases hk : k ∈ b
  · simp [hk] at h
  · by_cases hl : b.length < ways
    · simp [hk, hl] at h
    · simp only [hk, hl, if_false] at h
      cases hm : minKey est b with
      | none => simp [hm] at h
      | some w =>
        by_cases c : est w < est k
        · simp [hm, c] at h
          subst h
          exact ⟨minKey_mem est b w hm, c, minKey_least est b w hm⟩
        · simp [hm, c] at h

/-- A candidate whose estimate does not exceed that of every entry of a full
    bucket is rejected. -/
theorem weak_candidate_rejected (est : Nat → Nat) (b : List Nat) (k : Nat)
    (hk : k ∉ b) (full : ¬ b.length < ways) (weak : ∀ x, x ∈ b → est k ≤ est x) :
    offer est b k = (b, .rejected) := by
  unfold offer
  simp only [hk, full, if_false]
  cases hm : minKey est b with
  | none => rfl
  | some v =>
    have := weak v (minKey_mem est b v hm)
    have c : ¬ est v < est k := by omega
    simp [c]

/-- A key that was seen once cannot displace an entry that was seen. This is the
    lemma of SID 0015 for a candidate of frequency one. -/
theorem once_seen_never_displaces (est : Nat → Nat) (b : List Nat) (k : Nat)
    (hk : k ∉ b) (full : ¬ b.length < ways) (once : est k = 1)
    (seen : ∀ x, x ∈ b → 1 ≤ est x) : offer est b k = (b, .rejected) := by
  apply weak_candidate_rejected est b k hk full
  intro x hx
  have := seen x hx
  omega

/-- An offer removes at most the victim it names. -/
theorem offer_keeps_others (est : Nat → Nat) (b : List Nat) (k x : Nat) (hx : x ∈ b)
    (h : (offer est b k).2 ≠ .replaced x) : x ∈ (offer est b k).1 := by
  unfold offer at h ⊢
  by_cases hk : k ∈ b
  · simp [hk, hx]
  · by_cases hl : b.length < ways
    · simp [hk, hl, hx]
    · simp only [hk, hl, if_false] at h ⊢
      cases hm : minKey est b with
      | none => exact hx
      | some v =>
        by_cases c : est v < est k
        · simp [hm, c] at h
          simp [c]
          exact overwrite_keeps v k x (fun e => h (e ▸ rfl)) b hx
        · simp [c]; exact hx

/-! ## The sketch: halving keeps the order, and a minimum never undercounts -/

/-- Aging halves every counter. It never reverses an order. -/
theorem aging_keeps_order (a b : Nat) (h : a ≤ b) : a / 2 ≤ b / 2 :=
  by omega

/-- The estimate is the smallest of four counters. When no counter is below the
    true count, neither is the estimate. -/
theorem estimate_never_under (n c1 c2 c3 c4 : Nat)
    (h1 : n ≤ c1) (h2 : n ≤ c2) (h3 : n ≤ c3) (h4 : n ≤ c4) :
    n ≤ Nat.min (Nat.min c1 c2) (Nat.min c3 c4) := by
  simp [Nat.min_def]
  split <;> split <;> split <;> omega

/-! ## The validation of a slot -/

/-- The longest key and value of a slot. -/
def maxKey : Nat := 24
def maxValue : Nat := 16

/-- The fields of a slot as they are read from the file. Any bytes can be there. -/
structure Slot where
  check : Nat
  expiry : Nat
  keyLen : Nat
  valueLen : Nat
  pad : Nat
  key : Nat
  value : Nat

/-- The four states of a slot. -/
inductive State where
  | empty
  | corrupt
  | expired
  | live
  deriving DecidableEq

/-- Decides the state of a slot at the time `now`. `sum` is the checksum of the
    slot's other bytes and `maxTtl` the longest life of a hint. -/
def classify (sum : Slot → Nat) (now maxTtl : Nat) (s : Slot) : State :=
  if s.expiry = 0 then .empty
  else if s.keyLen = 0 ∨ maxKey < s.keyLen ∨ maxValue < s.valueLen ∨ s.pad ≠ 0 then .corrupt
  else if s.check ≠ sum s then .corrupt
  else if s.expiry ≤ now then .expired
  else if now + maxTtl < s.expiry then .corrupt
  else .live

/-- A lookup of the key `k` in one slot. -/
def readSlot (sum : Slot → Nat) (now maxTtl : Nat) (s : Slot) (k : Nat) : Option Nat :=
  if classify sum now maxTtl s = .live ∧ s.key = k then some s.value else none

/-- A live slot passed every check. -/
theorem live_is_checked (sum : Slot → Nat) (now maxTtl : Nat) (s : Slot)
    (h : classify sum now maxTtl s = .live) :
    s.check = sum s ∧ now < s.expiry ∧ s.expiry ≤ now + maxTtl ∧
      1 ≤ s.keyLen ∧ s.keyLen ≤ maxKey ∧ s.valueLen ≤ maxValue ∧ s.pad = 0 := by
  unfold classify at h
  by_cases h0 : s.expiry = 0
  · simp [h0] at h
  · by_cases h1 : s.keyLen = 0 ∨ maxKey < s.keyLen ∨ maxValue < s.valueLen ∨ s.pad ≠ 0
    · simp [h0, h1] at h
    · by_cases h2 : s.check ≠ sum s
      · simp [h0, h1, h2] at h
      · by_cases h3 : s.expiry ≤ now
        · simp [h0, h1, h2, h3] at h
        · by_cases h4 : now + maxTtl < s.expiry
          · simp [h0, h1, h2, h3, h4] at h
          · have hc : s.check = sum s := Classical.not_not.mp h2
            have hk : ¬ s.keyLen = 0 := fun e => h1 (Or.inl e)
            have hl : ¬ maxKey < s.keyLen := fun e => h1 (Or.inr (Or.inl e))
            have hv : ¬ maxValue < s.valueLen := fun e => h1 (Or.inr (Or.inr (Or.inl e)))
            have hp : s.pad = 0 :=
              Classical.not_not.mp (fun e => h1 (Or.inr (Or.inr (Or.inr e))))
            refine ⟨hc, ?_, ?_, ?_, ?_, ?_, hp⟩ <;> omega

/-- A reader gets a value only from a checked slot that holds the key asked for. -/
theorem read_is_sound (sum : Slot → Nat) (now maxTtl : Nat) (s : Slot) (k v : Nat)
    (h : readSlot sum now maxTtl s k = some v) :
    v = s.value ∧ s.key = k ∧ s.check = sum s ∧ now < s.expiry ∧ s.expiry ≤ now + maxTtl := by
  unfold readSlot at h
  by_cases c : classify sum now maxTtl s = .live ∧ s.key = k
  · simp [c] at h
    have checked := live_is_checked sum now maxTtl s c.1
    exact ⟨h.symm, c.2, checked.1, checked.2.1, checked.2.2.1⟩
  · simp [c] at h

/-- A slot whose checksum does not match yields nothing: a torn write is free space. -/
theorem torn_slot_reads_nothing (sum : Slot → Nat) (now maxTtl : Nat) (s : Slot) (k : Nat)
    (torn : s.check ≠ sum s) : readSlot sum now maxTtl s k = none := by
  cases h : readSlot sum now maxTtl s k with
  | none => rfl
  | some v => exact absurd (read_is_sound sum now maxTtl s k v h).2.2.1 torn

/-- An expired slot yields nothing. -/
theorem expired_slot_reads_nothing (sum : Slot → Nat) (now maxTtl : Nat) (s : Slot) (k : Nat)
    (old : s.expiry ≤ now) : readSlot sum now maxTtl s k = none := by
  cases h : readSlot sum now maxTtl s k with
  | none => rfl
  | some v =>
    have := (read_is_sound sum now maxTtl s k v h).2.2.2.1
    omega

/-- A slot that claims to live longer than any hint may yields nothing. -/
theorem far_future_slot_reads_nothing (sum : Slot → Nat) (now maxTtl : Nat) (s : Slot)
    (k : Nat) (far : now + maxTtl < s.expiry) : readSlot sum now maxTtl s k = none := by
  cases h : readSlot sum now maxTtl s k with
  | none => rfl
  | some v =>
    have := (read_is_sound sum now maxTtl s k v h).2.2.2.2
    omega

/-- A slot of zeros is empty, whatever the checksum function. -/
theorem zero_slot_is_empty (sum : Slot → Nat) (now maxTtl : Nat) :
    classify sum now maxTtl ⟨0, 0, 0, 0, 0, 0, 0⟩ = .empty := by
  simp [classify]

/-- A slot never yields the value of another key. -/
theorem other_key_reads_nothing (sum : Slot → Nat) (now maxTtl : Nat) (s : Slot) (k : Nat)
    (other : s.key ≠ k) : readSlot sum now maxTtl s k = none := by
  cases h : readSlot sum now maxTtl s k with
  | none => rfl
  | some v => exact absurd (read_is_sound sum now maxTtl s k v h).2.1 other

/-! ## The age of a slot across a wrap of the write counter -/

/-- The age of a slot stamped `stamp` when the counter of its shard reads `count`,
    both taken modulo 2^32. -/
def age (count stamp : Nat) : Nat := (count + 4294967296 - stamp) % 4294967296

/-- A slot written `d` writes ago has the age `d`, whether or not the counter
    wrapped in between, while `d` is below 2^32. -/
theorem age_exact (c d : Nat) (h : d < 4294967296) :
    age ((c + d) % 4294967296) (c % 4294967296) = d := by
  unfold age
  omega

/-- Of two slots, the one written longer ago has the greater age, across a wrap. -/
theorem older_has_greater_age (c d1 d2 : Nat) (h : d1 < d2) (h2 : d2 < 4294967296) :
    age (c % 4294967296) ((c + 4294967296 - d1) % 4294967296) <
      age (c % 4294967296) ((c + 4294967296 - d2) % 4294967296) := by
  unfold age
  omega
