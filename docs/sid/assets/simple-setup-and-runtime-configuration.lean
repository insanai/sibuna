/-!
# Formal Model of Run-Time Changes and Reload (SID 0018)

A model of the reload rule of SID 0018, checked with Lean 4.19.0.

1. Reload: the file decides the names, addresses and weights of a pool. A drain passes a reload exactly when the file keeps a server of that name and address.
2. Selection: a new flow never receives a drained server.
3. Watcher: one stamp of the file is loaded at most once, and a stamp that changed between two looks is not loaded.

Names, addresses and stamps are natural numbers. The socket, the command parser, health probes, the scheduler's choice among eligible servers and the flows that already hold a server are outside the model. Tests cover them.
-/

namespace SibunaRuntime

/-! ## Part A: Reload -/

/-- One server of a pool as it is served. -/
structure Server where
  name : Nat
  addr : Nat
  weight : Nat
  drained : Bool

/-- A pool is the list of its servers. -/
abbrev Pool := List Server

/-- Whether the serving pool has a drained server with the name and address of `s`. -/
def keeps (old : Pool) (s : Server) : Bool :=
  old.any (fun o => o.name == s.name && o.addr == s.addr && o.drained)

/-- A reload serves the servers of the file. Each one is drained when the serving pool
drained the same name at the same address. -/
def reload (old file : Pool) : Pool :=
  file.map (fun s => { s with drained := keeps old s })

/-- `set server ... state drain`. -/
def drain (p : Pool) (name : Nat) : Pool :=
  p.map (fun s => if s.name = name then { s with drained := true } else s)

/-- `set server ... weight`. -/
def reweigh (p : Pool) (name weight : Nat) : Pool :=
  p.map (fun s => if s.name = name then { s with weight := weight } else s)

/-- The file wins on names. -/
theorem reload_names (old file : Pool) :
    (reload old file).map (·.name) = file.map (·.name) := by
  simp [reload, List.map_map, Function.comp_def]

/-- The file wins on addresses. -/
theorem reload_addrs (old file : Pool) :
    (reload old file).map (·.addr) = file.map (·.addr) := by
  simp [reload, List.map_map, Function.comp_def]

/-- The file wins on weights, whatever `reweigh` did before. -/
theorem reload_weights (old file : Pool) :
    (reload old file).map (·.weight) = file.map (·.weight) := by
  simp [reload, List.map_map, Function.comp_def]

/-- A server added at run time is not in the file, so a reload does not serve it, and a
server removed at run time is served again. -/
theorem reload_membership (old file : Pool) (n : Nat) :
    n ∈ (reload old file).map (·.name) ↔ n ∈ file.map (·.name) := by
  rw [reload_names]

/-- `keeps` reads only the name and the address. -/
theorem keeps_congr (old : Pool) (s t : Server) (hn : t.name = s.name) (ha : t.addr = s.addr) :
    keeps old t = keeps old s := by
  simp [keeps, hn, ha]

/-- A drain survives when the file keeps the name and the address. -/
theorem drain_survives (old file : Pool) (o s : Server) (ho : o ∈ old) (hd : o.drained = true)
    (hn : o.name = s.name) (ha : o.addr = s.addr) (hs : s ∈ file) :
    { s with drained := true } ∈ reload old file := by
  have hk : keeps old s = true := by
    simp only [keeps, List.any_eq_true]
    exact ⟨o, ho, by simp [hn, ha, hd]⟩
  simp only [reload, List.mem_map]
  exact ⟨s, hs, by simp [hk]⟩

/-- A reload drains nothing that no operator drained. -/
theorem no_new_drain (old file : Pool) (t : Server) (ht : t ∈ reload old file)
    (hd : t.drained = true) :
    ∃ o, o ∈ old ∧ o.drained = true ∧ o.name = t.name ∧ o.addr = t.addr := by
  simp only [reload, List.mem_map] at ht
  obtain ⟨s, _, rfl⟩ := ht
  simp only [keeps, List.any_eq_true] at hd
  obtain ⟨o, ho, h⟩ := hd
  simp only [Bool.and_eq_true, beq_iff_eq] at h
  exact ⟨o, ho, h.2, h.1.1, h.1.2⟩

/-- When the file gives a name another address, the drain of that name ends. -/
theorem moved_server_is_ready (old : Pool) (s : Server)
    (h : ∀ o, o ∈ old → o.name = s.name → o.addr ≠ s.addr) : keeps old s = false := by
  cases hk : keeps old s with
  | false => rfl
  | true =>
    simp only [keeps, List.any_eq_true, Bool.and_eq_true, beq_iff_eq] at hk
    obtain ⟨o, ho, ⟨hn, ha⟩, _⟩ := hk
    exact absurd ha (h o ho hn)

/-- After a reload the pool keeps exactly the drains it kept: a server of the file is
kept by the reloaded pool when and only when the old pool kept it. -/
theorem keeps_after_reload (old file : Pool) (s : Server) (hs : s ∈ file) :
    keeps (reload old file) s = keeps old s := by
  cases hk : keeps old s with
  | true =>
    simp only [keeps, reload, List.any_eq_true, List.mem_map]
    exact ⟨{ s with drained := keeps old s }, ⟨s, hs, rfl⟩, by simp [hk]⟩
  | false =>
    cases hr : keeps (reload old file) s with
    | false => rfl
    | true =>
      simp only [keeps, reload, List.any_eq_true, List.mem_map] at hr
      obtain ⟨t, ⟨u, _, rfl⟩, h⟩ := hr
      simp only [Bool.and_eq_true, beq_iff_eq] at h
      have : keeps old u = keeps old s := keeps_congr old s u h.1.1 h.1.2
      have hu : keeps old u = true := h.2
      rw [this, hk] at hu
      exact absurd hu (by simp)

/-- Reloading the same file twice equals reloading it once. A reload with no command
in between changes nothing. -/
theorem reload_idempotent (old file : Pool) :
    reload (reload old file) file = reload old file := by
  simp only [reload]
  apply List.map_congr_left
  intro s hs
  have := keeps_after_reload old file s hs
  simp only [reload] at this
  rw [this]

/-- A drain changes no name, address or weight. -/
theorem drain_keeps_topology (p : Pool) (n : Nat) :
    (drain p n).map (fun s => (s.name, s.addr, s.weight)) =
      p.map (fun s => (s.name, s.addr, s.weight)) := by
  simp only [drain, List.map_map]
  apply List.map_congr_left
  intro s _
  simp only [Function.comp]
  split <;> rfl

/-! ## Part B: Selection -/

/-- The servers a new flow may receive. -/
def eligible (p : Pool) : Pool := p.filter (fun s => !s.drained)

/-- A new flow never receives a drained server. -/
theorem selected_is_ready (p : Pool) (s : Server) (h : s ∈ eligible p) : s.drained = false := by
  simp only [eligible, List.mem_filter, Bool.not_eq_true'] at h
  exact h.2

/-- After a drain no eligible server has the drained name. -/
theorem drained_name_not_eligible (p : Pool) (n : Nat) (s : Server)
    (h : s ∈ eligible (drain p n)) : s.name ≠ n := by
  simp only [eligible, drain, List.mem_filter, List.mem_map, Bool.not_eq_true'] at h
  obtain ⟨⟨t, _, rfl⟩, hd⟩ := h
  by_cases ht : t.name = n
  · simp [ht] at hd
  · simp [ht]

/-! ## Part C: The watcher -/

/-- The watcher loads when the stamp differs from the last load and equals the stamp of
the previous look. -/
def due (loaded previous now : Nat) : Bool := now != loaded && now == previous

/-- Every load records the stamp it read, so that stamp is never due again. One edit
causes one reload, whoever asked for it. -/
theorem loaded_stamp_not_due (stamp previous : Nat) : due stamp previous stamp = false := by
  simp [due]

/-- A stamp that changed since the previous look is not loaded: a writer may be at work. -/
theorem changing_stamp_not_due (loaded previous now : Nat) (h : now ≠ previous) :
    due loaded previous now = false := by
  simp [due, h]

/-- A new stamp that stayed for two looks is loaded. -/
theorem stable_new_stamp_due (loaded now : Nat) (h : now ≠ loaded) : due loaded now now = true := by
  simp [due, h]

end SibunaRuntime
