/-
  SID 0024, TLS on the workers. Core Lean 4, no libraries.

  Two small facts carry the design.

  1. A read leaves clear bytes in the session only when it filled the buffer of the
     caller. The session then says so, and the worker reads again without a socket
     event. So no clear byte waits for an event that will not come (invariant 5).

  2. Every whole ClientHello has exactly one owner: the worker or the runtime
     (invariant 1). The bytes that the runtime replays are the bytes that were read.
-/

/-- One read: the session holds `held` clear bytes and the caller has `room`. -/
structure Read where
  taken : Nat
  left : Nat
  full : Bool

def readOnce (held room : Nat) : Read :=
  let taken := min held room
  { taken := taken, left := held - taken, full := taken == room }

/-- Bytes stay behind only when the buffer was filled, and then the flag is set. -/
theorem left_bytes_are_announced (held room : Nat) :
    (readOnce held room).left > 0 → (readOnce held room).full = true := by
  intro h
  simp only [readOnce] at h ⊢
  have : min held room = room := by omega
  simp [this]

/-- A read never invents or loses bytes. -/
theorem read_keeps_every_byte (held room : Nat) :
    (readOnce held room).taken + (readOnce held room).left = held := by
  simp only [readOnce]
  omega

/-- A read never takes more than the caller has room for. -/
theorem read_fits (held room : Nat) : (readOnce held room).taken ≤ room := by
  simp only [readOnce]
  omega

/-- Who serves a connection after its ClientHello. -/
inductive Owner where
  | worker
  | runtime
  deriving DecidableEq

/-- The protocols a client may offer, as far as the choice looks at them. -/
structure Offer where
  http2 : Bool
  validation : Bool

def owner (offer : Offer) : Owner :=
  if offer.http2 || offer.validation then Owner.runtime else Owner.worker

/-- The worker keeps exactly the clients that offer neither. -/
theorem worker_keeps_plain_clients (offer : Offer) :
    owner offer = Owner.worker ↔ (offer.http2 = false ∧ offer.validation = false) := by
  cases offer with
  | mk http2 validation => cases http2 <;> cases validation <;> simp [owner]

/-- A client that offers HTTP/2 is never served by a worker. -/
theorem http2_goes_to_the_runtime (offer : Offer) (h : offer.http2 = true) :
    owner offer = Owner.runtime := by
  simp [owner, h]

/-- What the runtime reads: the bytes the worker saw, then the rest of the socket. -/
def replay (seen rest : List Nat) : List Nat := seen ++ rest

/-- The runtime reads the stream of the client, whole and in order, wherever the worker
    stopped reading. -/
theorem replay_is_the_stream (stream : List Nat) (cut : Nat) :
    replay (stream.take cut) (stream.drop cut) = stream := by
  simp [replay]
