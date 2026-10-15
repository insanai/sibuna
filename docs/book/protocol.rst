Part IV: The Sibuna Protocol
============================

We specify the wire protocol as implemented: the interstitial round trip, the stateless challenge record, both solution formats, verification order, single-use enforcement, and the session cookie.

The Challenge Round Trip
------------------------

.. admonition:: Objectives

   By the end of this chapter, we should be able to trace a browser from its first request to a minted session, name every endpoint and JSON field involved, and explain why the challenge carries the protected path's policy decision.

.. graphviz::
   :caption: The challenge round trip.
   :alt: A loop of eight steps: browser navigation, interstitial (HTTP 200), GET /__sibuna/challenge.json?need=, stateless id (payload + tag), Web Worker solving with the WASM or JS prover, POST /__sibuna/verify with the nonce or proof, verify, spent set and mint MAC token, Set-Cookie then reload, and back to the navigation with a session.

   digraph round_trip {
     graph [rankdir=TB, bgcolor="transparent", nodesep=0.5, ranksep=0.7];
     node [shape=box, style="rounded,filled", fontname="Helvetica", fontsize=10, fillcolor="#eff6ff", color="#1e40af", fontcolor="#172033"];
     edge [color="#64748b", fontname="Helvetica", fontsize=9, fontcolor="#64748b"];

     nav [label="Browser\nnavigation"];
     page [label="Interstitial\n(HTTP 200)", fillcolor="#fffbeb", color="#b45309"];
     fetch [label="GET /__sibuna/\nchallenge.json?need="];
     record [label="Stateless id:\npayload + tag", fillcolor="#f0fdf4", color="#15803d"];
     worker [label="Web Worker\nWASM / JS prover"];
     verify [label="POST /__sibuna/verify"];
     mint [label="Verify, spent set,\nmint MAC token", fillcolor="#f0fdf4", color="#15803d"];
     cookie [label="Set-Cookie\nthen reload", fillcolor="#fffbeb", color="#b45309"];

     { rank=same; nav; page; fetch; record; }
     { rank=same; cookie; mint; verify; worker; }

     nav -> page -> fetch -> record;
     record -> worker [label=" solve"];
     cookie -> mint -> verify [dir=back];
     verify -> worker [dir=back, label="nonce or proof"];
     nav -> cookie [dir=back, label=" session"];
   }

1. A navigation with no valid session reaches the policy engine and is classified ``CHALLENGE``. Because the request accepts ``text/html``, the daemon answers ``200`` with the interstitial page and the header ``X-Sibuna-Status: CHALLENGE``; an API client that does not accept HTML receives ``401`` with a JSON body whose ``challenge`` URL is ready to fetch. Either way the response carries a *requirement ticket*: the challenge this decision demands (algorithm, work bits, openings) and the rule's hash, sealed for this client with a keyed BLAKE3 tag under its own derived key and valid for one challenge lifetime.
2. The interstitial fetches ``GET /__sibuna/challenge.json?path=<original URL>&need=<ticket>``. A valid ticket decides the challenge: the work is fixed by the decision that demanded it, not recomputed from a reported URL and the fetch's own headers, which differ from the navigation's (``Accept``, ``Sec-Fetch-*``). Without a valid ticket (an API client that ignores the URL, a page left open past the lifetime) the server evaluates the reported URL, split into path and query by the same function that reads the request line, with the path put in the normal form admission uses (SID 0009); a URL longer than 8 KiB is refused with ``414``, never truncated, and a path without a normal form with ``400``. The ticket is advisory: admission still checks the session's work level, so a replayed or forged ticket can only cost its holder work.
3. The response is the challenge record:

   .. code-block:: json

      {"id":"AQEND...70 chars","algorithm":"posw","difficulty":13,"challenges":16,"expires_at":1757241234}

   For ``hashcash``, ``difficulty`` is the bit count and ``challenges`` is ``0``.
4. A Web Worker solves it with the WebAssembly module, or the JavaScript prover if WebAssembly is unavailable (Part VII), and posts either

   .. code-block:: json

      {"challenge_id":"...","nonce":"90766"}

   or

   .. code-block:: json

      {"challenge_id":"...","proof":"<base64url, 32(1 + t(n+1)) bytes>"}

   to ``POST /__sibuna/verify``.
5. On success the server answers ``200 {"status":"ok"}`` with a ``Set-Cookie`` header, and the page reloads its original location. Every later request carries the cookie and is admitted before policy evaluation.

.. admonition:: Why the path travels with the challenge

   The interstitial is served at the protected URL, so the browser knows where it is. Sending the path lets the server pick the *per-rule* difficulty and algorithm (a checkout route may demand 20 work bits of sequential work while a blog demands 16 bits of Hashcash) and binds the rule hash into the token, where ``X-Sibuna-Rule-Hash`` reports it upstream.

The Stateless Challenge Record
------------------------------

.. admonition:: Objectives

   Read the challenge encoder, understand every field's purpose, and see how the per-challenge nonce is derived without an entropy syscall on the hot path.

.. admonition:: Implementation: ``Coordinator::create_challenge_with_spec``

   Builds the 36-byte payload, tags it under the challenge key, and base64url-encodes the 52 bytes into a 70-character identifier. In ``crates/challenge/src/coordinator.rs`` (crate ``sibuna-challenge``).

.. code-block:: rust

   pub fn create_challenge_with_spec(
       &self,
       client_ip: &[u8],
       user_agent: &[u8],
       now: u64,
       spec: ChallengeSpec,
       rule_hash: u64,
   ) -> Challenge {
       self.adaptive.observe(now.saturating_mul(1000));
       let effective = ChallengeSpec {
           difficulty: spec.difficulty.saturating_add(self.adaptive.bump()),
           ..spec
       };
       let fingerprint = self.fingerprint(client_ip, user_agent);
       let difficulty = effective.parameter();
       let challenges = match effective.algorithm {
           Algorithm::Hashcash => 0,
           Algorithm::Posw => effective.posw_challenges,
       };

       let mut payload = [0u8; ID_PAYLOAD_LEN];
       payload[0] = ID_VERSION;
       payload[1] = effective.algorithm.to_byte();
       payload[2] = difficulty;
       payload[3] = challenges;
       payload[4..12].copy_from_slice(&now.to_le_bytes());
       payload[12..20].copy_from_slice(&fingerprint.to_le_bytes());
       payload[20..28].copy_from_slice(&self.next_nonce(now, fingerprint).to_le_bytes());
       payload[28..36].copy_from_slice(&rule_hash.to_le_bytes());
       let mut raw = [0u8; ID_RAW_LEN];
       raw[..ID_PAYLOAD_LEN].copy_from_slice(&payload);
       raw[ID_PAYLOAD_LEN..].copy_from_slice(&self.challenge_tag(&payload));

       Challenge {
           id: encoded::encode(&raw),
           algorithm: effective.algorithm,
           difficulty,
           challenges,
           expires_at: now.saturating_add(u64::from(self.challenge_ttl)),
       }
   }

The identifier is an ``Encoded<70>``: the text lives in an array of exactly its length, so issuing a challenge never allocates. ``ChallengeSpec::parameter`` maps work bits to the tier's own unit, Hashcash bits (at most 64) or PoSW depth (``difficulty - 3``, clamped to 4 through 24).

Three details deserve attention:

- *Adaptive difficulty.* The coordinator keeps an exponentially weighted moving average of the challenge issue rate in three atomics. Above a baseline of 50 challenges per second, each doubling of the rate adds one work bit, capped at six. A flood pays exponentially more while quiet traffic keeps the base cost.
- *The nonce is a PRF output*, keyed by the challenge key over a counter, the clock, and the fingerprint. It is unique (counter) and unpredictable (key), so an adversary cannot precompute solutions for identifiers it has not been issued, and the hot path never calls into the operating system for entropy.
- *Difficulty travels inside the tag.* A client cannot lower the difficulty by editing the record: the tag would fail before any proof is examined.

Verification Order and Single Use
---------------------------------

.. admonition:: Objectives

   Understand why the cheap checks run before the proof, why the challenge is marked spent only after the proof is valid, and how two concurrent submissions of one solution are resolved.

.. admonition:: Implementation: ``Coordinator::verify_and_mint``

   Decodes and authenticates the identifier, checks age and client binding, verifies the proof for the recorded tier, records the tag as spent, and mints the session token. In ``crates/challenge/src/coordinator.rs`` (crate ``sibuna-challenge``).

.. code-block:: rust

   pub fn verify_and_mint(
       &self,
       challenge_id: &[u8],
       solution: Solution<'_>,
       client_ip: &[u8],
       user_agent: &[u8],
       now: u64,
   ) -> Result<Verified, VerifyError> {
       let record = self.decode(challenge_id)?;
       let expires_at = record.issued_at.saturating_add(u64::from(self.challenge_ttl));
       if now > expires_at || record.issued_at > now.saturating_add(CLOCK_SKEW_SECONDS) {
           return Err(VerifyError::ChallengeExpired);
       }
       if record.fingerprint != self.fingerprint(client_ip, user_agent) {
           return Err(VerifyError::FingerprintMismatch);
       }
       check_solution(challenge_id, &record, solution)?;
       self.spent.mark_spent(&record.tag, expires_at, now).map_err(|error| match error {
           SpendError::DoubleSpend => VerifyError::DoubleSpendAttempt,
           SpendError::Full => VerifyError::StoreFull,
       })?;
       let work = WorkLevel {
           algorithm: record.algorithm.to_byte(),
           bits: record.algorithm.work_bits(record.difficulty),
       };
       Ok(Verified {
           token: self.mint_token(now, record.rule_hash, record.fingerprint, work),
           algorithm: record.algorithm,
           difficulty: record.difficulty,
           challenges: record.challenges,
           ttl_seconds: self.token_ttl,
       })
   }

The order is deliberate. Tag, age, and binding are constant-time checks that reject garbage before any hashing. A wrong proof must not consume the challenge, so the spent set is written only after ``check_solution`` succeeds. Two threads that both verify the same valid solution race on ``mark_spent``; the shard lock serialises them, exactly one wins, and the other receives ``VerifyError::DoubleSpendAttempt``. The clause ``issued_at > now + 60`` (``CLOCK_SKEW_SECONDS`` is 60) rejects records minted by a node whose clock runs ahead by more than a minute, which would otherwise extend a challenge's life.

Errors surface to the client as ``400`` with an Elm-style diagnostic (Part X): each ``VerifyError`` converts into ``sibuna_core::errors::ErrorKind``, whose explanation is the response body. The end-to-end tests assert on ``DOUBLE SPEND``, ``FINGERPRINT MISMATCH``, ``WRONG SOLUTION TYPE``, and ``MALFORMED CHALLENGE`` in the response body.

The Session Cookie
------------------

.. admonition:: Objectives

   Read the keyed-hash token, understand the cookie attributes, and explain the client binding.

.. admonition:: Implementation: ``token::mac::mint`` and ``token::mac::verify``

   Serialises the 40-byte payload, appends the first 16 bytes of keyed BLAKE3 over it, and verifies with a constant-time comparison. In ``crates/challenge/src/token/mac.rs`` (crate ``sibuna-challenge``). ``Coordinator::verify_cookie`` calls it with the client's fingerprint.

.. code-block:: rust

   pub fn verify(
       key: &[u8; 32],
       text: &[u8],
       now: u64,
       expected_fingerprint: Option<u64>,
   ) -> Result<Payload, TokenError> {
       if text.len() != TOKEN_LEN {
           return Err(TokenError::InvalidTokenLength);
       }
       let raw: [u8; RAW_LEN] =
           encoded::decode::<RAW_LEN, TOKEN_LEN>(text).ok_or(TokenError::InvalidEncoding)?;
       let (payload, given) = raw.split_at(PAYLOAD_LEN);
       let mut bytes = [0u8; PAYLOAD_LEN];
       bytes.copy_from_slice(payload);
       // Constant time: an early exit would tell a forger how many tag bytes were right.
       if !ct::eq(&tag(key, &bytes), given) {
           return Err(TokenError::InvalidTokenSignature);
       }
       let payload = Payload::from_bytes(&bytes)?;
       payload.check(now, expected_fingerprint)?;
       Ok(payload)
   }

The tag is checked before the payload is parsed: a payload of another version is refused with ``TokenError::InvalidEncoding`` only once it is known to be authentic, and a forged one never reaches the parser.

The cookie is emitted as

.. code-block:: text

   Set-Cookie: __sibuna_token=<75 chars>; Path=/; Max-Age=86400; HttpOnly;
       SameSite=Lax[; Secure]

``HttpOnly`` keeps it out of page scripts, ``SameSite=Lax`` stops cross-site replay while allowing top-level navigation, and ``Secure`` is added with ``--secure-cookie`` when TLS terminates in front of the daemon. Because the payload carries the keyed fingerprint of address and User-Agent, a cookie copied to another machine fails with ``TokenError::TokenBoundAddressMismatch``; the end-to-end test "the cookie is bound to the client identity" exercises exactly that path.

The payload begins with a version byte and the *work level* the holder paid: the mechanism (Hashcash or PoSW) and the work bits actually solved, including any load-adaptive bump. A session clears a challenge only when its level reaches what the route demands, computed from the rule's difficulty through the same clamping the challenge itself applies. Levels are ordered, not named: a cookie earned at 24 bits also covers every 16-bit route, while a 16-bit cookie presented to a 24-bit route falls through to the stronger interstitial and the new cookie replaces the old one. ``rule_hash`` remains the audit identity of the rule that issued the challenge; it is reported upstream, never used for admission. WAF findings and explicit denials are never cleared by a session. The end-to-end test "a session earned on a cheaper route does not admit a route that demands more work" exercises both directions.

.. admonition:: Forwarded addresses
   :class: warning

   Behind an ingress the client address arrives in ``X-Forwarded-For``. Sibuna trusts that header only with ``--trust-forwarded`` (implied in forward-auth mode). A reverse proxy exposed directly to the internet must leave it off, or any client could pick its own binding and its own rate-limit bucket.

.. admonition:: Exercise 4.1

   Sketch the sequence of two browsers behind one NAT address with identical User-Agents. Which checks do they share, which do they not, and what would an attacker on that NAT need to reuse the other browser's cookie?

.. admonition:: Explain the invariant

   Explain to an operator why the daemon does not "remember" outstanding challenges and why that is a security feature rather than a shortcut.
