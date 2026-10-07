#import "theme.typ": *
#import "figures.typ": *

#part_page("IV", [The Sibuna Protocol], [
  We specify the wire protocol as implemented: the interstitial round trip, the stateless
  challenge record, both solution formats, verification order, single-use enforcement, and the
  session cookie.
])

== The Challenge Round Trip

#objectives([
  By the end of this chapter, you should be able to trace a browser from its first request to a
  minted session, name every endpoint and JSON field involved, and explain why the challenge
  carries the protected path's policy decision.
])

#book_figure([The challenge round trip], challenge_round_trip())

1. A navigation with no valid session reaches the policy engine and is classified `CHALLENGE`.
   If the request accepts `text/html`, the daemon returns the interstitial page with status
   `200` and `X-Sibuna-Status: CHALLENGE`. Otherwise, it returns `401` with a JSON body
   containing a `challenge` URL.

   Both responses carry a *requirement ticket*. It records the required algorithm, work bits,
   opening count and rule hash. A keyed BLAKE3 tag seals it for this client under a separate
   derived key. It is valid for one challenge lifetime.
2. The interstitial fetches `GET /__sibuna/challenge.json?path=<original URL>&need=<ticket>`.
   A valid ticket preserves the work required by the original decision. Recomputing that
   decision from the fetch could change it: the fetch's `Accept` and `Sec-Fetch-*` headers
   differ from the navigation's headers.

   Without a valid ticket, the server evaluates the reported URL. The same function that
   reads a request line splits it into path and query. URLs longer than 8 KiB receive `414`
   rather than being truncated. The ticket does not grant admission. Admission still checks
   the session's work level, so replaying or forging a ticket cannot clear a stronger requirement.
3. The response is the challenge record:
   ```json
   {"id":"AQEND…70 chars","algorithm":"posw","difficulty":13,"challenges":16,"expires_at":1757241234}
   ```
   For `hashcash`, `difficulty` is the bit count and `challenges` is `0`.
4. A Web Worker solves it with the WebAssembly module, or the JavaScript prover if WebAssembly
   is unavailable (Part VII), and posts either
   ```json
   {"challenge_id":"…","nonce":"90766"}
   ```
   or
   ```json
   {"challenge_id":"…","proof":"<base64url, 32(1 + t(n+1)) bytes>"}
   ```
   to `POST /__sibuna/verify`.
5. On success the server answers `200 {"status":"ok"}` with a `Set-Cookie` header, and the page
   reloads its original location. Later requests carry the cookie. It satisfies a challenge
   decision when the session has paid enough work; inspection and explicit denials still apply.

#callout([Why the path travels with the challenge], [
  The interstitial is served at the protected URL. Its ticket preserves that request's
  difficulty, algorithm and rule hash. For example, checkout may demand 20 work bits of
  sequential work while a blog demands 16 bits of Hashcash. The reported path also permits
  evaluation when the ticket has expired or is absent. The token records the issuing rule's
  hash, which `X-Sibuna-Rule-Hash` reports upstream.
])

== The Stateless Challenge Record

#objectives([
  Read the challenge encoder, understand every field's purpose, and see how the per-challenge
  nonce is derived without an entropy syscall on the hot path.
])

#api_anchor([`Coordinator.createChallengeWithSpec`], [
  Builds the 36-byte payload, tags it under the challenge key, and base64url-encodes the 52
  bytes into a 70-character identifier.
], source: "libs/challenge/src/coordinator.zig")

```zig
pub fn createChallengeWithSpec(self: *Coordinator, client_ip: []const u8,
    user_agent: []const u8,
    now: u64, spec: ChallengeSpec, rule_hash: u64) ChallengePayload {
    self.adaptive.observe(now * 1000);
    var effective = spec;
    effective.difficulty += self.adaptive.bump();
    const fp = self.fingerprint(client_ip, user_agent);
    const difficulty: u8 = switch (effective.algorithm) {
        .hashcash => @intCast(effective.hashcashBits()),
        .posw => effective.poswDepth(),
    };
    const challenges: u8 = if (effective.algorithm == .posw) effective.posw_challenges else 0;

    var raw: [id_raw_len]u8 = undefined;
    raw[0] = version;
    raw[1] = @intFromEnum(effective.algorithm);
    raw[2] = difficulty;
    raw[3] = challenges;
    std.mem.writeInt(u64, raw[4..12], now, .little);
    std.mem.writeInt(u64, raw[12..20], fp, .little);
    std.mem.writeInt(u64, raw[20..28], self.nextNonce(now, fp), .little);
    std.mem.writeInt(u64, raw[28..36], rule_hash, .little);
    raw[payload_len..id_raw_len].* = self.tagFor(raw[0..payload_len]);
    // ... base64url encode and return the payload view
}
```

Three details deserve attention:

- *Adaptive difficulty.* The coordinator keeps an exponentially weighted moving average of the
  challenge issue rate in three atomics. Above a baseline of 50 challenges per second, each
  doubling of the rate adds one work bit, capped at six. This raises the expected puzzle
  work during a flood. Quiet traffic retains the base setting.
- *The nonce is a PRF output*, keyed by the challenge key over a counter, the clock, and the
  fingerprint. The counter distinguishes successive inputs, and the secret key makes the
  result unpredictable. This prevents preparing solutions for predictable future
  identifiers without calling the operating system for entropy on the request path.
- *Difficulty travels inside the tag.* A client cannot lower the difficulty by editing the
  record: the tag would fail before any proof is examined.

== Verification Order and Single Use

#objectives([
  Understand why the cheap checks run before the proof, why the challenge is marked spent only
  after the proof is valid, and how two concurrent submissions of one solution are resolved.
])

#api_anchor([`Coordinator.verifyAndMint`], [
  Decodes and authenticates the identifier, checks age and client binding, verifies the
  proof for the recorded tier, records the tag as spent, and mints the session token.
], source: "libs/challenge/src/coordinator.zig")

```zig
pub fn verifyAndMint(self: *Coordinator, challenge_id: []const u8, solution: Solution,
    client_ip: []const u8, user_agent: []const u8, now: u64) VerifyError!VerifiedResult {
    const decoded = try self.decode(challenge_id);
    const expires_at = decoded.issued_at + self.challenge_ttl;
    if (now > expires_at or decoded.issued_at > now + 60) return error.ChallengeExpired;
    if (decoded.fingerprint != self.fingerprint(client_ip, user_agent)) {
        return error.FingerprintMismatch;
    }
    try checkSolution(challenge_id, decoded, solution);
    self.spent.markSpent(&decoded.tag, expires_at, now) catch |err| switch (err) {
        error.DoubleSpendAttempt => return error.DoubleSpendAttempt,
        else => return error.StoreFull,
    };
    return self.mintToken(now, decoded.rule_hash, decoded.fingerprint);
}
```

Authentication, age and client binding are checked before the more expensive proof.
A wrong proof must not consume the challenge, so the spent set is written after
`checkSolution` succeeds. If two threads verify the same valid solution, they race on
`markSpent`. The shard spinlock serialises them: one wins and the other receives
`DoubleSpendAttempt`.

The `issued_at > now + 60` clause rejects records issued by a node whose clock is more than
a minute ahead. Otherwise, that clock error could extend the challenge's effective lifetime.

Errors surface to the client as `400` with an Elm-style diagnostic (Part X): the end-to-end
tests assert on `DOUBLE SPEND`, `FINGERPRINT MISMATCH`, `WRONG SOLUTION TYPE`, and
`MALFORMED CHALLENGE` in the response body.

== The Session Cookie

#objectives([
  Read the keyed-hash token, understand the cookie attributes, and explain the client binding.
])

#api_anchor([`MacToken.mint` and `MacToken.verify`], [
  Serialises the 40-byte payload, appends the first 16 bytes of keyed BLAKE3 over it, and
  verifies with a constant-time comparison.
], source: "libs/crypto/src/token.zig")

```zig
pub fn verify(key: *const [32]u8, token_str: []const u8, now: u64,
    expected_fingerprint: ?u64) TokenError!Payload {
    if (token_str.len != encoded_size) return error.InvalidTokenLength;
    var raw: [raw_size]u8 = undefined;
    b64.Decoder.decode(&raw, token_str) catch return error.InvalidEncoding;
    const expected = tag(key, raw[0..payload_size]);
    if (!std.crypto.timing_safe.eql([tag_size]u8, expected,
    raw[payload_size..raw_size].*)) {
        return error.InvalidTokenSignature;
    }
    const payload = Payload.deserialize(raw[0..payload_size]);
    try payload.check(now, expected_fingerprint);
    return payload;
}
```

The cookie is emitted as

```
Set-Cookie: __sibuna_token=<75 chars>; Path=/; Max-Age=86400; HttpOnly;
    SameSite=Lax[; Secure]
```

`HttpOnly` prevents page scripts from reading the cookie. `SameSite=Lax` restricts when a
browser sends it with cross-site requests while allowing top-level navigation. Add
`--secure-cookie` when TLS terminates in front of the daemon so that the cookie carries
`Secure`.

The payload contains a keyed fingerprint of the client address and User-Agent. A request
with a different fingerprint fails with `TokenBoundAddressMismatch`. The end-to-end test
"the cookie is bound to the client identity" exercises this check. Clients sharing the same
address and User-Agent also share this binding; it is not a person's identity.

The payload begins with a version byte and the *work level* the holder paid: the mechanism
(Hashcash or PoSW) and the work bits actually solved, including any adaptive increase.
A session satisfies a challenge when its work level reaches the route's requirement. The
requirement uses the same difficulty conversion and bounds as challenge issuance.

A cookie earned at 24 bits can satisfy a 16-bit route. A 16-bit cookie on a 24-bit route
receives a stronger challenge, and the new cookie replaces the old one. `rule_hash` identifies
the issuing rule for audit and upstream reporting; it does not decide admission. WAF findings
and explicit denials remain effective. The end-to-end test "a session earned on a cheaper
route does not admit a route that demands more work" covers both directions.

#warning([Forwarded addresses], [
  Behind an ingress the client address arrives in `X-Forwarded-For`. Sibuna trusts that header
  only with `--trust-forwarded` (implied in forward-auth mode). A reverse proxy exposed directly
  to the internet must leave it off, or any client could pick its own binding and its own
  rate-limit bucket.
])

#exercise([4.1], [
  Sketch the sequence of two browsers behind one NAT address with identical User-Agents. Which
  checks do they share, which do they not, and what would an attacker on that NAT need to reuse
  the other browser's cookie?
])

#teach_back([
  Explain to an operator why the daemon does not "remember" outstanding challenges and why that
  is a security feature rather than a shortcut.
])
