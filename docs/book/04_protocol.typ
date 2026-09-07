#import "theme.typ": *
#import "figures.typ": *

#part_page("IV", [The Sibuna Protocol], [
  We specify the wire protocol as implemented: the interstitial round trip, the stateless
  challenge record, both solution formats, verification order, single-use enforcement, and the
  session cookie.
])

= The Challenge Round Trip

#objectives([
  By the end of this chapter, you should be able to trace a browser from its first request to a
  minted session, name every endpoint and JSON field involved, and explain why the challenge
  carries the protected path's policy decision.
])

#book_figure([The challenge round trip], challenge_round_trip())

1. A navigation with no valid session reaches the policy engine and is classified `CHALLENGE`.
   Because the request accepts `text/html`, the daemon answers `200` with the interstitial
   page and the header `X-Sibuna-Status: CHALLENGE`; an API client that does not accept HTML
   receives `401` with a JSON body naming the challenge endpoint.
2. The interstitial fetches `GET /__sibuna/challenge.json?path=<original path>`. The server
   re-evaluates the policy for that path with the real client headers, so the rule that demanded
   the challenge decides the difficulty and algorithm, and the rule's hash is bound into the
   challenge.
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
   reloads its original location. Every later request carries the cookie and is admitted
   before policy evaluation.

#callout([Why the path travels with the challenge], [
  The interstitial is served at the protected URL, so the browser knows where it is. Sending
  the path lets the server pick the *per-rule* difficulty and algorithm (a checkout route may
  demand 20 work bits of sequential work while a blog demands 16 bits of Hashcash) and binds the
  rule hash into the token, where `X-Sibuna-Rule-Hash` reports it upstream.
])

= The Stateless Challenge Record

#objectives([
  Read the challenge encoder, understand every field's purpose, and see how the per-challenge
  nonce is derived without an entropy syscall on the hot path.
])

#api_anchor([`Coordinator.createChallengeWithSpec`], [
  Builds the 36-byte payload, tags it under the challenge key, and base64url-encodes the 52
  bytes into a 70-character identifier.
], source: "libs/challenge/src/coordinator.zig")

```zig
pub fn createChallengeWithSpec(self: *Coordinator, client_ip: []const u8, user_agent: []const u8,
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
  challenge issue rate in two atomics. Above a baseline of 50 challenges per second, each
  doubling of the rate adds one work bit, capped at six. A flood pays exponentially more while
  quiet traffic keeps the base cost.
- *The nonce is a PRF output*, keyed by the challenge key over a counter, the clock, and the
  fingerprint. It is unique (counter) and unpredictable (key), so an adversary cannot
  precompute solutions for identifiers it has not been issued, and the hot path never calls
  into the operating system for entropy.
- *Difficulty travels inside the tag.* A client cannot lower the difficulty by editing the
  record: the tag would fail before any proof is examined.

= Verification Order and Single Use

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

The order is deliberate. Tag, age, and binding are constant-time checks that reject garbage
before any hashing. A wrong proof must not consume the challenge, so the spent set is written
only after `checkSolution` succeeds. Two threads that both verify the same valid solution race
on `markSpent`; the shard spinlock serialises them, exactly one wins, and the other receives
`DoubleSpendAttempt`. The `issued_at > now + 60` clause rejects records minted by a node whose
clock runs ahead by more than a minute, which would otherwise extend a challenge's life.

Errors surface to the client as `400` with an Elm-style diagnostic (Part X): the end-to-end
tests assert on `DOUBLE SPEND`, `FINGERPRINT MISMATCH`, `WRONG SOLUTION TYPE`, and
`MALFORMED CHALLENGE` in the response body.

= The Session Cookie

#objectives([
  Read the keyed-hash token, understand the cookie attributes, and explain the client binding.
])

#api_anchor([`MacToken.mint` and `MacToken.verify`], [
  Serialises the 32-byte payload, appends the first 16 bytes of keyed BLAKE3 over it, and
  verifies with a constant-time comparison.
], source: "libs/crypto/src/token.zig")

```zig
pub fn verify(key: *const [32]u8, token_str: []const u8, now: u64,
    expected_fingerprint: ?u64) TokenError!Payload {
    if (token_str.len != encoded_size) return error.InvalidTokenLength;
    var raw: [raw_size]u8 = undefined;
    b64.Decoder.decode(&raw, token_str) catch return error.InvalidEncoding;
    const expected = tag(key, raw[0..payload_size]);
    if (!std.crypto.timing_safe.eql([tag_size]u8, expected, raw[payload_size..raw_size].*)) {
        return error.InvalidTokenSignature;
    }
    const payload = Payload.deserialize(raw[0..payload_size]);
    try payload.check(now, expected_fingerprint);
    return payload;
}
```

The cookie is emitted as

```
Set-Cookie: __sibuna_token=<64 chars>; Path=/; Max-Age=86400; HttpOnly; SameSite=Lax[; Secure]
```

`HttpOnly` keeps it out of page scripts, `SameSite=Lax` stops cross-site replay while allowing
top-level navigation, and `Secure` is added with `--secure-cookie` when TLS terminates in front
of the daemon. Because the payload carries the keyed fingerprint of address and User-Agent, a
cookie copied to another machine fails with `TokenBoundAddressMismatch`; the end-to-end test
"the cookie is bound to the client identity" exercises exactly that path.

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
