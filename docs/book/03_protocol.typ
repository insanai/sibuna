#import "theme.typ": *
#import "figures.typ": *

#part_page("III", [The Sibuna Protocol Specification], [
  We formalize the cryptographic primitives, challenge lifecycle, double-spend protection,
  96-byte compact binary token format, and client fingerprinting mechanisms.
])

= Challenge Issuance and Decay Mechanics

#objectives([
  By the end of this chapter, you should be able to specify the exact wire format of a Sibuna
  challenge, explain why monotonic atomic sequence counters guarantee collision resistance, and
  trace how the sharded decay cache guarantees atomic single-use spend protection.
])

== Challenge Structure and Generation

When an incoming request requires Proof-of-Work validation, the Sibuna coordinator generates a
globally unique challenge. The challenge must satisfy three cryptographic invariants:
1. *Uniqueness:* No two active challenges may share an identifier across the cluster.
2. *Bounded Lifetime:* Challenges must expire after a fixed TTL (default: 120 seconds) to bound
   the memory footprint of the active challenge store.
3. *Single-Use Spend Protection:* Once a valid solution (nonce) is verified, the challenge
   must transition atomically to the *spent* state to prevent replay attacks.

#api_anchor([`Coordinator.createChallenge`], [
  Generates a 32-byte hexadecimal challenge identifier using an atomic monotonic counter mixed
  with Wyhash pseudo-random entropy.
], source: "libs/challenge/src/coordinator.zig")

```zig
pub fn createChallenge(
    self: *Coordinator,
    client_ip: []const u8,
    user_agent: []const u8,
    now: u64,
) !ChallengePayload {
    const seq = self.counter.fetchAdd(1, .monotonic);
    var id_buf: [32]u8 = undefined;
    const cid = try std.fmt.bufPrint(
        &id_buf,
        "sib_{x:0>8}_{x:0>16}",
        .{ @as(u32, @truncate(now)), seq ^ std.hash.Wyhash.hash(seq, client_ip) },
    );
    const fp = crypto.token.computeFingerprint(client_ip, user_agent);
    try self.challenge_store.put(cid, self.default_difficulty, now, self.challenge_ttl, fp);
    return .{ .id = id_buf, .difficulty = self.default_difficulty, .algorithm = "sha256" };
}
```

== Atomic Single-Use Spend Protection

A critical failure mode in naive Proof-of-Work systems is the *Replay Attack*: an attacker
solves a challenge once and replays the solution across thousands of parallel HTTP connections.

To eliminate this vulnerability without introducing heavyweight distributed databases, Sibuna
maintains an in-memory decay store partitioned into 16 independent cache shards. When a solution
is submitted to `/__sibuna/verify`, the coordinator calls `getAndMarkSpent`:

```zig
pub fn getAndMarkSpent(
    self: *ChallengeStore,
    id: []const u8,
    now: u64,
    fingerprint: ?u64,
) StoreError!ChallengeRecord {
    const shard = &self.shards[shardIndex(id)];
    shard.lock.lock();
    defer shard.lock.unlock();

    const idx = shard.findSlot(id, now) orelse return error.ChallengeNotFound;
    const entry = &shard.entries[idx];
    if (!entry.occupied) return error.ChallengeNotFound;
    if (now > entry.issued_at + entry.ttl_seconds) return error.ChallengeExpired;
    if (entry.spent) return error.DoubleSpendAttempt;

    if (fingerprint) |fp| {
        if (entry.bound_fingerprint != 0 and entry.bound_fingerprint != fp) {
            return error.FingerprintMismatch;
        }
    }

    entry.spent = true;
    return entry.*;
}
```

The verification of non-spent status and the state transition to `spent = true` occur under the
atomic protection of the shard's spinlock. Any parallel or subsequent request presenting the same
challenge ID is instantly rejected with an Elm-style `DoubleSpendAttempt` diagnostic.

#v(4mm)

= The 96-Byte Compact Authorization Token

#objectives([
  Deconstruct the binary wire format of Sibuna authorization tokens, compare them with standard
  JSON Web Tokens (JWT), and understand how client fingerprinting prevents cookie theft across
  distributed proxy networks.
])

== Token Architecture: Binary vs JSON

Existing firewalls typically issue authorization cookies formatted as JSON Web Tokens (JWT).
A typical JWT includes a base64-encoded header (`{"alg":"HS256","typ":"JWT"}`), a JSON payload
containing standard claims (`{"iss":"...","exp":1725700000,"sub":"..."}`), and a signature.
Parsing such tokens requires base64 decoding, JSON string tokenization, map allocation, and
reflection.

Sibuna rejects JSON entirely in favor of a fixed-layout, 96-byte compact binary token.

#book_figure([Wire format of the 96-byte compact binary token], token_wire_format())

The token consists of two contiguous sections:
1. *Payload (32 Bytes):* Four 64-bit big-endian unsigned integers:
   - `timestamp` ($8$ bytes): Unix timestamp of token issuance.
   - `expiry` ($8$ bytes): Unix timestamp when the token ceases to be valid.
   - `rule_hash` ($8$ bytes): Hash of the firewall rule or difficulty tier under which the token was earned.
   - `client_fingerprint` ($8$ bytes): Cryptographic hash binding the token to the client's identity.
2. *Signature (64 Bytes):* An Ed25519 asymmetric cryptographic signature calculated over the 32-byte payload.

When encoded for HTTP transport as a cookie (`__sibuna_token`), the 96 raw bytes are transformed
via URL-safe Base64 without padding into exactly *128 ASCII characters*.

== Anti-Cookie-Theft Client Fingerprinting

In distributed scraping botnets, attackers frequently employ a *solver node*: a dedicated,
high-powered cloud server solves the Proof-of-Work puzzle and transmits the resulting cookie to
thousands of distributed residential scraping agents.

Sibuna neutralizes this tactic through *Client Fingerprinting*. When a challenge is issued,
the server computes a 64-bit Wyhash fingerprint from the client's network layer attributes:

```zig
pub fn computeFingerprint(client_ip: []const u8, user_agent: []const u8) u64 {
    var hasher = std.hash.Wyhash.init(0x1337_cafe_babe_dead);
    hasher.update(client_ip);
    hasher.update("||");
    hasher.update(user_agent);
    return hasher.final();
}
```

This fingerprint is embedded directly into the 32-byte payload and signed with the server's
private Ed25519 key. When an authorized request arrives carrying the cookie, Sibuna recomputes
the fingerprint from the incoming socket IP and User-Agent header, comparing it against the
deserialized payload.

If a scraping bot attempts to reuse a cookie obtained from a different IP address or user agent,
`Token.verify` immediately rejects the request with `error.TokenBoundAddressMismatch`. The stolen
cookie is completely inert.

#exercise([3.1], [
  Why is Ed25519 signature verification superior to symmetric HMAC-SHA256 for a multi-region
  reverse proxy cluster? What security advantage does asymmetric cryptography offer when
  distributing verification keys to edge sidecars?
], hint: [Edge sidecars only require the 32-byte public key; private signing keys remain confined to the challenge issuer.])
