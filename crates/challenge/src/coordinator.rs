//! The challenge coordinator: issues stateless challenges, verifies solutions, enforces
//! single use through the spent set, and mints session tokens.
//!
//! A challenge identifier is a self-authenticating record, a 36-byte little-endian payload
//! followed by a 16-byte keyed BLAKE3 tag under the challenge key, encoded as 70 URL-safe
//! base64 characters:
//!
//! ```text
//! +-----+-----+------+---+-----------+-------------+-------+-----------+------------+
//! | ver | alg | diff | t | issued_at | fingerprint | nonce | rule_hash | BLAKE3 tag |
//! |  1  |  1  |  1   | 1 |     8     |      8      |   8   |     8     |     16     |
//! +-----+-----+------+---+-----------+-------------+-------+-----------+------------+
//! ```
//!
//! Issuing one writes nothing. The coordinator remembers only challenges that were solved,
//! so the spent set's occupancy is bounded by work clients actually performed (SID 0006,
//! Theorem 19).

use core::fmt;
use core::num::NonZeroU32;
use std::sync::atomic::{AtomicU64, Ordering};

use sibuna_core::errors::ErrorKind;
use sibuna_crypto::blake3;
use sibuna_crypto::ct;
use sibuna_crypto::ed25519::{SigningKey, VerifyingKey};
use sibuna_pow::{hashcash, posw};
use sibuna_store::spent::{SpendError, SpentSet, Tag};

use crate::adaptive::{Adaptive, AdaptiveConfig};
use crate::encoded::{self, Encoded};
use crate::keys::{Keys, Seed};
use crate::spec::{Algorithm, ChallengeSpec};
use crate::token::{self, Payload, TokenError, WorkLevel, ed25519, mac};

mod ticket;

pub use ticket::{RequirementTicket, TICKET_LEN};

/// Length of the identifier payload in bytes.
pub const ID_PAYLOAD_LEN: usize = 36;
/// Length of the identifier tag in bytes; also the length of a spent-set tag.
pub const TAG_LEN: usize = 16;
/// Length of the raw identifier (payload and tag) in bytes.
pub const ID_RAW_LEN: usize = ID_PAYLOAD_LEN + TAG_LEN;
/// Length of a challenge identifier in characters.
pub const CHALLENGE_ID_LEN: usize = 70;
/// Version byte of the identifier format.
const ID_VERSION: u8 = 1;
/// How far ahead of our clock a record's issue time may be: a node whose clock runs ahead
/// must not extend a challenge's life.
const CLOCK_SKEW_SECONDS: u64 = 60;

/// The text of a challenge identifier.
pub type ChallengeId = Encoded<CHALLENGE_ID_LEN>;

/// Which session token format the coordinator mints and accepts.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub enum TokenScheme {
    /// Keyed BLAKE3 tags (75 characters); the default.
    #[default]
    Mac,
    /// Ed25519 signatures (139 characters).
    Ed25519,
}

/// How to build a [`Coordinator`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Options {
    /// The challenge [`Coordinator::create_challenge`] issues.
    pub default_spec: ChallengeSpec,
    /// Challenge lifetime in seconds.
    pub challenge_ttl: u32,
    /// Session token lifetime in seconds.
    pub token_ttl: u64,
    /// The session token format.
    pub token_scheme: TokenScheme,
    /// The cluster node id; `Some` binds the challenge key to it ([`Keys::bind_node`]).
    pub node: Option<NonZeroU32>,
    /// Tuning of the load-adaptive difficulty.
    pub adaptive: AdaptiveConfig,
    /// Tags the spent set holds (see [`SpentSet::with_capacity`]): at least the challenge
    /// lifetime times the peak rate of verified solutions.
    pub spent_capacity: usize,
}

impl Default for Options {
    /// The daemon's defaults: 16-bit Hashcash, five-minute challenges, one-day MAC tokens,
    /// no cluster binding, a spent set of 1,048,576 tags.
    fn default() -> Self {
        Options {
            default_spec: ChallengeSpec::default(),
            challenge_ttl: 300,
            token_ttl: 86_400,
            token_scheme: TokenScheme::Mac,
            node: None,
            adaptive: AdaptiveConfig::default(),
            spent_capacity: sibuna_store::spent::DEFAULT_CAPACITY,
        }
    }
}

/// An issued challenge: what the challenge record (`challenge.json`) reports.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Challenge {
    /// The challenge identifier, which is also the statement the client solves.
    pub id: ChallengeId,
    /// The tier.
    pub algorithm: Algorithm,
    /// Hashcash: leading zero bits. PoSW: tree depth.
    pub difficulty: u8,
    /// PoSW opening count; zero for Hashcash.
    pub challenges: u8,
    /// Last second at which a solution is accepted.
    pub expires_at: u64,
}

/// A client's answer to a challenge.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Solution<'a> {
    /// A Hashcash nonce.
    Nonce(u64),
    /// A PoSW proof, borrowed from the request.
    Proof(&'a [u8]),
}

/// A session token in the coordinator's scheme. `Debug` does not print the credential.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum SessionToken {
    /// A 75-character MAC token.
    Mac(mac::MacTokenText),
    /// A 139-character Ed25519 token.
    Ed25519(ed25519::Ed25519TokenText),
}

impl SessionToken {
    /// Borrows the token text, the cookie value.
    pub fn as_str(&self) -> &str {
        match self {
            SessionToken::Mac(text) => text.as_str(),
            SessionToken::Ed25519(text) => text.as_str(),
        }
    }

    /// Returns the scheme the token was minted in.
    pub fn scheme(&self) -> TokenScheme {
        match self {
            SessionToken::Mac(_) => TokenScheme::Mac,
            SessionToken::Ed25519(_) => TokenScheme::Ed25519,
        }
    }
}

impl fmt::Debug for SessionToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SessionToken({:?}, <{} characters>)", self.scheme(), self.as_str().len())
    }
}

/// The result of an accepted solution: the minted session token and what was solved.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Verified {
    /// The session token to set as the cookie.
    pub token: SessionToken,
    /// The tier that was solved.
    pub algorithm: Algorithm,
    /// The solved difficulty in the tier's unit (bits or depth).
    pub difficulty: u8,
    /// PoSW openings; zero for Hashcash.
    pub challenges: u8,
    /// The token's lifetime in seconds, the cookie's `Max-Age`.
    pub ttl_seconds: u64,
}

/// Why a solution was refused. The variants keep the Zig error names, which the daemon's
/// explanations (`sibuna_core::errors`) also use.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum VerifyError {
    /// The identifier is not 70 characters of canonical base64, or its version or algorithm
    /// byte is unknown.
    MalformedChallenge,
    /// The identifier's tag does not verify: it was not issued by this node.
    InvalidChallengeTag,
    /// The challenge is past its lifetime, or was issued more than a minute in the future.
    ChallengeExpired,
    /// The submitting client is not the client the challenge was issued to.
    FingerprintMismatch,
    /// The Hashcash digest has too few leading zero bits.
    DifficultyNotMet,
    /// The proof of sequential work does not verify.
    InvalidProof,
    /// A nonce for a PoSW challenge, or a proof for a Hashcash challenge.
    WrongSolutionType,
    /// The challenge was already solved.
    DoubleSpendAttempt,
    /// The spent set cannot record the challenge without evicting a live one.
    StoreFull,
}

impl fmt::Display for VerifyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            VerifyError::MalformedChallenge => "the challenge identifier is malformed",
            VerifyError::InvalidChallengeTag => "the challenge identifier failed authentication",
            VerifyError::ChallengeExpired => "the challenge has expired",
            VerifyError::FingerprintMismatch => "the challenge was issued to another client",
            VerifyError::DifficultyNotMet => "the nonce does not meet the difficulty",
            VerifyError::InvalidProof => "the proof of sequential work does not verify",
            VerifyError::WrongSolutionType => "the solution does not match the challenge's tier",
            VerifyError::DoubleSpendAttempt => "the challenge was already solved",
            VerifyError::StoreFull => "the spent set is full",
        })
    }
}

impl std::error::Error for VerifyError {}

/// Maps a verification error onto the daemon's explanation table, name for name.
impl From<VerifyError> for ErrorKind {
    fn from(error: VerifyError) -> ErrorKind {
        match error {
            VerifyError::MalformedChallenge => ErrorKind::MalformedChallenge,
            VerifyError::InvalidChallengeTag => ErrorKind::InvalidChallengeTag,
            VerifyError::ChallengeExpired => ErrorKind::ChallengeExpired,
            VerifyError::FingerprintMismatch => ErrorKind::FingerprintMismatch,
            VerifyError::DifficultyNotMet => ErrorKind::DifficultyNotMet,
            VerifyError::InvalidProof => ErrorKind::InvalidProof,
            VerifyError::WrongSolutionType => ErrorKind::WrongSolutionType,
            VerifyError::DoubleSpendAttempt => ErrorKind::DoubleSpendAttempt,
            VerifyError::StoreFull => ErrorKind::StoreFull,
        }
    }
}

/// The authenticated fields of a challenge identifier.
#[derive(Clone, Copy, Debug)]
struct Record {
    algorithm: Algorithm,
    difficulty: u8,
    challenges: u8,
    issued_at: u64,
    fingerprint: u64,
    rule_hash: u64,
    tag: Tag,
}

/// Issues and verifies challenges and session tokens. Share it between threads by reference
/// (for example in an `Arc`): every method takes `&self`, and none blocks except the brief
/// shard lock of the spent set.
pub struct Coordinator {
    keys: Keys,
    signing_key: SigningKey,
    verifying_key: VerifyingKey,
    token_scheme: TokenScheme,
    spent: SpentSet,
    default_spec: ChallengeSpec,
    challenge_ttl: u32,
    token_ttl: u64,
    adaptive: Adaptive,
    /// Counter of the per-challenge nonce; starts at 1 and wraps.
    counter: AtomicU64,
}

impl Coordinator {
    /// Builds a coordinator from `seed`: derives the key schedule, binds the challenge key to
    /// `options.node` when given, derives the Ed25519 key pair, and allocates the spent set
    /// (24 bytes per tag of `options.spent_capacity`, once). Never fails.
    pub fn new(seed: &Seed, options: Options) -> Coordinator {
        let mut keys = Keys::derive(seed);
        if let Some(node) = options.node {
            keys.bind_node(node);
        }
        let signing_key = SigningKey::from_seed(&keys.ed25519_seed);
        let verifying_key = signing_key.verifying_key();
        Coordinator {
            keys,
            signing_key,
            verifying_key,
            token_scheme: options.token_scheme,
            spent: SpentSet::with_capacity(options.spent_capacity),
            default_spec: options.default_spec,
            challenge_ttl: options.challenge_ttl,
            token_ttl: options.token_ttl,
            adaptive: Adaptive::new(options.adaptive),
            counter: AtomicU64::new(1),
        }
    }

    /// Returns the challenge [`Coordinator::create_challenge`] issues.
    pub fn default_spec(&self) -> ChallengeSpec {
        self.default_spec
    }

    /// Returns the session token format.
    pub fn token_scheme(&self) -> TokenScheme {
        self.token_scheme
    }

    /// Returns the challenge lifetime in seconds.
    pub fn challenge_ttl(&self) -> u32 {
        self.challenge_ttl
    }

    /// Returns the session token lifetime in seconds.
    pub fn token_ttl(&self) -> u64 {
        self.token_ttl
    }

    /// Borrows the load-adaptive difficulty controller, for telemetry.
    pub fn adaptive(&self) -> &Adaptive {
        &self.adaptive
    }

    /// Borrows the public key of Ed25519 tokens, which non-minting verifiers need.
    pub fn verifying_key(&self) -> &VerifyingKey {
        &self.verifying_key
    }

    /// Returns the keyed fingerprint of a client ([`token::fingerprint_keyed`] under the
    /// fingerprint key).
    pub fn fingerprint(&self, client_ip: &[u8], user_agent: &[u8]) -> u64 {
        token::fingerprint_keyed(&self.keys.fingerprint, client_ip, user_agent)
    }

    fn challenge_tag(&self, payload: &[u8; ID_PAYLOAD_LEN]) -> Tag {
        let full = blake3::keyed_hash(&self.keys.challenge, payload);
        let mut tag = [0u8; TAG_LEN];
        tag.copy_from_slice(&full[..TAG_LEN]);
        tag
    }

    /// Returns the per-challenge nonce: a PRF of a counter, the clock and the client, so
    /// identifiers are unique and unpredictable without an entropy system call on the
    /// request path. The counter needs no ordering beyond its own atomicity.
    fn next_nonce(&self, now: u64, fingerprint: u64) -> u64 {
        let count = self.counter.fetch_add(1, Ordering::Relaxed);
        let mut input = [0u8; 24];
        input[..8].copy_from_slice(&count.to_le_bytes());
        input[8..16].copy_from_slice(&now.to_le_bytes());
        input[16..].copy_from_slice(&fingerprint.to_le_bytes());
        let mut hasher = blake3::Hasher::new_keyed(&self.keys.challenge);
        hasher.update(&input).update(b"nonce");
        let digest = hasher.finalize();
        let mut first = [0u8; 8];
        first.copy_from_slice(&digest[..8]);
        u64::from_le_bytes(first)
    }

    /// Issues the default challenge to a client at time `now` (seconds), with rule hash 0.
    pub fn create_challenge(&self, client_ip: &[u8], user_agent: &[u8], now: u64) -> Challenge {
        self.create_challenge_with_spec(client_ip, user_agent, now, self.default_spec, 0)
    }

    /// Issues a challenge for `spec` to a client at time `now` (seconds), on behalf of the
    /// rule whose hash is `rule_hash`.
    ///
    /// Advances the adaptive controller's clock and adds its current bump to the
    /// difficulty before mapping it to the tier's parameter. Issuance is not counted: the
    /// controller follows verified solutions. Writes no state besides the controller's
    /// clock; never allocates.
    pub fn create_challenge_with_spec(
        &self,
        client_ip: &[u8],
        user_agent: &[u8],
        now: u64,
        spec: ChallengeSpec,
        rule_hash: u64,
    ) -> Challenge {
        self.adaptive.advance(now.saturating_mul(1000));
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

    /// Decodes and authenticates an identifier. The version byte is checked before the tag
    /// and the algorithm byte after it, as in Zig, so the same input yields the same error.
    fn decode(&self, challenge_id: &[u8]) -> Result<Record, VerifyError> {
        let raw: [u8; ID_RAW_LEN] = encoded::decode::<ID_RAW_LEN, CHALLENGE_ID_LEN>(challenge_id)
            .ok_or(VerifyError::MalformedChallenge)?;
        if raw[0] != ID_VERSION {
            return Err(VerifyError::MalformedChallenge);
        }
        let mut payload = [0u8; ID_PAYLOAD_LEN];
        payload.copy_from_slice(&raw[..ID_PAYLOAD_LEN]);
        let mut tag = [0u8; TAG_LEN];
        tag.copy_from_slice(&raw[ID_PAYLOAD_LEN..]);
        if !ct::eq(&self.challenge_tag(&payload), &tag) {
            return Err(VerifyError::InvalidChallengeTag);
        }
        let algorithm = Algorithm::from_byte(raw[1]).ok_or(VerifyError::MalformedChallenge)?;
        Ok(Record {
            algorithm,
            difficulty: raw[2],
            challenges: raw[3],
            issued_at: le_u64(&payload, 4),
            fingerprint: le_u64(&payload, 12),
            rule_hash: le_u64(&payload, 28),
            tag,
        })
    }

    /// Verifies a solution and mints a session token bound to the client and to the rule
    /// that demanded the challenge.
    ///
    /// Borrows the identifier and the solution for the call; never allocates. The order is
    /// deliberate: the cheap checks (identifier format and tag, then age, then client
    /// binding) run before the proof is examined, and the challenge is marked spent only
    /// once the proof is known to be valid, so a wrong proof never consumes it. Only a
    /// solution that is spent here counts toward the adaptive difficulty. Fails with
    /// the first [`VerifyError`] met in that order; [`VerifyError::DoubleSpendAttempt`] when
    /// the challenge was already solved, here or by a concurrent submission that won the
    /// spent set's shard lock.
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
        self.adaptive.observe(now.saturating_mul(1000));
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

    fn mint_token(
        &self,
        now: u64,
        rule_hash: u64,
        fingerprint: u64,
        work: WorkLevel,
    ) -> SessionToken {
        let payload = Payload {
            timestamp: now,
            expiry: now.saturating_add(self.token_ttl),
            rule_hash,
            client_fingerprint: fingerprint,
            work,
        };
        match self.token_scheme {
            TokenScheme::Mac => SessionToken::Mac(mac::mint(&self.keys.token, &payload)),
            TokenScheme::Ed25519 => {
                SessionToken::Ed25519(ed25519::mint(&self.signing_key, &payload))
            }
        }
    }

    /// Verifies a session cookie for a client at time `now` and returns its payload.
    ///
    /// Borrows the cookie for the call; never allocates. Fails with the [`TokenError`] of
    /// [`mac::verify`] or [`ed25519::verify`], whichever the coordinator's scheme selects;
    /// the token must be bound to this client's fingerprint.
    pub fn verify_cookie(
        &self,
        cookie: &[u8],
        client_ip: &[u8],
        user_agent: &[u8],
        now: u64,
    ) -> Result<Payload, TokenError> {
        let fingerprint = Some(self.fingerprint(client_ip, user_agent));
        match self.token_scheme {
            TokenScheme::Mac => mac::verify(&self.keys.token, cookie, now, fingerprint),
            TokenScheme::Ed25519 => ed25519::verify(&self.verifying_key, cookie, now, fingerprint),
        }
    }
}

impl fmt::Debug for Coordinator {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Coordinator")
            .field("token_scheme", &self.token_scheme)
            .field("default_spec", &self.default_spec)
            .field("challenge_ttl", &self.challenge_ttl)
            .field("token_ttl", &self.token_ttl)
            .field("adaptive", &self.adaptive)
            .finish_non_exhaustive()
    }
}

/// Checks the proof against the authenticated record. Hashcash costs one SHA-256; PoSW
/// costs `t (n + 1)` compressions and rejects a proof of the wrong length before hashing.
fn check_solution(
    challenge_id: &[u8],
    record: &Record,
    solution: Solution<'_>,
) -> Result<(), VerifyError> {
    match (record.algorithm, solution) {
        (Algorithm::Hashcash, Solution::Nonce(nonce)) => {
            if hashcash::verify_bits(challenge_id, nonce, u32::from(record.difficulty)) {
                Ok(())
            } else {
                Err(VerifyError::DifficultyNotMet)
            }
        }
        (Algorithm::Posw, Solution::Proof(proof)) => {
            let params = posw::Params { depth: record.difficulty, challenges: record.challenges };
            if posw::verify(challenge_id, params, proof) {
                Ok(())
            } else {
                Err(VerifyError::InvalidProof)
            }
        }
        (Algorithm::Hashcash, Solution::Proof(_)) | (Algorithm::Posw, Solution::Nonce(_)) => {
            Err(VerifyError::WrongSolutionType)
        }
    }
}

/// Reads the little-endian `u64` at `at`; callers pass constant offsets at most 28, so the
/// eight bytes lie within the 36-byte payload.
fn le_u64(payload: &[u8; ID_PAYLOAD_LEN], at: usize) -> u64 {
    let mut bytes = [0u8; 8];
    bytes.copy_from_slice(&payload[at..at + 8]);
    u64::from_le_bytes(bytes)
}

#[cfg(test)]
mod tests;
