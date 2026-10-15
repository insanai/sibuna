//! Requirement tickets: the challenge a decision demanded, sealed for one client.
//!
//! A ticket is a 28-byte little-endian payload and a 16-byte keyed BLAKE3 tag under the
//! requirement key, 59 URL-safe base64 characters:
//!
//! ```text
//! +-----+-----+------+---+-----------+-------------+-----------+------------+
//! | ver | alg | bits | t | issued_at | fingerprint | rule_hash | BLAKE3 tag |
//! |  1  |  1  |  1   | 1 |     8     |      8      |     8     |     16     |
//! +-----+-----+------+---+-----------+-------------+-----------+------------+
//! ```

use sibuna_crypto::{blake3, ct};
use sibuna_pow::posw;

use super::{CLOCK_SKEW_SECONDS, Coordinator, TAG_LEN};
use crate::encoded::{self, Encoded};
use crate::spec::{Algorithm, ChallengeSpec, Requirement};

const TICKET_VERSION: u8 = 1;
const TICKET_PAYLOAD_LEN: usize = 28;
const TICKET_RAW_LEN: usize = TICKET_PAYLOAD_LEN + TAG_LEN;
/// Length of a requirement ticket in characters (44 raw bytes).
pub const TICKET_LEN: usize = 59;

/// The text of a requirement ticket.
pub type RequirementTicket = Encoded<TICKET_LEN>;

impl Coordinator {
    fn ticket_tag(&self, payload: &[u8; TICKET_PAYLOAD_LEN]) -> [u8; TAG_LEN] {
        let full = blake3::keyed_hash(&self.keys.requirement, payload);
        let mut tag = [0u8; TAG_LEN];
        tag.copy_from_slice(&full[..TAG_LEN]);
        tag
    }

    /// Seals the requirement a decision placed on one client, for one challenge lifetime.
    ///
    /// The decision that demanded work authors the ticket, so issuance never reconstructs
    /// the protected request from a reported URL and the interstitial's own fetch headers.
    /// A ticket is advisory: admission still compares the work a session paid, so a stale or
    /// replayed ticket can only make its holder solve the wrong amount, never pass a route.
    /// The tag keeps the requirement and the rule identity server-authored. The difficulty is
    /// stored as one byte, saturating at 255. Never allocates.
    pub fn requirement_ticket(
        &self,
        requirement: Requirement,
        client_ip: &[u8],
        user_agent: &[u8],
        now: u64,
    ) -> RequirementTicket {
        let spec = requirement.spec;
        let mut payload = [0u8; TICKET_PAYLOAD_LEN];
        payload[0] = TICKET_VERSION;
        payload[1] = spec.algorithm.to_byte();
        payload[2] = u8::try_from(spec.difficulty).unwrap_or(u8::MAX);
        payload[3] = spec.posw_challenges;
        payload[4..12].copy_from_slice(&now.to_le_bytes());
        payload[12..20].copy_from_slice(&self.fingerprint(client_ip, user_agent).to_le_bytes());
        payload[20..28].copy_from_slice(&requirement.rule_hash.to_le_bytes());
        let mut raw = [0u8; TICKET_RAW_LEN];
        raw[..TICKET_PAYLOAD_LEN].copy_from_slice(&payload);
        raw[TICKET_PAYLOAD_LEN..].copy_from_slice(&self.ticket_tag(&payload));
        encoded::encode(&raw)
    }

    /// Opens a ticket and returns the sealed requirement, or `None` for anything this
    /// cluster did not author for this client within the challenge lifetime; callers then
    /// fall back to evaluating the reported target.
    ///
    /// Borrows `text` for the call; never allocates. The tag is compared in constant time
    /// before any field is trusted; then the version, the algorithm, the opening count
    /// (within the PoSW bounds, whatever the tier), the age and the client binding are
    /// checked.
    pub fn open_ticket(
        &self,
        text: &[u8],
        client_ip: &[u8],
        user_agent: &[u8],
        now: u64,
    ) -> Option<Requirement> {
        let raw: [u8; TICKET_RAW_LEN] = encoded::decode::<TICKET_RAW_LEN, TICKET_LEN>(text)?;
        let mut payload = [0u8; TICKET_PAYLOAD_LEN];
        payload.copy_from_slice(&raw[..TICKET_PAYLOAD_LEN]);
        if !ct::eq(&self.ticket_tag(&payload), &raw[TICKET_PAYLOAD_LEN..]) {
            return None;
        }
        let [version, algorithm, difficulty, posw_challenges, ..] = payload;
        if version != TICKET_VERSION {
            return None;
        }
        let algorithm = Algorithm::from_byte(algorithm)?;
        if !(posw::MIN_CHALLENGES..=posw::MAX_CHALLENGES).contains(&posw_challenges) {
            return None;
        }
        let issued = le_u64(&payload, 4);
        let expires_at = issued.saturating_add(u64::from(self.challenge_ttl));
        if issued > now.saturating_add(CLOCK_SKEW_SECONDS) || now > expires_at {
            return None;
        }
        if le_u64(&payload, 12) != self.fingerprint(client_ip, user_agent) {
            return None;
        }
        Some(Requirement {
            spec: ChallengeSpec { algorithm, difficulty: u32::from(difficulty), posw_challenges },
            rule_hash: le_u64(&payload, 20),
        })
    }
}

/// Reads the little-endian `u64` at `at`; callers pass constant offsets at most 20, so the
/// eight bytes lie within the 28-byte payload.
fn le_u64(payload: &[u8; TICKET_PAYLOAD_LEN], at: usize) -> u64 {
    let mut bytes = [0u8; 8];
    bytes.copy_from_slice(&payload[at..at + 8]);
    u64::from_le_bytes(bytes)
}
