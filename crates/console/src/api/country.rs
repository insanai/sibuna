//! The routes `geoip/country/preview` and `geoip/country/apply` (Zig's `country_routes.zig`).
//!
//! Both routes take every prefix of the country from the active GeoIP generation
//! ([`sibuna_geoip::prefixes`]), stage them in chunks of 32 under the SHA-256 of the set,
//! and then preview or apply in the same transaction. A preview answers a review digest
//! over the generation, the staged set and every operator-selected parameter; an apply, and
//! every preview page after the first, must present the digest of the same review, so a
//! changed form, generation or revision needs a fresh preview. The digest is a consistency
//! check, not a credential: the session and CSRF token are checked as for every mutation.

use std::fmt::{self, Write};

use sibuna_console_protocol::Text;
use sibuna_console_protocol::codec::{Decode, DecodeError, Encode, Fields, Path, WireEnum, field};
use sibuna_console_protocol::workflows::{
    self, ChangeKind, CountryApply, CountryChunk, CountryPreflight, CountrySummary, MAX_PREFIX,
    ReputationAction,
};
use sibuna_console_storage::reputation::{apply_country, preview_country, stage_country_chunk};
use sibuna_crypto::sha256::Sha256;
use sibuna_encoding::hex;
use sibuna_geoip::{Country, prefixes};
use sibuna_json::{Value, Writer};
use sibuna_serve::Context;
use sibuna_storage::Transaction;

use super::policies::Base;
use super::workflows::{ActionName, committed, revision, workflow_error};
use crate::dispatch::Call;
use crate::http::body::read_json;
use crate::http::{RouteError, reply};
use crate::routes::Handler;
use crate::shared::Shared;

/// The domain of the review digest.
const REVIEW_DOMAIN: &[u8] = b"sibuna-country-review-v1";

/// Serves `call.route`, one of this module's routes, after the dispatcher's checks.
///
/// Fails with the [`RouteError`] the route answers with.
pub fn handle(shared: &Shared, context: &mut Context<'_>, call: &Call) -> Result<(), RouteError> {
    match call.route.handler {
        Handler::CountryPreview => country(shared, context, call, false),
        Handler::CountryApply => country(shared, context, call, true),
        _ => Err(RouteError::Unavailable),
    }
}

/// The body of both routes.
struct CountryForm {
    country: String,
    expected_revision: String,
    action: ActionName,
    until: Option<String>,
    review: String,
    offset: u16,
}

impl Decode for CountryForm {
    fn decode(value: &Value<'_>, path: Path<'_>) -> Result<CountryForm, DecodeError> {
        let mut fields = Fields::new(value, path)?;
        let form = CountryForm {
            country: fields.required("country")?,
            expected_revision: fields.required("expected_revision")?,
            action: fields.or("action", ActionName(ReputationAction::Deny))?,
            until: fields.or_default("until")?,
            review: fields.or_default("review")?,
            offset: fields.or_default("offset")?,
        };
        fields.finish()?;
        Ok(form)
    }
}

/// What the operator reviewed: the parameters a review digest covers.
struct Review {
    country: [u8; 2],
    action: ReputationAction,
    expected: u64,
    expires: Option<u64>,
    generation: [u8; 32],
    digest: [u8; 32],
}

impl Review {
    /// Returns the review digest as 64 lowercase hex digits: SHA-256 over the domain, the
    /// generation, the set digest and `{"country":..,"action":..,"expected":..,"expires":..}`.
    fn digest(&self) -> String {
        let mut text = String::new();
        let mut json = Writer::new(&mut text);
        // Writing into a String cannot fail; the country is two ASCII letters.
        let _ = (|| {
            json.begin_object()?;
            field(&mut json, "country", std::str::from_utf8(&self.country).unwrap_or(""))?;
            field(&mut json, "action", ActionName(self.action).name())?;
            field(&mut json, "expected", &self.expected)?;
            field(&mut json, "expires", &self.expires)?;
            json.end_object()
        })();
        let mut hasher = Sha256::new();
        hasher.update(REVIEW_DOMAIN);
        hasher.update(&self.generation);
        hasher.update(&self.digest);
        hasher.update(text.as_bytes());
        hex::encode(&hasher.finalize())
    }
}

/// Returns the SHA-256 of a prefix set written as lines, Zig's staging digest.
fn set_digest(prefixes: &[String]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    for prefix in prefixes {
        hasher.update(prefix.as_bytes());
        hasher.update(b"\n");
    }
    hasher.finalize()
}

/// Returns the chunks that stage `prefixes` under `digest`, 32 prefixes each.
///
/// Fails with [`RouteError::BadRequest`] for a prefix longer than a reputation row holds,
/// which no CIDR text is.
fn chunks(digest: [u8; 32], prefixes: &[String]) -> Result<Vec<CountryChunk>, RouteError> {
    let size = usize::from(workflows::CHUNK_PREFIXES);
    let mut chunks = Vec::with_capacity(prefixes.len().div_ceil(size));
    for (ordinal, part) in prefixes.chunks(size).enumerate() {
        let prefixes = part
            .iter()
            .map(|prefix| Text::<MAX_PREFIX>::new(prefix).map_err(|_| RouteError::BadRequest))
            .collect::<Result<Vec<_>, _>>()?;
        let ordinal = u16::try_from(ordinal).map_err(|_| RouteError::BadRequest)?;
        chunks.push(CountryChunk { digest, ordinal, prefixes });
    }
    Ok(chunks)
}

/// The preview and apply of a country action.
fn country(
    shared: &Shared,
    context: &mut Context<'_>,
    call: &Call,
    applying: bool,
) -> Result<(), RouteError> {
    let mut body = [0u8; 512];
    let form: CountryForm = read_json(context, &mut body)?;
    let code =
        Country::parse(form.country.as_bytes()).ok_or(RouteError::fail(400, "CONSOLEPOLICY"))?;
    let active = shared.geo.active().ok_or(RouteError::fail(409, "CONSOLEGEOIP"))?;
    let prefixes = prefixes::country(&active.database, code, prefixes::MAX_COUNTRY_PREFIXES)
        .map_err(|_| RouteError::fail(422, "CONSOLECAPACITY"))?;
    let digest = set_digest(&prefixes);
    let review = Review {
        country: code.to_bytes(),
        action: form.action.0,
        expected: revision(&form.expected_revision)?,
        expires: form.until.as_deref().map(revision).transpose()?,
        generation: *active.database.digest(),
        digest,
    };
    drop(active);
    let reviewed = review.digest();
    if (applying || form.offset != 0) && form.review != reviewed {
        return Err(RouteError::fail(409, "CONSOLEPOLICY"));
    }
    // At most 1,024 prefixes: the count fits.
    let count = u16::try_from(prefixes.len()).map_err(|_| RouteError::BadRequest)?;
    let job = Job {
        chunks: chunks(digest, &prefixes)?,
        auth: call.auth(shared)?,
        count,
        review,
        offset: form.offset,
        applying,
    };
    let generation = hex::encode(&job.review.generation);
    let credential = call.credential(shared)?;
    let (base, now) = (Base::of(shared), call.now);
    let outcome = shared
        .storage
        .transact(move |tx| Box::pin(async move { job.run(tx, &credential, &base, now).await }))
        .map_err(workflow_error)?;
    match outcome {
        Outcome::Applied(revision) => committed(shared, context, revision),
        Outcome::Previewed(summary) => {
            let preview =
                Preview { summary: &summary, generation: &generation, review: &reviewed };
            Ok(reply::json(context, &preview)?)
        }
    }
}

/// One country transaction: stage every chunk, then preview or apply.
struct Job {
    chunks: Vec<CountryChunk>,
    auth: sibuna_console_protocol::users::Auth,
    count: u16,
    review: Review,
    offset: u16,
    applying: bool,
}

/// What a country transaction committed.
enum Outcome {
    /// The preview of the staged set.
    Previewed(CountrySummary),
    /// The policy revision the apply committed.
    Applied(u64),
}

impl Job {
    async fn run(
        self,
        tx: &mut Transaction,
        credential: &sibuna_console_storage::Credential,
        base: &Base,
        now: u64,
    ) -> Result<Outcome, sibuna_console_storage::ConsoleStorageError> {
        for chunk in &self.chunks {
            stage_country_chunk(tx, credential, chunk, now).await?;
        }
        let options = base.options();
        let review = &self.review;
        if self.applying {
            let apply = CountryApply {
                auth: self.auth,
                expected_revision: review.expected,
                digest: review.digest,
                count: self.count,
                country: review.country,
                action: review.action,
                until: review.expires,
                geo_generation: Text::from_string(hex::encode(&review.generation))
                    .unwrap_or_default(),
            };
            let revision = apply_country(tx, credential, &options, &apply, now).await?;
            return Ok(Outcome::Applied(revision));
        }
        let preflight = CountryPreflight {
            auth: self.auth,
            expected_revision: review.expected,
            digest: review.digest,
            count: self.count,
            country: review.country,
            action: review.action,
            diff_offset: self.offset,
        };
        Ok(Outcome::Previewed(preview_country(tx, credential, &options, &preflight, now).await?))
    }
}

/// A preview in Zig's shape, with the generation and the review digest.
struct Preview<'a> {
    summary: &'a CountrySummary,
    generation: &'a str,
    review: &'a str,
}

impl Encode for Preview<'_> {
    fn encode<W: Write>(&self, json: &mut Writer<W>) -> fmt::Result {
        let summary = self.summary;
        json.begin_object()?;
        field(json, "prefixes", &summary.prefixes)?;
        field(json, "nodes_before", &summary.nodes_before)?;
        field(json, "nodes_after", &summary.nodes_after)?;
        field(json, "overlaps", &summary.overlaps)?;
        field(json, "previous", &summary.previous)?;
        field(json, "added", &summary.added)?;
        field(json, "removed", &summary.removed)?;
        field(json, "retained", &summary.retained)?;
        field(json, "previous_generation", &summary.previous_generation)?;
        field(json, "removed_sample", &summary.removed_sample)?;
        field(json, "sample", &summary.sample)?;
        field(json, "generation", self.generation)?;
        field(json, "review", self.review)?;
        json.key("changes")?;
        json.begin_array()?;
        for change in &summary.changes {
            json.begin_object()?;
            field(json, "prefix", &change.prefix)?;
            field(json, "kind", change_kind(change.kind))?;
            json.end_object()?;
        }
        json.end_array()?;
        field(json, "next_offset", &summary.next_offset)?;
        json.end_object()
    }
}

fn change_kind(kind: ChangeKind) -> &'static str {
    match kind {
        ChangeKind::Added => "added",
        ChangeKind::Retained => "retained",
        ChangeKind::Removed => "removed",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn review() -> Review {
        Review {
            country: *b"US",
            action: ReputationAction::Deny,
            expected: 7,
            expires: None,
            generation: [1; 32],
            digest: [2; 32],
        }
    }

    #[test]
    fn reviews_pin_every_parameter() {
        let first = review().digest();
        assert_eq!(first.len(), 64);
        assert_eq!(first, review().digest());
        let changes = [
            Review { country: *b"DE", ..review() },
            Review { action: ReputationAction::Allow, ..review() },
            Review { expected: 8, ..review() },
            Review { expires: Some(3700), ..review() },
            Review { generation: [3; 32], ..review() },
            Review { digest: [4; 32], ..review() },
        ];
        for changed in changes {
            assert_ne!(changed.digest(), first);
        }
    }

    #[test]
    fn sets_stage_in_chunks_of_32() {
        let prefixes: Vec<String> = (0..70).map(|index| format!("10.0.{index}.0/24")).collect();
        let digest = set_digest(&prefixes);
        let staged = chunks(digest, &prefixes).unwrap();
        assert_eq!(staged.len(), 3);
        assert_eq!(staged[2].ordinal, 2);
        assert_eq!(staged[2].prefixes.len(), 6);
        assert!(chunks(digest, &[]).unwrap().is_empty());
        assert_ne!(set_digest(&prefixes[..1]), digest);
    }
}
