//! The GeoIP commands (Zig's `console_command_geo.zig`): `geoip status` prints the active
//! generation; `geoip update` asks the daemon to import a publisher version and waits, within
//! one monotonic budget that includes every HTTP wait, until the next generation is active.
//!
//! The import runs in the daemon; this client only observes the committed generation. A
//! timed-out wait does not mean the import rolled back: activation may have committed
//! before a reply was lost.

use std::io::Write;
use std::time::{Duration, Instant};

use sibuna_console_protocol::codec::{self, Decode, DecodeError, Fields, Path};
use sibuna_console_protocol::geo::valid_source_digests;
use sibuna_geoip::Provider;
use sibuna_json::Value;

use super::args::{Args, Kind};
use super::{CommandError, Field, REQUEST_TIMEOUT, Session, body, emit, require_ok};
use crate::client::{ClientError, Method};

/// The longest pause between two status queries.
const POLL: Duration = Duration::from_secs(2);
/// The most ranges a generation holds.
const MAX_RANGES: u32 = 1024 * 1024;
/// What an embedded build snapshot reports as its source.
const EMBEDDED: &str = "embedded snapshot";

/// The import job's state.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Status {
    Idle,
    Downloading,
    Validating,
    Storing,
    Applied,
    Failed,
}

impl Status {
    fn parse(name: &str) -> Option<Status> {
        Some(match name {
            "idle" => Status::Idle,
            "downloading" => Status::Downloading,
            "validating" => Status::Validating,
            "storing" => Status::Storing,
            "applied" => Status::Applied,
            "failed" => Status::Failed,
            _ => return None,
        })
    }

    fn name(self) -> &'static str {
        match self {
            Status::Idle => "idle",
            Status::Downloading => "downloading",
            Status::Validating => "validating",
            Status::Storing => "storing",
            Status::Applied => "applied",
            Status::Failed => "failed",
        }
    }

    fn is_busy(self) -> bool {
        matches!(self, Status::Downloading | Status::Validating | Status::Storing)
    }
}

/// The reply of `GET /console/api/geoip`, every member required.
struct Wire {
    revision: u64,
    digest: String,
    provider: String,
    source_version: String,
    source_digests: String,
    ranges: u32,
    loaded_at: u64,
    status: String,
    processed_ranges: u32,
    source: String,
    license: String,
    attribution: String,
}

impl Decode for Wire {
    fn decode(value: &Value<'_>, path: Path<'_>) -> Result<Wire, DecodeError> {
        let mut fields = Fields::new(value, path)?;
        let wire = Wire {
            revision: fields.required("revision")?,
            digest: fields.required("digest")?,
            provider: fields.required("provider")?,
            source_version: fields.required("source_version")?,
            source_digests: fields.required("source_digests")?,
            ranges: fields.required("ranges")?,
            loaded_at: fields.required("loaded_at")?,
            status: fields.required("status")?,
            processed_ranges: fields.required("processed_ranges")?,
            source: fields.required("source")?,
            license: fields.required("license")?,
            attribution: fields.required("attribution")?,
        };
        fields.finish()?;
        Ok(wire)
    }
}

/// What the command reads from a status reply.
#[derive(Debug, PartialEq, Eq)]
struct Metadata {
    revision: u64,
    digest: String,
    provider: String,
    version: String,
    status: Status,
    progress: u32,
}

/// Decodes and checks a status reply: the publisher's own title, licence and attribution,
/// bounded counts, and either no generation (revision 0) or a complete one. An embedded
/// build snapshot reports revision 0 with a populated generation.
fn parse(bytes: &[u8]) -> Result<Metadata, CommandError> {
    let wire: Wire = codec::from_json(bytes).map_err(|_| CommandError::InvalidResponse)?;
    let valid = check(&wire).ok_or(CommandError::InvalidResponse)?;
    let status = Status::parse(&wire.status).filter(|_| valid);
    let status = status.ok_or(CommandError::InvalidResponse)?;
    Ok(Metadata {
        revision: wire.revision,
        digest: wire.digest,
        provider: wire.provider,
        version: wire.source_version,
        status,
        progress: wire.processed_ranges,
    })
}

/// Returns whether `wire` is consistent; `None` when the provider is unknown.
fn check(wire: &Wire) -> Option<bool> {
    let provider = Provider::parse(&wire.provider)?;
    let bounded = wire.revision <= i64::MAX as u64
        && wire.ranges <= MAX_RANGES
        && wire.processed_ranges <= MAX_RANGES;
    let embedded = wire.revision == 0 && wire.source == EMBEDDED;
    let labelled = (embedded || wire.source == provider.title())
        && wire.license == provider.license()
        && wire.attribution == provider.attribution().unwrap_or_default()
        && valid_source_digests(&wire.source_digests);
    let generation = if wire.revision == 0 && !embedded {
        wire.digest.is_empty()
            && wire.source_version.is_empty()
            && wire.ranges == 0
            && wire.loaded_at == 0
    } else {
        wire.digest.len() == 64
            && wire.digest.bytes().all(|byte| byte.is_ascii_hexdigit())
            && provider.is_version_valid(&wire.source_version)
            && wire.ranges != 0
            && (wire.loaded_at == 0) == embedded
    };
    Some(bounded && labelled && generation)
}

/// Runs `geoip status` or `geoip update` and prints the final status reply.
///
/// Fails with the session's error, [`CommandError::Conflict`] when another import runs or
/// the generation that became active is not the requested one,
/// [`CommandError::ImportFailed`] when the import failed, and a deadline error when the
/// budget of `--timeout` seconds runs out.
pub fn run(
    session: &Session,
    args: &Args<'_>,
    out: &mut dyn Write,
    notes: &mut dyn Write,
) -> Result<(), CommandError> {
    let end = Instant::now() + Duration::from_secs(u64::from(args.timeout));
    let (bytes, before) = query(session, end)?;
    if args.kind == Kind::GeoStatus || already_active(&before, args)? {
        return emit(out, &bytes);
    }
    if before.revision == i64::MAX as u64 || before.status.is_busy() {
        return Err(CommandError::Conflict);
    }
    submit(session, args, before.revision, end)?;
    let mut last = None;
    loop {
        let (bytes, current) = query(session, end)?;
        if current.revision != before.revision {
            if current.revision != before.revision + 1 || !already_active(&current, args)? {
                return Err(CommandError::Conflict);
            }
            return emit(out, &bytes);
        }
        if current.status == Status::Failed {
            return Err(CommandError::ImportFailed);
        }
        if last != Some((current.status, current.progress)) {
            let _ =
                writeln!(notes, "GeoIP {}: {} ranges", current.status.name(), current.progress);
            last = Some((current.status, current.progress));
        }
        std::thread::sleep(deadline(end)?.saturating_duration_since(Instant::now()).min(POLL));
    }
}

/// Returns true when the requested version is the active generation.
///
/// Fails with [`CommandError::Conflict`] when it is, but with another digest than the
/// operator's `--checksum`.
fn already_active(metadata: &Metadata, args: &Args<'_>) -> Result<bool, CommandError> {
    if metadata.revision == 0
        || metadata.version != args.version
        || metadata.provider != args.provider
    {
        return Ok(false);
    }
    if !args.checksum.is_empty() && !metadata.digest.eq_ignore_ascii_case(args.checksum) {
        return Err(CommandError::Conflict);
    }
    Ok(true)
}

/// Returns the deadline of the next request: the budget's end, at most 20 seconds away.
///
/// Fails with a deadline error once the budget has run out.
fn deadline(end: Instant) -> Result<Instant, CommandError> {
    let now = Instant::now();
    if now >= end {
        return Err(CommandError::Client(ClientError::Deadline));
    }
    Ok(end.min(now + REQUEST_TIMEOUT))
}

/// Reads and checks the status; returns the reply's bytes and what they say.
fn query(session: &Session, end: Instant) -> Result<(Vec<u8>, Metadata), CommandError> {
    let mut response =
        session.request_until(Method::Get, "/console/api/geoip", b"", deadline(end)?)?;
    require_ok(response.status)?;
    let metadata = parse(&response.body)?;
    Ok((std::mem::take(&mut response.body), metadata))
}

/// Asks for the import of the requested version at the observed revision.
fn submit(
    session: &Session,
    args: &Args<'_>,
    revision: u64,
    end: Instant,
) -> Result<(), CommandError> {
    let expected = revision.to_string();
    let request = body(&[
        ("provider", Field::Text(args.provider)),
        ("source_version", Field::Text(args.version)),
        ("expected_revision", Field::Text(&expected)),
        ("checksum", Field::Text(args.checksum)),
    ]);
    let response = session.request_until(
        Method::Post,
        "/console/api/geoip",
        request.as_bytes(),
        deadline(end)?,
    )?;
    require_ok(response.status)?;
    struct Accepted(bool);
    impl Decode for Accepted {
        fn decode(value: &Value<'_>, path: Path<'_>) -> Result<Accepted, DecodeError> {
            let mut fields = Fields::new(value, path)?;
            let accepted = Accepted(fields.required("accepted")?);
            fields.finish()?;
            Ok(accepted)
        }
    }
    match codec::from_json::<Accepted>(&response.body) {
        Ok(Accepted(true)) => Ok(()),
        _ => Err(CommandError::InvalidResponse),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn wire(revision: &str, digest: &str, version: &str, ranges: u32, loaded: u64) -> String {
        format!(
            "{{\"revision\":{revision},\"digest\":\"{digest}\",\"provider\":\"dbip\",\
             \"source_version\":\"{version}\",\"source_digests\":\"\",\"ranges\":{ranges},\
             \"loaded_at\":{loaded},\"status\":\"applied\",\"processed_ranges\":{ranges},\
             \"source\":\"DB-IP IP to Country Lite\",\"license\":\"CC BY 4.0\",\
             \"attribution\":\"https://db-ip.com\"}}"
        )
    }

    #[test]
    fn status_replies_are_checked_against_the_publisher() {
        let digest = "a".repeat(64);
        let active = parse(wire("3", &digest, "2026-09", 10, 17).as_bytes()).unwrap();
        assert_eq!((active.revision, active.status, active.progress), (3, Status::Applied, 10));
        assert!(parse(wire("0", "", "", 0, 0).as_bytes()).is_ok());
        assert!(parse(wire("0", &digest, "2026-09", 10, 0).as_bytes()).is_err());
        assert!(parse(wire("3", &digest, "2026-09-09", 10, 17).as_bytes()).is_err());
        assert!(parse(wire("3", &digest, "2026-09", 0, 17).as_bytes()).is_err());
        assert!(parse(wire("3", "abc", "2026-09", 10, 17).as_bytes()).is_err());
        let embedded =
            wire("0", &digest, "2026-09", 10, 0).replace("DB-IP IP to Country Lite", EMBEDDED);
        assert!(parse(embedded.as_bytes()).is_ok());
        let extra = wire("3", &digest, "2026-09", 10, 17).replace("}", ",\"csv\":\"x\"}");
        assert!(parse(extra.as_bytes()).is_err());
        let foreign = wire("3", &digest, "2026-09", 10, 17).replace("CC BY 4.0", "MIT");
        assert!(parse(foreign.as_bytes()).is_err());
    }
}
