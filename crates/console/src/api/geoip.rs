//! The routes `GET` and `POST /console/api/geoip` (Zig's `geoip_routes.zig`): the active
//! generation's metadata and import status, and starting an import.
//!
//! `GET` answers what this console restored or imported, with the provider's title,
//! licence and attribution (`embedded snapshot` as the source while the build's snapshot
//! serves lookups). `POST` checks the request and starts the one import thread; it answers
//! `{"accepted":true}` at once, and the page polls `GET` for progress.
//!
//! Changes from Zig: a field longer than its bound answers 400 `CONSOLE002`, where Zig
//! answered 503 `CONSOLE004`.

use std::fmt::{self, Write};

use sibuna_console_protocol::codec::{Decode, DecodeError, Encode, Fields, Path, field};
use sibuna_console_protocol::geo::Authorization;
use sibuna_geoip::Provider;
use sibuna_http::Method;
use sibuna_json::{Value, Writer};
use sibuna_serve::Context;

use crate::dispatch::Call;
use crate::geo::import::{ImportError, ImportRequest, ImportStatus, MAX_CSV, Shown};
use crate::http::body::read_json;
use crate::http::{RouteError, reply};
use crate::shared::Shared;

/// The largest request body.
const MAX_BODY: usize = 16 * 1024;
/// The source a build's embedded snapshot reports.
const EMBEDDED: &str = "embedded snapshot";

/// Serves `call.route`, one of this module's routes, after the dispatcher's checks.
///
/// Fails with 400 `CONSOLE002` for a malformed import request, 429 `CONSOLE003` while an
/// import runs, and 503 `CONSOLE004` when the import thread cannot start.
pub fn handle(shared: &Shared, context: &mut Context<'_>, call: &Call) -> Result<(), RouteError> {
    match call.route.method {
        Method::Get => {
            let status =
                Status { shown: shared.importer.shown(), import: shared.importer.status() };
            Ok(reply::json(context, &status)?)
        }
        Method::Post => start(shared, context, call),
        _ => Err(RouteError::BadRequest),
    }
}

/// The reply of `GET`.
struct Status {
    shown: Shown,
    import: ImportStatus,
}

impl Encode for Status {
    fn encode<W: Write>(&self, json: &mut Writer<W>) -> fmt::Result {
        let metadata = &self.shown.metadata;
        let provider =
            Provider::parse(metadata.provider.as_str()).unwrap_or(Provider::UserCountry);
        let source = if self.shown.embedded { EMBEDDED } else { provider.title() };
        json.begin_object()?;
        json.key("revision")?;
        json.uint(metadata.revision)?;
        field(json, "digest", metadata.digest.as_str())?;
        field(json, "provider", provider.name())?;
        field(json, "source_version", metadata.source_version.as_str())?;
        field(json, "source_digests", metadata.source_digests.as_str())?;
        field(json, "ranges", &metadata.ranges)?;
        json.key("loaded_at")?;
        json.uint(metadata.loaded_at)?;
        field(json, "status", self.import.state.name())?;
        field(json, "processed_ranges", &self.import.processed_ranges)?;
        field(json, "source", source)?;
        field(json, "license", provider.license())?;
        field(json, "attribution", provider.attribution().unwrap_or_default())?;
        json.end_object()
    }
}

/// The body of `POST`.
struct ImportForm {
    provider: String,
    source_version: String,
    expected_revision: u64,
    checksum: String,
    csv: String,
}

impl Decode for ImportForm {
    fn decode(value: &Value<'_>, path: Path<'_>) -> Result<ImportForm, DecodeError> {
        let mut fields = Fields::new(value, path)?;
        let form = ImportForm {
            provider: fields.or("provider", Provider::UserCountry.name().to_owned())?,
            source_version: fields.required("source_version")?,
            expected_revision: fields.required("expected_revision")?,
            checksum: fields.or_default("checksum")?,
            csv: fields.or_default("csv")?,
        };
        fields.finish()?;
        Ok(form)
    }
}

/// `POST`: starts an import at the revision the administrator saw.
fn start(shared: &Shared, context: &mut Context<'_>, call: &Call) -> Result<(), RouteError> {
    let mut body = vec![0u8; MAX_BODY];
    let form: ImportForm = read_json(context, &mut body)?;
    let provider = Provider::parse(&form.provider).ok_or(RouteError::BadRequest)?;
    if form.expected_revision >= i64::MAX as u64
        || form.source_version.len() > sibuna_geoip::provider::MAX_VERSION
        || form.checksum.len() > 64
        || form.csv.len() > MAX_CSV
    {
        return Err(RouteError::BadRequest);
    }
    let auth = call.auth(shared)?;
    let request = ImportRequest {
        credential: call.credential(shared)?,
        auth: Authorization {
            session_digest: auth.session_digest,
            csrf_digest: auth.csrf_digest,
            require_totp: auth.require_totp,
            client: auth.client.clone(),
        },
        expected_revision: form.expected_revision,
        provider,
        version: form.source_version,
        checksum: form.checksum,
        csv: form.csv.into_bytes(),
    };
    match shared.importer.start(shared, request) {
        Ok(()) => Ok(reply::json_bytes(context, b"{\"accepted\":true}", &[])?),
        Err(ImportError::Busy) => Err(RouteError::fail(429, "CONSOLE003")),
        Err(ImportError::Invalid(_)) => Err(RouteError::BadRequest),
        Err(_) => Err(RouteError::Unavailable),
    }
}
