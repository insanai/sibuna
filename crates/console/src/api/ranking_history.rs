//! The route `rankings/history` (Zig's `ranking_history_routes.zig`): one retained
//! ranking archive of a window, newest first, as metadata and the archive's bytes in hex.
//! The scan runs under the work bound; missing archives are not zero traffic.

use std::fmt::{self, Write};

use sibuna_console_protocol::codec::{Encode, field};
use sibuna_console_protocol::ranking_history::{self, Form, Page, Query};
use sibuna_console_storage::rankings::read_history;
use sibuna_json::Writer;
use sibuna_serve::Context;

use super::events::read_error;
use super::policies::{spend, work_bound};
use crate::dispatch::Call;
use crate::http::body::read_json;
use crate::http::{RouteError, reply};
use crate::limits::Spend;
use crate::shared::Shared;

/// Serves `rankings/history` after the dispatcher's checks.
///
/// Fails with 429 `CONSOLE429` past the query allowance and with `RANKHISTORY` for a
/// refused window or a read storage refused or could not serve.
pub fn handle(shared: &Shared, context: &mut Context<'_>, call: &Call) -> Result<(), RouteError> {
    spend(shared, call, Spend::Query, "CONSOLE429")?;
    let mut body = [0u8; 1024];
    let form: Form = read_json(context, &mut body)?;
    let query = Query {
        session_digest: [0; 32],
        require_totp: shared.config.behind_proxy,
        observed_at: call.now,
        request: form.into(),
    };
    ranking_history::validate(&query).map_err(|_| RouteError::fail(400, "RANKHISTORY"))?;
    let credential = call.credential(shared)?;
    let bound = work_bound(shared);
    let now = call.now;
    let page = shared
        .storage
        .transact(move |tx| {
            Box::pin(async move { read_history(tx, &credential, &query, bound, now).await })
        })
        .map_err(|failure| match failure.failure() {
            sibuna_console_protocol::storage::Failure::Conflict => {
                failure.route_error("RANKHISTORY")
            }
            _ => read_error(failure, "RANKHISTORY"),
        })?;
    Ok(reply::json(context, &PageReply(&page))?)
}

/// An archive page in Zig's shape.
struct PageReply<'a>(&'a Page);

impl Encode for PageReply<'_> {
    fn encode<W: Write>(&self, json: &mut Writer<W>) -> fmt::Result {
        let page = self.0;
        json.begin_object()?;
        field(json, "version", &1u8)?;
        json.key("metadata")?;
        json.begin_object()?;
        field(json, "from_minute", &page.from_minute)?;
        field(json, "until_minute", &page.until_minute)?;
        field(json, "retention_days", &page.retention_days)?;
        field(json, "observed_at", &page.observed_at)?;
        field(json, "cursor", &page.cursor)?;
        field(json, "next", &page.next)?;
        json.end_object()?;
        field(json, "archive", sibuna_encoding::hex::encode(&page.payload).as_str())?;
        json.end_object()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sibuna_console_protocol::codec::to_json;

    #[test]
    fn pages_write_metadata_and_hex() {
        let page = Page { payload: vec![0xab, 0x01], observed_at: 60, ..Page::default() };
        let text = to_json(&PageReply(&page));
        assert!(text.starts_with("{\"version\":1,\"metadata\":{\"from_minute\":0,"), "{text}");
        assert!(text.ends_with(",\"archive\":\"ab01\"}"), "{text}");
    }
}
