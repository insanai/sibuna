//! One incident's redacted request and response heads (`events/heads`), read one incident
//! at a time so that event pages never grow with them. A missing row of
//! `console_incident_heads` means "not recorded"; the heads leave storage as lowercase hex.

use sibuna_console_protocol::Text;
use sibuna_console_protocol::incident_heads::{Heads, Read, ResponseState};
use sibuna_storage::Sql;
use sibuna_storage::Transaction;

use super::EVENTS_NEED;
use crate::access::{self, Credential};
use crate::error::ConsoleStorageError;
use crate::row::{self, Fields};

const HEADS: Sql = Sql::both(
    "SELECT request_head, response_head, request_truncated, response_truncated, \
     response_state FROM console_incident_heads WHERE incident_id = $1",
);

/// Returns the stored response state named `name`; the `CHECK` of
/// `console_incident_heads.response_state` lists exactly these.
fn parse_state(name: &str) -> Option<ResponseState> {
    match name {
        "captured" => Some(ResponseState::Captured),
        "local" => Some(ResponseState::Local),
        "unobserved" => Some(ResponseState::Unobserved),
        "unavailable" => Some(ResponseState::Unavailable),
        _ => None,
    }
}

/// Reads the redacted heads of incident `input.id`; `recorded` is false when none were
/// captured. The credential is `credential`; `input.session_digest` is not read.
///
/// Fails with [`ConsoleStorageError::InvalidInput`] for an id of 0 or beyond 2^63 - 1, like
/// [`access::authorize_in`] with [`EVENTS_NEED`], and with the driver's error or
/// [`sibuna_storage::StorageError::InvalidRow`] for a stored row the types cannot hold.
pub async fn read_heads(
    tx: &mut Transaction,
    credential: &Credential,
    input: &Read,
    now: u64,
) -> Result<Heads, ConsoleStorageError> {
    if input.id == 0 || input.id > row::MAX_INTEGER {
        return Err(ConsoleStorageError::InvalidInput("incident id"));
    }
    access::authorize_in(tx, credential, EVENTS_NEED, now).await?;
    let rows = tx.fetch_all(HEADS, &[row::int(input.id)?.into()]).await?;
    let Some(cells) = row::first(rows) else {
        return Ok(Heads { id: input.id, ..Heads::default() });
    };
    let mut fields = Fields::new(cells, "console_incident_heads");
    let request = fields.bytes("request_head")?;
    let response = fields.bytes("response_head")?;
    let request_truncated = fields.flag("request_truncated")?;
    let response_truncated = fields.flag("response_truncated")?;
    let response_state = fields.parsed("response_state", parse_state)?;
    let request = Text::from_string(sibuna_encoding::hex::encode(&request))
        .map_err(|_| fields.invalid("request_head"))?;
    let response = Text::from_string(sibuna_encoding::hex::encode(&response))
        .map_err(|_| fields.invalid("response_head"))?;
    Ok(Heads {
        id: input.id,
        recorded: true,
        request,
        response,
        request_truncated,
        response_truncated,
        response_state,
        ..Heads::default()
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn states_parse_the_names_of_the_check() {
        for (name, state) in [
            ("captured", ResponseState::Captured),
            ("local", ResponseState::Local),
            ("unobserved", ResponseState::Unobserved),
            ("unavailable", ResponseState::Unavailable),
        ] {
            assert_eq!(parse_state(name), Some(state));
        }
        assert_eq!(parse_state("unknown"), None);
    }
}
