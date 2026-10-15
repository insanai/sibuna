//! The routes `settings/query` and `settings/change` (Zig's `settings_routes.zig`).
//!
//! Administrators read the settings catalogue and change one numeric setting at its
//! revision (S20); a retention change must be confirmed. Browser sessions only: the routes
//! have no token scope.

use sibuna_console_protocol::Text;
use sibuna_console_protocol::codec::{Decode, DecodeError, Fields, Path};
use sibuna_console_protocol::notifications::{SettingChange, SettingsPage};
use sibuna_console_protocol::settings;
use sibuna_console_storage::ConsoleStorageError;
use sibuna_console_storage::settings::{change_setting, query_settings};
use sibuna_json::Value;
use sibuna_serve::Context;

use crate::dispatch::Call;
use crate::http::body::read_json;
use crate::http::{RouteError, reply};
use crate::routes::Handler;
use crate::shared::Shared;
use crate::storage::StorageFailure;

/// Serves `call.route`, one of this module's routes, after the dispatcher's checks.
///
/// Fails with the [`RouteError`] the route answers with.
pub fn handle(shared: &Shared, context: &mut Context<'_>, call: &Call) -> Result<(), RouteError> {
    match call.route.handler {
        Handler::SettingsQuery => query(shared, context, call),
        Handler::SettingsChange => change(shared, context, call),
        _ => Err(RouteError::Unavailable),
    }
}

/// Maps a settings or notifications storage failure as Zig did: a full table is 503
/// `CONSOLENOTIFYFULL`, every other refusal `CONSOLESETTINGS`.
pub(crate) fn settings_error(failure: StorageFailure) -> RouteError {
    match &failure {
        StorageFailure::Console(ConsoleStorageError::Capacity) => {
            RouteError::fail(503, "CONSOLENOTIFYFULL")
        }
        _ => failure.route_error("CONSOLESETTINGS"),
    }
}

/// `settings/query`: every setting with its value and revision. The body is not read.
fn query(shared: &Shared, context: &mut Context<'_>, call: &Call) -> Result<(), RouteError> {
    let credential = call.credential(shared)?;
    let now = call.now;
    let page: SettingsPage = shared
        .storage
        .transact(move |tx| Box::pin(async move { query_settings(tx, &credential, now).await }))
        .map_err(settings_error)?;
    Ok(reply::json(context, &page)?)
}

/// The body of `settings/change`.
struct ChangeForm {
    key: String,
    value: String,
    confirmed: bool,
    expected_revision: u64,
}

impl Decode for ChangeForm {
    fn decode(value: &Value<'_>, path: Path<'_>) -> Result<ChangeForm, DecodeError> {
        let mut fields = Fields::new(value, path)?;
        let form = ChangeForm {
            key: fields.required("key")?,
            value: fields.required("value")?,
            confirmed: fields.or_default("confirmed")?,
            expected_revision: fields.required("expected_revision")?,
        };
        fields.finish()?;
        Ok(form)
    }
}

/// `settings/change`: one setting at its revision.
fn change(shared: &Shared, context: &mut Context<'_>, call: &Call) -> Result<(), RouteError> {
    let mut body = [0u8; 2048];
    let form: ChangeForm = read_json(context, &mut body)?;
    let refused = || RouteError::fail(400, "CONSOLESETTINGS");
    if !settings::is_valid(&form.key, &form.value) {
        return Err(refused());
    }
    let input = SettingChange {
        confirmed: form.confirmed,
        auth: call.auth(shared)?,
        key: Text::from_string(form.key).map_err(|_| refused())?,
        value: Text::from_string(form.value).map_err(|_| refused())?,
        expected_revision: form.expected_revision,
    };
    let credential = call.credential(shared)?;
    let now = call.now;
    shared
        .storage
        .transact(move |tx| {
            Box::pin(async move { change_setting(tx, &credential, &input, now).await })
        })
        .map_err(settings_error)?;
    Ok(reply::json_bytes(context, b"{\"ok\":true}", &[])?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use sibuna_console_protocol::codec::from_json;

    #[test]
    fn change_forms_accept_the_interface_body() {
        let form: ChangeForm = from_json(
            br#"{"key":"retention.audit","confirmed":true,"value":"20","expected_revision":"4"}"#,
        )
        .unwrap();
        assert_eq!((form.expected_revision, form.confirmed), (4, true));
        assert!(from_json::<ChangeForm>(br#"{"key":"a","value":"1"}"#).is_err());
        let full = StorageFailure::Console(ConsoleStorageError::Capacity);
        assert_eq!(settings_error(full), RouteError::fail(503, "CONSOLENOTIFYFULL"));
    }
}
