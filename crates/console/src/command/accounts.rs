//! The account commands (Zig's `console_command.zig` operations): `users`, `add-user`,
//! `set-user`, `reset-password` and `revoke-sessions`. Ids and revisions travel as decimal
//! strings, as the interface sends them.

use std::io::Write;

use sibuna_console_protocol::codec::WireEnum;

use super::args::{Args, Kind};
use super::{CommandError, Field, Session, body, emit, reply};

/// Runs the account command and prints its validated reply.
///
/// Fails with the session's error, or [`CommandError::InvalidResponse`] for a reply that
/// breaks its contract.
pub fn run(session: &Session, args: &Args<'_>, out: &mut dyn Write) -> Result<(), CommandError> {
    let (target, request) = operation(args);
    let response = session.post(target, request.as_bytes())?;
    reply::account(args, &response.body)?;
    emit(out, &response.body)
}

/// Returns the route and body of the command.
fn operation(args: &Args<'_>) -> (&'static str, String) {
    match args.kind {
        Kind::Add => {
            let members = [
                ("username", Field::Text(args.username)),
                ("role", Field::Text(args.role.name())),
            ];
            ("/console/api/users/create", body(&members))
        }
        Kind::Users => {
            let after = args.after.to_string();
            ("/console/api/users/query", body(&[("after", Field::Text(&after))]))
        }
        _ => {
            let (target, revision) = (args.target.to_string(), args.revision.to_string());
            let access = args.kind == Kind::Access;
            let members = [
                ("target", Field::Text(&target)),
                ("expected_revision", Field::Text(&revision)),
                ("operation", Field::Text(args.kind.operation())),
                ("role", if access { Field::Text(args.role.name()) } else { Field::Null }),
                ("disabled", if access { Field::Bool(args.disabled) } else { Field::Null }),
            ];
            ("/console/api/users/change", body(&members))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::command::args::parse;

    #[test]
    fn account_operations_match_the_interface() {
        let auth =
            ["--origin", "http://127.0.0.1:1", "--username", "admin", "--password-file", "p"];
        let mut words = vec!["set-user", "9007199254740993"];
        words.extend_from_slice(&auth);
        words.extend_from_slice(&["--revision", "2", "--role", "operator", "--disabled", "true"]);
        let (route, request) = operation(&parse(&words).unwrap());
        assert_eq!(route, "/console/api/users/change");
        assert_eq!(
            request,
            "{\"target\":\"9007199254740993\",\"expected_revision\":\"2\",\"operation\":\
             \"access\",\"role\":\"operator\",\"disabled\":true}"
        );
        let mut words = vec!["revoke-sessions", "3"];
        words.extend_from_slice(&auth);
        words.extend_from_slice(&["--revision", "4"]);
        let (_, request) = operation(&parse(&words).unwrap());
        assert!(request.ends_with("\"operation\":\"revoke\",\"role\":null,\"disabled\":null}"));
        let mut words = vec!["add-user", "viewer"];
        words.extend_from_slice(&auth);
        let (route, request) = operation(&parse(&words).unwrap());
        assert_eq!(route, "/console/api/users/create");
        assert_eq!(request, "{\"username\":\"viewer\",\"role\":\"viewer\"}");
        let mut words = vec!["users"];
        words.extend_from_slice(&auth);
        assert_eq!(operation(&parse(&words).unwrap()).1, "{\"after\":\"0\"}");
    }
}
