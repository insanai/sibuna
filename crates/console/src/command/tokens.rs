//! The token commands (Zig's `console_command_token.zig`): `tokens`, `mint-token`,
//! `revoke-token` and `remove-token`. They need an administrator's password sign-in;
//! automation credentials can run other commands but never mint, list or revoke tokens.

use std::io::Write;

use sibuna_console_protocol::codec::WireEnum;
use sibuna_console_protocol::tokens::Scope;

use super::args::{Args, Kind};
use super::{CommandError, Field, Session, body, emit, reply};

/// Runs the token command and prints its validated reply.
///
/// Fails with the session's error, or [`CommandError::InvalidResponse`] for a reply that
/// breaks its contract.
pub fn run(session: &Session, args: &Args<'_>, out: &mut dyn Write) -> Result<(), CommandError> {
    let (target, request) = operation(args);
    let response = session.post(target, request.as_bytes())?;
    reply::token(args, &response.body)?;
    emit(out, &response.body)
}

/// Returns the route and body of the command.
fn operation(args: &Args<'_>) -> (&'static str, String) {
    match args.kind {
        Kind::MintToken => {
            let scopes: Vec<&str> = Scope::ALL
                .iter()
                .filter(|scope| args.scopes & scope.bit() != 0)
                .map(|scope| scope.name())
                .collect();
            let expires = args.expires.map(|expires| expires.to_string());
            let members = [
                ("label", Field::Text(args.username)),
                ("role", Field::Text(args.role.name())),
                ("scopes", Field::Texts(&scopes)),
                ("expires", expires.as_deref().map_or(Field::Null, Field::Text)),
            ];
            ("/console/api/tokens/create", body(&members))
        }
        Kind::Tokens => {
            let after = args.after.to_string();
            ("/console/api/tokens/query", body(&[("after", Field::Text(&after))]))
        }
        _ => {
            let (target, revision) = (args.target.to_string(), args.revision.to_string());
            let members = [
                ("target", Field::Text(&target)),
                ("expected_revision", Field::Text(&revision)),
                ("remove", Field::Bool(args.kind == Kind::RemoveToken)),
            ];
            ("/console/api/tokens/revoke", body(&members))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::command::args::parse;

    #[test]
    fn token_operations_match_the_interface() {
        let auth =
            ["--origin", "http://127.0.0.1:1", "--username", "admin", "--password-file", "p"];
        let mut words = vec!["mint-token", "deploy", "--role", "operator"];
        words.extend_from_slice(&auth);
        words.extend_from_slice(&["--scope", "policy_write", "--scope", "policy_read"]);
        let (route, request) = operation(&parse(&words).unwrap());
        assert_eq!(route, "/console/api/tokens/create");
        assert_eq!(
            request,
            "{\"label\":\"deploy\",\"role\":\"operator\",\"scopes\":[\"policy_read\",\
             \"policy_write\"],\"expires\":null}"
        );
        let mut words = vec!["remove-token", "5"];
        words.extend_from_slice(&auth);
        words.extend_from_slice(&["--revision", "2"]);
        assert_eq!(
            operation(&parse(&words).unwrap()).1,
            "{\"target\":\"5\",\"expected_revision\":\"2\",\"remove\":true}"
        );
    }
}
