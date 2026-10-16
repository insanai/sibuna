//! Anubis (TecharoHQ) as a product under test, started and solved as `tools.py` and
//! `compare.py` did.
//!
//! Anubis runs with a policy that challenges every browser User-Agent and disables DNSBL and
//! its honeypot, at difficulty 2 (two leading zero hexadecimal digits, the work of Sibuna's 8
//! zero bits), with `GOMAXPROCS` equal to Sibuna's worker count. Its challenge page embeds the
//! challenge as JSON in `<script id="anubis_challenge">`; a proof is the nonce whose
//! `SHA-256(randomData || decimal(nonce))` meets the difficulty, sent to `pass-challenge`
//! with the verification cookie of the page. The answer is a redirect that sets the session
//! cookie.

use std::fs;
use std::path::Path;
use std::process::Command;

use sibuna_crypto::sha256::Sha256;
use sibuna_inflate::Limits;
use sibuna_json::Value;
use sibuna_pow::hashcash;

use crate::daemon::browser_headers;
use crate::error::{Error, Result};
use crate::http::{self, Response};
use crate::json::{member, member_str, member_u64};
use crate::process::{self, CpuSet};
use crate::server::{Launch, Server};

/// The prefix of Anubis's own endpoints.
pub const API: &str = "/.within.website/x/cmd/anubis/api/";

/// The forward-auth endpoint: `200` with a valid session, `401` for a browser without one.
pub const CHECK: &str = "/.within.website/x/cmd/anubis/api/check";

/// The policy of `tools.py`: challenge every browser User-Agent, no DNSBL, no honeypot.
pub const POLICY: &str = "bots:\n  - name: generic-browser\n    user_agent_regex: Mozilla\n    \
                          action: CHALLENGE\ndnsbl: false\nhoneypot:\n  enabled: false\n";

/// Leading zero hexadecimal digits Anubis asks for: the work of Sibuna's 8 zero bits.
pub const DIFFICULTY: u32 = 2;

/// The fixed HS512 secret of `compare.py`.
const HS512_SECRET: &str =
    "sibuna-benchmark-fixed-secret-with-64-bytes-00000000000000000000000000000000";

/// The most nonces we try before giving up; difficulty 2 needs 256 on average.
const MAX_NONCE: u64 = 1 << 24;

/// The largest challenge page we decompress.
const MAX_PAGE: u64 = 16 << 20;

/// How Anubis signs its session tokens.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TokenScheme {
    /// The default: an Ed25519 key generated at start.
    Ed25519,
    /// `--hs512-secret`: HMAC-SHA-512 with a fixed secret.
    Hs512,
}

impl TokenScheme {
    /// Returns `ed25519` or `hs512`, the names of `compare.py`.
    pub fn name(self) -> &'static str {
        match self {
            TokenScheme::Ed25519 => "ed25519",
            TokenScheme::Hs512 => "hs512",
        }
    }
}

/// What an Anubis process runs as.
#[derive(Clone, Copy, Debug)]
pub struct Setup {
    /// The origin port in reverse-proxy mode; `None` for forward auth (`--target=`).
    pub origin_port: Option<u16>,
    /// `GOMAXPROCS`, Sibuna's worker count.
    pub workers: usize,
    /// How sessions are signed.
    pub scheme: TokenScheme,
}

impl Setup {
    /// Returns the command line of `tools.py` and `compare.py` for a server on `port` with
    /// its metrics on `metrics_port` and its policy in the file `policy`.
    pub fn args(&self, port: u16, metrics_port: u16, policy: &Path) -> Vec<String> {
        let target =
            self.origin_port.map_or_else(String::new, |p| format!("http://127.0.0.1:{p}"));
        let mut args = vec![
            "--bind".to_owned(),
            format!("127.0.0.1:{port}"),
            "--metrics-bind".to_owned(),
            format!("127.0.0.1:{metrics_port}"),
            format!("--target={target}"),
            "--difficulty".to_owned(),
            DIFFICULTY.to_string(),
            "--policy-fname".to_owned(),
            policy.display().to_string(),
            "--slog-level".to_owned(),
            "ERROR".to_owned(),
            "--cookie-secure=false".to_owned(),
        ];
        if self.scheme == TokenScheme::Hs512 {
            args.extend(["--hs512-secret".to_owned(), HS512_SECRET.to_owned()]);
        }
        args
    }

    /// Returns the probe that tells the server is ready, and the status it answers with:
    /// the check endpoint (`401`) in forward-auth mode, the challenge page (`200`) otherwise.
    pub fn probe(&self) -> (&'static str, u16) {
        match self.origin_port {
            None => (CHECK, 401),
            Some(_) => ("/private", 200),
        }
    }
}

/// Starts Anubis from `binary` with `setup`, pinned to `cpus`, its policy and log in `dir`,
/// and waits until it answers.
///
/// # Errors
///
/// Fails when the policy cannot be written or Anubis does not become ready.
pub fn start(
    label: &str,
    binary: &Path,
    setup: &Setup,
    cpus: &CpuSet,
    dir: &Path,
) -> Result<Server> {
    let policy = dir.join(format!("{label}-policy.yaml"));
    fs::write(&policy, POLICY).map_err(|e| Error::io(policy.display(), e))?;
    let port = process::free_port()?;
    let metrics_port = process::free_port()?;
    let (probe, ready_status) = setup.probe();
    Server::start(Launch {
        label,
        binary,
        args: setup.args(port, metrics_port, &policy),
        env: vec![("GOMAXPROCS", setup.workers.to_string())],
        cpus,
        port,
        log_dir: dir,
        probe,
        ready_status,
    })
}

/// Returns the version line Anubis prints for `--version`, if it runs.
pub fn version(binary: &Path) -> Option<String> {
    let output = Command::new(binary).arg("--version").output().ok()?;
    let text = String::from_utf8_lossy(&output.stdout);
    text.lines().next().map(|line| line.trim().to_owned()).filter(|line| !line.is_empty())
}

/// The challenge embedded in an Anubis challenge page.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Challenge {
    /// `challenge.id`, sent back as `id`.
    pub id: String,
    /// `challenge.randomData`, the prefix of the hashed statement.
    pub random_data: String,
    /// `rules.difficulty`, in leading zero hexadecimal digits.
    pub difficulty: u32,
}

/// Returns the challenge in the `<script id="anubis_challenge">` element of `page`, or
/// `None` when there is none or it lacks a field.
pub fn parse_challenge(page: &[u8]) -> Option<Challenge> {
    let text = std::str::from_utf8(page).ok()?;
    let start = text.find("<script id=\"anubis_challenge\"")?;
    let element = text.get(start..)?;
    let content = element.get(element.find('>')? + 1..)?;
    let json = content.get(..content.find("</script>")?)?;
    let value: Value<'_> = sibuna_json::parse(json.trim().as_bytes()).ok()?;
    let challenge = member(&value, "challenge")?;
    let difficulty = member_u64(member(&value, "rules")?, "difficulty")?;
    Some(Challenge {
        id: member_str(challenge, "id")?.to_owned(),
        random_data: member_str(challenge, "randomData")?.to_owned(),
        difficulty: u32::try_from(difficulty).ok()?,
    })
}

/// Returns the first nonce below `max_nonce` whose `SHA-256(random_data || decimal(nonce))`
/// starts with `difficulty` zero hexadecimal digits, with that digest in lowercase hex.
pub fn solve(random_data: &str, difficulty: u32, max_nonce: u64) -> Option<(u64, String)> {
    let mut prefix = Sha256::new();
    prefix.update(random_data.as_bytes());
    (0..max_nonce).find_map(|nonce| {
        let mut hasher = prefix.clone();
        hasher.update(nonce.to_string().as_bytes());
        let digest = hasher.finalize();
        hashcash::meets_hex(&digest, difficulty).then(|| (nonce, hex(&digest)))
    })
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Percent-encodes `text` for a query value as Python's `urlencode` does: letters, digits
/// and `_.-~` stay, a space becomes `+`, every other byte becomes `%XX`.
pub fn query_encode(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for byte in text.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'_' | b'.' | b'-' | b'~' => {
                out.push(char::from(byte));
            }
            b' ' => out.push('+'),
            _ => out.push_str(&format!("%{byte:02X}")),
        }
    }
    out
}

/// A solved challenge, ready to be sent: `GET target` with `Cookie: cookie` answers `302`
/// and sets the session cookie.
#[derive(Clone, Debug)]
pub struct Pass {
    /// The `pass-challenge` request target with its query.
    pub target: String,
    /// The cookies of the challenge page (the verification cookie).
    pub cookie: String,
}

/// Fetches a challenge page for `/private` from the Anubis on `port`, solves it, and
/// returns the request that passes it, as `compare.py`'s `solution` did.
///
/// # Errors
///
/// Fails when the page is refused, holds no challenge, asks for another difficulty than
/// [`DIFFICULTY`], or has no solution below 2^24.
pub fn prepare_pass(port: u16) -> Result<Pass> {
    let bad = |what: String| {
        Error::new("ANUBIS CHALLENGE", format!("Anubis on port {port}: {what}."))
            .hint("Check that Anubis runs with the policy and `--difficulty 2` of the harness.")
    };
    let page = http::request(port, "GET", "/private", &browser_headers(), b"")?;
    if page.status != 200 {
        return Err(bad(format!("the challenge page answered {}", page.status)));
    }
    let body = page_body(&page).map_err(|e| bad(format!("the page does not decompress: {e}")))?;
    let challenge =
        parse_challenge(&body).ok_or_else(|| bad("no challenge in the page".into()))?;
    if challenge.difficulty != DIFFICULTY {
        return Err(bad(format!("the difficulty is {}, not {DIFFICULTY}", challenge.difficulty)));
    }
    let (nonce, digest) = solve(&challenge.random_data, challenge.difficulty, MAX_NONCE)
        .ok_or_else(|| bad("no nonce below 2^24 solves the challenge".into()))?;
    let redirect = query_encode(&format!("http://127.0.0.1:{port}/private"));
    let target = format!(
        "{API}pass-challenge?id={}&nonce={nonce}&response={digest}&elapsedTime=1000\
         &redir={redirect}",
        query_encode(&challenge.id)
    );
    Ok(Pass { target, cookie: page.cookie_header() })
}

/// Returns the body of `page`, decompressed when it came gzip-encoded (we send
/// `Accept-Encoding: gzip`, like a browser).
fn page_body(page: &Response) -> std::result::Result<Vec<u8>, sibuna_inflate::Error> {
    let gzip = page.header_values("content-encoding").any(|v| v.eq_ignore_ascii_case("gzip"));
    if !gzip {
        return Ok(page.body.clone());
    }
    let limits = Limits { max_input_bytes: MAX_PAGE, max_output_bytes: MAX_PAGE, max_members: 1 };
    sibuna_inflate::gunzip(&page.body, limits)
}

/// Obtains an Anubis session cookie from the server on `port` by solving its challenge, as
/// a browser would.
///
/// # Errors
///
/// Fails like [`prepare_pass`], or when passing the challenge does not redirect with a
/// session cookie.
pub fn session_cookie(port: u16) -> Result<String> {
    let pass = prepare_pass(port)?;
    let mut headers = browser_headers();
    headers.push(("Cookie".to_owned(), pass.cookie));
    let passed = http::request(port, "GET", &pass.target, &headers, b"")?;
    let cookie = passed.cookie_header();
    if passed.status != 302 || cookie.is_empty() {
        return Err(Error::new(
            "ANUBIS CHALLENGE",
            format!(
                "Anubis on port {port}: pass-challenge answered {} with cookies `{cookie}`.",
                passed.status
            ),
        )
        .hint("Run Anubis by hand and pass a challenge in a browser to see the problem."));
    }
    Ok(cookie)
}

#[cfg(test)]
mod tests {
    use super::*;

    const PAGE: &str = "<html><body><script id=\"anubis_challenge\" type=\"application/json\">\
        {\"rules\":{\"algorithm\":\"fast\",\"difficulty\":2},\"challenge\":{\"id\":\"01a1-42\",\
        \"method\":\"fast\",\"randomData\":\"4781bba3\",\"difficulty\":2,\"spent\":false}}\n\
        </script><script id=\"anubis_base_prefix\">\"\"</script></body></html>";

    #[test]
    fn parses_the_embedded_challenge() {
        let challenge = parse_challenge(PAGE.as_bytes()).unwrap();
        assert_eq!(
            challenge,
            Challenge { id: "01a1-42".into(), random_data: "4781bba3".into(), difficulty: 2 }
        );
        assert_eq!(parse_challenge(b"<html>no challenge</html>"), None);
        let truncated = &PAGE[..PAGE.find("</script>").unwrap()];
        assert_eq!(parse_challenge(truncated.as_bytes()), None);
        let no_id = PAGE.replace("\"id\"", "\"key\"");
        assert_eq!(parse_challenge(no_id.as_bytes()), None);
    }

    #[test]
    fn solves_like_the_python_solver() {
        let (nonce, digest) = solve("4781bba3", 2, MAX_NONCE).unwrap();
        assert!(digest.starts_with("00"), "{digest}");
        assert_eq!(digest, hex(&Sha256::digest(format!("4781bba3{nonce}").as_bytes())));
        for earlier in 0..nonce {
            let text = format!("4781bba3{earlier}");
            assert!(!hex(&Sha256::digest(text.as_bytes())).starts_with("00"));
        }
        assert_eq!(solve("x", 64, 10), None);
    }

    #[test]
    fn encodes_query_values_like_urlencode() {
        assert_eq!(
            query_encode("http://127.0.0.1:8080/private"),
            "http%3A%2F%2F127.0.0.1%3A8080%2Fprivate"
        );
        assert_eq!(query_encode("a b~_.-Z9"), "a+b~_.-Z9");
    }

    #[test]
    fn has_the_command_line_of_tools_py() {
        let policy = Path::new("/tmp/p.yaml");
        let setup = Setup { origin_port: None, workers: 4, scheme: TokenScheme::Ed25519 };
        assert_eq!(
            setup.args(80, 81, policy).join(" "),
            "--bind 127.0.0.1:80 --metrics-bind 127.0.0.1:81 --target= --difficulty 2 \
             --policy-fname /tmp/p.yaml --slog-level ERROR --cookie-secure=false"
        );
        assert_eq!(setup.probe(), (CHECK, 401));
        let setup = Setup { origin_port: Some(9), scheme: TokenScheme::Hs512, ..setup };
        let args = setup.args(80, 81, policy);
        assert!(args.contains(&"--target=http://127.0.0.1:9".to_owned()));
        assert_eq!(args[args.len() - 2], "--hs512-secret");
        assert_eq!(args[args.len() - 1].len(), 76);
        assert_eq!(setup.probe(), ("/private", 200));
    }
}
