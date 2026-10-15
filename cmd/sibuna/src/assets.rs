//! The files the daemon serves itself: the WebAssembly solver, its worker script and the
//! challenge interstitial, embedded at build time.
//!
//! The interstitial is split into its template default, where the solver script is replaced
//! by the fixed `{{ challenge }}` slot, and the solver block, which the daemon supplies at
//! render time and no operator template can alter. The page's Content-Security-Policy
//! allows exactly that script by its SHA-256 hash.

use std::sync::OnceLock;

use sibuna_encoding::base64;

/// The browser solver, built by `build.rs` from `cmd/sibuna-pow-wasm`.
pub const WASM_SOLVER: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/sibuna-pow.wasm"));
/// The solver's Web Worker.
pub const WORKER_JS: &str = include_str!("../../../web/worker.js");
/// The challenge interstitial as shipped, solver script included.
pub const CHALLENGE_HTML: &str = include_str!("../../../web/challenge.html");

const SOLVER_START: &str = "<script>";
const SOLVER_END: &str = "</script>";

/// The default Content-Security-Policy line of every page but the challenge.
pub const SECURITY_POLICY: &str = "Content-Security-Policy: default-src 'none'; \
    base-uri 'none'; form-action 'none'; frame-ancestors 'none'; \
    style-src 'unsafe-inline'; img-src 'self'\r\n";

const REQUIREMENT_OPEN: &str = "<div hidden id=\"sibuna-requirement\" data-ticket=\"";
const REQUIREMENT_CLOSE: &str = "\"></div>";
/// The longest ticket written into the page; longer text is left out.
const TICKET_CAPACITY: usize = 64;

/// The interstitial split for templating, computed once from the embedded page.
#[derive(Debug)]
pub struct ChallengePage {
    /// The template default: the page with the solver block replaced by `{{ challenge }}`.
    pub template: String,
    /// The solver block, `<script>` to `</script>` inclusive.
    pub solver: &'static str,
    /// The Content-Security-Policy line that admits only the solver script.
    pub security_policy: String,
}

/// Returns the split interstitial. The embedded page is a build input, so a page without a
/// solver script is a build defect; the tests check that the shipped page has one.
pub fn challenge_page() -> &'static ChallengePage {
    static PAGE: OnceLock<ChallengePage> = OnceLock::new();
    PAGE.get_or_init(|| split(CHALLENGE_HTML))
}

fn split(html: &'static str) -> ChallengePage {
    let start = html.find(SOLVER_START).unwrap_or(html.len());
    let end = html
        .get(start..)
        .and_then(|rest| rest.find(SOLVER_END))
        .map_or(html.len(), |at| start + at + SOLVER_END.len());
    let solver = html.get(start..end).unwrap_or_default();
    let script = solver
        .strip_prefix(SOLVER_START)
        .and_then(|inner| inner.strip_suffix(SOLVER_END))
        .unwrap_or_default();
    let digest = sibuna_crypto::sha256::Sha256::digest(script.as_bytes());
    let hash = base64::encode(base64::STANDARD, &digest);
    let template = format!(
        "{}{{{{ challenge }}}}{}",
        html.get(..start).unwrap_or_default(),
        html.get(end..).unwrap_or_default()
    );
    let security_policy = format!(
        "Content-Security-Policy: default-src 'none'; base-uri 'none'; form-action 'none'; \
         frame-ancestors 'none'; style-src 'unsafe-inline'; img-src 'self'; \
         connect-src 'self'; worker-src 'self'; script-src 'sha256-{hash}'\r\n"
    );
    ChallengePage { template, solver, security_policy }
}

/// Returns the challenge slot's contents as text, borrowing `buffer` for it.
pub fn challenge_block<'b>(ticket: &[u8], buffer: &'b mut [u8; BLOCK_CAPACITY]) -> &'b str {
    let solver = challenge_page().solver;
    let mut length = 0;
    let mut push = |bytes: &[u8]| {
        if let Some(target) = buffer.get_mut(length..length + bytes.len()) {
            target.copy_from_slice(bytes);
            length += bytes.len();
        }
    };
    if is_ticket(ticket) {
        push(REQUIREMENT_OPEN.as_bytes());
        push(ticket);
        push(REQUIREMENT_CLOSE.as_bytes());
    }
    push(solver.as_bytes());
    // Every piece is ASCII or a slice of the UTF-8 page, so the text is valid.
    std::str::from_utf8(&buffer[..length]).unwrap_or_default()
}

/// The capacity of a challenge block: the requirement markup with the longest ticket, and
/// room for the solver script of the shipped page.
pub const BLOCK_CAPACITY: usize =
    REQUIREMENT_OPEN.len() + TICKET_CAPACITY + REQUIREMENT_CLOSE.len() + CHALLENGE_HTML.len();

fn is_ticket(ticket: &[u8]) -> bool {
    !ticket.is_empty()
        && ticket.len() <= TICKET_CAPACITY
        && ticket.iter().all(|&byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_challenge_default_keeps_the_interstitial_and_isolates_the_solver_block() {
        let page = challenge_page();
        assert!(page.template.contains("{{ challenge }}"));
        assert!(!page.template.contains("<script"));
        assert!(page.solver.starts_with("<script>"));
        assert!(page.solver.contains("/__sibuna/verify"));
        let mut buffer = [0u8; BLOCK_CAPACITY];
        let carried = challenge_block(b"abc-_9", &mut buffer).to_owned();
        assert!(carried.starts_with(&format!("{REQUIREMENT_OPEN}abc-_9\"")));
        assert!(carried.ends_with(page.solver));
        assert_eq!(challenge_block(b"\"><script>", &mut buffer), page.solver);
    }

    #[test]
    fn the_challenge_policy_admits_the_solver_by_hash() {
        let policy = &challenge_page().security_policy;
        assert!(policy.starts_with("Content-Security-Policy: default-src 'none';"));
        assert!(policy.contains("script-src 'sha256-"));
        assert!(policy.ends_with("'\r\n"));
        assert!(!SECURITY_POLICY.contains("script-src"));
    }

    #[test]
    fn the_embedded_solver_is_a_webassembly_module() {
        assert!(WASM_SOLVER.starts_with(b"\0asm"));
        assert!(WORKER_JS.contains("solvePoswJs"));
    }
}
