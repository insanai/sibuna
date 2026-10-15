//! Helpers the management pages share (users, tokens, audit, settings and nodes): request
//! tickets, page cursors and checkbox fields. An expired session ends with
//! [`crate::page::Context::end_session`], as on every page.
//!
//! Each Zig controller kept a module-level generation counter and a fixed `[128]u64`
//! cursor array; here each page owns a [`Ticket`] and a [`Cursor`].

use sibuna_json::Value;

use crate::error::UiError;
use crate::json;

/// The most pages a catalog browses before the operator must narrow it.
pub const MAX_PAGES: usize = 128;

/// The request id of a page's newest request: `<prefix>-<generation>`.
///
/// Only a reply to the newest request is accepted, so a late reply to an older one can
/// never change the page. The generation survives [`Ticket::forget`] (and a session
/// reset), as Zig's module-level counter did, so an id is never reused within a page load.
#[derive(Debug, Default)]
pub struct Ticket {
    generation: u64,
    current: String,
}

impl Ticket {
    /// Issues the next id `<prefix>-<generation>` and returns it.
    ///
    /// # Errors
    ///
    /// [`UiError::InvalidRequest`] once the generation is exhausted.
    pub fn issue(&mut self, prefix: &str) -> Result<&str, UiError> {
        self.generation = self.generation.checked_add(1).ok_or(UiError::InvalidRequest)?;
        self.current = format!("{prefix}-{}", self.generation);
        Ok(&self.current)
    }

    /// Returns true when `id` names the newest request.
    pub fn is(&self, id: &str) -> bool {
        !self.current.is_empty() && self.current == id
    }

    /// Returns the newest id, or the empty text.
    pub fn as_str(&self) -> &str {
        &self.current
    }

    /// Forgets the newest id and keeps the generation; returns the ticket for a reset
    /// page.
    pub fn forget(&mut self) -> Ticket {
        Ticket { generation: self.generation, current: String::new() }
    }
}

/// The cursor of a paged catalog: one start cursor per visited page, at most
/// [`MAX_PAGES`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Cursor {
    pages: Vec<u64>,
    page: usize,
}

impl Cursor {
    /// Returns a cursor at the first page, which starts at `start`.
    pub fn new(start: u64) -> Cursor {
        Cursor { pages: vec![start], page: 0 }
    }

    /// Returns to the first page, which starts at `start`.
    pub fn restart(&mut self, start: u64) {
        *self = Cursor::new(start);
    }

    /// Returns to the first page without changing its start.
    pub fn first(&mut self) {
        self.page = 0;
    }

    /// Moves to the next page, which starts at `next`; false at the browsing limit.
    pub fn advance(&mut self, next: u64) -> bool {
        if self.is_last() {
            return false;
        }
        self.page += 1;
        self.pages.truncate(self.page);
        self.pages.push(next);
        true
    }

    /// Moves to the previous page; false on the first.
    pub fn back(&mut self) -> bool {
        let Some(page) = self.page.checked_sub(1) else { return false };
        self.page = page;
        true
    }

    /// Returns the current page's start cursor.
    pub fn start(&self) -> u64 {
        self.pages.get(self.page).copied().unwrap_or_default()
    }

    /// Returns the current page's index, counted from 0.
    pub fn index(&self) -> usize {
        self.page
    }

    /// Returns true on the last page the browsing limit allows.
    pub fn is_last(&self) -> bool {
        self.page + 1 >= MAX_PAGES
    }
}

impl Default for Cursor {
    fn default() -> Cursor {
        Cursor::new(0)
    }
}

/// Returns true when the form checkbox `key` is ticked (the browser sends `"on"`).
pub fn is_on(fields: &Value<'_>, key: &str) -> bool {
    json::string(fields, key) == "on"
}

/// Parses the decimal index that follows `prefix` in an action name such as
/// `users-open-3`.
pub fn index_after(name: &str, prefix: &str) -> Option<usize> {
    name.strip_prefix(prefix)?.parse().ok()
}

/// A deterministic mutator for the reply fuzz tests of the management pages: a xorshift
/// generator that flips bits, truncates, duplicates and splices valid replies.
#[cfg(test)]
pub(crate) mod fuzz {
    /// A xorshift64 generator.
    pub struct Rng(pub u64);

    impl Rng {
        /// Returns the next value.
        pub fn next(&mut self) -> u64 {
            self.0 ^= self.0 << 13;
            self.0 ^= self.0 >> 7;
            self.0 ^= self.0 << 17;
            self.0
        }

        /// Returns a value below `bound` (which is not zero).
        pub fn below(&mut self, bound: usize) -> usize {
            (self.next() % bound as u64) as usize
        }
    }

    /// Returns a mutation of one of `seeds`: one to four bit flips, truncations,
    /// duplications or splices with another seed.
    pub fn mutate(rng: &mut Rng, seeds: &[&str]) -> Vec<u8> {
        let mut input = seeds[rng.below(seeds.len())].as_bytes().to_vec();
        for _ in 0..=rng.below(4) {
            if input.is_empty() {
                break;
            }
            let at = rng.below(input.len());
            match rng.below(4) {
                0 => input[at] ^= 1 << rng.below(8),
                1 => input.truncate(at),
                2 => {
                    let end = (at + rng.below(32)).min(input.len());
                    let copy = input[at..end].to_vec();
                    input.splice(at..at, copy);
                }
                _ => {
                    let other = seeds[rng.below(seeds.len())].as_bytes();
                    let from = rng.below(other.len());
                    let end = (from + rng.below(64)).min(other.len());
                    let cut = (at + rng.below(64)).min(input.len());
                    input.splice(at..cut, other[from..end].iter().copied());
                }
            }
        }
        input
    }
}

#[cfg(test)]
mod tests {
    use super::fuzz::{Rng, mutate};
    use super::*;
    use crate::pages::settings::templates::Templates;
    use crate::pages::{Audit, Settings, Tokens, Users};

    const SEEDS: [&str; 7] = [
        r#"{"version":1,"next":8,"rows":[{"id":1,"username":"viewer","role":"viewer",
            "revision":1,"disabled":false,"must_change":false,"totp_enabled":false,
            "password_expires":0,"last_login":null},{"id":"8","username":"a.b","role":"admin",
            "revision":"3","disabled":true,"must_change":true,"totp_enabled":true,
            "password_expires":5,"last_login":7}]}"#,
        r#"{"version":1,"rows":[{"id":"9","revision":"2","label":"ci","role":"operator",
            "scopes":["stats_read","policy_write"],"created_by":"1","created_at":12,
            "expires":99,"disabled":false,"active":true}],"next":null}"#,
        r#"{"version":1,"rows":[{"id":"41","actor":1,"subject":18,"recorded_at":100,
            "action":"policy.edit","target":"api-rate","actor_role":"admin",
            "client_ip":"198.51.100.7"}],"next":null}"#,
        r#"{"version":1,"row":{"id":"41","actor":1,"subject":18,"recorded_at":100,
            "action":"policy.edit","target":"api-rate","actor_role":null},
            "before":"{"a":1}","after":null,"before_truncated":true,
            "after_truncated":false,"before_redacted":false,"after_redacted":true}"#,
        r#"{"rows":[{"id":"3","revision":"5","kind":"syslog","transport":"tcp","label":"siem",
            "target":"logs:6514","target_host":"logs","secret_set":true,"events":15,
            "cooldown_seconds":60,"enabled":false,"last_attempt_at":null,
            "last_outcome":"failed","last_detail":"refused"}],"next":"4"}"#,
        r#"[{"key":"retention.audit","value":"30","revision":"4","updated_at":1,
            "updated_by":1}]"#,
        r#"{"kind":"denied","revision":"2","customized":true,"html":"<p>No</p>"}"#,
    ];

    /// The mandatory fuzz test: random replies never panic a decoder, and an accepted page
    /// keeps its bounds and order.
    #[test]
    fn random_replies_never_panic_and_accepted_pages_keep_their_bounds() {
        let mut rng = Rng(0x9e37_79b9_7f4a_7c15);
        let mut accepted = 0;
        for _ in 0..100_000 {
            let input = mutate(&mut rng, &SEEDS);
            let Ok(value) = sibuna_json::parse(&input) else { continue };
            let mut users = Users::default();
            if users.accept_page(&value).is_ok() {
                accepted += 1;
                assert!(users.rows.len() <= 8);
                assert!(users.rows.windows(2).all(|pair| pair[0].id < pair[1].id));
            }
            let mut tokens = Tokens::default();
            if tokens.accept_page(&value).is_ok() {
                accepted += 1;
                assert!(tokens.rows.iter().all(|row| row.scopes != 0 && row.id != 0));
            }
            let mut audit = Audit::default();
            if audit.accept_page(&value).is_ok() {
                accepted += 1;
                assert!(audit.rows.windows(2).all(|pair| pair[0].id > pair[1].id));
            }
            audit.selected = 41;
            let _ = audit.accept_detail(&value);
            let mut settings = Settings::default();
            if settings.accept_page(&value).is_ok() {
                accepted += 1;
                assert!(settings.rows.iter().all(|row| (1..=15).contains(&row.events)));
            }
            let mut templates = Templates::default();
            if templates.accept(&value).is_ok() {
                accepted += 1;
                assert!(templates.committed.len() <= 16 * 1024);
            }
        }
        assert!(accepted > 500, "{accepted}");
    }

    #[test]
    fn tickets_never_repeat_and_cursors_stop_at_the_browsing_limit() {
        let mut ticket = Ticket::default();
        assert_eq!(ticket.issue("users").unwrap(), "users-1");
        assert!(ticket.is("users-1") && !ticket.is(""));
        let mut ticket = ticket.forget();
        assert!(!ticket.is("users-1"));
        assert_eq!(ticket.issue("users").unwrap(), "users-2");
        let mut cursor = Cursor::new(7);
        assert!(!cursor.back());
        for next in 1..MAX_PAGES as u64 {
            assert!(cursor.advance(next));
        }
        assert!(cursor.is_last() && !cursor.advance(1000));
        assert_eq!(cursor.start(), 127);
        assert!(cursor.back());
        assert_eq!(cursor.start(), 126);
        cursor.first();
        assert_eq!(cursor.start(), 7);
        assert_eq!(index_after("users-open-3", "users-open-"), Some(3));
        assert_eq!(index_after("users-open-x", "users-open-"), None);
    }
}
