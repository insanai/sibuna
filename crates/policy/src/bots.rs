//! Built-in bot signatures: AI scrapers, scraper libraries and search crawlers, matched as
//! case-insensitive substrings of the User-Agent.

use sibuna_patterns::{Automaton, Options};

/// User-Agent tokens of AI training and answer-engine crawlers.
pub const AI_SCRAPERS: [&str; 18] = [
    "GPTBot",
    "ChatGPT-User",
    "ClaudeBot",
    "Claude-Web",
    "anthropic-ai",
    "Bytespider",
    "CCBot",
    "Diffbot",
    "FacebookBot",
    "Google-Extended",
    "PerplexityBot",
    "Omgilibot",
    "Applebot-Extended",
    "Amazonbot",
    "cohere-ai",
    "Timpibot",
    "YouBot",
    "DataForSeoBot",
];

/// User-Agent tokens of HTTP libraries and headless automation.
pub const SCRAPER_LIBRARIES: [&str; 17] = [
    "python-requests",
    "aiohttp",
    "httpx",
    "urllib",
    "Scrapy",
    "curl/",
    "Wget/",
    "Go-http-client",
    "Java/",
    "libwww-perl",
    "node-fetch",
    "Axios",
    "PostmanRuntime",
    "HeadlessChrome",
    "PhantomJS",
    "Selenium",
    "Puppeteer",
];

/// User-Agent tokens of search-engine crawlers (not challenged by the engine).
pub const SEARCH_CRAWLERS: [&str; 5] =
    ["Googlebot", "bingbot", "Baiduspider", "YandexBot", "DuckDuckBot"];

/// Tag of `AI_SCRAPERS` entries in the engine's bot automaton.
pub(crate) const AI_SCRAPER_TAG: u8 = 1;
/// Tag of `SCRAPER_LIBRARIES` entries in the engine's bot automaton.
pub(crate) const LIBRARY_TAG: u8 = 2;

/// The engine's bot matcher: AI scrapers then scraper libraries, case-insensitive. Pattern
/// ids follow that order, so `name` maps a match back to its static signature.
#[derive(Clone, Debug)]
pub(crate) struct BotMatcher {
    automaton: Automaton,
}

impl BotMatcher {
    /// Builds the matcher from the two challenged tables.
    pub(crate) fn new() -> BotMatcher {
        let options = Options {
            ascii_case_insensitive: true,
            max_states: 1 + total_len(&AI_SCRAPERS) + total_len(&SCRAPER_LIBRARIES),
            max_patterns: AI_SCRAPERS.len() + SCRAPER_LIBRARIES.len(),
        };
        let pairs = AI_SCRAPERS
            .iter()
            .map(|name| (name.as_bytes(), AI_SCRAPER_TAG))
            .chain(SCRAPER_LIBRARIES.iter().map(|name| (name.as_bytes(), LIBRARY_TAG)));
        match Automaton::from_patterns(options, pairs) {
            Ok(automaton) => BotMatcher { automaton },
            // The tables are constants sized within the options above; a failure is a
            // programming error that the unit tests would catch.
            Err(error) => unreachable!("built-in bot signatures do not compile: {error}"),
        }
    }

    /// Returns the signature that ends first in `user_agent` (the longest one there).
    #[inline]
    pub(crate) fn find_first(&self, user_agent: &[u8]) -> Option<&'static str> {
        let found = self.automaton.find_first(user_agent)?;
        let index = found.pattern.index();
        let library = || SCRAPER_LIBRARIES.get(index.checked_sub(AI_SCRAPERS.len())?);
        AI_SCRAPERS.get(index).or_else(library).copied()
    }

    pub(crate) fn heap_bytes(&self) -> usize {
        self.automaton.heap_bytes()
    }
}

fn total_len(names: &[&str]) -> usize {
    names.iter().map(|name| name.len()).sum()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bot_matcher_names_the_first_signature_case_insensitively() {
        let bots = BotMatcher::new();
        let ua = b"Mozilla/5.0 (compatible; gptbot/1.2; +https://openai.com/gptbot)";
        assert_eq!(bots.find_first(ua), Some("GPTBot"));
        assert_eq!(bots.find_first(b"Python-Requests/2.28.1"), Some("python-requests"));
        assert_eq!(bots.find_first(b"curl/8.0"), Some("curl/"));
        assert_eq!(bots.find_first(b"Mozilla/5.0 (Macintosh) AppleWebKit/537.36"), None);
        assert_eq!(bots.find_first(b"Googlebot/2.1"), None);
    }
}
