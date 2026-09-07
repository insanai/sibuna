//! Built-in Bot Signatures Database
//!
//! Signatures for AI scrapers, automated crawlers, and headless scraping frameworks.

pub const AI_SCRAPERS = [_][]const u8{
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
};

pub const SCRAPER_LIBRARIES = [_][]const u8{
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
};

pub const SEARCH_CRAWLERS = [_][]const u8{
    "Googlebot",
    "bingbot",
    "Baiduspider",
    "YandexBot",
    "DuckDuckBot",
};
