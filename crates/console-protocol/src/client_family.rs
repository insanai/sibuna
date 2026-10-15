//! Bounded client-family labels for sampled traffic: a small deterministic classifier over
//! the User-Agent value shared by the collector and the browser. Labels are display
//! families, never an admission input; an unrecognised agent stays unknown, not zero.

/// An operating-system family.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub enum Os {
    /// No agent, or none recognised.
    #[default]
    Unknown,
    /// Windows.
    Windows,
    /// macOS.
    Macos,
    /// iOS and iPadOS.
    Ios,
    /// Android.
    Android,
    /// Linux and ChromeOS.
    Linux,
    /// A browser on another system.
    Other,
    /// An automated client.
    Bot,
}

/// A browser family.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub enum Browser {
    /// No agent, or none recognised.
    #[default]
    Unknown,
    /// Chrome and Chromium.
    Chrome,
    /// Firefox.
    Firefox,
    /// Safari.
    Safari,
    /// Edge.
    Edge,
    /// Opera.
    Opera,
    /// An automated client.
    Bot,
    /// Another browser.
    Other,
}

/// The response statuses with their own histogram slot.
pub const STATUS_CODES: [u16; 20] = [
    200, 201, 204, 206, 301, 302, 304, 307, 308, 400, 401, 403, 404, 405, 413, 429, 500, 502, 503,
    504,
];

/// One histogram slot per listed status, then "other status", then "no status sampled".
pub const STATUS_SLOTS: usize = STATUS_CODES.len() + 2;

const STATUS_LABELS: [&str; STATUS_SLOTS] = [
    "200", "201", "204", "206", "301", "302", "304", "307", "308", "400", "401", "403", "404",
    "405", "413", "429", "500", "502", "503", "504", "other", "none",
];

/// An agent's operating system and browser.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct Family {
    /// The operating-system family.
    pub os: Os,
    /// The browser family.
    pub browser: Browser,
}

/// Classifies a User-Agent value. The empty agent is unknown; automated clients are bots
/// in both dimensions.
pub fn classify(agent: &str) -> Family {
    if agent.is_empty() {
        return Family::default();
    }
    if is_bot(agent) {
        return Family { os: Os::Bot, browser: Browser::Bot };
    }
    Family { os: operating_system(agent), browser: browser(agent) }
}

/// Returns the histogram slot of a response status; zero means no status was sampled.
pub fn status_slot(status: u16) -> usize {
    if status == 0 {
        return STATUS_SLOTS - 1;
    }
    STATUS_CODES.iter().position(|&code| code == status).unwrap_or(STATUS_SLOTS - 2)
}

/// Returns the label of a histogram slot: the status, "other" or "none". A slot past the
/// end reads "none".
pub fn status_label(slot: usize) -> &'static str {
    STATUS_LABELS.get(slot).copied().unwrap_or("none")
}

/// Returns the display label of an operating-system family.
pub fn os_label(os: Os) -> &'static str {
    match os {
        Os::Unknown => "Unknown",
        Os::Windows => "Windows",
        Os::Macos => "macOS",
        Os::Ios => "iOS",
        Os::Android => "Android",
        Os::Linux => "Linux",
        Os::Other => "Other",
        Os::Bot => "Automated",
    }
}

/// Returns the display label of a browser family.
pub fn browser_label(value: Browser) -> &'static str {
    match value {
        Browser::Unknown => "Unknown",
        Browser::Chrome => "Chrome",
        Browser::Firefox => "Firefox",
        Browser::Safari => "Safari",
        Browser::Edge => "Edge",
        Browser::Opera => "Opera",
        Browser::Bot => "Automated",
        Browser::Other => "Other",
    }
}

/// ASCII case-insensitive substring search (Zig's `indexOfIgnoreCase`).
fn contains(agent: &str, needle: &str) -> bool {
    let needle = needle.as_bytes();
    if needle.is_empty() {
        return true;
    }
    agent.as_bytes().windows(needle.len()).any(|window| window.eq_ignore_ascii_case(needle))
}

fn is_bot(agent: &str) -> bool {
    const MARKS: [&str; 13] = [
        "bot",
        "crawl",
        "spider",
        "curl/",
        "wget/",
        "python",
        "go-http",
        "java/",
        "httpclient",
        "scrapy",
        "headless",
        "monitor",
        "fetch",
    ];
    MARKS.iter().any(|mark| contains(agent, mark))
}

fn operating_system(agent: &str) -> Os {
    let any = |marks: &[&str]| marks.iter().any(|mark| contains(agent, mark));
    if any(&["iphone", "ipad", "ipod"]) {
        Os::Ios
    } else if any(&["android"]) {
        Os::Android
    } else if any(&["windows"]) {
        Os::Windows
    } else if any(&["mac os", "macintosh"]) {
        Os::Macos
    } else if any(&["cros", "linux", "x11"]) {
        Os::Linux
    } else if any(&["mozilla", "opera"]) {
        Os::Other
    } else {
        Os::Unknown
    }
}

fn browser(agent: &str) -> Browser {
    let any = |marks: &[&str]| marks.iter().any(|mark| contains(agent, mark));
    if any(&["edg/", "edge/", "edga/", "edgios/"]) {
        Browser::Edge
    } else if any(&["opr/", "opera"]) {
        Browser::Opera
    } else if any(&["firefox/", "fxios/"]) {
        Browser::Firefox
    } else if any(&["chrome/", "crios/", "chromium/"]) {
        Browser::Chrome
    } else if contains(agent, "safari/") && contains(agent, "version/") {
        Browser::Safari
    } else if contains(agent, "mozilla") {
        Browser::Other
    } else {
        Browser::Unknown
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Port of client_family.zig "client families are deterministic, bounded and never
    // invent a platform".
    #[test]
    fn client_families_are_deterministic_bounded_and_never_invent_a_platform() {
        let cases = [
            (
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) \
                 Chrome/126.0 Safari/537.36 Edg/126.0",
                Os::Windows,
                Browser::Edge,
            ),
            (
                "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_5) AppleWebKit/605.1.15 (KHTML, like \
                 Gecko) Version/17.5 Safari/605.1.15",
                Os::Macos,
                Browser::Safari,
            ),
            (
                "Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) AppleWebKit/605.1.15 \
                 (KHTML, like Gecko) CriOS/126.0 Mobile/15E148 Safari/604.1",
                Os::Ios,
                Browser::Chrome,
            ),
            (
                "Mozilla/5.0 (X11; Linux x86_64; rv:127.0) Gecko/20100101 Firefox/127.0",
                Os::Linux,
                Browser::Firefox,
            ),
            (
                "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) \
                 Chrome/126.0 Mobile Safari/537.36 OPR/80.0",
                Os::Android,
                Browser::Opera,
            ),
            ("curl/8.6.0", Os::Bot, Browser::Bot),
            ("Googlebot/2.1 (+http://www.google.com/bot.html)", Os::Bot, Browser::Bot),
            ("", Os::Unknown, Browser::Unknown),
            ("SomethingElse/1.0", Os::Unknown, Browser::Unknown),
        ];
        for (agent, os, browser) in cases {
            assert_eq!(classify(agent), Family { os, browser }, "{agent}");
        }
        assert_eq!(status_slot(200), 0);
        assert_eq!(status_slot(418), STATUS_SLOTS - 2);
        assert_eq!(status_slot(0), STATUS_SLOTS - 1);
        assert_eq!(status_label(status_slot(429)), "429");
        assert_eq!(status_label(STATUS_SLOTS - 1), "none");
        assert_eq!(status_label(STATUS_SLOTS - 2), "other");
        for (slot, code) in STATUS_CODES.iter().enumerate() {
            assert_eq!(status_label(slot), code.to_string());
        }
    }
}
