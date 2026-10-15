//! Per-rule quotas of terminal rules (`policy_limits.zig`). Previews never consume the
//! node-local GCRA cells.

use std::fmt::{self, Write as _};

use sibuna_html::write_value;
use sibuna_json::Value;

use super::data::Invalid;
use crate::render::Html;

/// The message for a quota the console refuses.
pub const INVALID_MESSAGE: &str = "POLICY007: Quotas require a terminal action, burst \
     1\u{2013}1000000, window 1\u{2013}86400 seconds and ban 0\u{2013}86400 seconds. For WEIGH, \
     clear all three quota fields.";

/// A rule's quota: a burst paced over a window, and a local ban on excess.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Limits {
    /// Requests in a burst, 1 to 1,000,000.
    pub rate: u32,
    /// The pacing window, 1 to 86,400 seconds.
    pub window_seconds: u32,
    /// The local ban, 0 to 86,400 seconds.
    pub ban_seconds: u32,
}

impl Limits {
    /// Returns the quota if it is within the bounds the console accepts.
    pub fn validate(self) -> Result<Limits, Invalid> {
        if self.rate == 0
            || self.rate > 1_000_000
            || self.window_seconds == 0
            || self.window_seconds > 86_400
            || self.ban_seconds > 86_400
        {
            return Err(Invalid);
        }
        Ok(self)
    }
}

/// Reads the `limits` member of a rule or decision: absent or null is no quota, otherwise
/// an object of the three known integer members (the burst and window required).
pub fn read(root: &Value<'_>) -> Result<Option<Limits>, Invalid> {
    let object = root.as_object().ok_or(Invalid)?;
    let Some(item) = object.get("limits").filter(|item| !item.is_null()) else {
        return Ok(None);
    };
    let members = item.as_object().ok_or(Invalid)?;
    let mut limits = Limits::default();
    for (key, value) in members.iter() {
        let slot = match key {
            "rate" => &mut limits.rate,
            "window_seconds" => &mut limits.window_seconds,
            "ban_seconds" => &mut limits.ban_seconds,
            _ => return Err(Invalid),
        };
        *slot = crate::json::integer(value).and_then(|n| u32::try_from(n).ok()).ok_or(Invalid)?;
    }
    limits.validate().map(Some)
}

/// Reads a quota field of the editor: decimal digits only.
pub fn number(text: &str) -> Result<u32, Invalid> {
    if !text.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(Invalid);
    }
    text.parse().map_err(|_| Invalid)
}

/// Draws the quota sentence of a rule or decision, if it has a quota.
pub fn summary(out: &mut Html<'_>, limits: Option<Limits>) -> fmt::Result {
    let Some(limits) = limits else { return Ok(()) };
    out.write_str("<p>Rule quota: burst ")?;
    write_value(out, &limits.rate)?;
    out.write_str(", paced over ")?;
    write_value(out, &limits.window_seconds)?;
    out.write_str(" seconds. Local ban on excess: ")?;
    write_value(out, &limits.ban_seconds)?;
    out.write_str(" seconds.</p>")
}
