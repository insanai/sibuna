//! The policy file schema, read with Zig's typed-parse rules (see `json`).
//!
//! Every value is read before any is applied, so a JSON-level error leaves nothing
//! half-applied and is reported in document order, as Zig's typed parse reports it.

use crate::inspection::{Mode, Modes};
use crate::json::{Int, Members, Reader, Result};
use crate::limits::Limits;

pub(crate) struct Thresholds {
    pub(crate) challenge_at: Option<i32>,
    pub(crate) deny_at: Option<i32>,
    pub(crate) bits_step: Option<i32>,
}

pub(crate) struct Challenge {
    pub(crate) difficulty: Option<u32>,
    pub(crate) algorithm: Option<Vec<u8>>,
}

/// One rule as written. `*_regex` and `remote_addresses` are accepted spellings of the
/// same criteria; a rule may use only one spelling of each.
#[derive(Default)]
pub(crate) struct RuleEntry {
    pub(crate) name: Option<Vec<u8>>,
    pub(crate) action: Option<Vec<u8>>,
    pub(crate) path: Option<Vec<u8>>,
    pub(crate) path_regex: Option<Vec<u8>>,
    pub(crate) user_agent: Option<Vec<u8>>,
    pub(crate) user_agent_regex: Option<Vec<u8>>,
    pub(crate) headers: Option<Members>,
    pub(crate) headers_regex: Option<Members>,
    pub(crate) remote_addresses: Option<Vec<Vec<u8>>>,
    pub(crate) cidrs: Option<Vec<Vec<u8>>>,
    pub(crate) challenge: Option<Challenge>,
    pub(crate) weight: Option<i32>,
    pub(crate) limits: Option<Limits>,
}

#[derive(Default)]
pub(crate) struct File {
    pub(crate) default_action: Option<Vec<u8>>,
    pub(crate) waf: Option<bool>,
    pub(crate) inspection: Option<Modes>,
    pub(crate) thresholds: Option<Thresholds>,
    pub(crate) ip_rules: Option<Vec<(Vec<u8>, Vec<u8>)>>,
    pub(crate) rules: Option<Vec<RuleEntry>>,
}

fn i32_value(reader: &mut Reader<'_>) -> Result<i32> {
    // `Int::I32` keeps the value within i32.
    reader.int(Int::I32).map(|value| value as i32)
}

fn u32_value(reader: &mut Reader<'_>) -> Result<u32> {
    // `Int::U32` keeps the value within u32.
    reader.int(Int::U32).map(|value| value as u32)
}

/// A `Limits` object: `rate` and `window_seconds` required, `ban_seconds` optional.
pub(crate) fn limits(reader: &mut Reader<'_>) -> Result<Limits> {
    let mut limits = Limits::default();
    let seen = reader.object(&["rate", "window_seconds", "ban_seconds"], |reader, field| {
        let value = u32_value(reader)?;
        match field {
            0 => limits.rate = value,
            1 => limits.window_seconds = value,
            _ => limits.ban_seconds = value,
        }
        Ok(())
    })?;
    reader.require(&seen, &[0, 1])?;
    Ok(limits)
}

/// An `inspection` object: each category's mode, by name or tag number.
fn modes(reader: &mut Reader<'_>) -> Result<Modes> {
    let mut modes = Modes::default();
    let names = ["disabled", "audit", "enforce"];
    reader.object(&["path_traversal", "sqli", "xss", "rce"], |reader, field| {
        let mode = Mode::ALL[reader.enumeration(&names)?];
        match field {
            0 => modes.path_traversal = mode,
            1 => modes.sqli = mode,
            2 => modes.xss = mode,
            _ => modes.rce = mode,
        }
        Ok(())
    })?;
    Ok(modes)
}

fn thresholds(reader: &mut Reader<'_>) -> Result<Thresholds> {
    let mut thresholds = Thresholds { challenge_at: None, deny_at: None, bits_step: None };
    reader.object(&["challenge_at", "deny_at", "bits_step"], |reader, field| {
        let value = reader.optional(i32_value)?;
        match field {
            0 => thresholds.challenge_at = value,
            1 => thresholds.deny_at = value,
            _ => thresholds.bits_step = value,
        }
        Ok(())
    })?;
    Ok(thresholds)
}

fn challenge(reader: &mut Reader<'_>) -> Result<Challenge> {
    let mut challenge = Challenge { difficulty: None, algorithm: None };
    reader.object(&["difficulty", "algorithm"], |reader, field| {
        if field == 0 {
            challenge.difficulty = reader.optional(u32_value)?;
        } else {
            challenge.algorithm = reader.optional(Reader::string)?;
        }
        Ok(())
    })?;
    Ok(challenge)
}

const RULE_FIELDS: [&str; 13] = [
    "name",
    "action",
    "path",
    "path_regex",
    "user_agent",
    "user_agent_regex",
    "headers",
    "headers_regex",
    "remote_addresses",
    "cidrs",
    "challenge",
    "weight",
    "limits",
];

fn rule(reader: &mut Reader<'_>) -> Result<RuleEntry> {
    let mut entry = RuleEntry::default();
    reader.object(&RULE_FIELDS, |reader, field| {
        match field {
            0 => entry.name = reader.optional(Reader::string)?,
            1 => entry.action = reader.optional(Reader::string)?,
            2 => entry.path = reader.optional(Reader::string)?,
            3 => entry.path_regex = reader.optional(Reader::string)?,
            4 => entry.user_agent = reader.optional(Reader::string)?,
            5 => entry.user_agent_regex = reader.optional(Reader::string)?,
            6 => entry.headers = Some(reader.members()?),
            7 => entry.headers_regex = Some(reader.members()?),
            8 => entry.remote_addresses = reader.optional(Reader::string_list)?,
            9 => entry.cidrs = reader.optional(Reader::string_list)?,
            10 => entry.challenge = reader.optional(challenge)?,
            11 => entry.weight = reader.optional(i32_value)?,
            _ => entry.limits = reader.optional(limits)?,
        }
        Ok(())
    })?;
    Ok(entry)
}

/// A list of rules (`[]const Rule`).
fn rules(reader: &mut Reader<'_>) -> Result<Vec<RuleEntry>> {
    reader.list(rule)
}

const FILE_FIELDS: [&str; 6] =
    ["default_action", "waf", "inspection", "thresholds", "ip_rules", "rules"];

/// Reads a whole policy file, then requires the end of the document.
pub(crate) fn file(text: &[u8]) -> Result<File> {
    let mut reader = Reader::new(text);
    let mut file = File::default();
    reader.object(&FILE_FIELDS, |reader, field| {
        match field {
            0 => file.default_action = reader.optional(Reader::string)?,
            1 => file.waf = reader.optional(Reader::boolean)?,
            2 => file.inspection = reader.optional(modes)?,
            3 => file.thresholds = reader.optional(thresholds)?,
            4 => file.ip_rules = reader.optional(Reader::string_map)?,
            _ => file.rules = reader.optional(rules)?,
        }
        Ok(())
    })?;
    reader.finish()?;
    Ok(file)
}
