//! The numeric setting catalog. The interface and the storage owner enforce the same
//! bounds; no arbitrary keys, expressions or secret-bearing values enter this interface.

/// Which settings page a setting belongs to.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub enum Group {
    /// Notification thresholds.
    #[default]
    Notification,
    /// Retention periods.
    Retention,
}

/// One setting: its key, label, default value and largest value.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Definition {
    /// The storage key.
    pub key: &'static str,
    /// The interface label.
    pub label: &'static str,
    /// The default value, in decimal.
    pub default: &'static str,
    /// The largest value; the smallest is 1.
    pub maximum: u32,
    /// The settings page.
    pub group: Group,
}

/// Every setting.
pub const CATALOG: [Definition; 6] = [
    Definition {
        key: "notify.spike_factor",
        label: "Spike multiplier",
        default: "3",
        maximum: 1_000_000,
        group: Group::Notification,
    },
    Definition {
        key: "notify.spike_minimum",
        label: "Minimum denials",
        default: "100",
        maximum: 1_000_000,
        group: Group::Notification,
    },
    Definition {
        key: "retention.minutes",
        label: "Minute history (days)",
        default: "90",
        maximum: 90,
        group: Group::Retention,
    },
    Definition {
        key: "retention.rankings",
        label: "Rankings (days)",
        default: "7",
        maximum: 7,
        group: Group::Retention,
    },
    Definition {
        key: "retention.incidents",
        label: "Incidents (days)",
        default: "30",
        maximum: 30,
        group: Group::Retention,
    },
    Definition {
        key: "retention.audit",
        label: "Audit (days)",
        default: "365",
        maximum: 365,
        group: Group::Retention,
    },
];

/// The keys of [`CATALOG`], in order.
pub const KEYS: [&str; CATALOG.len()] = {
    let mut keys = [""; CATALOG.len()];
    let mut index = 0;
    while index < CATALOG.len() {
        keys[index] = CATALOG[index].key;
        index += 1;
    }
    keys
};

/// Returns the definition of `key`, if it is a setting.
pub fn definition(key: &str) -> Option<&'static Definition> {
    CATALOG.iter().find(|entry| entry.key == key)
}

/// Returns true when `value` is 1 to 7 decimal digits naming a number from 1 to the
/// setting's maximum. Signs, spaces, fractions and exponents are refused.
pub fn is_valid(key: &str, value: &str) -> bool {
    let Some(entry) = definition(key) else { return false };
    if !(1..=7).contains(&value.len()) || !value.bytes().all(|byte| byte.is_ascii_digit()) {
        return false;
    }
    value.parse::<u32>().is_ok_and(|number| (1..=entry.maximum).contains(&number))
}

#[cfg(test)]
mod tests {
    use super::*;

    // Port of settings.zig "numeric settings reject unknown keys, expressions and retention
    // beyond fixed capacity".
    #[test]
    fn numeric_settings_reject_unknown_keys_expressions_and_retention_beyond_capacity() {
        for entry in &CATALOG {
            assert!(is_valid(entry.key, entry.default));
        }
        for value in ["", "0", "-1", "+1", "1.0", " 1", "1e2", "999999999"] {
            assert!(!is_valid("retention.minutes", value));
        }
        assert!(!is_valid("retention.minutes", "91"));
        assert!(!is_valid("retention.rankings", "8"));
        assert!(!is_valid("retention.incidents", "31"));
        assert!(!is_valid("retention.audit", "366"));
        assert!(!is_valid("retention.other", "1"));
        assert!(is_valid("retention.minutes", "1"));
        assert_eq!(KEYS[0], "notify.spike_factor");
    }
}
