//! The country an incident was attributed to when it was persisted. This is
//! persistence-time attribution, not a reconstructed request-time location.

use std::fmt::{self, Write};

use sibuna_json::{Value, Writer};

use crate::codec::{
    Decode, DecodeError, DecodeErrorKind, Encode, Fields, Path, field, optional_str,
};
use crate::text::Text;

/// A country filter: empty, `unknown`, `not_recorded` or a two-letter code.
pub type Filter = Text<12>;

/// A country code or GeoIP generation that breaks the mapping's format.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct InvalidCountry;

impl fmt::Display for InvalidCountry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("expected a two-letter country code and a 64-digit hex generation")
    }
}

impl std::error::Error for InvalidCountry {}

/// A mapping as it crosses the wire, borrowing the [`Mapping`] it describes.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct Wire<'a> {
    /// The country code; `None` when the address was not in the dataset.
    pub code: Option<&'a str>,
    /// The GeoIP generation (dataset digest); `None` when nothing was recorded.
    pub generation: Option<&'a str>,
    /// A grouped row whose members map to different countries.
    pub mixed: bool,
    /// An attribution was recorded.
    pub recorded: bool,
}

impl Encode for Wire<'_> {
    fn encode<W: Write>(&self, json: &mut Writer<W>) -> fmt::Result {
        json.begin_object()?;
        json.key("code")?;
        optional_str(json, self.code)?;
        json.key("generation")?;
        optional_str(json, self.generation)?;
        field(json, "mixed", &self.mixed)?;
        field(json, "recorded", &self.recorded)?;
        json.end_object()
    }
}

/// An incident's country attribution.
///
/// Three cases stay distinct: nothing recorded (`recorded` false), recorded but not in the
/// dataset (`recorded` true, empty `code`), and a known country.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash)]
pub struct Mapping {
    /// The two-letter code; empty when unknown.
    pub code: Text<2>,
    /// The GeoIP generation as 64 hex digits; empty when nothing was recorded.
    pub generation: Text<64>,
    /// A grouped row whose members map to different countries.
    pub mixed: bool,
    /// An attribution was recorded.
    pub recorded: bool,
}

impl Mapping {
    /// Returns the wire form, borrowing this mapping's text.
    pub fn wire(&self) -> Wire<'_> {
        Wire {
            code: Some(self.code.as_str()).filter(|code| !code.is_empty()),
            generation: Some(self.generation.as_str()).filter(|hash| !hash.is_empty()),
            mixed: self.mixed,
            recorded: self.recorded,
        }
    }

    /// Returns true if the mapping passes a [`Filter`]; mixed groups pass only the empty
    /// filter.
    pub fn matches(&self, filter: &str) -> bool {
        if filter.is_empty() {
            return true;
        }
        if self.mixed {
            return false;
        }
        match filter {
            "not_recorded" => !self.recorded,
            "unknown" => self.recorded && self.code.is_empty(),
            _ => self.code == filter,
        }
    }

    /// Builds a mapping from its wire form; a generation implies a recorded attribution.
    ///
    /// # Errors
    ///
    /// [`InvalidCountry`] for a code that is not two capital letters or a generation that is
    /// not 64 hex digits.
    pub fn from_wire(input: Wire<'_>) -> Result<Mapping, InvalidCountry> {
        if input.code.is_some_and(|code| code.len() != 2 || !valid_filter(code)) {
            return Err(InvalidCountry);
        }
        if input.generation.is_some_and(|hash| {
            hash.len() != 64 || !hash.bytes().all(|byte| byte.is_ascii_hexdigit())
        }) {
            return Err(InvalidCountry);
        }
        Ok(Mapping {
            code: Text::new(input.code.unwrap_or_default()).map_err(|_| InvalidCountry)?,
            generation: Text::new(input.generation.unwrap_or_default())
                .map_err(|_| InvalidCountry)?,
            mixed: input.mixed,
            recorded: input.recorded || input.generation.is_some(),
        })
    }
}

impl Encode for Mapping {
    fn encode<W: Write>(&self, json: &mut Writer<W>) -> fmt::Result {
        self.wire().encode(json)
    }
}

impl Decode for Mapping {
    fn decode(value: &Value<'_>, path: Path<'_>) -> Result<Mapping, DecodeError> {
        let mut fields = Fields::new(value, path)?;
        let code: Option<String> = fields.or_default("code")?;
        let generation: Option<String> = fields.or_default("generation")?;
        let wire = Wire {
            code: code.as_deref(),
            generation: generation.as_deref(),
            mixed: fields.or_default("mixed")?,
            recorded: fields.or_default("recorded")?,
        };
        fields.finish()?;
        Mapping::from_wire(wire).map_err(|_| {
            DecodeError::new(path, DecodeErrorKind::Invalid("an invalid country or generation"))
        })
    }
}

/// Returns true for a valid [`Filter`]: empty, `unknown`, `not_recorded` or two capital
/// ASCII letters.
pub fn valid_filter(value: &str) -> bool {
    matches!(value, "" | "unknown" | "not_recorded")
        || (value.len() == 2 && value.bytes().all(|byte| byte.is_ascii_uppercase()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::codec::{from_json, to_json};

    // Port of event_country.zig "missing mapping, unknown address and mixed source groups
    // remain distinct". The pointer-identity checks become a lifetime: `wire` borrows.
    #[test]
    fn missing_mapping_unknown_address_and_mixed_source_groups_remain_distinct() {
        let absent = Mapping::default();
        let a64 = "a".repeat(64);
        let b64 = "b".repeat(64);
        let unknown =
            Mapping::from_wire(Wire { generation: Some(&a64), ..Default::default() }).unwrap();
        let known = Mapping::from_wire(Wire {
            code: Some("US"),
            generation: Some(&b64),
            ..Default::default()
        })
        .unwrap();
        assert!(absent.matches("not_recorded") && !absent.matches("unknown"));
        assert!(unknown.matches("unknown") && !unknown.matches("not_recorded"));
        assert!(known.matches("US") && !known.matches("DE"));
        let view = known.wire();
        assert_eq!(view.code, Some("US"));
        assert_eq!(view.generation, Some(b64.as_str()));
        let multiple = Mapping::from_wire(Wire { recorded: true, ..Default::default() }).unwrap();
        assert!(multiple.matches("unknown") && !multiple.matches("not_recorded"));
        assert!(!Mapping { mixed: true, ..Default::default() }.matches("not_recorded"));
        assert_eq!(
            Mapping::from_wire(Wire { code: Some("U'"), ..Default::default() }),
            Err(InvalidCountry)
        );
        let z64 = "z".repeat(64);
        assert_eq!(
            Mapping::from_wire(Wire {
                code: Some("US"),
                generation: Some(&z64),
                ..Default::default()
            }),
            Err(InvalidCountry)
        );
    }

    #[test]
    fn mappings_round_trip() {
        let known = Mapping {
            code: Text::new("DE").unwrap(),
            generation: Text::new(&"c".repeat(64)).unwrap(),
            mixed: false,
            recorded: true,
        };
        let text = to_json(&known);
        assert_eq!(
            text,
            format!(
                "{{\"code\":\"DE\",\"generation\":\"{}\",\"mixed\":false,\"recorded\":true}}",
                "c".repeat(64)
            )
        );
        assert_eq!(from_json::<Mapping>(text.as_bytes()), Ok(known));
        assert_eq!(
            to_json(&Mapping::default()),
            "{\"code\":null,\"generation\":null,\"mixed\":false,\"recorded\":false}"
        );
    }
}
