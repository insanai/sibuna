//! Operator-declared server coordinates, independent of country-only client GeoIP data.

use std::fmt::{self, Write};

use sibuna_json::{Value, Writer};

use crate::codec::{Decode, DecodeError, Encode, Fields, Path, field};

/// A position in degrees: latitude in -90..=90, longitude in -180..=180.
#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub struct Location {
    /// Latitude in degrees, north positive.
    pub lat: f64,
    /// Longitude in degrees, east positive.
    pub lon: f64,
}

/// Text that is not a valid `latitude,longitude` pair.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct InvalidLocation;

impl fmt::Display for InvalidLocation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("expected `latitude,longitude` in degrees, such as `1.3521,103.8198`")
    }
}

impl std::error::Error for InvalidLocation {}

impl Location {
    /// Returns true when both coordinates are finite and in range.
    pub fn is_valid(&self) -> bool {
        self.lat.is_finite()
            && self.lon.is_finite()
            && self.lat.abs() <= 90.0
            && self.lon.abs() <= 180.0
    }

    /// Parses `latitude,longitude` (at most 64 bytes), the conventional order. There is no
    /// lookup and no inferred default.
    ///
    /// # Errors
    ///
    /// [`InvalidLocation`] for malformed, non-finite or out-of-range input.
    pub fn parse(text: &str) -> Result<Location, InvalidLocation> {
        if text.len() > 64 {
            return Err(InvalidLocation);
        }
        let (lat, lon) = text.split_once(',').ok_or(InvalidLocation)?;
        let value = Location {
            lat: crate::codec::zig_parse_f64(lat).ok_or(InvalidLocation)?,
            lon: crate::codec::zig_parse_f64(lon).ok_or(InvalidLocation)?,
        };
        if value.is_valid() { Ok(value) } else { Err(InvalidLocation) }
    }
}

impl Encode for Location {
    fn encode<W: Write>(&self, json: &mut Writer<W>) -> fmt::Result {
        json.begin_object()?;
        field(json, "lat", &self.lat)?;
        field(json, "lon", &self.lon)?;
        json.end_object()
    }
}

impl Decode for Location {
    fn decode(value: &Value<'_>, path: Path<'_>) -> Result<Location, DecodeError> {
        let mut fields = Fields::new(value, path)?;
        let location = Location { lat: fields.required("lat")?, lon: fields.required("lon")? };
        fields.finish()?;
        Ok(location)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::codec::{from_json, to_json};

    // Port of location.zig "server coordinates preserve boundaries and reject nonfinite or
    // malformed input".
    #[test]
    fn server_coordinates_preserve_boundaries_and_reject_nonfinite_or_malformed_input() {
        for value in ["0,0", "90,180", "-90,-180", "1.3521,103.8198"] {
            assert!(Location::parse(value).unwrap().is_valid());
        }
        for value in ["", "1", "1,2,3", "91,0", "0,-181", "nan,0", "0,inf"] {
            assert_eq!(Location::parse(value), Err(InvalidLocation));
        }
    }

    #[test]
    fn locations_round_trip_as_zig_floats() {
        let location = Location { lat: 1.3521, lon: 103.0 };
        assert_eq!(to_json(&location), "{\"lat\":1.3521,\"lon\":103}");
        assert_eq!(from_json::<Location>(b"{\"lat\":1.3521,\"lon\":103}"), Ok(location));
    }
}
