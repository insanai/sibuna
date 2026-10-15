//! The world boundaries asset (`world-110m.bin`): its buffer, validation and reading.
//!
//! The globe needs country outlines that the authentication module must not carry, so the
//! bridge downloads them after sign-in into a buffer the module provides
//! (`sb_geometry_input`) and reports the length (`sb_geometry_loaded`). The format is
//! described in `web/assets/GEOGRAPHY.md`: `SBG1` or `SBG2`, optional country centres,
//! then closed rings of little-endian `i16` longitude and latitude pairs in hundredths of
//! a degree. Projection and drawing belong to the globe page.

use std::fmt;

/// The largest geometry file, in bytes.
pub const MAX_BYTES: usize = 128 * 1024;
/// The most rings a file may hold.
pub const MAX_RINGS: usize = 1024;
/// The most vertices a file may hold, over all rings.
pub const MAX_VERTICES: usize = 16_384;
/// The most country centres an `SBG2` file may hold.
pub const MAX_CENTERS: usize = 256;

/// Why geometry bytes were refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GeometryError {
    /// The bytes do not follow the format.
    Invalid,
    /// The file or its vertex count exceeds the bounds.
    TooLarge,
}

impl fmt::Display for GeometryError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            GeometryError::Invalid => "the geometry does not follow the SBG format",
            GeometryError::TooLarge => "the geometry exceeds its bounds",
        })
    }
}

impl std::error::Error for GeometryError {}

/// A longitude and latitude, in degrees.
#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub struct Point {
    /// Longitude, -180 to 180.
    pub lon: f64,
    /// Latitude, -90 to 90.
    pub lat: f64,
}

/// The geometry the session holds, and the state of its download.
///
/// The download buffer is allocated with the value, never in [`Geometry::input`]:
/// `glue.js` reads `memory.buffer` before it calls `sb_geometry_input`, so that export
/// must not grow linear memory.
#[derive(Debug)]
pub struct Geometry {
    /// The bridge writes the downloaded file here; always [`MAX_BYTES`] long.
    buffer: Vec<u8>,
    /// The length of validated geometry at the start of `buffer`.
    length: Option<usize>,
    /// A download is in flight.
    pub busy: bool,
    /// After a failed download, no new one starts before this browser second.
    pub retry_at: u64,
}

impl Default for Geometry {
    fn default() -> Geometry {
        Geometry { buffer: vec![0; MAX_BYTES], length: None, busy: false, retry_at: 0 }
    }
}

impl Geometry {
    /// Returns the buffer the bridge writes a download into, [`MAX_BYTES`] long, without
    /// allocating. Any validated geometry is forgotten, since the bridge is about to
    /// overwrite it.
    pub fn input(&mut self) -> &mut [u8] {
        self.length = None;
        &mut self.buffer
    }

    /// Validates the first `length` bytes the bridge wrote and keeps them.
    ///
    /// # Errors
    ///
    /// [`GeometryError`] if the bytes are invalid or `length` exceeds the buffer; the
    /// geometry is then absent.
    pub fn load(&mut self, length: usize) -> Result<(), GeometryError> {
        self.length = None;
        let bytes = self.buffer.get(..length).ok_or(GeometryError::TooLarge)?;
        validate(bytes)?;
        self.length = Some(length);
        Ok(())
    }

    /// Forgets the geometry.
    pub fn unload(&mut self) {
        self.length = None;
    }

    /// Returns the validated geometry, if any.
    pub fn bytes(&self) -> Option<&[u8]> {
        self.length.and_then(|length| self.buffer.get(..length))
    }

    /// Returns true when validated geometry is held.
    pub fn is_loaded(&self) -> bool {
        self.length.is_some()
    }
}

/// The parsed file header.
struct Header<'a> {
    /// Where the first ring starts.
    offset: usize,
    rings: u16,
    /// The centre records, six bytes each.
    centers: &'a [u8],
}

fn read_u16(bytes: &[u8], at: usize) -> Option<u16> {
    let pair = bytes.get(at..at.checked_add(2)?)?;
    Some(u16::from_le_bytes([pair[0], pair[1]]))
}

fn read_i16(bytes: &[u8], at: usize) -> Option<i16> {
    read_u16(bytes, at).map(|value| value as i16)
}

/// Reads the point stored at the start of `bytes` (two `i16` in hundredths of a degree).
fn decode_point(bytes: &[u8]) -> Option<Point> {
    Some(Point {
        lon: f64::from(read_i16(bytes, 0)?) / 100.0,
        lat: f64::from(read_i16(bytes, 2)?) / 100.0,
    })
}

fn is_code(bytes: &[u8]) -> bool {
    bytes.len() >= 2 && bytes[0].is_ascii_uppercase() && bytes[1].is_ascii_uppercase()
}

fn header(bytes: &[u8]) -> Result<Header<'_>, GeometryError> {
    let magic = bytes.get(..4).ok_or(GeometryError::Invalid)?;
    if magic == b"SBG1" {
        let rings = read_u16(bytes, 4).ok_or(GeometryError::Invalid)?;
        return Ok(Header { offset: 6, rings, centers: &[] });
    }
    if magic != b"SBG2" {
        return Err(GeometryError::Invalid);
    }
    let count = read_u16(bytes, 4).ok_or(GeometryError::Invalid)?;
    let rings = read_u16(bytes, 6).ok_or(GeometryError::Invalid)?;
    let offset = 8 + usize::from(count) * 6;
    if usize::from(count) > MAX_CENTERS || offset > bytes.len() {
        return Err(GeometryError::Invalid);
    }
    let centers = bytes.get(8..offset).ok_or(GeometryError::Invalid)?;
    for record in centers.as_chunks::<6>().0 {
        let position = decode_point(&record[2..]).ok_or(GeometryError::Invalid)?;
        if !is_code(record) || position.lon.abs() > 180.0 || position.lat.abs() > 90.0 {
            return Err(GeometryError::Invalid);
        }
    }
    Ok(Header { offset, rings, centers })
}

/// Checks `bytes` against the format and its bounds.
///
/// # Errors
///
/// [`GeometryError::TooLarge`] for more than [`MAX_BYTES`] bytes or [`MAX_VERTICES`]
/// vertices, and [`GeometryError::Invalid`] for anything else out of format: a short
/// header, an unknown magic, a ring count of zero or above [`MAX_RINGS`], a code that is
/// not two capital letters, a ring of fewer than four points or not closed, a coordinate
/// out of range, or trailing bytes.
pub fn validate(bytes: &[u8]) -> Result<(), GeometryError> {
    if bytes.len() > MAX_BYTES {
        return Err(GeometryError::TooLarge);
    }
    let info = header(bytes)?;
    if info.rings == 0 || usize::from(info.rings) > MAX_RINGS {
        return Err(GeometryError::Invalid);
    }
    let mut offset = info.offset;
    let mut vertices = 0usize;
    for _ in 0..info.rings {
        let head = bytes.get(offset..offset + 4).ok_or(GeometryError::Invalid)?;
        let count = read_u16(head, 2).ok_or(GeometryError::Invalid)?;
        if !is_code(head) || count < 4 {
            return Err(GeometryError::Invalid);
        }
        vertices += usize::from(count);
        if vertices > MAX_VERTICES {
            return Err(GeometryError::TooLarge);
        }
        offset += 4;
        let length = usize::from(count) * 4;
        let coordinates = bytes.get(offset..offset + length).ok_or(GeometryError::Invalid)?;
        if coordinates.get(..4) != coordinates.get(length - 4..) {
            return Err(GeometryError::Invalid);
        }
        for pair in coordinates.as_chunks::<4>().0 {
            let lon = i16::from_le_bytes([pair[0], pair[1]]);
            let lat = i16::from_le_bytes([pair[2], pair[3]]);
            if !(-18000..=18000).contains(&lon) || !(-9000..=9000).contains(&lat) {
                return Err(GeometryError::Invalid);
            }
        }
        offset += length;
    }
    if offset != bytes.len() {
        return Err(GeometryError::Invalid);
    }
    Ok(())
}

/// Returns the representative position of the country `code` (two ASCII capitals as a
/// big-endian `u16`, as the statistics carry it), if the geometry lists one.
pub fn center(bytes: &[u8], code: u16) -> Option<Point> {
    let info = header(bytes).ok()?;
    info.centers
        .as_chunks::<6>()
        .0
        .iter()
        .find(|record| u16::from_be_bytes([record[0], record[1]]) == code)
        .and_then(|record| decode_point(&record[2..]))
}

/// One closed ring of validated geometry.
#[derive(Clone, Copy, Debug)]
pub struct Ring<'a> {
    /// The country code, two ASCII capitals (`ZZ` when unknown).
    pub code: [u8; 2],
    /// The points, four bytes each; the first equals the last.
    pub coordinates: &'a [u8],
}

impl Ring<'_> {
    /// Returns the ring's points in order.
    pub fn points(&self) -> impl Iterator<Item = Point> + '_ {
        self.coordinates.as_chunks::<4>().0.iter().filter_map(|pair| decode_point(pair))
    }
}

/// Returns the rings of geometry that [`validate`] accepted; invalid bytes yield no rings.
pub fn rings(bytes: &[u8]) -> impl Iterator<Item = Ring<'_>> {
    let (mut offset, count) = match header(bytes) {
        Ok(info) => (info.offset, info.rings),
        Err(_) => (bytes.len(), 0),
    };
    (0..count).map_while(move |_| {
        let head = bytes.get(offset..offset + 4)?;
        let length = usize::from(read_u16(head, 2)?) * 4;
        let coordinates = bytes.get(offset + 4..offset + 4 + length)?;
        offset += 4 + length;
        Some(Ring { code: [head[0], head[1]], coordinates })
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const VALID: &[u8] = b"SBG1\x01\x00US\x04\x00\
        \x00\x00\x00\x00\x64\x00\x00\x00\x64\x00\x64\x00\x00\x00\x00\x00";

    #[test]
    fn geometry_validator_rejects_partial_headers_open_rings_and_trailing_data() {
        validate(VALID).unwrap();
        for length in 0..VALID.len() {
            assert_eq!(validate(&VALID[..length]), Err(GeometryError::Invalid), "{length}");
        }
        let mut longer = VALID.to_vec();
        longer.push(b'x');
        assert_eq!(validate(&longer), Err(GeometryError::Invalid));
        assert_eq!(validate(&vec![0; MAX_BYTES + 1]), Err(GeometryError::TooLarge));
    }

    #[test]
    fn the_committed_world_validates_and_yields_its_rings_and_centres() {
        let world = include_bytes!("../web/assets/world-110m.bin");
        validate(world).unwrap();
        let rings: Vec<Ring<'_>> = rings(world).collect();
        assert!(!rings.is_empty() && rings.len() <= MAX_RINGS);
        assert!(rings.iter().all(|ring| ring.points().count() >= 4));
        let code = u16::from_be_bytes(*b"FR");
        let france = center(world, code).unwrap();
        assert!(france.lat > 40.0 && france.lat < 52.0);
    }

    #[test]
    fn loading_needs_valid_bytes_written_through_the_input_buffer() {
        let mut geometry = Geometry::default();
        assert!(geometry.load(10).is_err());
        geometry.input()[..VALID.len()].copy_from_slice(VALID);
        geometry.load(VALID.len()).unwrap();
        assert_eq!(geometry.bytes(), Some(VALID));
        assert!(geometry.load(MAX_BYTES + 1).is_err());
        assert!(!geometry.is_loaded());
    }

    /// Mutated geometry never panics, and accepted bytes always yield closed rings.
    #[test]
    fn fuzz_validation_never_panics() {
        let world = include_bytes!("../web/assets/world-110m.bin");
        let mut seed = 0x9e37_79b9_7f4a_7c15_u64;
        let mut next = move || {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            seed
        };
        for round in 0..100_000 {
            let source: &[u8] = if round % 2 == 0 { VALID } else { &world[..512] };
            let mut bytes = source.to_vec();
            for _ in 0..1 + next() % 4 {
                let at = (next() as usize) % bytes.len();
                match next() % 3 {
                    0 => bytes[at] ^= 1 << (next() % 8),
                    1 => bytes.truncate(at),
                    _ => bytes.insert(at, next() as u8),
                }
                if bytes.is_empty() {
                    break;
                }
            }
            if validate(&bytes).is_ok() {
                for ring in rings(&bytes) {
                    assert_eq!(
                        ring.coordinates.get(..4),
                        ring.coordinates.get(ring.coordinates.len() - 4..)
                    );
                }
            }
            let _ = center(&bytes, u16::from_be_bytes(*b"US"));
        }
    }
}
