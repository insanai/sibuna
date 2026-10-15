//! The publishers of country data and the facts about them callers must not invent.
//!
//! Providers publish the same `start,end,country` rows under different licences, version
//! syntaxes, compression and hosts. This module owns those facts, so callers never embed
//! download URLs or attribution text.

use std::fmt;

/// The longest provider name, in bytes.
pub const MAX_NAME: usize = 12;
/// The longest version text, in bytes.
pub const MAX_VERSION: usize = 10;
/// The longest URL a provider produces, in bytes.
pub const MAX_URL: usize = 160;
/// The most source files one provider publishes.
pub const MAX_FILES: usize = 2;

const GITHUB: &str = "https://github.com/sapics/ip-location-db/releases/download/";

/// How a provider compresses its source files.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Compression {
    /// Plain CSV files.
    None,
    /// One gzip-compressed CSV file.
    Gzip,
}

/// A publisher of country data. The discriminant is the snapshot header's provider byte.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum Provider {
    /// sapics/ip-location-db `user-country`: two daily CSV files, public domain (PDDL).
    UserCountry = 1,
    /// DB-IP IP to Country Lite: one monthly gzip file, CC BY 4.0 with attribution.
    Dbip = 2,
}

/// Why a provider could not name a file or a URL.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ProviderError {
    /// The file index is not below the provider's file count.
    NoSuchFile,
    /// The version does not follow the provider's version syntax.
    InvalidVersion,
}

impl fmt::Display for ProviderError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            ProviderError::NoSuchFile => "the provider publishes no such file",
            ProviderError::InvalidVersion => "the version does not follow the provider syntax",
        })
    }
}

impl std::error::Error for ProviderError {}

impl Provider {
    /// Every provider, in discriminant order.
    pub const ALL: [Provider; 2] = [Provider::UserCountry, Provider::Dbip];

    /// Returns the provider named `text` (`user-country` or `dbip`), or `None`.
    pub fn parse(text: &str) -> Option<Provider> {
        Provider::ALL.into_iter().find(|provider| provider.name() == text)
    }

    /// Returns the provider whose snapshot header byte is `byte`, or `None`.
    pub fn from_byte(byte: u8) -> Option<Provider> {
        Provider::ALL.into_iter().find(|provider| *provider as u8 == byte)
    }

    /// Returns the provider's command-line and storage name.
    pub fn name(self) -> &'static str {
        match self {
            Provider::UserCountry => "user-country",
            Provider::Dbip => "dbip",
        }
    }

    /// Returns the dataset's title for interfaces.
    pub fn title(self) -> &'static str {
        match self {
            Provider::UserCountry => "ip-location-db user-country",
            Provider::Dbip => "DB-IP IP to Country Lite",
        }
    }

    /// Returns the licence the data is published under.
    pub fn license(self) -> &'static str {
        match self {
            Provider::UserCountry => "PDDL 1.0",
            Provider::Dbip => "CC BY 4.0",
        }
    }

    /// Returns the attribution link the licence requires, or `None` when none is required.
    pub fn attribution(self) -> Option<&'static str> {
        match self {
            Provider::UserCountry => None,
            Provider::Dbip => Some("https://db-ip.com"),
        }
    }

    /// Returns the attribution text the licence requires, or `None`.
    pub fn attribution_text(self) -> Option<&'static str> {
        match self {
            Provider::UserCountry => None,
            Provider::Dbip => Some("IP Geolocation by DB-IP"),
        }
    }

    /// Returns the publisher's home page.
    pub fn homepage(self) -> &'static str {
        match self {
            Provider::UserCountry => "https://github.com/sapics/ip-location-db",
            Provider::Dbip => "https://db-ip.com/db/lite.php",
        }
    }

    /// Returns how the source files are compressed.
    pub fn compression(self) -> Compression {
        match self {
            Provider::UserCountry => Compression::None,
            Provider::Dbip => Compression::Gzip,
        }
    }

    /// Returns how many source files make one generation.
    pub fn file_count(self) -> u8 {
        match self {
            Provider::UserCountry => 2,
            Provider::Dbip => 1,
        }
    }

    /// Returns the version syntax for messages, `YYYY-MM-DD` or `YYYY-MM`.
    pub fn version_syntax(self) -> &'static str {
        match self {
            Provider::UserCountry => "YYYY-MM-DD",
            Provider::Dbip => "YYYY-MM",
        }
    }

    /// Returns true when `text` is a valid version of this provider: a real calendar date
    /// for `user-country`, a month for `dbip`, from the year 2000 on.
    pub fn is_version_valid(self, text: &str) -> bool {
        match self {
            Provider::UserCountry => is_valid_date(text),
            Provider::Dbip => is_valid_month(text),
        }
    }

    /// Returns the name of source file `file` (counted from zero) for `version`.
    ///
    /// Fails with [`ProviderError`] when the file or the version is not valid.
    pub fn file_name(self, file: u8, version: &str) -> Result<String, ProviderError> {
        if file >= self.file_count() {
            return Err(ProviderError::NoSuchFile);
        }
        if !self.is_version_valid(version) {
            return Err(ProviderError::InvalidVersion);
        }
        Ok(match (self, file) {
            (Provider::UserCountry, 0) => "user-country-ipv4.csv".to_owned(),
            (Provider::UserCountry, _) => "user-country-ipv6.csv".to_owned(),
            (Provider::Dbip, _) => format!("dbip-country-lite-{version}.csv.gz"),
        })
    }

    /// Returns the download URL of source file `file` for `version`, at most [`MAX_URL`]
    /// bytes long. Fails like [`Provider::file_name`].
    pub fn url(self, file: u8, version: &str) -> Result<String, ProviderError> {
        let name = self.file_name(file, version)?;
        Ok(match self {
            Provider::UserCountry => format!("{GITHUB}latest/{name}"),
            Provider::Dbip => format!("https://download.db-ip.com/free/{name}"),
        })
    }

    /// Returns the URL of the publisher's SHA-256 file for source file `file`, or `None`
    /// when the provider publishes none. Fails like [`Provider::file_name`].
    pub fn checksum_url(self, file: u8, version: &str) -> Result<Option<String>, ProviderError> {
        let name = self.file_name(file, version)?;
        Ok(match self {
            Provider::UserCountry => Some(format!("{GITHUB}checksum/{name}.sha256")),
            Provider::Dbip => None,
        })
    }

    /// Returns true when a single HTTPS redirect from the publisher URL may reach `host`.
    /// The comparison is exact.
    pub fn is_redirect_allowed(self, host: &str) -> bool {
        match self {
            Provider::UserCountry => {
                host == "release-assets.githubusercontent.com"
                    || host == "objects.githubusercontent.com"
            }
            Provider::Dbip => false,
        }
    }
}

impl fmt::Display for Provider {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

/// Returns the decimal value of `text` when it is one or more ASCII digits (at most four).
fn digits(text: &[u8]) -> Option<u16> {
    if text.is_empty() || text.len() > 4 || !text.iter().all(u8::is_ascii_digit) {
        return None;
    }
    Some(text.iter().fold(0, |value, &digit| value * 10 + u16::from(digit - b'0')))
}

/// Returns true for `YYYY-MM` with a year from 2000 and a month from 1 to 12.
pub fn is_valid_month(text: &str) -> bool {
    match text.as_bytes() {
        [year @ .., b'-', m1, m2] if year.len() == 4 => {
            let (Some(year), Some(month)) = (digits(year), digits(&[*m1, *m2])) else {
                return false;
            };
            year >= 2000 && (1..=12).contains(&month)
        }
        _ => false,
    }
}

/// Returns true for `YYYY-MM-DD` naming a real day, with a year from 2000.
pub fn is_valid_date(text: &str) -> bool {
    let bytes = text.as_bytes();
    if bytes.len() != 10 || bytes[7] != b'-' {
        return false;
    }
    let (Some(month_text), Some(day)) = (text.get(..7), digits(&bytes[8..10])) else {
        return false;
    };
    if !is_valid_month(month_text) {
        return false;
    }
    // A valid month text has four year digits and two month digits.
    let (Some(year), Some(month)) = (digits(&bytes[..4]), digits(&bytes[5..7])) else {
        return false;
    };
    day >= 1 && day <= days_in_month(year, month)
}

fn days_in_month(year: u16, month: u16) -> u16 {
    let leap = (year.is_multiple_of(4) && !year.is_multiple_of(100)) || year.is_multiple_of(400);
    match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if leap => 29,
        2 => 28,
        _ => 0,
    }
}

/// Why a publisher checksum file was refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ChecksumError {
    /// The file is shorter than a digest and a name, or longer than 256 bytes.
    Length,
    /// The first 64 bytes are not hexadecimal.
    Digest,
    /// No space or tab separates the digest from the name.
    Separator,
    /// The file names a different source file.
    Name,
}

impl fmt::Display for ChecksumError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            ChecksumError::Length => "the checksum file has the wrong length",
            ChecksumError::Digest => "the checksum file does not start with 64 hex digits",
            ChecksumError::Separator => "the checksum file lacks a space before the name",
            ChecksumError::Name => "the checksum file names a different file",
        })
    }
}

impl std::error::Error for ChecksumError {}

/// Parses `<64 hex digits>  <name>` as written by `sha256sum` (a `*` before the name marks
/// binary mode) and returns the digest when the name is `expected_name`.
///
/// Borrows both arguments for the call. Surrounding spaces, tabs, CR and LF are ignored.
/// Fails with [`ChecksumError`].
pub fn parse_checksum_file(text: &[u8], expected_name: &str) -> Result<[u8; 32], ChecksumError> {
    let end = text.iter().rposition(|byte| !is_checksum_space(*byte)).map_or(0, |i| i + 1);
    let start = text.iter().position(|byte| !is_checksum_space(*byte)).unwrap_or(end);
    // `start <= end`: both are found from the same non-space bytes, or are both `end`.
    let trimmed = &text[start..end];
    if trimmed.len() < 66 || trimmed.len() > 256 {
        return Err(ChecksumError::Length);
    }
    let (hex, rest) = trimmed.split_at(64);
    let mut digest = [0u8; 32];
    for (out, &[high, low]) in digest.iter_mut().zip(hex.as_chunks::<2>().0) {
        let high = hex_digit(high).ok_or(ChecksumError::Digest)?;
        let low = hex_digit(low).ok_or(ChecksumError::Digest)?;
        *out = high << 4 | low;
    }
    let name_start = rest.iter().position(|&byte| byte != b' ' && byte != b'\t');
    let name = match name_start {
        Some(0) | None => return Err(ChecksumError::Separator),
        Some(start) => &rest[start..],
    };
    let name = name.strip_prefix(b"*").unwrap_or(name);
    if name != expected_name.as_bytes() {
        return Err(ChecksumError::Name);
    }
    Ok(digest)
}

fn is_checksum_space(byte: u8) -> bool {
    matches!(byte, b' ' | b'\t' | b'\r' | b'\n')
}

fn hex_digit(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn provider_names_versions_and_files_are_fixed_by_the_library() {
        assert_eq!(Provider::parse("user-country"), Some(Provider::UserCountry));
        assert_eq!(Provider::parse("dbip"), Some(Provider::Dbip));
        assert_eq!(Provider::parse("maxmind"), None);
        let user = Provider::UserCountry;
        assert!(user.is_version_valid("2026-09-09"));
        assert!(user.is_version_valid("2024-02-29"));
        assert!(!user.is_version_valid("2023-02-29"));
        assert!(!user.is_version_valid("2026-09"));
        assert!(!user.is_version_valid("2026-13-01"));
        assert!(Provider::Dbip.is_version_valid("2026-09"));
        for v in ["../evil", "2026-13", "2026-00", "2026- 1", "//a.b/c", "2026-09-09"] {
            assert!(!Provider::Dbip.is_version_valid(v), "{v}");
        }
        assert_eq!(
            user.url(1, "2026-09-09").unwrap(),
            format!("{GITHUB}latest/user-country-ipv6.csv")
        );
        assert_eq!(
            user.checksum_url(0, "2026-09-09").unwrap().unwrap(),
            format!("{GITHUB}checksum/user-country-ipv4.csv.sha256")
        );
        assert_eq!(
            Provider::Dbip.url(0, "2026-09").unwrap(),
            "https://download.db-ip.com/free/dbip-country-lite-2026-09.csv.gz"
        );
        assert_eq!(Provider::Dbip.checksum_url(0, "2026-09").unwrap(), None);
        assert_eq!(Provider::Dbip.url(1, "2026-09"), Err(ProviderError::NoSuchFile));
        assert_eq!(user.url(0, "2026-09"), Err(ProviderError::InvalidVersion));
        assert!(user.is_redirect_allowed("release-assets.githubusercontent.com"));
        assert!(!user.is_redirect_allowed("evil.githubusercontent.com"));
        assert!(!Provider::Dbip.is_redirect_allowed("release-assets.githubusercontent.com"));
        assert_eq!(user.attribution(), None);
        assert_eq!(Provider::Dbip.attribution(), Some("https://db-ip.com"));
    }

    #[test]
    fn publisher_checksum_files_are_matched_by_name() {
        let hex = "bc74ffee42cced41df6d64239b5227e874e4fd52a12f900830bab4ca391f4a6d";
        let name = "user-country-ipv4.csv";
        let digest = parse_checksum_file(format!("{hex}  {name}\n").as_bytes(), name).unwrap();
        assert_eq!(digest[0], 0xbc);
        assert_eq!(digest[31], 0x6d);
        parse_checksum_file(format!("{hex} *{name}").as_bytes(), name).unwrap();
        let other = format!("{hex}  other.csv");
        assert_eq!(parse_checksum_file(other.as_bytes(), name), Err(ChecksumError::Name));
        assert_eq!(parse_checksum_file(hex.as_bytes(), name), Err(ChecksumError::Length));
        let bad = format!("zz{}  x", &hex[2..]);
        assert_eq!(parse_checksum_file(bad.as_bytes(), "x"), Err(ChecksumError::Digest));
        let glued = format!("{hex}xy");
        assert_eq!(parse_checksum_file(glued.as_bytes(), "y"), Err(ChecksumError::Separator));
        let upper = format!("\t {}\t{name} \r\n", hex.to_ascii_uppercase());
        assert_eq!(parse_checksum_file(upper.as_bytes(), name), Ok(digest));
    }

    #[test]
    fn provider_bytes_and_url_bounds() {
        for provider in Provider::ALL {
            assert_eq!(Provider::from_byte(provider as u8), Some(provider));
            assert!(provider.name().len() <= MAX_NAME);
            assert!(usize::from(provider.file_count()) <= MAX_FILES);
        }
        assert_eq!(Provider::from_byte(0), None);
        assert_eq!(Provider::from_byte(3), None);
        let url = Provider::UserCountry.checksum_url(1, "2026-09-09").unwrap().unwrap();
        assert!(url.len() <= MAX_URL);
        assert!(is_valid_date("2000-02-29"));
        assert!(!is_valid_date("1900-02-28"));
        assert!(!is_valid_date("2100-02-29"));
        assert!(!is_valid_date("2026-04-31"));
        assert!(!is_valid_date("2026-04-00"));
        assert!(!is_valid_date("2026-04-0\u{e9}"));
    }
}
