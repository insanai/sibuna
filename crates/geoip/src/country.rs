//! ISO 3166-1 alpha-2 country codes accepted from publishers.
//!
//! The list holds the assigned codes plus the transitionally reserved `AN` and `FX`, which
//! published RIR-derived data still carries. `ZZ` means unknown: it is a valid code in a
//! source file, but no range in a database carries it.

use std::fmt;

/// The accepted codes, two letters each, separated by single spaces, in ascending order.
const CODES: &[u8] = b"AD AE AF AG AI AL AM AN AO AQ AR AS AT AU AW AX AZ BA BB BD BE BF BG \
BH BI BJ BL BM BN BO BQ BR BS BT BV BW BY BZ CA CC CD CF CG CH CI CK CL CM CN CO CR CU CV CW \
CX CY CZ DE DJ DK DM DO DZ EC EE EG EH ER ES ET FI FJ FK FM FO FR FX GA GB GD GE GF GG GH GI \
GL GM GN GP GQ GR GS GT GU GW GY HK HM HN HR HT HU ID IE IL IM IN IO IQ IR IS IT JE JM JO JP \
KE KG KH KI KM KN KP KR KW KY KZ LA LB LC LI LK LR LS LT LU LV LY MA MC MD ME MF MG MH MK ML \
MM MN MO MP MQ MR MS MT MU MV MW MX MY MZ NA NC NE NF NG NI NL NO NP NR NU NZ OM PA PE PF PG \
PH PK PL PM PN PR PS PT PW PY QA RE RO RS RU RW SA SB SC SD SE SG SH SI SJ SK SL SM SN SO SR \
SS ST SV SX SY SZ TC TD TF TG TH TJ TK TL TM TN TO TR TT TV TW TZ UA UG UM US UY UZ VA VC VE \
VG VI VN VU WF WS XK YE YT ZA ZM ZW";

/// How many codes the list holds; `ZZ` is not one of them.
pub const COUNT: usize = CODES.len().div_ceil(3);

/// How many entries a table indexed by [`index`] needs: one per pair of uppercase letters.
pub const INDEX_COUNT: usize = 26 * 26;

/// Membership of every listed code: bit `second` of row `first`, letters counted from `A`.
const LISTED: [u32; 26] = listed_table();

const fn listed_table() -> [u32; 26] {
    let mut table = [0u32; 26];
    let mut i = 0;
    while i < CODES.len() {
        table[(CODES[i] - b'A') as usize] |= 1 << (CODES[i + 1] - b'A');
        i += 3;
    }
    table
}

/// A valid code from the list, or `ZZ` for unknown. Two uppercase ASCII letters.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Country([u8; 2]);

impl Country {
    /// The code publishers use for addresses with no known country.
    pub const UNKNOWN: Country = Country(*b"ZZ");

    /// Returns the country for `code` when it is a listed code or `ZZ`.
    ///
    /// Borrows `code` for the call; returns `None` for anything else, including lowercase.
    #[inline]
    pub fn parse(code: &[u8]) -> Option<Country> {
        match *code {
            [first, second] if is_valid_pair([first, second]) => Some(Country([first, second])),
            _ => None,
        }
    }

    /// Returns the country for two bytes, as [`Country::parse`] does.
    #[inline]
    pub fn from_bytes(code: [u8; 2]) -> Option<Country> {
        is_valid_pair(code).then_some(Country(code))
    }

    /// Returns true for `ZZ`.
    #[inline]
    pub fn is_unknown(self) -> bool {
        self == Country::UNKNOWN
    }

    /// Returns the two ASCII letters.
    #[inline]
    pub fn to_bytes(self) -> [u8; 2] {
        self.0
    }

    /// Returns the code as text, for example `"DE"`.
    pub fn as_str(&self) -> &str {
        // Both bytes are uppercase ASCII letters, so the text is always valid UTF-8.
        std::str::from_utf8(&self.0).unwrap_or("ZZ")
    }

    /// Returns the dense position of the code in a table of [`INDEX_COUNT`] entries.
    #[inline]
    pub fn index(self) -> u16 {
        u16::from(self.0[0] - b'A') * 26 + u16::from(self.0[1] - b'A')
    }
}

impl fmt::Debug for Country {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Country({})", self.as_str())
    }
}

impl fmt::Display for Country {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[inline]
fn is_valid_pair([first, second]: [u8; 2]) -> bool {
    if !first.is_ascii_uppercase() || !second.is_ascii_uppercase() {
        return false;
    }
    if [first, second] == *b"ZZ" {
        return true;
    }
    // Both letters are uppercase, so the row and the shift are below 26.
    LISTED[usize::from(first - b'A')] & (1 << (second - b'A')) != 0
}

/// Returns true when `code` is a listed code or `ZZ`.
#[inline]
pub fn is_valid(code: &[u8]) -> bool {
    Country::parse(code).is_some()
}

/// Returns the dense position of any two uppercase letters in a table of [`INDEX_COUNT`]
/// entries, or `None` when either byte is not an uppercase letter.
pub fn index(code: [u8; 2]) -> Option<u16> {
    let [first, second] = code;
    if !first.is_ascii_uppercase() || !second.is_ascii_uppercase() {
        return None;
    }
    Some(u16::from(first - b'A') * 26 + u16::from(second - b'A'))
}

/// Returns the `n`th listed code in ascending order, or `None` when `n >= COUNT`.
pub fn nth(n: usize) -> Option<Country> {
    let start = n.checked_mul(3)?;
    let code = CODES.get(start..start.checked_add(2)?)?;
    Country::parse(code)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn assigned_and_transitionally_reserved_codes_validate_others_do_not() {
        for code in ["US", "DE", "ZZ", "AN", "FX", "XK", "ZW", "AD"] {
            assert!(is_valid(code.as_bytes()), "{code}");
        }
        for code in ["AA", "us", "", "USA", "Z", "QQ"] {
            assert!(!is_valid(code.as_bytes()), "{code}");
        }
        assert_eq!(index(*b"AA"), Some(0));
        assert_eq!(index(*b"ZZ"), Some(675));
        assert_eq!(index(*b"aA"), None);
        assert_eq!(nth(0).unwrap().as_str(), "AD");
        assert_eq!(nth(COUNT - 1).unwrap().as_str(), "ZW");
        assert_eq!(nth(COUNT), None);
        assert!(Country::UNKNOWN.is_unknown());
    }

    #[test]
    fn the_table_agrees_with_a_linear_scan_of_the_list() {
        assert_eq!(COUNT, 252);
        for first in 0u8..=255 {
            for second in 0u8..=255 {
                let code = [first, second];
                let listed = CODES.chunks(3).any(|chunk| chunk[..2] == code);
                assert_eq!(is_valid(&code), listed || code == *b"ZZ", "{code:?}");
            }
        }
        let codes: Vec<Country> = (0..COUNT).map(|n| nth(n).unwrap()).collect();
        assert!(codes.windows(2).all(|pair| pair[0] < pair[1]));
        assert_eq!(Country::parse(b"DE").unwrap().index(), index(*b"DE").unwrap());
        assert_eq!(Country::parse(b"FX").unwrap().to_string(), "FX");
    }
}
