//! Rule patterns compiled once, when a rule enters an engine.
//!
//! `rule::pattern_matches` interprets the grammar on every call. The engine instead decides
//! the form of each pattern once and keeps what the form needs: the exact text, the prefix,
//! or a case-folded needle with a Horspool shift table for the substring search, so the hot
//! path does no parsing and builds no table.

/// A pattern in the grammar of `rule::pattern_matches`, compiled.
#[derive(Clone, Debug)]
pub(crate) enum TextMatcher {
    /// Matches every text.
    Any,
    /// Matches exactly this text (case-sensitive).
    Exact(Box<[u8]>),
    /// Matches texts that start with this prefix (case-sensitive).
    Prefix(Box<[u8]>),
    /// Matches texts that contain the needle without regard to ASCII case.
    Substring(Substring),
}

impl TextMatcher {
    /// Compiles `pattern`; the result matches exactly the texts `pattern_matches` accepts.
    pub(crate) fn new(pattern: &[u8]) -> TextMatcher {
        if pattern.is_empty() || pattern == b".*" || pattern == b"*" {
            return TextMatcher::Any;
        }
        if let [b'^', inner @ .., b'$'] = pattern {
            if inner.ends_with(b"*") {
                return TextMatcher::prefix_wildcard(inner);
            }
            return TextMatcher::Exact(inner.into());
        }
        TextMatcher::prefix_wildcard(pattern)
    }

    fn prefix_wildcard(pattern: &[u8]) -> TextMatcher {
        let prefix = pattern.strip_suffix(b".*").or_else(|| pattern.strip_suffix(b"*"));
        match prefix {
            Some([]) => TextMatcher::Any,
            Some(prefix) => TextMatcher::Prefix(prefix.into()),
            None if pattern.starts_with(b"/") => TextMatcher::Exact(pattern.into()),
            None => TextMatcher::Substring(Substring::new(pattern)),
        }
    }

    /// Returns true when `text` matches.
    #[inline]
    pub(crate) fn matches(&self, text: &[u8]) -> bool {
        match self {
            TextMatcher::Any => true,
            TextMatcher::Exact(exact) => **exact == *text,
            TextMatcher::Prefix(prefix) => text.starts_with(prefix),
            TextMatcher::Substring(substring) => substring.is_in(text),
        }
    }

    /// Returns the heap bytes the matcher holds.
    pub(crate) fn heap_bytes(&self) -> usize {
        match self {
            TextMatcher::Any => 0,
            TextMatcher::Exact(bytes) | TextMatcher::Prefix(bytes) => bytes.len(),
            TextMatcher::Substring(substring) => substring.heap_bytes(),
        }
    }
}

/// A non-empty needle searched without regard to ASCII case by Horspool's algorithm
/// (Horspool, Software: Practice and Experience, 1980) over case-folded bytes.
#[derive(Clone, Debug)]
pub(crate) struct Substring {
    /// The needle in ASCII lower case.
    needle: Box<[u8]>,
    /// Shift for the folded byte under the window's last position.
    shift: Box<[u8; 256]>,
}

impl Substring {
    /// Compiles `needle`, which must not be empty (the grammar never yields an empty one).
    fn new(needle: &[u8]) -> Substring {
        let needle: Box<[u8]> = needle.to_ascii_lowercase().into();
        // Shifts are capped at 255; a capped shift is still safe (it only moves less).
        let length = needle.len().min(255) as u8;
        let mut shift = Box::new([length; 256]);
        let last = needle.len().saturating_sub(1);
        for (index, &byte) in needle.iter().enumerate().take(last) {
            let distance = (last - index).min(255) as u8;
            shift[usize::from(byte)] = distance;
            shift[usize::from(byte.to_ascii_uppercase())] = distance;
        }
        Substring { needle, shift }
    }

    /// Returns true when the needle occurs in `text`.
    #[inline]
    fn is_in(&self, text: &[u8]) -> bool {
        let length = self.needle.len();
        let Some(last) = length.checked_sub(1) else { return true };
        let mut start = 0;
        while let Some(window) = text.get(start..start + length) {
            // `window` has `length` bytes, so `last` indexes into it.
            let tail = window[last];
            if window.eq_ignore_ascii_case(&self.needle) {
                return true;
            }
            start += usize::from(self.shift[usize::from(tail)]).max(1);
        }
        false
    }

    fn heap_bytes(&self) -> usize {
        self.needle.len() + 256
    }
}

/// Returns true when the compiled form of `pattern` agrees with `pattern_matches` on `text`;
/// used by tests to check the compiler against the interpreter.
#[cfg(test)]
pub(crate) fn agrees(pattern: &[u8], text: &[u8]) -> bool {
    TextMatcher::new(pattern).matches(text) == crate::rule::pattern_matches(pattern, text)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compiled_patterns_agree_with_the_grammar() {
        let patterns: [&[u8]; 16] = [
            b"", b".*", b"*", b"^$", b"^*$", b"^/a.*$", b"^/a$", b"/api/*", b"/api/.*", b"/x",
            b"Mozilla", b"bot", b"^", b"$", b"a*", b"\xffZz",
        ];
        let texts: [&[u8]; 12] = [
            b"",
            b"/a",
            b"/a/b",
            b"/api/v1",
            b"/x",
            b"/X",
            b"mozilla/5",
            b"robot",
            b"x^y",
            b"a",
            b"\xffzZ",
            b"Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
        ];
        for pattern in patterns {
            for text in texts {
                assert!(agrees(pattern, text), "{pattern:?} {text:?}");
            }
        }
    }

    #[test]
    fn substring_search_agrees_with_a_naive_search() {
        let mut state = 0x9e37_79b9_7f4a_7c15u64;
        let alphabet = b"abAB/ -";
        for _ in 0..20_000 {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            let needle_len = 1 + (state % 4) as usize;
            let text_len = ((state >> 8) % 12) as usize;
            let byte = |i: usize| alphabet[((state >> (16 + i * 3)) % 7) as usize];
            let needle: Vec<u8> = (0..needle_len).map(byte).collect();
            let text: Vec<u8> = (0..text_len).map(|i| byte(i + 4)).collect();
            let expected = crate::rule::contains_ignore_case(&text, &needle);
            assert_eq!(Substring::new(&needle).is_in(&text), expected, "{needle:?} {text:?}");
        }
    }
}
