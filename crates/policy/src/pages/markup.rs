//! A strict HTML subset for operator response pages.
//!
//! The validator parses tag names and quoted attributes instead of guessing where a browser
//! would put token boundaries. It accepts no recovery, no foreign content, no executable
//! attributes, no encoded URLs and no CSS escapes. It runs when a template is stored, never
//! on the request path. Every step advances through the source, so validation is linear.

use std::fmt;

/// Why markup was refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum MarkupError {
    /// A forbidden element, scheme, comment or malformed tag.
    ForbiddenContent,
    /// An attribute outside the allowed set, or a malformed attribute.
    ForbiddenAttribute,
    /// A URL that is not a literal local path or fragment.
    ExternalReference,
    /// A placeholder inside a tag or a raw-text element.
    PlaceholderInTag,
}

impl fmt::Display for MarkupError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            MarkupError::ForbiddenContent => "forbidden content",
            MarkupError::ForbiddenAttribute => "forbidden attribute",
            MarkupError::ExternalReference => "external reference",
            MarkupError::PlaceholderInTag => "placeholder inside a tag",
        })
    }
}

impl std::error::Error for MarkupError {}

const TAGS: &str = " html head body title meta style div span p a img br hr h1 h2 h3 h4 h5 h6 \
    main header footer section article aside nav strong em b i small code pre ul ol li \
    table thead tbody tfoot tr th td caption colgroup col blockquote details summary \
    button progress svg path ";
const ATTRIBUTES: &str = " id class title lang dir role tabindex hidden open disabled type \
    charset name content alt width height loading rel colspan rowspan headers scope \
    value max viewbox fill stroke stroke-width d ";
const BOOLEAN_ATTRIBUTES: &str = " hidden open disabled ";
const DOCTYPE: &[u8] = b"<!doctype html>";

/// Checks that `source` stays within the subset.
///
/// Fails with the first `MarkupError` found.
pub fn validate(source: &[u8]) -> Result<(), MarkupError> {
    // Keep clear diagnostics for schemes even when nested inside another attribute.
    for token in [&b"javascript:"[..], b"vbscript:", b"data:", b"<!--"] {
        if crate::rule::contains_ignore_case(source, token) {
            return Err(MarkupError::ForbiddenContent);
        }
    }
    let mut parser = Parser { source, at: 0 };
    while let Some(open) = crate::bytes::find_byte(source, parser.at, b'<') {
        parser.at = open;
        if crate::bytes::starts_with_ignore_case(&source[open..], DOCTYPE) {
            parser.at += DOCTYPE.len();
            continue;
        }
        parser.tag()?;
    }
    Ok(())
}

struct Parser<'a> {
    source: &'a [u8],
    at: usize,
}

impl<'a> Parser<'a> {
    fn tag(&mut self) -> Result<(), MarkupError> {
        self.at += 1;
        let closing = self.take(b'/');
        let name = self.read_name();
        if !listed(TAGS, name) {
            return Err(MarkupError::ForbiddenContent);
        }
        if closing {
            self.space();
            return if self.take(b'>') { Ok(()) } else { Err(MarkupError::ForbiddenContent) };
        }
        let raw_text = equal(name, b"style") || equal(name, b"title");
        while self.at < self.source.len() {
            let before = self.at;
            self.space();
            if self.take(b'>') {
                return if raw_text { self.raw(name) } else { Ok(()) };
            }
            if self.take(b'/') {
                return if !self.take(b'>') || raw_text {
                    Err(MarkupError::ForbiddenContent)
                } else {
                    Ok(())
                };
            }
            // Attributes must be separated by whitespace.
            if before == self.at {
                return Err(MarkupError::ForbiddenAttribute);
            }
            self.attribute()?;
        }
        Err(MarkupError::ForbiddenContent)
    }

    fn attribute(&mut self) -> Result<(), MarkupError> {
        let name = self.read_name();
        if name.is_empty() {
            return Err(MarkupError::ForbiddenAttribute);
        }
        let url = equal(name, b"href") || equal(name, b"src");
        let style = equal(name, b"style");
        let allowed = url
            || style
            || listed(ATTRIBUTES, name)
            || crate::bytes::starts_with_ignore_case(name, b"aria-")
            || crate::bytes::starts_with_ignore_case(name, b"data-");
        if !allowed {
            return Err(MarkupError::ForbiddenAttribute);
        }
        let after_name = self.at;
        self.space();
        if !self.take(b'=') {
            if !listed(BOOLEAN_ATTRIBUTES, name) {
                return Err(MarkupError::ForbiddenAttribute);
            }
            self.at = after_name;
            return Ok(());
        }
        self.space();
        let quote = match self.source.get(self.at) {
            Some(&quote @ (b'\'' | b'"')) => quote,
            _ => return Err(MarkupError::ForbiddenAttribute),
        };
        self.at += 1;
        let start = self.at;
        let end = crate::bytes::find_byte(self.source, start, quote)
            .ok_or(MarkupError::ForbiddenAttribute)?;
        let value = &self.source[start..end];
        self.at = end + 1;
        if crate::bytes::contains(value, b"{{") {
            return Err(MarkupError::PlaceholderInTag);
        }
        if value.contains(&b'<') {
            return Err(MarkupError::ForbiddenAttribute);
        }
        if url {
            validate_url(value)?;
        }
        if style {
            validate_css(value)?;
        }
        Ok(())
    }

    /// Raw-text elements (`style`, `title`) hold neither markup nor template slots; the
    /// fixed solver slot must never be swallowed by one in the browser's parser.
    fn raw(&mut self, name: &[u8]) -> Result<(), MarkupError> {
        let end = crate::bytes::find_byte(self.source, self.at, b'<')
            .ok_or(MarkupError::ForbiddenContent)?;
        let value = &self.source[self.at..end];
        if crate::bytes::contains(value, b"{{") {
            return Err(MarkupError::PlaceholderInTag);
        }
        if equal(name, b"style") {
            validate_css(value)?;
        }
        self.at = end + 1;
        if !self.take(b'/') || !equal(self.read_name(), name) {
            return Err(MarkupError::ForbiddenContent);
        }
        self.space();
        if self.take(b'>') { Ok(()) } else { Err(MarkupError::ForbiddenContent) }
    }

    fn read_name(&mut self) -> &'a [u8] {
        let start = self.at;
        let rest = &self.source[start..];
        self.at += rest.iter().take_while(|b| b.is_ascii_alphanumeric() || **b == b'-').count();
        &self.source[start..self.at]
    }

    fn space(&mut self) {
        let rest = &self.source[self.at..];
        self.at += rest.iter().take_while(|&&b| whitespace(b)).count();
    }

    fn take(&mut self, byte: u8) -> bool {
        if self.source.get(self.at) == Some(&byte) {
            self.at += 1;
            true
        } else {
            false
        }
    }
}

fn validate_url(value: &[u8]) -> Result<(), MarkupError> {
    let local = matches!(value.first(), Some(b'/' | b'#')) && !value.starts_with(b"//");
    // Entity decoding and backslash normalisation can turn an apparent path into //host.
    let clean = value.iter().all(|&b| b > 32 && b != 127 && b != b'&' && b != b'\\');
    if local && clean { Ok(()) } else { Err(MarkupError::ExternalReference) }
}

fn validate_css(value: &[u8]) -> Result<(), MarkupError> {
    for token in [&b"\\"[..], b"&", b"/*", b"url", b"@import", b"expression", b"{{"] {
        if crate::rule::contains_ignore_case(value, token) {
            return Err(MarkupError::ForbiddenContent);
        }
    }
    Ok(())
}

fn whitespace(byte: u8) -> bool {
    matches!(byte, b' ' | b'\t' | b'\r' | b'\n' | 12)
}

fn equal(a: &[u8], b: &[u8]) -> bool {
    a.eq_ignore_ascii_case(b)
}

fn listed(list: &str, name: &[u8]) -> bool {
    !name.is_empty()
        && list.split(' ').any(|word| !word.is_empty() && equal(word.as_bytes(), name))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strict_markup_rejects_browser_recovery_encoded_urls_and_foreign_content() {
        let bad: [&[u8]; 13] = [
            b"<img/src=\"/missing\"onerror=\"alert(1)\">",
            b"<img src=\"/missing\"onerror=\"alert(1)\">",
            b"<img\x0conerror=\"alert(1)\">",
            b"<a href=\"/&#47;example.com\">x</a>",
            b"<img src=\"/\\example.com/x\">",
            b"<svg><foreignObject><p>foreign</p></foreignObject></svg>",
            b"<style>{{ challenge }}</style>",
            b"<p style=\"background:u\\72l(x)\">x</p>",
            b"<p style=\"background:u&#114;l(x)\">x</p>",
            b"<style>@im/**/port 'x';</style>",
            b"<img srcset=\"/ok,https://example.com/x 2x\">",
            b"<a href=\"/ok\" ping=\"/tracking\">x</a>",
            b"<img src=\"/ok\"/onerror=\"alert(1)\">",
        ];
        for source in bad {
            assert!(validate(source).is_err(), "{:?}", String::from_utf8_lossy(source));
        }
        assert_eq!(
            validate(b"<!doctype html><p title=\"a > b\" aria-label=\"Message\">Hello</p>"),
            Ok(())
        );
        assert_eq!(validate(b"<button disabled class=\"btn\">Wait</button>"), Ok(()));
        assert_eq!(
            validate(b"<style>@keyframes fade {from {opacity:0} to {opacity:1}}</style>"),
            Ok(())
        );
    }

    #[test]
    fn markup_edge_cases_fail_closed() {
        assert_eq!(validate(b"<p"), Err(MarkupError::ForbiddenContent));
        assert_eq!(validate(b"<p class="), Err(MarkupError::ForbiddenAttribute));
        assert_eq!(validate(b"<p class=\"x"), Err(MarkupError::ForbiddenAttribute));
        assert_eq!(validate(b"<title>x"), Err(MarkupError::ForbiddenContent));
        assert_eq!(validate(b"<title>x</p>"), Err(MarkupError::ForbiddenContent));
        assert_eq!(validate(b"<br/>"), Ok(()));
        assert_eq!(validate(b"<style/>"), Err(MarkupError::ForbiddenContent));
        assert_eq!(validate(b"<p hidden>x</p>"), Ok(()));
        assert_eq!(validate(b"<p class>x</p>"), Err(MarkupError::ForbiddenAttribute));
        assert_eq!(validate(b"text only"), Ok(()));
    }
}
