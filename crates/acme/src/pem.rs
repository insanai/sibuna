//! PEM: base64 between `-----BEGIN LABEL-----` and `-----END LABEL-----`.

use sibuna_encoding::base64::{self, STANDARD};

/// The largest PEM text we decode: the bound of a certificate chain.
pub const MAX_PEM: usize = 256 * 1024;

/// Writes one PEM block with lines of 64 characters.
pub fn encode(label: &str, der: &[u8]) -> String {
    let body = base64::encode(STANDARD, der);
    let mut out = String::with_capacity(body.len() + body.len() / 64 + 2 * label.len() + 40);
    out.push_str("-----BEGIN ");
    out.push_str(label);
    out.push_str("-----\n");
    let mut rest = body.as_str();
    while !rest.is_empty() {
        let (line, tail) = rest.split_at(rest.len().min(64));
        out.push_str(line);
        out.push('\n');
        rest = tail;
    }
    out.push_str("-----END ");
    out.push_str(label);
    out.push_str("-----\n");
    out
}

/// Reads every block with the given label, in order. Text outside the blocks and blocks
/// with other labels are skipped. Returns `None` for text over [`MAX_PEM`], a block
/// without its end line, or a body that is not base64.
pub fn decode(label: &str, text: &str) -> Option<Vec<Vec<u8>>> {
    if text.len() > MAX_PEM {
        return None;
    }
    let begin = format!("-----BEGIN {label}-----");
    let end = format!("-----END {label}-----");
    let mut blocks = Vec::new();
    let mut body: Option<String> = None;
    for line in text.lines().map(str::trim) {
        match &mut body {
            None if line == begin => body = Some(String::new()),
            None => {}
            Some(collected) if line == end => {
                blocks.push(base64::decode(STANDARD, collected.as_bytes()).ok()?);
                body = None;
            }
            Some(collected) => collected.push_str(line),
        }
    }
    body.is_none().then_some(blocks)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    #[test]
    fn blocks_round_trip() {
        let first: Vec<u8> = (0..200).map(|n| n as u8).collect();
        let text = format!(
            "{}junk\n{}{}",
            encode("CERTIFICATE", &first),
            encode("PRIVATE KEY", &[9]),
            encode("CERTIFICATE", &[1, 2, 3])
        );
        assert!(text.lines().all(|line| line.len() <= 64));
        assert_eq!(decode("CERTIFICATE", &text).unwrap(), [first, vec![1, 2, 3]]);
        assert_eq!(decode("PRIVATE KEY", &text).unwrap(), [vec![9]]);
        assert_eq!(decode("CERTIFICATE", "nothing").unwrap().len(), 0);
    }

    #[test]
    fn broken_blocks_are_refused() {
        assert!(decode("CERTIFICATE", "-----BEGIN CERTIFICATE-----\nAAAA\n").is_none());
        let bad = "-----BEGIN CERTIFICATE-----\n!!!!\n-----END CERTIFICATE-----\n";
        assert!(decode("CERTIFICATE", bad).is_none());
    }
}
