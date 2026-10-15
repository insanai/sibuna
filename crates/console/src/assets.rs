//! The interface's files, served under content digests (Zig's `assets.zig`).
//!
//! The daemon embeds the files at build time and hands their bytes to the console
//! ([`AssetBytes`]); this crate does not embed them, so it builds without the WebAssembly
//! module. Each of `console.wasm`, `glue.js` and `console.css` is served at
//! `/console/assets/<16 hex digits of its SHA-256>/<name>` with an immutable cache policy,
//! so a new build names its files anew. The shell's placeholders `{{ wasm }}`, `{{ glue }}`
//! and `{{ css }}` are replaced by those digit prefixes once, at start; the shell is the
//! only revalidated document. The world geometry is served by the dispatcher at a fixed
//! path, and only to signed-in accounts.

use std::fmt;

use sibuna_crypto::sha256::Sha256;
use sibuna_http::Method;
use sibuna_serve::{Context, ServeError};

/// The cache policy of digest-named files.
pub const IMMUTABLE: &[u8] = b"public, max-age=31536000, immutable";
/// The length of a digest prefix in hex digits.
pub const PREFIX_LEN: usize = 16;
/// The directory every asset path begins with.
pub const ROOT: &str = "/console/assets/";
/// The fixed path of the world geometry.
pub const WORLD_PATH: &str = "/console/assets/world-110m.bin";

const NAMES: [&str; 3] = ["console.wasm", "glue.js", "console.css"];
const TYPES: [&[u8]; 3] = [b"application/wasm", b"text/javascript", b"text/css"];
const PLACEHOLDERS: [&str; 3] = ["{{ wasm }}", "{{ glue }}", "{{ css }}"];

/// The interface's files as the daemon embedded them.
#[derive(Clone, Copy, Default, PartialEq, Eq)]
pub struct AssetBytes {
    /// The interface module (`console.wasm`).
    pub wasm: &'static [u8],
    /// The browser bridge (`glue.js`).
    pub glue: &'static [u8],
    /// The stylesheet (`console.css`).
    pub css: &'static [u8],
    /// The shell template (`shell.html`) with its placeholders.
    pub shell: &'static [u8],
    /// The world geometry (`world-110m.bin`).
    pub world: &'static [u8],
}

impl fmt::Debug for AssetBytes {
    /// Shows the sizes, not the bytes.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AssetBytes")
            .field("wasm", &self.wasm.len())
            .field("glue", &self.glue.len())
            .field("css", &self.css.len())
            .field("shell", &self.shell.len())
            .field("world", &self.world.len())
            .finish()
    }
}

/// The served files: digest prefixes and the resolved shell.
#[derive(Clone)]
pub struct Assets {
    bytes: AssetBytes,
    prefixes: [String; 3],
    shell: Vec<u8>,
}

impl fmt::Debug for Assets {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Assets")
            .field("bytes", &self.bytes)
            .field("prefixes", &self.prefixes)
            .finish_non_exhaustive()
    }
}

impl Assets {
    /// Hashes the files and resolves the shell's placeholders.
    pub fn new(bytes: AssetBytes) -> Assets {
        let files = [bytes.wasm, bytes.glue, bytes.css];
        let prefixes = files.map(|content| {
            let digest = Sha256::digest(content);
            sibuna_encoding::hex::encode(digest.get(..PREFIX_LEN / 2).unwrap_or_default())
        });
        let shell = resolve(bytes.shell, &prefixes);
        Assets { bytes, prefixes, shell }
    }

    /// Returns the shell with every placeholder resolved.
    pub fn shell(&self) -> &[u8] {
        &self.shell
    }

    /// Returns the world geometry.
    pub fn world(&self) -> &'static [u8] {
        self.bytes.world
    }

    /// Returns the served path of asset `index` (0 wasm, 1 glue, 2 css), or `None`.
    pub fn path(&self, index: usize) -> Option<String> {
        Some(format!("{ROOT}{}/{}", self.prefixes.get(index)?, NAMES.get(index)?))
    }

    /// Returns the index of the asset served at `target`, or `None` for any other path,
    /// including an asset name under another digest.
    pub fn lookup(&self, target: &[u8]) -> Option<usize> {
        let rest = target.strip_prefix(ROOT.as_bytes())?;
        let (prefix, name) = rest.split_at_checked(PREFIX_LEN)?;
        let name = name.strip_prefix(b"/")?;
        (0..NAMES.len()).find(|&index| {
            self.prefixes.get(index).is_some_and(|known| known.as_bytes() == prefix)
                && NAMES.get(index).is_some_and(|known| known.as_bytes() == name)
        })
    }

    /// Answers a `GET` or `HEAD` of a digest-named asset and returns true, or returns false
    /// without answering for any other request.
    ///
    /// Fails with the listener's error when writing fails.
    pub fn serve(&self, context: &mut Context<'_>) -> Result<bool, ServeError> {
        if !matches!(context.method(), Method::Get | Method::Head) {
            return Ok(false);
        }
        let Some(index) = self.lookup(context.target()) else { return Ok(false) };
        let files = [self.bytes.wasm, self.bytes.glue, self.bytes.css];
        let (Some(content), Some(kind)) = (files.get(index), TYPES.get(index)) else {
            return Ok(false);
        };
        context.respond_cached(200, kind, content, IMMUTABLE, &[])?;
        Ok(true)
    }
}

/// Returns `template` with each placeholder replaced by its digest prefix.
fn resolve(template: &[u8], prefixes: &[String; 3]) -> Vec<u8> {
    let mut shell = Vec::with_capacity(template.len());
    let mut rest = template;
    while !rest.is_empty() {
        let next = PLACEHOLDERS
            .iter()
            .zip(prefixes)
            .filter_map(|(placeholder, prefix)| {
                let at = find(rest, placeholder.as_bytes())?;
                Some((at, placeholder.len(), prefix))
            })
            .min_by_key(|(at, _, _)| *at);
        let Some((at, length, prefix)) = next else {
            shell.extend_from_slice(rest);
            break;
        };
        let (before, after) = rest.split_at(at);
        shell.extend_from_slice(before);
        shell.extend_from_slice(prefix.as_bytes());
        rest = after.get(length..).unwrap_or_default();
    }
    shell
}

fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|window| window == needle)
}

#[cfg(test)]
mod tests {
    use super::*;

    const SHELL: &[u8] = b"<link href=\"/console/assets/{{ css }}/console.css\">\
        <script src=\"/console/assets/{{ glue }}/glue.js\" \
        data-wasm=\"/console/assets/{{ wasm }}/console.wasm\"></script>";

    fn assets() -> Assets {
        Assets::new(AssetBytes {
            wasm: b"\0asm",
            glue: b"console.log(1)",
            css: b"body{}",
            shell: SHELL,
            world: b"world",
        })
    }

    // assets.zig: "assets resolve only under their own digest and the shell names every one".
    #[test]
    fn assets_resolve_only_under_their_own_digest() {
        let assets = assets();
        for (index, name) in NAMES.iter().enumerate() {
            let path = assets.path(index).unwrap();
            assert_eq!(assets.lookup(path.as_bytes()), Some(index));
            let shell = String::from_utf8(assets.shell().to_vec()).unwrap();
            assert!(shell.contains(&path), "{shell}");
            let wrong = format!("{ROOT}0000000000000000/{name}");
            assert_eq!(assets.lookup(wrong.as_bytes()), None);
        }
        assert_eq!(assets.lookup(b"/console/assets/console.wasm"), None);
        assert_eq!(assets.lookup(b"/console/assets/"), None);
        assert!(find(assets.shell(), b"{{").is_none());
        assert!(find(assets.shell(), b"world-110m").is_none());
        let expected = sibuna_encoding::hex::encode(&Sha256::digest(b"\0asm")[..8]);
        assert_eq!(assets.path(0).unwrap(), format!("/console/assets/{expected}/console.wasm"));
    }

    #[test]
    fn unknown_placeholders_and_text_pass_through() {
        let prefixes = [String::from("a"), String::from("b"), String::from("c")];
        assert_eq!(resolve(b"{{ x }}{{ css }}{{ wasm }}", &prefixes), b"{{ x }}ca");
        assert_eq!(resolve(b"", &prefixes), b"");
        assert_eq!(resolve(b"{{ glue }", &prefixes), b"{{ glue }");
    }
}
