//! The file where a node keeps the last revision that it served, so that it can start
//! while the database does not answer (SID 0028).
//!
//! ```text
//!   sibuna-authority-cache 1 REVISION DIGEST\n
//!   DOCUMENT
//! ```
//!
//! The file is written beside its final name and renamed, with mode 0600. A reader
//! trusts it only when the document has the digest of the first line.

use std::fs;
use std::io::{self, Read, Write};
use std::path::Path;

use crate::document::{self, LIMITS};
use crate::error::Error;
use crate::follow::Published;

const MAGIC: &str = "sibuna-authority-cache 1";
/// The longest first line: the magic, a number of 20 digits and a digest.
const MAX_HEADER: usize = 128;

/// Writes `published` to the cache file at `path`, in the place of its content. Fails
/// with the error of the file system. The old file stays when the write fails.
pub fn write_cache(path: &Path, published: &Published) -> io::Result<()> {
    let mut waiting = path.as_os_str().to_owned();
    waiting.push(format!(".{}.tmp", std::process::id()));
    let waiting = Path::new(&waiting);
    let mut options = fs::OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
    let written = options.open(waiting).and_then(|mut file| {
        writeln!(file, "{MAGIC} {} {}", published.revision, published.digest)?;
        file.write_all(published.document.as_bytes())?;
        file.sync_all()
    });
    let renamed = written.and_then(|()| fs::rename(waiting, path));
    if renamed.is_err() {
        let _ = fs::remove_file(waiting);
    }
    renamed
}

/// Reads the revision in the cache file at `path`. Fails with [`Error::Unavailable`]
/// when the file cannot be read and with [`Error::Damaged`] when it is not a cache
/// file, is too long, or its document does not have the digest of its first line.
pub fn read_cache(path: &Path) -> Result<Published, Error> {
    let name = path.display();
    let limit = (LIMITS.max_input_bytes + MAX_HEADER + 1) as u64;
    let mut bytes = Vec::new();
    fs::File::open(path)
        .and_then(|file| file.take(limit).read_to_end(&mut bytes))
        .map_err(|error| Error::Unavailable(format!("the cache {name}: {error}")))?;
    let damaged = || Error::Damaged(format!("{name} is not a cache of a revision"));
    let text = String::from_utf8(bytes).map_err(|_| damaged())?;
    let (header, document) = text.split_once('\n').ok_or_else(damaged)?;
    let fields = header.strip_prefix(MAGIC).ok_or_else(damaged)?;
    let mut fields = fields.split_ascii_whitespace();
    let (Some(revision), Some(digest), None) = (fields.next(), fields.next(), fields.next())
    else {
        return Err(damaged());
    };
    let revision: u64 = revision.parse().map_err(|_| damaged())?;
    let fits = document.len() <= LIMITS.max_input_bytes;
    if revision == 0 || !fits || document::digest(document.as_bytes()) != digest {
        return Err(damaged());
    }
    Ok(Published { revision, digest: digest.to_owned(), document: document.to_owned() })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scratch(name: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("sibuna-cache-{}-{name}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn published(document: &str) -> Published {
        let digest = document::digest(document.as_bytes());
        Published { revision: 7, digest, document: document.to_owned() }
    }

    #[test]
    fn a_cache_reads_back_what_was_written_and_is_private() {
        let dir = scratch("round");
        let path = dir.join("cache");
        let first = published(r#"{"backends":{}}"#);
        write_cache(&path, &first).unwrap();
        assert_eq!(read_cache(&path).unwrap(), first);
        let second = published("{\"a\":\"line\\nfeed\"}");
        write_cache(&path, &second).unwrap();
        assert_eq!(read_cache(&path).unwrap(), second);
        assert_eq!(fs::read_dir(&dir).unwrap().count(), 1, "no temporary file stays");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(fs::metadata(&path).unwrap().permissions().mode() & 0o777, 0o600);
        }
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn a_changed_cut_or_foreign_cache_is_refused() {
        let dir = scratch("bad");
        let path = dir.join("cache");
        assert!(read_cache(&path).unwrap_err().is_unavailable());
        let good = published(r#"{"backends":{}}"#);
        write_cache(&path, &good).unwrap();
        let text = fs::read_to_string(&path).unwrap();
        let cases = [
            text.replace("backends", "backendz"),
            text[..text.len() - 1].to_owned(),
            text.replace("cache 1 7", "cache 1 0"),
            text.replace("cache 1", "cache 2"),
            "hello".to_owned(),
            String::new(),
            format!("{MAGIC} 7 {} extra\n{}", good.digest, good.document),
        ];
        for case in cases {
            fs::write(&path, &case).unwrap();
            assert_eq!(read_cache(&path).unwrap_err().code(), "DBA008", "{case}");
        }
        fs::write(&path, [0xff, 0xfe]).unwrap();
        assert_eq!(read_cache(&path).unwrap_err().code(), "DBA008");
        fs::remove_dir_all(dir).unwrap();
    }
}
