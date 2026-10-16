//! `--database-url-file`: a PostgreSQL URL kept out of the command line and the process
//! list, in a file only its owner may read.

use std::io::Read;
use std::path::Path;

use crate::error::{StorageError, UrlFileProblem};

/// The largest database URL file accepted, in bytes.
pub const MAX_URL_FILE: u64 = 4096;

/// Reads the PostgreSQL URL stored in the file at `path` and returns it without surrounding
/// white space.
///
/// Fails with [`StorageError::UrlFile`] when the file cannot be read, when group or others
/// have any permission on it (Unix), when it exceeds [`MAX_URL_FILE`] bytes, is not UTF-8, is
/// empty, or does not start with `postgres://` or `postgresql://`. The error never contains
/// the file's content.
///
/// Windows has no mode bits and this function does not inspect ACLs there: restricting the
/// file to the account that runs Sibuna is the operator's job.
pub fn read_database_url_file(path: impl AsRef<Path>) -> Result<String, StorageError> {
    let path = path.as_ref();
    let fail = |problem| StorageError::UrlFile { path: path.to_path_buf(), problem };
    let file = std::fs::File::open(path).map_err(|error| fail(UrlFileProblem::Read(error)))?;
    let metadata = file.metadata().map_err(|error| fail(UrlFileProblem::Read(error)))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = metadata.permissions().mode() & 0o7777;
        if mode & 0o077 != 0 {
            return Err(fail(UrlFileProblem::NotPrivate(mode)));
        }
    }
    if metadata.len() > MAX_URL_FILE {
        return Err(fail(UrlFileProblem::TooLarge));
    }
    let mut bytes = Vec::new();
    // Read one byte past the bound in case the file grew after the size check.
    file.take(MAX_URL_FILE + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| fail(UrlFileProblem::Read(error)))?;
    if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > MAX_URL_FILE {
        return Err(fail(UrlFileProblem::TooLarge));
    }
    let text = String::from_utf8(bytes).map_err(|_| fail(UrlFileProblem::NotUtf8))?;
    let url = text.trim();
    if url.is_empty() {
        return Err(fail(UrlFileProblem::Empty));
    }
    if !(url.starts_with("postgres://") || url.starts_with("postgresql://")) {
        return Err(fail(UrlFileProblem::NotPostgres));
    }
    Ok(url.to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scratch(name: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("sibuna-url-{}-{name}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        dir.join("url")
    }

    /// Writes `content` to `path` with `mode` on Unix; elsewhere the mode is not applied.
    fn write(path: &Path, content: &[u8], mode: u32) {
        std::fs::write(path, content).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).unwrap();
        }
        #[cfg(not(unix))]
        let _ = mode;
    }

    #[test]
    fn an_owner_only_file_yields_the_trimmed_url() {
        let path = scratch("ok");
        write(&path, b"  postgres://u:p@db/sibuna\r\n", 0o600);
        assert_eq!(read_database_url_file(&path).unwrap(), "postgres://u:p@db/sibuna");
        std::fs::remove_dir_all(path.parent().unwrap()).unwrap();
    }

    #[test]
    fn unsafe_or_malformed_files_are_rejected_without_echoing_the_secret() {
        let path = scratch("bad");
        type Case<'a> = (&'a [u8], u32, fn(&UrlFileProblem) -> bool);
        let mut cases: Vec<Case<'_>> = vec![
            (b" \n", 0o600, |p| matches!(p, UrlFileProblem::Empty)),
            (b"mysql://u:secret@db/x", 0o600, |p| matches!(p, UrlFileProblem::NotPostgres)),
            (b"postgres://\xff", 0o600, |p| matches!(p, UrlFileProblem::NotUtf8)),
            (&[b'a'; 5000], 0o600, |p| matches!(p, UrlFileProblem::TooLarge)),
        ];
        // Only Unix has mode bits to check; Windows leaves the ACL to the operator.
        if cfg!(unix) {
            let exposed: Case<'_> = (b"postgres://u:secret@db/x", 0o640, |p| {
                matches!(p, UrlFileProblem::NotPrivate(_))
            });
            cases.push(exposed);
        }
        for (content, mode, expected) in cases {
            write(&path, content, mode);
            let error = read_database_url_file(&path).unwrap_err();
            let StorageError::UrlFile { problem, .. } = &error else { panic!("{error}") };
            assert!(expected(problem), "{error}");
            assert!(!error.to_string().contains("secret"));
        }
        let missing = read_database_url_file(path.with_file_name("missing")).unwrap_err();
        assert!(matches!(missing, StorageError::UrlFile { problem: UrlFileProblem::Read(_), .. }));
        std::fs::remove_dir_all(path.parent().unwrap()).unwrap();
    }
}
