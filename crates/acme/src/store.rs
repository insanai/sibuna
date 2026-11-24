//! The files of automatic HTTPS (SID 0021): the account key, the certificates with their
//! keys, the retry state and the locks.
//!
//! ```text
//! STORAGE/                                   mode 0700
//!   acme-v02.api.letsencrypt.org-directory/  one directory per authority
//!     account.key                            mode 0600, PKCS#8 PEM
//!     certs/example.org/cert.pem             the chain, leaf first
//!     certs/example.org/key.pem              mode 0600
//!     certs/example.org/retry                the failure count and the next attempt
//!     locks/example.org.lock
//! ```
//!
//! A file is written under a temporary name and renamed, so a reader never sees half a
//! file. Several nodes may share the directory.

use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

use crate::{Error, KeyPair, pem};

/// A lock older than this is left over from a node that died: an order ends in five
/// minutes.
pub const STALE_LOCK: Duration = Duration::from_secs(15 * 60);
/// The largest file the store reads.
const MAX_FILE: u64 = pem::MAX_PEM as u64;

/// The directory of one authority inside the storage directory.
#[derive(Clone, Debug)]
pub struct Store {
    root: PathBuf,
}

/// A certificate chain and its key, as stored.
#[derive(Debug)]
pub struct Stored {
    /// The chain as PEM, leaf first.
    pub chain_pem: String,
    /// The private key of the leaf.
    pub key: KeyPair,
}

/// The retry state of a name that failed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Retry {
    /// Consecutive failures.
    pub failures: u32,
    /// The time of the next attempt, in seconds since 1970.
    pub next_attempt: u64,
}

/// A held lock. Dropping it removes the lock file.
#[derive(Debug)]
pub struct Lock {
    path: PathBuf,
}

impl Drop for Lock {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.path);
    }
}

/// The directory name of an authority: its URL without the scheme, with every other
/// character than a letter, a digit, a dot or a hyphen turned into a hyphen.
pub fn authority_id(directory: &str) -> String {
    let rest = directory.split_once("://").map_or(directory, |(_, rest)| rest);
    let id: String = rest
        .chars()
        .take(100)
        .map(|c| match c.to_ascii_lowercase() {
            c if c.is_ascii_alphanumeric() || c == '.' || c == '-' => c,
            _ => '-',
        })
        .collect();
    let id = id.trim_matches(['-', '.']);
    if id.is_empty() { "authority".to_owned() } else { id.to_owned() }
}

fn failure(path: &Path, error: impl std::fmt::Display) -> Error {
    Error::storage(format!("{}: {error}.", path.display()))
}

/// Creates a directory and its parents, readable by the owner only.
pub(crate) fn create_private_dir(path: &Path) -> io::Result<()> {
    let mut builder = fs::DirBuilder::new();
    builder.recursive(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt as _;
        builder.mode(0o700);
    }
    builder.create(path)
}

/// Opens a new file that only the owner may read. Fails when the file exists.
pub(crate) fn create_private_file(path: &Path) -> io::Result<File> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }
    options.open(path)
}

/// Reads a file of at most [`MAX_FILE`] bytes. A missing file is `None`.
pub(crate) fn read_bounded(path: &Path) -> Result<Option<String>, Error> {
    let file = match File::open(path) {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(failure(path, error)),
    };
    let mut text = String::new();
    file.take(MAX_FILE + 1).read_to_string(&mut text).map_err(|e| failure(path, e))?;
    if text.len() as u64 > MAX_FILE {
        return Err(failure(path, "the file exceeds 256 KiB"));
    }
    Ok(Some(text))
}

/// The temporary name beside `path`, unique to this process.
pub(crate) fn temporary(path: &Path) -> PathBuf {
    let mut name = path.as_os_str().to_owned();
    name.push(format!(".tmp-{}", std::process::id()));
    PathBuf::from(name)
}

/// Writes a private file under a temporary name and gives it its final name.
pub(crate) fn write_private(path: &Path, text: &str) -> Result<(), Error> {
    let temporary = temporary(path);
    let _ = fs::remove_file(&temporary);
    let written = create_private_file(&temporary).and_then(|mut file| {
        file.write_all(text.as_bytes())?;
        file.sync_all()
    });
    let renamed = written.and_then(|()| fs::rename(&temporary, path));
    renamed.map_err(|error| {
        let _ = fs::remove_file(&temporary);
        failure(path, error)
    })
}

/// Checks that a name is safe as a path component: a lower-case DNS name.
///
/// A wildcard `*.example.org` is stored as `_.example.org`, and the colons of an IPv6
/// address as underscores. No host name has an underscore, so the names stay apart.
fn component(name: &str) -> Result<String, Error> {
    let stored = match name.strip_prefix("*.") {
        Some(parent) => format!("_.{parent}"),
        None => name.replace(':', "_"),
    };
    let safe = !name.is_empty()
        && name.len() <= 253
        && !name.starts_with('.')
        && !name.contains("..")
        && !name.contains('_')
        && stored
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b"-._".contains(&b));
    if safe { Ok(stored) } else { Err(Error::storage(format!("`{name}` is no stored name."))) }
}

impl Store {
    /// Opens the store of the authority at `directory` under `storage`, and creates its
    /// directories with mode 0700. Fails with `ACME001` when they cannot be created.
    pub fn open(storage: &Path, directory: &str) -> Result<Self, Error> {
        Self::open_at(storage.join(authority_id(directory)))
    }

    /// Opens the store of the local authority under `storage`: the directory `local`.
    pub fn open_local(storage: &Path) -> Result<Self, Error> {
        Self::open_at(storage.join(crate::local::DIRECTORY))
    }

    fn open_at(root: PathBuf) -> Result<Self, Error> {
        for path in [root.join("certs"), root.join("locks")] {
            create_private_dir(&path).map_err(|error| failure(&path, error))?;
        }
        Ok(Self { root })
    }

    fn name_dir(&self, name: &str) -> Result<PathBuf, Error> {
        Ok(self.root.join("certs").join(component(name)?))
    }

    /// Loads the account key, or creates it. Two nodes that start together end with the
    /// same key: the file is linked into place only when no file is there.
    pub fn load_account(&self) -> Result<KeyPair, Error> {
        let path = self.root.join("account.key");
        if read_bounded(&path)?.is_none() {
            let temporary = temporary(&path);
            let _ = fs::remove_file(&temporary);
            let text = KeyPair::generate()?.to_pem();
            create_private_file(&temporary)
                .and_then(|mut file| {
                    file.write_all(text.as_bytes()).and_then(|()| file.sync_all())
                })
                .map_err(|error| failure(&temporary, error))?;
            let linked = fs::hard_link(&temporary, &path);
            let _ = fs::remove_file(&temporary);
            match linked {
                Ok(()) => {}
                // Another node created the key first. We use that one.
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
                Err(error) => return Err(failure(&path, error)),
            }
        }
        let text = read_bounded(&path)?.ok_or_else(|| failure(&path, "the file vanished"))?;
        KeyPair::from_pem(&text).map_err(|_| failure(&path, "the file holds no P-256 key"))
    }

    /// Loads the certificate of `name`. Returns `None` when there is none, and when the
    /// key on disk does not belong to the leaf, as it may during a write by another node.
    pub fn load_certificate(&self, name: &str) -> Result<Option<Stored>, Error> {
        let dir = self.name_dir(name)?;
        let (Some(chain_pem), Some(key_pem)) =
            (read_bounded(&dir.join("cert.pem"))?, read_bounded(&dir.join("key.pem"))?)
        else {
            return Ok(None);
        };
        let Ok(key) = KeyPair::from_pem(&key_pem) else { return Ok(None) };
        let leaf =
            pem::decode("CERTIFICATE", &chain_pem).and_then(|chain| chain.into_iter().next());
        let public = key.subject_public_key_info();
        let matches =
            leaf.is_some_and(|leaf| leaf.windows(public.len()).any(|window| window == public));
        Ok(matches.then_some(Stored { chain_pem, key }))
    }

    /// Stores a certificate: the key with mode 0600 first, then the chain.
    pub fn save_certificate(
        &self,
        name: &str,
        chain_pem: &str,
        key: &KeyPair,
    ) -> Result<(), Error> {
        let dir = self.name_dir(name)?;
        create_private_dir(&dir).map_err(|error| failure(&dir, error))?;
        write_private(&dir.join("key.pem"), &key.to_pem())?;
        write_private(&dir.join("cert.pem"), chain_pem)
    }

    /// The DNS-01 record that an order of `name` presented and has not removed yet:
    /// its owner and its value. A daemon that died in between finds it at its start.
    pub fn load_presented(&self, name: &str) -> Option<(String, String)> {
        let path = self.name_dir(name).ok()?.join("dns");
        let text = read_bounded(&path).ok()??;
        let (owner, value) = text.trim().split_once(' ')?;
        Some((owner.to_owned(), value.to_owned()))
    }

    /// Records that the DNS-01 record `owner` with `value` is about to be presented.
    pub fn save_presented(&self, name: &str, owner: &str, value: &str) -> Result<(), Error> {
        let dir = self.name_dir(name)?;
        create_private_dir(&dir).map_err(|error| failure(&dir, error))?;
        write_private(&dir.join("dns"), &format!("{owner} {value}\n"))
    }

    /// Forgets the presented record of `name` after its cleanup.
    pub fn clear_presented(&self, name: &str) {
        if let Ok(dir) = self.name_dir(name) {
            let _ = fs::remove_file(dir.join("dns"));
        }
    }

    /// The retry state of `name`, if a failure left one. An unreadable file is no state.
    pub fn load_retry(&self, name: &str) -> Option<Retry> {
        let path = self.name_dir(name).ok()?.join("retry");
        let text = read_bounded(&path).ok()??;
        let (failures, next_attempt) = text.trim().split_once(' ')?;
        Some(Retry { failures: failures.parse().ok()?, next_attempt: next_attempt.parse().ok()? })
    }

    /// Records a failure of `name`, so that a restart waits as the running daemon would.
    pub fn save_retry(&self, name: &str, retry: Retry) -> Result<(), Error> {
        let dir = self.name_dir(name)?;
        create_private_dir(&dir).map_err(|error| failure(&dir, error))?;
        write_private(&dir.join("retry"), &format!("{} {}\n", retry.failures, retry.next_attempt))
    }

    /// Forgets the failures of `name` after a success.
    pub fn clear_retry(&self, name: &str) {
        if let Ok(dir) = self.name_dir(name) {
            let _ = fs::remove_file(dir.join("retry"));
        }
    }

    /// Takes the lock of `name`. Returns `None` while another node holds it. A lock is
    /// removed and taken when it is older than [`STALE_LOCK`], or when the process that
    /// wrote it on this host is gone.
    pub fn lock(&self, name: &str) -> Result<Option<Lock>, Error> {
        let path = self.root.join("locks").join(format!("{}.lock", component(name)?));
        for _ in 0..2 {
            match create_private_file(&path) {
                Ok(mut file) => {
                    let _ = writeln!(file, "{}", Holder::this());
                    return Ok(Some(Lock { path }));
                }
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
                Err(error) => return Err(failure(&path, error)),
            }
            let age = fs::metadata(&path)
                .and_then(|meta| meta.modified())
                .ok()
                .and_then(|modified| SystemTime::now().duration_since(modified).ok());
            let abandoned = read_bounded(&path)
                .ok()
                .flatten()
                .is_some_and(|text| Holder::parse(&text).is_some_and(|holder| holder.is_gone()));
            if !abandoned && age.is_none_or(|age| age < STALE_LOCK) {
                return Ok(None);
            }
            let _ = fs::remove_file(&path);
        }
        Ok(None)
    }
}

/// Who wrote a lock file: the host, the process, and the moment the process first took
/// a lock. A daemon that stops in the middle of an order leaves its lock behind. The
/// next start on the same host sees that the writer is gone and does not wait.
#[derive(Debug, PartialEq, Eq)]
struct Holder {
    host: String,
    process: u32,
    started: u128,
}

impl Holder {
    /// This process.
    fn this() -> Self {
        static STARTED: std::sync::OnceLock<u128> = std::sync::OnceLock::new();
        let started = *STARTED.get_or_init(|| {
            let since = SystemTime::now().duration_since(SystemTime::UNIX_EPOCH);
            since.map_or(0, |since| since.as_nanos())
        });
        let host = fs::read_to_string("/proc/sys/kernel/hostname").unwrap_or_default();
        let host = host.trim();
        // An empty host name would shift the words of the file.
        let host = if host.is_empty() { "-" } else { host };
        Self { host: host.to_owned(), process: std::process::id(), started }
    }

    fn parse(text: &str) -> Option<Self> {
        let mut words = text.split_ascii_whitespace();
        let host = words.next()?.to_owned();
        let process = words.next()?.parse().ok()?;
        let started = words.next()?.parse().ok()?;
        Some(Self { host, process, started })
    }

    /// Whether the writer ran on this host and no longer runs. Without a host name or
    /// without `/proc` we cannot tell, and the age of the lock decides.
    fn is_gone(&self) -> bool {
        let this = Self::this();
        if this.host == "-" || self.host != this.host || !Path::new("/proc/self").exists() {
            return false;
        }
        if self.process == this.process {
            // The number of an earlier process, as in a container that starts again.
            return self.started != this.started;
        }
        !Path::new("/proc").join(self.process.to_string()).exists()
    }
}

impl std::fmt::Display for Holder {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} {} {}", self.host, self.process, self.started)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;
    use crate::x509;

    /// A storage directory that is removed with the test.
    struct Scratch(PathBuf);

    impl Scratch {
        fn new(tag: &str) -> Self {
            let name = format!("sibuna-acme-store-{}-{tag}", std::process::id());
            let path = std::env::temp_dir().join(name);
            let _ = fs::remove_dir_all(&path);
            Self(path)
        }

        fn store(&self) -> Store {
            Store::open(&self.0, "https://ca.example/directory").unwrap()
        }
    }

    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn chain(key: &KeyPair) -> String {
        let der = x509::challenge_certificate(key, "example.org", "a.b", 1_795_516_496).unwrap();
        pem::encode("CERTIFICATE", &der)
    }

    #[test]
    fn authorities_get_readable_directory_names() {
        assert_eq!(
            authority_id("https://acme-v02.api.letsencrypt.org/directory"),
            "acme-v02.api.letsencrypt.org-directory"
        );
        assert_eq!(authority_id("https://127.0.0.1:14000/dir"), "127.0.0.1-14000-dir");
        assert_eq!(authority_id("https://CA.example/../x"), "ca.example-..-x");
        assert_eq!(authority_id("://"), "authority");
    }

    #[test]
    fn the_account_key_is_created_once_and_private() {
        let scratch = Scratch::new("account");
        let first = scratch.store().load_account().unwrap();
        let second = scratch.store().load_account().unwrap();
        assert_eq!(first.public_point(), second.public_point());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            let root = scratch.0.join("ca.example-directory");
            let mode = |path: &Path| fs::metadata(path).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode(&root.join("account.key")), 0o600);
            assert_eq!(mode(&root), 0o700);
            assert_eq!(mode(&root.join("certs")), 0o700);
        }
    }

    #[test]
    fn a_certificate_is_stored_with_a_private_key_and_read_back() {
        let scratch = Scratch::new("cert");
        let store = scratch.store();
        assert!(store.load_certificate("example.org").unwrap().is_none());
        let key = KeyPair::generate().unwrap();
        let text = chain(&key);
        store.save_certificate("example.org", &text, &key).unwrap();
        let stored = store.load_certificate("example.org").unwrap().unwrap();
        assert_eq!(stored.key.public_point(), key.public_point());
        assert_eq!(stored.chain_pem, text);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            let dir = scratch.0.join("ca.example-directory/certs/example.org");
            let mode = fs::metadata(dir.join("key.pem")).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600);
        }
        // A second save replaces the first.
        let next = KeyPair::generate().unwrap();
        store.save_certificate("example.org", &chain(&next), &next).unwrap();
        let stored = store.load_certificate("example.org").unwrap().unwrap();
        assert_eq!(stored.key.public_point(), next.public_point());
    }

    #[test]
    fn a_key_that_does_not_belong_to_the_leaf_is_ignored() {
        let scratch = Scratch::new("mismatch");
        let store = scratch.store();
        let key = KeyPair::generate().unwrap();
        let other = KeyPair::generate().unwrap();
        store.save_certificate("example.org", &chain(&key), &other).unwrap();
        assert!(store.load_certificate("example.org").unwrap().is_none());
    }

    #[test]
    fn names_cannot_leave_the_store() {
        let scratch = Scratch::new("names");
        let store = scratch.store();
        let key = KeyPair::generate().unwrap();
        for name in ["../x", "a/b", "", ".hidden", "UPPER.example", "a..b"] {
            assert_eq!(store.save_certificate(name, "x", &key).unwrap_err().code, "ACME001");
            assert!(store.lock(name).is_err());
        }
    }

    #[test]
    fn the_retry_state_survives_and_is_cleared() {
        let scratch = Scratch::new("retry");
        let store = scratch.store();
        assert_eq!(store.load_retry("example.org"), None);
        let retry = Retry { failures: 3, next_attempt: 1_795_516_496 };
        store.save_retry("example.org", retry).unwrap();
        assert_eq!(scratch.store().load_retry("example.org"), Some(retry));
        store.clear_retry("example.org");
        assert_eq!(store.load_retry("example.org"), None);
    }

    #[test]
    fn wildcards_addresses_and_presented_records_have_files_of_their_own() {
        let scratch = Scratch::new("names");
        let store = scratch.store();
        assert_eq!(component("*.example.org").unwrap(), "_.example.org");
        assert_eq!(component("2001:db8::1").unwrap(), "2001_db8__1");
        assert_eq!(component("127.0.0.1").unwrap(), "127.0.0.1");
        for bad in ["", "../x", "a/b", "_.example.org", "A.example"] {
            assert!(component(bad).is_err(), "{bad}");
        }
        assert_eq!(store.load_presented("*.example.org"), None);
        store.save_presented("*.example.org", "_acme-challenge.example.org", "abc-_1").unwrap();
        let found = store.load_presented("*.example.org").unwrap();
        assert_eq!(found, ("_acme-challenge.example.org".to_owned(), "abc-_1".to_owned()));
        assert_eq!(store.load_presented("example.org"), None);
        store.clear_presented("*.example.org");
        assert_eq!(store.load_presented("*.example.org"), None);
        assert!(store.lock("*.example.org").unwrap().is_some());
    }

    #[test]
    fn one_holder_has_the_lock_and_a_stale_lock_is_taken() {
        let scratch = Scratch::new("lock");
        let store = scratch.store();
        let held = store.lock("example.org").unwrap().unwrap();
        assert!(store.lock("example.org").unwrap().is_none());
        assert!(store.lock("other.example").unwrap().is_some());
        drop(held);
        let again = store.lock("example.org").unwrap().unwrap();
        // A node died with the lock: the file is older than the bound.
        let old = SystemTime::now() - STALE_LOCK - Duration::from_secs(5);
        File::options().write(true).open(&again.path).unwrap().set_modified(old).unwrap();
        std::mem::forget(again);
        assert!(store.lock("example.org").unwrap().is_some());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn a_lock_of_a_process_that_is_gone_is_taken_at_once() {
        let scratch = Scratch::new("gone");
        let store = scratch.store();
        let path = store.root.join("locks").join("example.org.lock");
        let this = Holder::this();
        let leave = |holder: &Holder| fs::write(&path, holder.to_string()).unwrap();
        // No process has this number.
        leave(&Holder { host: this.host.clone(), process: u32::MAX, started: 1 });
        drop(store.lock("example.org").unwrap().unwrap());
        // Our number, from an earlier start.
        leave(&Holder { host: this.host.clone(), process: this.process, started: 1 });
        drop(store.lock("example.org").unwrap().unwrap());
        // Another host: we cannot see its processes.
        leave(&Holder { host: "elsewhere".to_owned(), process: u32::MAX, started: 1 });
        assert!(store.lock("example.org").unwrap().is_none());
        assert_eq!(Holder::parse(&this.to_string()), Some(this));
    }

    #[test]
    fn an_unwritable_storage_is_reported_with_a_hint() {
        let scratch = Scratch::new("file");
        fs::write(&scratch.0, b"a file, not a directory").unwrap();
        let error = Store::open(&scratch.0, "https://ca.example/directory").unwrap_err();
        assert_eq!(error.code, "ACME001");
        assert!(error.hint.contains("global.acme.storage"));
        fs::remove_file(&scratch.0).unwrap();
    }
}
