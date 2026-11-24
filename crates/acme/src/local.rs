//! The local authority (SID 0021): a root and an intermediate that the daemon creates
//! and keeps, for names that no public authority validates.
//!
//! ```text
//! STORAGE/local/
//!   root.pem            the root certificate and its key, mode 0600, 10 years
//!   root.crt            the root certificate alone, the file to install in clients
//!   intermediate.pem    the intermediate and its key, mode 0600, 7 days
//!
//!   root --signs--> intermediate --signs--> leaf (12 hours by default)
//! ```
//!
//! Several nodes may share the directory. The root is linked into place only when no
//! root is there, so all nodes end with one root. The intermediate is replaced by one
//! rename. A leaf carries the intermediate that signed it.

use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};

use crate::store::write_private;
use crate::store::{create_private_dir, create_private_file, read_bounded, temporary};
use crate::{Error, Issued, KeyPair, pem, random_serial, schedule, x509};

/// The common name of the root.
pub const ROOT_NAME: &str = "Sibuna Local Authority - Root";
/// The common name of the intermediate, the issuer of every leaf.
pub const INTERMEDIATE_NAME: &str = "Sibuna Local Authority - Intermediate";
/// The directory of the local authority under the storage directory. It is also the
/// name to open the [`crate::store::Store`] of its leaves with.
pub const DIRECTORY: &str = "local";
/// The lifetime of the root, in seconds: ten years.
pub const ROOT_LIFETIME: u64 = 3650 * 86_400;
/// The lifetime of the intermediate, in seconds: seven days.
pub const INTERMEDIATE_LIFETIME: u64 = 7 * 86_400;
/// A validity starts this many seconds early, for clients whose clock is behind.
const BACKDATE: u64 = 60;

/// A certificate with its key, as one of the two authority files holds them.
struct Signer {
    key: KeyPair,
    certificate: Vec<u8>,
    fields: x509::Certificate,
}

impl Signer {
    /// Reads a PEM text with one certificate and its key. Returns `None` when a part is
    /// missing or the key does not belong to the certificate.
    fn parse(text: &str) -> Option<Self> {
        let certificate = pem::decode("CERTIFICATE", text)?.into_iter().next()?;
        let key = KeyPair::from_pem(text).ok()?;
        let public = key.subject_public_key_info();
        if !certificate.windows(public.len()).any(|window| window == public) {
            return None;
        }
        let fields = x509::read(&certificate)?;
        Some(Self { key, certificate, fields })
    }

    fn to_pem(&self) -> String {
        pem::encode("CERTIFICATE", &self.certificate) + &self.key.to_pem()
    }

    fn key_id(&self) -> [u8; 20] {
        x509::key_id(&self.key.subject_public_key_info())
    }
}

fn failure(path: &Path, what: impl std::fmt::Display) -> Error {
    Error::local(format!("{}: {what}.", path.display()))
}

/// The local authority of one storage directory.
#[derive(Debug)]
pub struct LocalAuthority {
    directory: PathBuf,
}

impl LocalAuthority {
    /// Opens the local authority under `storage`, and creates its directory and its
    /// root when they are missing. `now` is in seconds since 1970. Fails with `ACME011`
    /// when the directory cannot be written or the root on disk cannot be read.
    pub fn open(storage: &Path, now: u64) -> Result<Self, Error> {
        let directory = storage.join(DIRECTORY);
        create_private_dir(&directory).map_err(|error| failure(&directory, error))?;
        let authority = Self { directory };
        let root = authority.root(now)?;
        // The file for clients follows the root, also when another node made the root.
        let path = authority.root_path();
        let text = pem::encode("CERTIFICATE", &root.certificate);
        let current = read_bounded(&path).ok().flatten();
        if current.as_deref() != Some(text.as_str()) {
            write_private(&path, &text).map_err(|error| failure(&path, error.message))?;
        }
        Ok(authority)
    }

    /// The path of the root certificate, the file that clients install.
    pub fn root_path(&self) -> PathBuf {
        self.directory.join("root.crt")
    }

    /// The root certificate as PEM. Fails with `ACME011` when the file is unreadable.
    pub fn root_pem(&self) -> Result<String, Error> {
        let path = self.root_path();
        let text = read_bounded(&path).map_err(|error| failure(&path, error.message))?;
        text.ok_or_else(|| failure(&path, "the file is missing"))
    }

    /// Loads the root, or creates it. The new root is linked into place only when no
    /// root is there, so two nodes that start together use the same one.
    fn root(&self, now: u64) -> Result<Signer, Error> {
        let path = self.directory.join("root.pem");
        let read = |path: &Path| read_bounded(path).map_err(|error| failure(path, error.message));
        if read(&path)?.is_none() {
            let key = KeyPair::generate()?;
            let template = x509::Template {
                issuer: ROOT_NAME,
                subject: ROOT_NAME,
                not_before: now.saturating_sub(BACKDATE),
                not_after: now + ROOT_LIFETIME,
                serial: random_serial()?,
                authority: true,
                path_len: Some(1),
                subject_key_id: true,
                ..x509::Template::default()
            };
            let certificate = x509::write(&template, &key.subject_public_key_info(), &key)?;
            let text = pem::encode("CERTIFICATE", &certificate) + &key.to_pem();
            link_new(&path, &text).map_err(|error| failure(&path, error))?;
        }
        let text = read(&path)?.ok_or_else(|| failure(&path, "the file vanished"))?;
        Signer::parse(&text)
            .ok_or_else(|| failure(&path, "the file does not hold a root and its key"))
    }

    /// Loads the intermediate, or signs a new one when there is none, when two thirds
    /// of its life have passed, or when it ends before `needed_until`.
    fn intermediate(&self, root: &Signer, now: u64, needed_until: u64) -> Result<Signer, Error> {
        let path = self.directory.join("intermediate.pem");
        let text = read_bounded(&path).map_err(|error| failure(&path, error.message))?;
        let usable = text.as_deref().and_then(Signer::parse).filter(|found| {
            let fields = &found.fields;
            let due = schedule::renew_at(fields.not_before, fields.not_after);
            fields.issuer == ROOT_NAME && now < due && fields.not_after >= needed_until
        });
        if let Some(found) = usable {
            return Ok(found);
        }
        let key = KeyPair::generate()?;
        let template = x509::Template {
            issuer: ROOT_NAME,
            subject: INTERMEDIATE_NAME,
            not_before: now.saturating_sub(BACKDATE),
            not_after: (now + INTERMEDIATE_LIFETIME).min(root.fields.not_after),
            serial: random_serial()?,
            authority: true,
            path_len: Some(0),
            subject_key_id: true,
            authority_key_id: Some(root.key_id()),
            ..x509::Template::default()
        };
        let certificate = x509::write(&template, &key.subject_public_key_info(), &root.key)?;
        let fields = x509::read(&certificate)
            .ok_or_else(|| failure(&path, "the new intermediate cannot be read"))?;
        let signer = Signer { key, certificate, fields };
        write_private(&path, &signer.to_pem()).map_err(|error| failure(&path, error.message))?;
        Ok(signer)
    }

    /// Issues a certificate for a TLS server. `names` are its DNS names and IP
    /// addresses, the first of which is also its common name. It is valid for
    /// `lifetime` seconds from one minute before `now`, and never longer than the
    /// intermediate that signs it. Fails with `ACME011`, or for no name.
    pub fn issue(&self, names: &[&str], lifetime: u64, now: u64) -> Result<Issued, Error> {
        let Some(subject) = names.first() else {
            return Err(Error::local("A certificate needs a name."));
        };
        let root = self.root(now)?;
        let wanted = now.saturating_add(lifetime);
        let intermediate = self.intermediate(&root, now, wanted.min(root.fields.not_after))?;
        let key = KeyPair::generate()?;
        let template = x509::Template {
            issuer: INTERMEDIATE_NAME,
            subject,
            names,
            not_before: now.saturating_sub(BACKDATE),
            not_after: wanted.min(intermediate.fields.not_after),
            serial: random_serial()?,
            server: true,
            authority_key_id: Some(intermediate.key_id()),
            ..x509::Template::default()
        };
        let leaf = x509::write(&template, &key.subject_public_key_info(), &intermediate.key)?;
        let chain_pem = pem::encode("CERTIFICATE", &leaf)
            + &pem::encode("CERTIFICATE", &intermediate.certificate);
        Ok(Issued { chain_pem, key })
    }
}

/// Writes `text` to a private temporary file and links it to `path` when no file is
/// there. A file that another node linked first stays.
fn link_new(path: &Path, text: &str) -> io::Result<()> {
    let temporary = temporary(path);
    let _ = fs::remove_file(&temporary);
    let written = create_private_file(&temporary)
        .and_then(|mut file| file.write_all(text.as_bytes()).and_then(|()| file.sync_all()));
    let linked = written.and_then(|()| fs::hard_link(&temporary, path));
    let _ = fs::remove_file(&temporary);
    match linked {
        Err(error) if error.kind() != io::ErrorKind::AlreadyExists => Err(error),
        _ => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use std::process::Command;
    use std::sync::atomic::{AtomicU32, Ordering};

    use super::*;

    const NOW: u64 = 1_795_516_496;

    /// A storage directory of one test, removed with it.
    struct Scratch(PathBuf);

    impl Scratch {
        fn new() -> Self {
            static SERIAL: AtomicU32 = AtomicU32::new(0);
            let serial = SERIAL.fetch_add(1, Ordering::Relaxed);
            let name = format!("sibuna-acme-local-{}-{serial}", std::process::id());
            let path = std::env::temp_dir().join(name);
            let _ = fs::remove_dir_all(&path);
            Self(path)
        }
    }

    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn chain(issued: &Issued) -> Vec<x509::Certificate> {
        let blocks = pem::decode("CERTIFICATE", &issued.chain_pem).unwrap();
        blocks.iter().map(|der| x509::read(der).unwrap()).collect()
    }

    #[test]
    fn a_leaf_names_hosts_and_addresses_and_chains_to_the_intermediate() {
        let scratch = Scratch::new();
        let authority = LocalAuthority::open(&scratch.0, NOW).unwrap();
        let issued = authority.issue(&["localhost", "127.0.0.1", "::1"], 43_200, NOW).unwrap();
        let chain = chain(&issued);
        assert_eq!(chain.len(), 2);
        assert_eq!(chain[0].issuer, INTERMEDIATE_NAME);
        assert_eq!(chain[1].issuer, ROOT_NAME);
        assert_eq!(chain[0].names, ["localhost", "127.0.0.1", "::1"]);
        assert!(chain[0].names_host("127.0.0.1") && !chain[0].names_host("127.0.0.2"));
        assert_eq!((chain[0].not_before, chain[0].not_after), (NOW - 60, NOW + 43_200));
        assert_eq!(chain[1].not_after, NOW + INTERMEDIATE_LIFETIME);
        assert_eq!(authority.issue(&[], 60, NOW).unwrap_err().code, "ACME011");
    }

    #[test]
    fn the_root_is_kept_and_the_intermediate_is_replaced_in_time() {
        let scratch = Scratch::new();
        let first = LocalAuthority::open(&scratch.0, NOW).unwrap();
        let root = first.root_pem().unwrap();
        let before = fs::read_to_string(scratch.0.join("local/intermediate.pem")).ok();
        assert_eq!(before, None);
        first.issue(&["a.internal"], 60, NOW).unwrap();
        let intermediate = fs::read_to_string(scratch.0.join("local/intermediate.pem")).unwrap();
        // A second node, and a later start, find the same root and intermediate.
        let second = LocalAuthority::open(&scratch.0, NOW + 3600).unwrap();
        second.issue(&["b.internal"], 60, NOW + 3600).unwrap();
        assert_eq!(second.root_pem().unwrap(), root);
        let same = fs::read_to_string(scratch.0.join("local/intermediate.pem")).unwrap();
        assert_eq!(same, intermediate);
        // After two thirds of seven days the intermediate is new. The root is not.
        let late = NOW + 5 * 86_400;
        let issued = second.issue(&["b.internal"], 60, late).unwrap();
        let replaced = fs::read_to_string(scratch.0.join("local/intermediate.pem")).unwrap();
        assert_ne!(replaced, intermediate);
        assert_eq!(second.root_pem().unwrap(), root);
        assert_eq!(chain(&issued)[1].not_after, late + INTERMEDIATE_LIFETIME);
        // A leaf never outlives its issuer.
        let long = second.issue(&["b.internal"], 30 * 86_400, late).unwrap();
        assert_eq!(chain(&long)[0].not_after, late + INTERMEDIATE_LIFETIME);
    }

    #[cfg(unix)]
    #[test]
    fn the_keys_of_the_authority_are_private() {
        use std::os::unix::fs::PermissionsExt as _;
        let scratch = Scratch::new();
        let authority = LocalAuthority::open(&scratch.0, NOW).unwrap();
        authority.issue(&["a.internal"], 60, NOW).unwrap();
        let mode = |name: &str| {
            fs::metadata(scratch.0.join("local").join(name)).unwrap().permissions().mode() & 0o777
        };
        assert_eq!((mode("root.pem"), mode("intermediate.pem"), mode("")), (0o600, 0o600, 0o700));
        assert!(!authority.root_pem().unwrap().contains("PRIVATE KEY"));
    }

    #[test]
    fn a_damaged_root_is_reported_and_not_replaced() {
        let scratch = Scratch::new();
        LocalAuthority::open(&scratch.0, NOW).unwrap();
        let path = scratch.0.join("local/root.pem");
        fs::write(&path, "no pem").unwrap();
        let error = LocalAuthority::open(&scratch.0, NOW).unwrap_err();
        assert_eq!(error.code, "ACME011");
        assert_eq!(fs::read_to_string(&path).unwrap(), "no pem");
    }

    /// `openssl verify` accepts the chain for a TLS server, and refuses it without the
    /// intermediate. Skipped when `openssl` is not installed.
    #[test]
    fn openssl_verifies_the_chain_with_the_root() {
        let scratch = Scratch::new();
        let now =
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs();
        let authority = LocalAuthority::open(&scratch.0, now).unwrap();
        let issued = authority.issue(&["localhost", "127.0.0.1"], 3600, now).unwrap();
        let blocks = pem::decode("CERTIFICATE", &issued.chain_pem).unwrap();
        let file = |name: &str, der: &[u8]| {
            let path = scratch.0.join(name);
            fs::write(&path, pem::encode("CERTIFICATE", der)).unwrap();
            path
        };
        let (leaf, intermediate) = (file("leaf.pem", &blocks[0]), file("int.pem", &blocks[1]));
        let verify = |with_intermediate: bool, extra: &[&str]| {
            let mut command = Command::new("openssl");
            command.args(["verify", "-x509_strict", "-purpose", "sslserver"]);
            command.arg("-CAfile").arg(authority.root_path());
            if with_intermediate {
                command.arg("-untrusted").arg(&intermediate);
            }
            command.args(extra).arg(&leaf).output()
        };
        let Ok(output) = verify(true, &[]) else { return };
        let text = String::from_utf8_lossy(&output.stdout).into_owned()
            + &String::from_utf8_lossy(&output.stderr);
        assert!(output.status.success(), "{text}");
        assert!(verify(true, &["-verify_hostname", "localhost"]).unwrap().status.success());
        assert!(verify(true, &["-verify_ip", "127.0.0.1"]).unwrap().status.success());
        assert!(!verify(true, &["-verify_hostname", "other.test"]).unwrap().status.success());
        assert!(!verify(false, &[]).unwrap().status.success());
    }
}
