//! The local authority (SID 0021): a root and an intermediate that the daemon creates
//! and keeps, for names that no public authority validates.
//!
//! ```text
//! STORAGE/local/
//!   root.pem            the root certificate and its key, mode 0600, 10 years
//!   root.crt            the root certificate alone, the file to install in clients,
//!                       mode 0644; the directory itself has mode 0755
//!   intermediate.pem    the intermediate and its key, mode 0600, 7 days
//!   intermediate.previous.pem, revoked/, crl.der, crl.pem    see [`revocation`]
//!
//!   root --signs--> intermediate --signs--> leaf (12 hours by default)
//! ```
//!
//! Several nodes may share the directory. The root is linked into place only when no
//! root is there, so all nodes end with one root. The intermediate is replaced by one
//! rename. A leaf carries the intermediate that signed it.

mod revocation;

use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};

use crate::store::{create_private_dir, create_private_file, read_bounded, temporary};
use crate::store::{set_mode, write_private};
use crate::{Error, Issued, KeyPair, constraints, pem, random_serial, schedule, x509};

pub use revocation::{CRL_LIFETIME, LONGEST_LEAF, MAX_REVOKED, Revoked, parse_serial, serial_of};

/// The file of the intermediate before the present one. It signs the revocation list
/// of its leaves until it expires.
const PREVIOUS: &str = "intermediate.previous.pem";
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

/// The root certificate of a local authority, for the operator who installs it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Root {
    /// The path of the file to install in clients.
    pub path: PathBuf,
    /// The certificate as PEM.
    pub pem: String,
    /// The validity and the name of the certificate.
    pub fields: x509::Certificate,
}

/// Reads the root certificate under `storage` and creates nothing. Returns `None`
/// when no local authority exists there yet. Fails with `ACME011` when the file cannot
/// be read or holds no certificate.
pub fn read_root(storage: &Path) -> Result<Option<Root>, Error> {
    let path = storage.join(DIRECTORY).join("root.crt");
    let Some(pem) = read_bounded(&path).map_err(|error| failure(&path, error.message))? else {
        return Ok(None);
    };
    let fields = pem::decode("CERTIFICATE", &pem)
        .and_then(|blocks| x509::read(blocks.first()?))
        .ok_or_else(|| failure(&path, "the file holds no certificate"))?;
    Ok(Some(Root { path, pem, fields }))
}

/// The local authority of one storage directory.
#[derive(Debug)]
pub struct LocalAuthority {
    directory: PathBuf,
    /// The DER value of the name constraints that a new root gets and that the root on
    /// disk must have.
    constraints: Option<Vec<u8>>,
}

impl LocalAuthority {
    /// Opens the local authority under `storage`, and creates its directory and its
    /// root when they are missing. `now` is in seconds since 1970.
    ///
    /// `permitted` lists the DNS suffixes and the address ranges `ADDRESS/PREFIX` that
    /// a new root may sign for; see [`constraints::value`]. The empty list constrains
    /// nothing. A root that exists is never rewritten.
    ///
    /// The directory gets mode 0755 and `root.crt` mode 0644, so that a user who can
    /// reach the storage directory can read the root. The keys stay private.
    ///
    /// Fails with `ACME011` when the directory cannot be written, when the root on disk
    /// cannot be read, when an entry of `permitted` is malformed, or when the root on
    /// disk has other constraints than `permitted`.
    pub fn open(storage: &Path, now: u64, permitted: &[String]) -> Result<Self, Error> {
        let directory = storage.join(DIRECTORY);
        create_private_dir(&directory).map_err(|error| failure(&directory, error))?;
        set_mode(&directory, 0o755).map_err(|error| failure(&directory, error))?;
        let constraints = constraints::value(permitted).map_err(|entry| {
            Error::local(format!("`{entry}` is no DNS suffix and no address range."))
        })?;
        let authority = Self { directory, constraints };
        let root = authority.root(now)?;
        authority.check_constraints(&root)?;
        // The file for clients follows the root, also when another node made the root.
        let path = authority.root_path();
        let text = pem::encode("CERTIFICATE", &root.certificate);
        let current = read_bounded(&path).ok().flatten();
        if current.as_deref() != Some(text.as_str()) {
            write_private(&path, &text).map_err(|error| failure(&path, error.message))?;
        }
        set_mode(&path, 0o644).map_err(|error| failure(&path, error))?;
        Ok(authority)
    }

    /// Fails when the root on disk does not carry exactly the constraints of the
    /// configuration. A client that installed the root trusts what the root says, so a
    /// changed list would promise what the installed root does not keep.
    fn check_constraints(&self, root: &Signer) -> Result<(), Error> {
        let found = x509::parts(&root.certificate).and_then(|parts| {
            x509::extension_value(parts.extensions, constraints::NAME_CONSTRAINTS)
        });
        if found == self.constraints.as_deref() {
            return Ok(());
        }
        let path = self.directory.join("root.pem");
        let what = match (found, &self.constraints) {
            (Some(_), None) => "The root has name constraints and the configuration lists none",
            (None, _) => "The root has no name constraints and the configuration lists some",
            (Some(_), Some(_)) => "The root has other name constraints than the configuration",
        };
        Err(Error::constraints(format!("{}: {what}.", path.display())))
    }

    /// Whether the chain `chain_pem` of a stored leaf ends at the present root: its last
    /// certificate is an intermediate that this root signed. A leaf of a root that the
    /// storage lost is of no use to a client that installed the present root.
    pub fn issued_here(&self, chain_pem: &str) -> bool {
        let root = self.directory.join("root.pem");
        let Some(root) = read_bounded(&root).ok().flatten().as_deref().and_then(Signer::parse)
        else {
            return false;
        };
        let last = pem::decode("CERTIFICATE", chain_pem)
            .and_then(|chain| chain.last().and_then(|der| x509::read(der)));
        last.is_some_and(|last| last.authority_key_id == root.key_id())
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
                name_constraints: self.constraints.as_deref(),
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
            let ours = fields.authority_key_id == root.key_id();
            ours && fields.issuer == ROOT_NAME && now < due && fields.not_after >= needed_until
        });
        if let Some(found) = usable {
            return Ok(found);
        }
        self.keep_previous(root, text.as_deref(), now);
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

    /// Keeps the intermediate that is about to be replaced, when the present root signed
    /// it and it has not expired: its leaves may still live, and a revocation list for
    /// them needs its key. A failure to write it costs that list and nothing else.
    fn keep_previous(&self, root: &Signer, text: Option<&str>, now: u64) {
        let Some(text) = text else { return };
        let Some(old) = Signer::parse(text) else { return };
        if old.fields.authority_key_id == root.key_id() && old.fields.not_after > now {
            let _ = write_private(&self.directory.join(PREVIOUS), text);
        }
    }

    /// Issues a certificate for a TLS server. `names` are its DNS names and IP
    /// addresses. The first is also its common name; an address is written there as
    /// `address 10.0.0.1`, because a verifier takes a common name that looks like a
    /// host name for one and holds it against the DNS constraints of the root. The
    /// names are not compared with the constraints: the caller's configuration check
    /// does that, and a client refuses a leaf outside them. It is valid for
    /// `lifetime` seconds from one minute before `now`, and never longer than the
    /// intermediate that signs it. A lifetime under two minutes starts half of itself
    /// early instead, so that two thirds of the validity lie ahead. Fails with
    /// `ACME011`, or for no name.
    pub fn issue(&self, names: &[&str], lifetime: u64, now: u64) -> Result<Issued, Error> {
        self.issue_as(crate::KeyType::P256, names, lifetime, now)
    }

    /// As [`LocalAuthority::issue`], with a key of the kind `kind` for the certificate.
    /// The intermediate signs with its own key, which is on P-256. An RSA key is made
    /// by the `openssl` program; without it the call fails with `ACME015`.
    pub fn issue_as(
        &self,
        kind: crate::KeyType,
        names: &[&str],
        lifetime: u64,
        now: u64,
    ) -> Result<Issued, Error> {
        let Some(first) = names.first() else {
            return Err(Error::local("A certificate needs a name."));
        };
        let subject = match first.parse::<std::net::IpAddr>() {
            Ok(_) => format!("address {first}"),
            Err(_) => (*first).to_owned(),
        };
        let root = self.root(now)?;
        let wanted = now.saturating_add(lifetime);
        let intermediate = self.intermediate(&root, now, wanted.min(root.fields.not_after))?;
        let key = KeyPair::generate_as(kind)?;
        let template = x509::Template {
            issuer: INTERMEDIATE_NAME,
            subject: &subject,
            names,
            not_before: now.saturating_sub(BACKDATE.min(lifetime / 2)),
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
        let authority = LocalAuthority::open(&scratch.0, NOW, &[]).unwrap();
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
        // A short lifetime is renewed inside its life: at two thirds of the validity.
        let short = tests::chain(&authority.issue(&["localhost"], 10, NOW).unwrap());
        assert_eq!((short[0].not_before, short[0].not_after), (NOW - 5, NOW + 10));
        assert_eq!(schedule::renew_at(short[0].not_before, short[0].not_after), NOW + 5);
        let root = read_root(&scratch.0).unwrap().unwrap();
        assert_eq!(
            (root.fields.issuer.as_str(), root.pem),
            (ROOT_NAME, authority.root_pem().unwrap())
        );
        assert_eq!(root.fields.not_after, NOW + ROOT_LIFETIME);
        assert_eq!(read_root(&scratch.0.join("nothing")).unwrap(), None);
    }

    #[test]
    fn the_root_is_kept_and_the_intermediate_is_replaced_in_time() {
        let scratch = Scratch::new();
        let first = LocalAuthority::open(&scratch.0, NOW, &[]).unwrap();
        let root = first.root_pem().unwrap();
        let before = fs::read_to_string(scratch.0.join("local/intermediate.pem")).ok();
        assert_eq!(before, None);
        first.issue(&["a.internal"], 60, NOW).unwrap();
        let intermediate = fs::read_to_string(scratch.0.join("local/intermediate.pem")).unwrap();
        // A second node, and a later start, find the same root and intermediate.
        let second = LocalAuthority::open(&scratch.0, NOW + 3600, &[]).unwrap();
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
        let authority = LocalAuthority::open(&scratch.0, NOW, &[]).unwrap();
        authority.issue(&["a.internal"], 60, NOW).unwrap();
        let mode = |name: &str| {
            fs::metadata(scratch.0.join("local").join(name)).unwrap().permissions().mode() & 0o777
        };
        assert_eq!((mode("root.pem"), mode("intermediate.pem")), (0o600, 0o600));
        // The root certificate is for every user. The directory lets them reach it.
        assert_eq!((mode("root.crt"), mode("")), (0o644, 0o755));
        assert!(!authority.root_pem().unwrap().contains("PRIVATE KEY"));
        // A storage that an earlier version made private is opened up at the next open.
        let private = |name: &str, mode: u32| {
            let path = scratch.0.join("local").join(name);
            fs::set_permissions(path, fs::Permissions::from_mode(mode)).unwrap();
        };
        private("root.crt", 0o600);
        private("", 0o700);
        LocalAuthority::open(&scratch.0, NOW, &[]).unwrap();
        assert_eq!((mode("root.crt"), mode("")), (0o644, 0o755));
    }

    fn list(entries: &[&str]) -> Vec<String> {
        entries.iter().map(|entry| (*entry).to_owned()).collect()
    }

    #[test]
    fn the_constraints_are_those_of_the_root_on_disk() {
        let scratch = Scratch::new();
        let permitted = list(&["corp.internal", "10.0.0.0/8"]);
        LocalAuthority::open(&scratch.0, NOW, &permitted).unwrap();
        let root = fs::read(scratch.0.join("local/root.pem")).unwrap();
        // The same list opens the same root. Another list, or none, is refused, and the
        // root stays as it is.
        LocalAuthority::open(&scratch.0, NOW, &permitted).unwrap();
        for other in [list(&[]), list(&["corp.internal"]), list(&["other.internal"])] {
            let error = LocalAuthority::open(&scratch.0, NOW, &other).unwrap_err();
            assert_eq!(error.code, "ACME011");
            assert!(error.message.contains("name constraints"), "{}", error.message);
            assert!(error.hint.contains("internal.constraints"), "{}", error.hint);
        }
        assert_eq!(fs::read(scratch.0.join("local/root.pem")).unwrap(), root);
        // A root without constraints refuses a list in the same way.
        let plain = Scratch::new();
        LocalAuthority::open(&plain.0, NOW, &[]).unwrap();
        let error = LocalAuthority::open(&plain.0, NOW, &permitted).unwrap_err();
        assert!(error.message.contains("no name constraints"), "{}", error.message);
        let error = LocalAuthority::open(&Scratch::new().0, NOW, &list(&["a b"])).unwrap_err();
        assert!(error.message.contains("`a b`"), "{}", error.message);
    }

    #[test]
    fn a_leaf_of_a_lost_root_is_not_ours() {
        let scratch = Scratch::new();
        let authority = LocalAuthority::open(&scratch.0, NOW, &[]).unwrap();
        let old = authority.issue(&["a.internal"], 600, NOW).unwrap();
        assert!(authority.issued_here(&old.chain_pem));
        assert!(!authority.issued_here("no chain"));
        // The storage loses the root. The intermediate of the old root stays behind.
        fs::remove_file(scratch.0.join("local/root.pem")).unwrap();
        let authority = LocalAuthority::open(&scratch.0, NOW, &[]).unwrap();
        assert!(!authority.issued_here(&old.chain_pem));
        // The next leaf is signed by a new intermediate, of the new root.
        let new = authority.issue(&["a.internal"], 600, NOW).unwrap();
        assert!(authority.issued_here(&new.chain_pem));
        assert_ne!(chain(&new)[1].authority_key_id, chain(&old)[1].authority_key_id);
    }

    /// `openssl verify` accepts a chain whose leaf has a key on P-384, signed by the
    /// P-256 intermediate. Skipped without `openssl`.
    #[test]
    fn openssl_verifies_a_leaf_with_a_key_on_p384() {
        let _spawn = crate::SPAWN.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        let scratch = Scratch::new();
        let now =
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs();
        let authority = LocalAuthority::open(&scratch.0, now, &[]).unwrap();
        let issued = authority.issue_as(crate::KeyType::P384, &["localhost"], 3600, now).unwrap();
        assert_eq!(issued.key.key_type(), crate::KeyType::P384);
        let blocks = pem::decode("CERTIFICATE", &issued.chain_pem).unwrap();
        let public = issued.key.subject_public_key_info();
        assert!(blocks[0].windows(public.len()).any(|window| window == public));
        let file = |name: &str, der: &[u8]| {
            let path = scratch.0.join(name);
            fs::write(&path, pem::encode("CERTIFICATE", der)).unwrap();
            path
        };
        let (leaf, intermediate) = (file("leaf.pem", &blocks[0]), file("int.pem", &blocks[1]));
        let mut command = Command::new("openssl");
        command.args(["verify", "-x509_strict", "-purpose", "sslserver"]);
        command.arg("-CAfile").arg(authority.root_path());
        command.arg("-untrusted").arg(&intermediate);
        command.args(["-verify_hostname", "localhost"]).arg(&leaf);
        let Ok(output) = command.output() else { return };
        assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));
        let mut shown = Command::new("openssl");
        shown.args(["x509", "-noout", "-text", "-in"]).arg(&leaf);
        let text = String::from_utf8_lossy(&shown.output().unwrap().stdout).into_owned();
        assert!(text.contains("secp384r1") && text.contains("ecdsa-with-SHA256"), "{text}");
    }

    /// `openssl verify` accepts a chain whose leaf has an RSA key, signed by the P-256
    /// intermediate. Skipped without `openssl`.
    #[test]
    fn openssl_verifies_a_leaf_with_an_rsa_key() {
        if crate::keygen::probe().is_err() {
            return;
        }
        let _spawn = crate::SPAWN.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        let scratch = Scratch::new();
        let now =
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs();
        let authority = LocalAuthority::open(&scratch.0, now, &[]).unwrap();
        let kind = crate::KeyType::Rsa2048;
        let issued = authority.issue_as(kind, &["localhost"], 3600, now).unwrap();
        assert_eq!(issued.key.key_type(), kind);
        let blocks = pem::decode("CERTIFICATE", &issued.chain_pem).unwrap();
        let public = issued.key.subject_public_key_info();
        assert!(blocks[0].windows(public.len()).any(|window| window == public));
        let file = |name: &str, der: &[u8]| {
            let path = scratch.0.join(name);
            fs::write(&path, pem::encode("CERTIFICATE", der)).unwrap();
            path
        };
        let (leaf, intermediate) = (file("leaf.pem", &blocks[0]), file("int.pem", &blocks[1]));
        let mut command = Command::new("openssl");
        command.args(["verify", "-x509_strict", "-purpose", "sslserver"]);
        command.arg("-CAfile").arg(authority.root_path());
        command.arg("-untrusted").arg(&intermediate);
        command.args(["-verify_hostname", "localhost"]).arg(&leaf);
        let output = command.output().unwrap();
        assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));
        let mut shown = Command::new("openssl");
        shown.args(["x509", "-noout", "-text", "-in"]).arg(&leaf);
        let text = String::from_utf8_lossy(&shown.output().unwrap().stdout).into_owned();
        // The leaf has the RSA key. The intermediate, on P-256, signed it.
        assert!(text.contains("Public-Key: (2048 bit)"), "{text}");
        assert!(text.contains("rsaEncryption") && text.contains("ecdsa-with-SHA256"), "{text}");
    }

    /// `openssl verify` accepts a leaf inside the constraints of the root and refuses a
    /// leaf outside them that the same keys signed. Skipped without `openssl`.
    #[test]
    fn openssl_enforces_the_constraints_of_the_root() {
        let _spawn = crate::SPAWN.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        let now =
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs();
        let verify = |permitted: &[&str], names: &[&str]| {
            let scratch = Scratch::new();
            let authority = LocalAuthority::open(&scratch.0, now, &list(permitted)).unwrap();
            let issued = authority.issue(names, 3600, now).unwrap();
            let blocks = pem::decode("CERTIFICATE", &issued.chain_pem).unwrap();
            let file = |name: &str, der: &[u8]| {
                let path = scratch.0.join(name);
                fs::write(&path, pem::encode("CERTIFICATE", der)).unwrap();
                path
            };
            let (leaf, intermediate) = (file("leaf.pem", &blocks[0]), file("int.pem", &blocks[1]));
            let mut command = Command::new("openssl");
            command.args(["verify", "-x509_strict", "-purpose", "sslserver"]);
            command.arg("-CAfile").arg(authority.root_path());
            command.arg("-untrusted").arg(&intermediate).arg(&leaf);
            command.output().ok().map(|output| {
                let text = String::from_utf8_lossy(&output.stdout).into_owned()
                    + &String::from_utf8_lossy(&output.stderr);
                (output.status.success(), text)
            })
        };
        let Some(inside) = verify(&["corp.internal", "10.0.0.0/8"], &["a.corp.internal"]) else {
            return;
        };
        assert!(inside.0, "{}", inside.1);
        let accepted = |permitted: &[&str], names: &[&str]| verify(permitted, names).unwrap().0;
        let both = ["corp.internal", "10.0.0.0/8"];
        assert!(accepted(&both, &["corp.internal", "10.1.2.3"]));
        assert!(!accepted(&both, &["bank.example"]));
        assert!(!accepted(&both, &["a.corp.internal", "bank.example"]));
        assert!(!accepted(&both, &["evilcorp.internal"]));
        assert!(!accepted(&both, &["192.168.1.1"]));
        // A list of one kind closes the other kind.
        assert!(accepted(&["corp.internal"], &["a.corp.internal"]));
        assert!(!accepted(&["corp.internal"], &["10.1.2.3"]));
        assert!(!accepted(&["corp.internal"], &["::1"]));
        assert!(accepted(&["10.0.0.0/8"], &["10.1.2.3"]));
        assert!(!accepted(&["10.0.0.0/8"], &["a.corp.internal"]));
        assert!(accepted(&["fd00::/8"], &["fd00::1"]));
        assert!(!accepted(&["fd00::/8"], &["10.1.2.3"]));
    }

    #[test]
    fn a_damaged_root_is_reported_and_not_replaced() {
        let scratch = Scratch::new();
        LocalAuthority::open(&scratch.0, NOW, &[]).unwrap();
        let path = scratch.0.join("local/root.pem");
        fs::write(&path, "no pem").unwrap();
        let error = LocalAuthority::open(&scratch.0, NOW, &[]).unwrap_err();
        assert_eq!(error.code, "ACME011");
        assert_eq!(fs::read_to_string(&path).unwrap(), "no pem");
    }

    /// `openssl verify` accepts the chain for a TLS server, and refuses it without the
    /// intermediate. Skipped when `openssl` is not installed.
    #[test]
    fn openssl_verifies_the_chain_with_the_root() {
        let _spawn = crate::SPAWN.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        let scratch = Scratch::new();
        let now =
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs();
        let authority = LocalAuthority::open(&scratch.0, now, &[]).unwrap();
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
