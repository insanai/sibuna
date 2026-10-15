//! Trust anchors: the system roots, an operator's PEM file of CA certificates, or both.

use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};

use rustls::RootCertStore;
use rustls::pki_types::CertificateDer;
use rustls::pki_types::pem::PemObject;

use crate::error::{CaFileProblem, TlsError};

/// The largest CA file we read, as in the Zig daemon. A real private CA bundle is a few
/// kilobytes; the bound keeps a mistaken path (a log file, a disk image) from being read
/// whole.
pub const MAX_CA_FILE_BYTES: u64 = 128 * 1024;

/// Which certificates we accept as roots of trust.
///
/// The anchors are the system roots when `system` is true, together with the certificates
/// of `ca_file` when it names one. [`Trust::from_ca_file`] gives the console's rule for
/// `--console-peer-ca-file`: the file *replaces* the system roots. The default trusts the
/// system roots only. Host-name verification is independent of this choice and always on.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Trust {
    /// Trust the operating system's root store (read through `rustls-native-certs`).
    pub system: bool,
    /// A PEM file of CA certificates, at most [`MAX_CA_FILE_BYTES`] long.
    pub ca_file: Option<PathBuf>,
}

impl Default for Trust {
    fn default() -> Trust {
        Trust { system: true, ca_file: None }
    }
}

impl Trust {
    /// Trust only the CA certificates in the PEM file at `path`, not the system roots.
    pub fn from_ca_file(path: impl Into<PathBuf>) -> Trust {
        Trust { system: false, ca_file: Some(path.into()) }
    }

    /// Reads the trust anchors this value names. This reads files (the system store can be
    /// a few hundred certificates), so callers do it once, at start-up, through
    /// [`crate::Connector::load`].
    ///
    /// # Errors
    ///
    /// [`TlsError::NoTrustAnchors`] when neither source is named,
    /// [`TlsError::SystemRoots`] when the system store yields no usable certificate, and
    /// [`TlsError::CaFile`] when the CA file is unusable.
    pub(crate) fn load_roots(&self) -> Result<RootCertStore, TlsError> {
        let mut roots = RootCertStore::empty();
        if !self.system && self.ca_file.is_none() {
            return Err(TlsError::NoTrustAnchors);
        }
        if self.system {
            add_system_roots(&mut roots)?;
        }
        if let Some(path) = &self.ca_file {
            let pem = read_ca_file(path)
                .map_err(|problem| TlsError::CaFile { path: path.clone(), problem })?;
            add_pem_roots(&mut roots, &pem)
                .map_err(|problem| TlsError::CaFile { path: path.clone(), problem })?;
        }
        Ok(roots)
    }
}

/// Adds every parsable certificate of the system store. A store usually holds a few
/// certificates the parser rejects (old or unusual ones); like rustls' own examples we skip
/// those and fail only when nothing usable remains.
fn add_system_roots(roots: &mut RootCertStore) -> Result<(), TlsError> {
    let loaded = rustls_native_certs::load_native_certs();
    let (added, _ignored) = roots.add_parsable_certificates(loaded.certs);
    if added == 0 {
        let detail = loaded.errors.first().map(ToString::to_string).unwrap_or_default();
        return Err(TlsError::SystemRoots(detail));
    }
    Ok(())
}

/// Reads the CA file after checking that it is a regular file of a sane size. The size is
/// checked again while reading, so a file that grows in between is still bounded.
fn read_ca_file(path: &Path) -> Result<Vec<u8>, CaFileProblem> {
    let file = File::open(path).map_err(|_| CaFileProblem::Unreadable)?;
    let metadata = file.metadata().map_err(|_| CaFileProblem::Unreadable)?;
    if !metadata.is_file() {
        return Err(CaFileProblem::NotRegularFile);
    }
    if metadata.len() > MAX_CA_FILE_BYTES {
        return Err(CaFileProblem::TooLarge);
    }
    let mut pem = Vec::with_capacity(usize::try_from(metadata.len()).unwrap_or_default());
    file.take(MAX_CA_FILE_BYTES + 1)
        .read_to_end(&mut pem)
        .map_err(|_| CaFileProblem::Unreadable)?;
    if pem.is_empty() {
        return Err(CaFileProblem::Empty);
    }
    if pem.len() as u64 > MAX_CA_FILE_BYTES {
        return Err(CaFileProblem::TooLarge);
    }
    Ok(pem)
}

/// Adds the `CERTIFICATE` sections of `pem` to `roots`; other sections (a private key
/// pasted by mistake, for example) are skipped. Every certificate must parse.
///
/// Returns how many were added.
pub(crate) fn add_pem_roots(
    roots: &mut RootCertStore,
    pem: &[u8],
) -> Result<usize, CaFileProblem> {
    if pem.is_empty() {
        return Err(CaFileProblem::Empty);
    }
    let mut count = 0;
    for certificate in CertificateDer::pem_slice_iter(pem) {
        let certificate = certificate.map_err(|_| CaFileProblem::Malformed)?;
        roots.add(certificate).map_err(|_| CaFileProblem::Malformed)?;
        count += 1;
    }
    if count == 0 {
        return Err(CaFileProblem::NoCertificates);
    }
    Ok(count)
}

#[cfg(test)]
mod tests {
    use super::*;

    const CA: &[u8] = include_bytes!("../tests/data/ca.pem");
    const LEAF: &[u8] = include_bytes!("../tests/data/localhost.pem");
    const KEY: &[u8] = include_bytes!("../tests/data/localhost.key");

    /// A temporary directory per test, removed when the test ends.
    struct Scratch(PathBuf);

    impl Scratch {
        fn new(test: &str) -> Scratch {
            let name = format!("sibuna-tls-{}-{test}", std::process::id());
            let directory = std::env::temp_dir().join(name);
            std::fs::create_dir_all(&directory).unwrap();
            Scratch(directory)
        }

        fn path(&self, name: &str) -> PathBuf {
            self.0.join(name)
        }
    }

    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn problem(trust: &Trust) -> CaFileProblem {
        match trust.load_roots() {
            Err(TlsError::CaFile { problem, .. }) => problem,
            other => panic!("expected a CA file error, got {other:?}"),
        }
    }

    #[test]
    fn pem_roots_take_certificates_and_skip_other_sections() {
        let mut roots = RootCertStore::empty();
        let mut bundle = KEY.to_vec();
        bundle.extend_from_slice(CA);
        bundle.extend_from_slice(LEAF);
        assert_eq!(add_pem_roots(&mut roots, &bundle), Ok(2));
        assert_eq!(roots.len(), 2);
        assert_eq!(add_pem_roots(&mut roots, KEY), Err(CaFileProblem::NoCertificates));
        assert_eq!(add_pem_roots(&mut roots, b"no pem here"), Err(CaFileProblem::NoCertificates));
        assert_eq!(add_pem_roots(&mut roots, b""), Err(CaFileProblem::Empty));
        let broken = b"-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n";
        assert_eq!(add_pem_roots(&mut roots, broken), Err(CaFileProblem::Malformed));
        let unterminated = b"-----BEGIN CERTIFICATE-----\nMIIB\n";
        assert_eq!(add_pem_roots(&mut roots, unterminated), Err(CaFileProblem::Malformed));
    }

    #[test]
    fn a_ca_file_replaces_the_system_roots() {
        let scratch = Scratch::new("replaces");
        let path = scratch.path("ca.pem");
        std::fs::write(&path, CA).unwrap();
        let roots = Trust::from_ca_file(&path).load_roots().unwrap();
        assert_eq!(roots.len(), 1);
        assert_eq!(Trust::default(), Trust { system: true, ca_file: None });
    }

    #[test]
    fn unusable_ca_files_are_refused_with_the_reason() {
        assert!(matches!(
            Trust { system: false, ca_file: None }.load_roots(),
            Err(TlsError::NoTrustAnchors)
        ));
        let scratch = Scratch::new("unusable");
        let missing = scratch.path("missing.pem");
        assert_eq!(problem(&Trust::from_ca_file(&missing)), CaFileProblem::Unreadable);
        let directory = scratch.path("directory");
        std::fs::create_dir_all(&directory).unwrap();
        assert_eq!(problem(&Trust::from_ca_file(&directory)), CaFileProblem::NotRegularFile);
        let empty = scratch.path("empty.pem");
        std::fs::write(&empty, b"").unwrap();
        assert_eq!(problem(&Trust::from_ca_file(&empty)), CaFileProblem::Empty);
        let large = scratch.path("large.pem");
        let mut content = CA.to_vec();
        content.resize(MAX_CA_FILE_BYTES as usize + 1, b'\n');
        std::fs::write(&large, &content).unwrap();
        assert_eq!(problem(&Trust::from_ca_file(&large)), CaFileProblem::TooLarge);
        content.truncate(MAX_CA_FILE_BYTES as usize);
        std::fs::write(&large, &content).unwrap();
        assert_eq!(Trust::from_ca_file(&large).load_roots().unwrap().len(), 1);
        let key_only = scratch.path("key.pem");
        std::fs::write(&key_only, KEY).unwrap();
        assert_eq!(problem(&Trust::from_ca_file(&key_only)), CaFileProblem::NoCertificates);
    }

    /// Deterministic fuzz of the CA file parser: mutated, truncated, duplicated and
    /// spliced PEM never panics, and a successful parse never adds more certificates than
    /// the input has `BEGIN` markers.
    #[test]
    fn mutated_pem_never_panics() {
        let mut state = 0x9e37_79b9_7f4a_7c15_u64;
        let mut next = move || {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state
        };
        let seeds = [CA, LEAF, KEY];
        let mut input = Vec::with_capacity(4096);
        for round in 0..100_000_u32 {
            input.clear();
            let seed = seeds[(next() % 3) as usize];
            input.extend_from_slice(seed);
            mutate(&mut input, &mut next, seeds[(round % 3) as usize]);
            let mut roots = RootCertStore::empty();
            if let Ok(count) = add_pem_roots(&mut roots, &input) {
                let markers = input.windows(11).filter(|w| w == b"-----BEGIN ").count();
                assert!(count <= markers && roots.len() == count);
            }
        }
    }

    fn mutate(input: &mut Vec<u8>, next: &mut impl FnMut() -> u64, other: &[u8]) {
        let len = input.len().max(1) as u64;
        match next() % 5 {
            0 => {
                for _ in 0..1 + next() % 4 {
                    let at = (next() % len) as usize;
                    if let Some(byte) = input.get_mut(at) {
                        *byte ^= 1 << (next() % 8);
                    }
                }
            }
            1 => input.truncate((next() % len) as usize),
            2 => {
                let copy = input.clone();
                input.extend_from_slice(&copy);
            }
            3 => {
                let cut = (next() % len) as usize;
                input.truncate(cut);
                let from = (next() % other.len() as u64) as usize;
                input.extend_from_slice(other.get(from..).unwrap_or_default());
            }
            _ => {
                let at = (next() % len) as usize;
                input.insert(at.min(input.len()), (next() & 0xff) as u8);
            }
        }
    }
}
