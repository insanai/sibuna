//! Certificates for a TLS listener, loaded the way HAProxy loads `crt`.
//!
//! A bundle is one PEM file with a certificate chain, leaf first, and its private key. We
//! accept single files and directories of `*.pem` files. The first bundle is the default
//! certificate. The DNS names in each leaf select a bundle by the server name of the
//! handshake, exact names before wildcards.

use std::collections::HashMap;
use std::io::{self, Read};
use std::path::Path;
use std::sync::Arc;

use rustls::pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject};
use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::CertifiedKey;
use sibuna_lb::TlsOptions;

use crate::Error;

const MAX_PEM: usize = 256 * 1024;
const MAX_BUNDLES: usize = 256;
const MAX_OCSP: usize = 64 * 1024;

/// Reads a PEM file of at most 256 KiB.
fn pem(path: &Path) -> io::Result<Vec<u8>> {
    let mut bytes = Vec::new();
    let named = |error: io::Error| io::Error::new(error.kind(), named(path, error));
    let file = std::fs::File::open(path).map_err(named)?;
    file.take(MAX_PEM as u64 + 1).read_to_end(&mut bytes).map_err(named)?;
    if bytes.len() > MAX_PEM {
        return Err(io::Error::other(format!("{}: TLS PEM exceeds 256 KiB", path.display())));
    }
    Ok(bytes)
}

fn named(path: &Path, error: impl std::fmt::Display) -> Error {
    format!("{}: {error}", path.display()).into()
}

/// Builds a checked key from PEM bytes. The key must match the leaf certificate.
fn bundle(path: &Path, chain: &[u8], key: &[u8]) -> Result<Arc<CertifiedKey>, Error> {
    let certs = CertificateDer::pem_slice_iter(chain)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| named(path, e))?;
    if certs.is_empty() {
        return Err(named(path, "no certificate found"));
    }
    let key = PrivateKeyDer::from_pem_slice(key).map_err(|e| named(path, e))?;
    let provider = rustls::crypto::ring::default_provider();
    let mut certified =
        CertifiedKey::from_der(certs, key, &provider).map_err(|e| named(path, e))?;
    certified.ocsp = stapled(path)?;
    Ok(Arc::new(certified))
}

/// The OCSP response to staple to a certificate: the DER file `<certificate>.ocsp`, when
/// it exists, as in HAProxy. Whoever renews the certificate refreshes this file and
/// reloads. We do not fetch or check the response.
fn stapled(certificate: &Path) -> Result<Option<Vec<u8>>, Error> {
    let mut name = certificate.as_os_str().to_owned();
    name.push(".ocsp");
    let path = Path::new(&name);
    let file = match std::fs::File::open(path) {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(named(path, error)),
    };
    let mut bytes = Vec::new();
    file.take(MAX_OCSP as u64 + 1).read_to_end(&mut bytes).map_err(|e| named(path, e))?;
    if bytes.is_empty() || bytes.len() > MAX_OCSP {
        return Err(named(path, "an OCSP response has 1 to 65536 bytes"));
    }
    Ok(Some(bytes))
}

/// Builds the verifier of client certificates from a PEM file of CA certificates.
pub(crate) fn client_verifier(
    spec: &TlsOptions,
    provider: Arc<rustls::crypto::CryptoProvider>,
) -> Result<Option<Arc<dyn rustls::server::danger::ClientCertVerifier>>, Error> {
    let Some(file) = &spec.client_ca else { return Ok(None) };
    let path = Path::new(file);
    let mut roots = rustls::RootCertStore::empty();
    for certificate in CertificateDer::pem_slice_iter(&pem(path)?) {
        roots.add(certificate.map_err(|e| named(path, e))?).map_err(|e| named(path, e))?;
    }
    if roots.is_empty() {
        return Err(named(path, "no CA certificate found"));
    }
    let builder =
        rustls::server::WebPkiClientVerifier::builder_with_provider(Arc::new(roots), provider);
    let builder = if spec.client_optional { builder.allow_unauthenticated() } else { builder };
    Ok(Some(builder.build().map_err(|e| named(path, e))?))
}

/// The bundle paths named by `crt`, directories expanded to their sorted `*.pem` files.
fn bundle_paths(crt: &[String]) -> Result<Vec<std::path::PathBuf>, Error> {
    let mut paths = Vec::new();
    for entry in crt {
        let entry = Path::new(entry);
        if entry.is_dir() {
            let mut files = Vec::new();
            for file in std::fs::read_dir(entry).map_err(|e| named(entry, e))? {
                let file = file.map_err(|e| named(entry, e))?.path();
                if file.extension().is_some_and(|ext| ext == "pem") && file.is_file() {
                    files.push(file);
                }
            }
            if files.is_empty() {
                return Err(named(entry, "the directory holds no .pem file"));
            }
            files.sort();
            paths.extend(files);
        } else {
            paths.push(entry.to_path_buf());
        }
        if paths.len() > MAX_BUNDLES {
            return Err("a TLS listener loads at most 256 certificates".into());
        }
    }
    Ok(paths)
}

/// Selects a certificate by server name. Without a match it presents the default
/// certificate, or refuses the handshake under `strict_sni`.
#[derive(Debug)]
pub(crate) struct Certificates {
    default: Arc<CertifiedKey>,
    exact: HashMap<String, Arc<CertifiedKey>>,
    wildcard: HashMap<String, Arc<CertifiedKey>>,
    strict: bool,
}

impl Certificates {
    /// Loads every bundle of a listener. The first loaded bundle becomes the default.
    pub fn load(spec: &TlsOptions) -> Result<Self, Error> {
        let mut bundles = Vec::new();
        if let (Some(cert), Some(key)) = (&spec.cert_file, &spec.key_file) {
            let path = Path::new(cert);
            bundles.push(bundle(path, &pem(path)?, &pem(Path::new(key))?)?);
        }
        for path in bundle_paths(&spec.crt)? {
            let bytes = pem(&path)?;
            bundles.push(bundle(&path, &bytes, &bytes)?);
        }
        let default = bundles.first().cloned().ok_or("a TLS listener needs a certificate")?;
        let mut exact = HashMap::new();
        let mut wildcard = HashMap::new();
        for certified in &bundles {
            let Some(leaf) = certified.cert.first() else { continue };
            for name in dns_names(leaf) {
                let name = name.to_ascii_lowercase();
                // The first bundle that names a host keeps it, as in HAProxy.
                match name.strip_prefix("*.") {
                    Some(parent) => wildcard.entry(parent.to_owned()).or_insert(certified.clone()),
                    None => exact.entry(name).or_insert(certified.clone()),
                };
            }
        }
        Ok(Self { default, exact, wildcard, strict: spec.strict_sni })
    }

    fn select(&self, name: Option<&str>) -> Option<Arc<CertifiedKey>> {
        let Some(name) = name else { return Some(self.default.clone()) };
        let name = name.trim_end_matches('.').to_ascii_lowercase();
        if let Some(found) = self.exact.get(&name) {
            return Some(found.clone());
        }
        if let Some((_, parent)) = name.split_once('.')
            && let Some(found) = self.wildcard.get(parent)
        {
            return Some(found.clone());
        }
        (!self.strict).then(|| self.default.clone())
    }
}

impl ResolvesServerCert for Certificates {
    fn resolve(&self, hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        self.select(hello.server_name())
    }
}

/// One DER element: its tag, its content and the bytes after it.
fn element(der: &[u8]) -> Option<(u8, &[u8], &[u8])> {
    let (&tag, rest) = der.split_first()?;
    let (&first, rest) = rest.split_first()?;
    let (length, rest) = if first < 0x80 {
        (usize::from(first), rest)
    } else {
        let count = usize::from(first & 0x7f);
        if count == 0 || count > 4 || rest.len() < count {
            return None;
        }
        let length = rest[..count].iter().fold(0usize, |n, &b| (n << 8) | usize::from(b));
        (length, &rest[count..])
    };
    (rest.len() >= length).then(|| (tag, &rest[..length], &rest[length..]))
}

/// The children of a constructed DER element.
fn children(mut content: &[u8]) -> impl Iterator<Item = (u8, &[u8])> {
    std::iter::from_fn(move || {
        let (tag, value, rest) = element(content)?;
        content = rest;
        Some((tag, value))
    })
}

/// The dNSName entries of a certificate's subjectAltName extension. A certificate we
/// cannot walk yields no name, so it can only serve as the default.
fn dns_names(certificate: &CertificateDer<'_>) -> Vec<String> {
    const SUBJECT_ALT_NAME: &[u8] = &[0x55, 0x1d, 0x11];
    let mut names = Vec::new();
    let Some((0x30, certificate, _)) = element(certificate.as_ref()) else { return names };
    let Some((0x30, tbs, _)) = element(certificate) else { return names };
    // Extensions are the explicitly tagged field [3] of TBSCertificate.
    let Some((_, extensions)) = children(tbs).find(|(tag, _)| *tag == 0xa3) else {
        return names;
    };
    let Some((0x30, extensions, _)) = element(extensions) else { return names };
    for (_, extension) in children(extensions) {
        let mut fields = children(extension);
        if fields.next() != Some((0x06, SUBJECT_ALT_NAME)) {
            continue;
        }
        // The value is the last field. An optional critical flag may precede it.
        let Some((0x04, value)) = fields.last() else { continue };
        let Some((0x30, general_names, _)) = element(value) else { continue };
        for (tag, name) in children(general_names) {
            if tag == 0x82
                && let Ok(name) = std::str::from_utf8(name)
            {
                names.push(name.to_owned());
            }
        }
    }
    names
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    fn fixture(name: &str) -> String {
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../tls/tests/data")
            .join(name)
            .to_str()
            .unwrap()
            .to_owned()
    }

    fn separate() -> TlsOptions {
        TlsOptions {
            crt: Vec::new(),
            cert_file: Some(fixture("localhost.pem")),
            key_file: Some(fixture("localhost.key")),
            ..TlsOptions::default()
        }
    }

    #[test]
    fn reads_dns_names_from_the_leaf() {
        let leaf = CertificateDer::from_pem_file(fixture("localhost.pem")).unwrap();
        assert!(dns_names(&leaf).iter().any(|name| name == "localhost"));
    }

    #[test]
    fn rejects_truncated_and_oversized_der_lengths() {
        assert!(element(&[0x30]).is_none());
        assert!(element(&[0x30, 0x05, 1, 2]).is_none());
        assert!(element(&[0x30, 0x85, 1, 1, 1, 1, 1]).is_none());
        assert!(element(&[0x30, 0x80]).is_none());
        assert_eq!(element(&[0x04, 0x01, 7, 9]), Some((0x04, &[7][..], &[9][..])));
    }

    #[test]
    fn combined_bundle_and_directory_select_by_server_name() {
        let dir = std::env::temp_dir().join(format!("sibuna-certs-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let mut combined = std::fs::read(fixture("localhost.pem")).unwrap();
        combined.extend(std::fs::read(fixture("localhost.key")).unwrap());
        std::fs::write(dir.join("site.pem"), &combined).unwrap();
        std::fs::write(dir.join("notes.txt"), b"ignored").unwrap();
        let mut spec = separate();
        spec.cert_file = None;
        spec.key_file = None;
        spec.crt = vec![dir.to_str().unwrap().to_owned()];
        let certs = Certificates::load(&spec).unwrap();
        assert!(certs.select(Some("LOCALHOST.")).is_some());
        assert!(certs.select(Some("unknown.example")).is_some());
        spec.strict_sni = true;
        let strict = Certificates::load(&spec).unwrap();
        assert!(strict.select(Some("unknown.example")).is_none());
        assert!(strict.select(Some("localhost")).is_some());
        assert!(strict.select(None).is_some());
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn mismatched_key_names_the_file() {
        let mut spec = separate();
        spec.key_file = Some(fixture("ca.pem"));
        let error = Certificates::load(&spec).unwrap_err().to_string();
        assert!(error.contains("localhost.pem"), "{error}");
    }

    #[test]
    fn an_ocsp_file_beside_a_bundle_is_stapled() {
        let dir = std::env::temp_dir().join(format!("sibuna-ocsp-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let bundle = dir.join("site.pem");
        let mut pem = std::fs::read(fixture("localhost.pem")).unwrap();
        pem.extend(std::fs::read(fixture("localhost.key")).unwrap());
        std::fs::write(&bundle, pem).unwrap();
        let spec =
            TlsOptions { crt: vec![bundle.to_str().unwrap().to_owned()], ..TlsOptions::default() };
        assert_eq!(Certificates::load(&spec).unwrap().select(None).unwrap().ocsp, None);
        std::fs::write(dir.join("site.pem.ocsp"), b"response").unwrap();
        let stapled = Certificates::load(&spec).unwrap().select(None).unwrap();
        assert_eq!(stapled.ocsp.as_deref(), Some(&b"response"[..]));
        // An empty file is a mistake, not a response.
        std::fs::write(dir.join("site.pem.ocsp"), b"").unwrap();
        let error = Certificates::load(&spec).err().unwrap().to_string();
        assert!(error.contains("site.pem.ocsp"), "{error}");
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
