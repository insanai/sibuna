//! The revoked certificates of the local authority and its revocation lists (SID 0021).
//!
//! ```text
//! STORAGE/local/
//!   revoked/SERIAL              one file per revoked certificate, mode 0600:
//!                               "REVOKED_AT DROP_AFTER NAME"
//!   intermediate.previous.pem   the intermediate before the present one
//!   crl.der                     the list of the present intermediate, mode 0644
//!   crl.pem                     the lists of every living intermediate, mode 0644
//! ```
//!
//! An entry is a file of its own, so nothing here needs a lock: an entry is created by
//! one rename and removed by one unlink, also when several nodes share the directory.
//! A list is signed by the issuer of the certificates it speaks for. A leaf of the
//! intermediate that was replaced may still live, so that intermediate signs a list of
//! its own until it expires. Every list holds every entry.

use std::fs;
use std::path::{Path, PathBuf};

use super::{BACKDATE, INTERMEDIATE_NAME, LocalAuthority, Signer};
use crate::store::{create_private_dir, read_bounded, set_mode, write_private};
use crate::{Error, crl, pem, x509};

/// The most revoked certificates that the directory holds.
pub const MAX_REVOKED: usize = 1024;
/// The validity of a revocation list, in seconds: one day.
pub const CRL_LIFETIME: u64 = 86_400;
/// How long the entry of a certificate that the storage does not hold stays: the
/// longest life of a leaf, two days, and the minute by which a validity starts early.
pub const LONGEST_LEAF: u64 = 172_800 + BACKDATE;

/// One revoked certificate.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Revoked {
    /// The serial number of the certificate.
    pub serial: u64,
    /// When it was revoked, in seconds since 1970.
    pub revoked_at: u64,
    /// The time after which the entry is dropped: the certificate has expired then.
    pub drop_after: u64,
    /// The name of the certificate, or `-` when it is not known.
    pub name: String,
}

fn failure(path: &Path, what: impl std::fmt::Display) -> Error {
    Error::revocation(format!("{}: {what}.", path.display()))
}

/// The serial number that 1 to 16 hexadecimal digits spell, as `show certs` and
/// `openssl x509 -serial` print it. Returns `None` for anything else, and for zero,
/// which no certificate has.
pub fn parse_serial(text: &str) -> Option<u64> {
    let well_formed =
        (1..=16).contains(&text.len()) && text.bytes().all(|b| b.is_ascii_hexdigit());
    u64::from_str_radix(text, 16).ok().filter(|serial| well_formed && *serial != 0)
}

/// The serial number of a certificate as a number, when it fits 64 bits. Every
/// certificate of the local authority has such a serial.
pub fn serial_of(certificate: &x509::Certificate) -> Option<u64> {
    let digits = match certificate.serial.as_slice() {
        [0, rest @ ..] => rest,
        other => other,
    };
    (digits.len() <= 8).then(|| digits.iter().fold(0, |n, &byte| (n << 8) | u64::from(byte)))
}

/// Reads the line of an entry file.
fn parse_entry(serial: u64, line: &str) -> Option<Revoked> {
    let mut words = line.split_ascii_whitespace();
    let revoked_at = words.next()?.parse().ok()?;
    let drop_after = words.next()?.parse().ok()?;
    let name = words.next().unwrap_or("-").to_owned();
    Some(Revoked { serial, revoked_at, drop_after, name })
}

impl LocalAuthority {
    fn revoked_dir(&self) -> PathBuf {
        self.directory.join("revoked")
    }

    fn entry_path(&self, serial: u64) -> PathBuf {
        self.revoked_dir().join(format!("{serial:016x}"))
    }

    /// The path of the revocation list of the present intermediate, in DER.
    pub fn crl_path(&self) -> PathBuf {
        self.directory.join("crl.der")
    }

    /// The path of the revocation lists of every living intermediate, in PEM.
    pub fn crl_pem_path(&self) -> PathBuf {
        self.directory.join("crl.pem")
    }

    /// Whether the certificate with this serial number is revoked. A look at one file.
    pub fn is_revoked(&self, serial: u64) -> bool {
        self.entry_path(serial).exists()
    }

    /// Whether the leaf of the chain `chain_pem` is revoked.
    pub fn chain_is_revoked(&self, chain_pem: &str) -> bool {
        let leaf = pem::decode("CERTIFICATE", chain_pem)
            .and_then(|chain| chain.first().and_then(|der| x509::read(der)));
        leaf.as_ref().and_then(serial_of).is_some_and(|serial| self.is_revoked(serial))
    }

    /// The revoked certificates, sorted by serial number. An entry whose certificate
    /// has expired at `now` is removed from the directory and left out. At most
    /// [`MAX_REVOKED`] entries are read; files with other names are ignored. Fails with
    /// `ACME016` when the directory cannot be read.
    pub fn revoked(&self, now: u64) -> Result<Vec<Revoked>, Error> {
        let directory = self.revoked_dir();
        let listing = match fs::read_dir(&directory) {
            Ok(listing) => listing,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(error) => return Err(failure(&directory, error)),
        };
        let mut entries = Vec::new();
        for file in listing.flatten() {
            let name = file.file_name();
            let serial = name.to_str().filter(|name| name.len() == 16).and_then(parse_serial);
            let Some(serial) = serial else { continue };
            let line = read_bounded(&file.path()).ok().flatten();
            let Some(entry) = line.and_then(|line| parse_entry(serial, &line)) else { continue };
            if entry.drop_after < now {
                let _ = fs::remove_file(file.path());
                continue;
            }
            entries.push(entry);
            if entries.len() == MAX_REVOKED {
                break;
            }
        }
        entries.sort_by_key(|entry| entry.serial);
        Ok(entries)
    }

    /// Revokes the certificate with the serial number `serial` at `now`. `not_after`
    /// is the end of its validity, or `None` when the certificate is not at hand: the
    /// entry then stays for the longest life of a leaf. `name` is kept for the
    /// operator. A certificate that is revoked already keeps its entry. The lists are
    /// not written here; see [`LocalAuthority::refresh_crl`].
    ///
    /// Fails with `ACME016` when the entry cannot be written, or when the directory
    /// holds [`MAX_REVOKED`] entries of certificates that have not expired.
    pub fn revoke(
        &self,
        serial: u64,
        not_after: Option<u64>,
        name: &str,
        now: u64,
    ) -> Result<Revoked, Error> {
        let known = self.revoked(now)?;
        if let Some(entry) = known.iter().find(|entry| entry.serial == serial) {
            return Ok(entry.clone());
        }
        let directory = self.revoked_dir();
        if known.len() >= MAX_REVOKED {
            return Err(Error::revocation(format!(
                "{}: the directory holds {MAX_REVOKED} revoked certificates that have not \
                 expired, and takes no more.",
                directory.display()
            )));
        }
        create_private_dir(&directory).map_err(|error| failure(&directory, error))?;
        let plain = !name.is_empty() && name.bytes().all(|byte| byte.is_ascii_graphic());
        let entry = Revoked {
            serial,
            revoked_at: now,
            drop_after: not_after.unwrap_or(now + LONGEST_LEAF),
            name: if plain { name.to_owned() } else { "-".to_owned() },
        };
        let path = self.entry_path(serial);
        let line = format!("{} {} {}\n", entry.revoked_at, entry.drop_after, entry.name);
        write_private(&path, &line).map_err(|error| failure(&path, error.message))?;
        Ok(entry)
    }

    /// The intermediate before the present one, while it lives and the present root
    /// signed it. A file of an intermediate that has expired is removed.
    fn previous(&self, root: &Signer, now: u64) -> Option<Signer> {
        let path = self.directory.join(super::PREVIOUS);
        let found = read_bounded(&path).ok().flatten().as_deref().and_then(Signer::parse)?;
        let ours = found.fields.authority_key_id == root.key_id();
        if ours && found.fields.not_after > now {
            return Some(found);
        }
        let _ = fs::remove_file(&path);
        None
    }

    /// The list of `signer` at `now`, in DER.
    fn list(
        &self,
        signer: &Signer,
        revoked: &[Revoked],
        number: u64,
        now: u64,
    ) -> Result<Vec<u8>, Error> {
        let entries = revoked
            .iter()
            .map(|entry| crl::Entry { serial: entry.serial, revoked_at: entry.revoked_at });
        let list = crl::List {
            issuer: INTERMEDIATE_NAME.to_owned(),
            this_update: now.saturating_sub(BACKDATE),
            next_update: (now + CRL_LIFETIME).min(signer.fields.not_after),
            number,
            authority_key_id: signer.key_id().to_vec(),
            entries: entries.collect(),
        };
        crl::write(&list, &signer.key)
    }

    /// Writes the revocation lists when they are due at `now`, and returns whether it
    /// wrote them. They are due when `crl.der` is missing or unreadable, when the
    /// present intermediate did not sign it, when it does not list exactly the revoked
    /// certificates, when half of its validity has passed, and when `crl.pem` does not
    /// hold one list for each living intermediate. `force` writes them in any case.
    ///
    /// The number of a list is `now`, and at least one more than the number of the
    /// list it replaces. Both files are written under a temporary name and renamed,
    /// with mode 0644. Fails with `ACME016`, or with `ACME011` when the intermediate
    /// cannot be loaded.
    pub fn refresh_crl(&self, now: u64, force: bool) -> Result<bool, Error> {
        let root = self.root(now)?;
        let present = self.intermediate(&root, now, now)?;
        let previous = self.previous(&root, now);
        let revoked = self.revoked(now)?;
        let (der_path, pem_path) = (self.crl_path(), self.crl_pem_path());
        let current = fs::read(&der_path).ok().and_then(|der| crl::read(&der, None));
        let blocks = read_bounded(&pem_path).ok().flatten();
        let blocks = blocks.and_then(|text| pem::decode(crl::LABEL, &text)).map_or(0, |b| b.len());
        let fresh = current.as_ref().is_some_and(|list| {
            let half = list.this_update + list.next_update.saturating_sub(list.this_update) / 2;
            let same = list
                .entries
                .iter()
                .map(|entry| entry.serial)
                .eq(revoked.iter().map(|entry| entry.serial));
            list.authority_key_id == present.key_id() && same && now < half
        });
        if fresh && !force && blocks == 1 + usize::from(previous.is_some()) {
            return Ok(false);
        }
        let number = now.max(current.map_or(0, |list| list.number.saturating_add(1)));
        let der = self.list(&present, &revoked, number, now)?;
        let mut text = pem::encode(crl::LABEL, &der);
        if let Some(previous) = &previous {
            text += &pem::encode(crl::LABEL, &self.list(previous, &revoked, number, now)?);
        }
        publish(&der_path, &der)?;
        write_private(&pem_path, &text).map_err(|error| failure(&pem_path, error.message))?;
        set_mode(&pem_path, 0o644).map_err(|error| failure(&pem_path, error))?;
        Ok(true)
    }
}

/// Writes bytes for every reader: under a temporary name, then renamed, mode 0644.
fn publish(path: &Path, bytes: &[u8]) -> Result<(), Error> {
    let temporary = crate::store::temporary(path);
    let written = fs::write(&temporary, bytes)
        .and_then(|()| set_mode(&temporary, 0o644))
        .and_then(|()| fs::rename(&temporary, path));
    written.map_err(|error| {
        let _ = fs::remove_file(&temporary);
        failure(path, error)
    })
}

#[cfg(test)]
mod tests;
