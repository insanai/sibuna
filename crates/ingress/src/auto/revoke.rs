//! The revocation of a certificate of the local authority, for the admin command
//! `revoke cert` (SID 0021).
//!
//! ```text
//!   revoke cert NAME|SERIAL
//!     |  NAME: the stored certificate of the managed name gives the serial number
//!     |  write STORAGE/local/revoked/SERIAL, write the revocation lists
//!     v  wake the certificate thread
//!   the thread finds the served certificate revoked and issues a new one
//! ```

use std::path::Path;

use sibuna_acme::local::{self, LocalAuthority, Revoked};
use sibuna_acme::store::Store;
use sibuna_acme::{Error, pem, x509};

use super::Automatic;

/// Why `revoke cert` revoked nothing.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RevokeError {
    /// The word names nothing that the local authority can revoke. The text says why.
    Nothing(String),
    /// The entry or the revocation list could not be written.
    Failed(Error),
}

impl From<Error> for RevokeError {
    fn from(error: Error) -> Self {
        Self::Failed(error)
    }
}

impl Automatic {
    /// Revokes a certificate of the local authority at `now`, in seconds since 1970.
    /// `target` is a managed name of the local authority, whose stored certificate is
    /// revoked, or a serial number of 1 to 16 hexadecimal digits. A word that is both
    /// is taken as the name. The entry and the revocation lists are written before the
    /// call returns, and the certificate thread is woken: it replaces a served
    /// certificate that is revoked.
    ///
    /// Reads and writes files of the storage directory. Returns the entry. Fails with
    /// [`RevokeError::Nothing`] when the storage has no local authority, when the name
    /// has no certificate of it, or when the word is neither a name nor a serial.
    pub fn revoke(&self, target: &str, now: u64) -> Result<Revoked, RevokeError> {
        let options = &self.shared.options;
        let storage = Path::new(&options.storage);
        if local::read_root(storage)?.is_none() {
            let text = format!("The storage {} has no local authority.", storage.display());
            return Err(RevokeError::Nothing(text));
        }
        let authority = LocalAuthority::open(storage, now, &options.internal.constraints)?;
        let name = target.to_ascii_lowercase();
        let managed = self.shared.names().iter().any(|known| known.local && known.name == name);
        let entry = if managed {
            let (serial, not_after) = stored_leaf(storage, &authority, &name)?;
            authority.revoke(serial, Some(not_after), &name, now)?
        } else if let Some(serial) = local::parse_serial(target) {
            authority.revoke(serial, None, "-", now)?
        } else {
            let text = format!(
                "`{target}` is no name that the local authority issues for here, and no \
                 serial number."
            );
            return Err(RevokeError::Nothing(text));
        };
        authority.refresh_crl(now, false)?;
        self.shared.notify();
        Ok(entry)
    }
}

/// The serial number and the end of the validity of the stored certificate of `name`,
/// when the present root of the local authority stands behind it.
fn stored_leaf(
    storage: &Path,
    authority: &LocalAuthority,
    name: &str,
) -> Result<(u64, u64), RevokeError> {
    let stored = Store::open_local(storage)?.load_certificate(name)?;
    let leaf =
        stored.filter(|stored| authority.issued_here(&stored.chain_pem)).and_then(|stored| {
            let chain = pem::decode("CERTIFICATE", &stored.chain_pem)?;
            let fields = x509::read(chain.first()?)?;
            Some((local::serial_of(&fields)?, fields.not_after))
        });
    leaf.ok_or_else(|| {
        RevokeError::Nothing(format!("`{name}` has no certificate of the local authority yet."))
    })
}
