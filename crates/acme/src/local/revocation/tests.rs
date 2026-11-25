#![allow(clippy::unwrap_used)]
use std::os::unix::fs::PermissionsExt as _;
use std::process::Command;
use std::sync::atomic::{AtomicU32, Ordering};

use super::super::{INTERMEDIATE_LIFETIME, PREVIOUS};
use super::*;
use crate::Issued;

const NOW: u64 = 1_800_000_000;

struct Scratch(PathBuf);

impl Scratch {
    fn new() -> Self {
        static SERIAL: AtomicU32 = AtomicU32::new(0);
        let serial = SERIAL.fetch_add(1, Ordering::Relaxed);
        let name = format!("sibuna-acme-revoked-{}-{serial}", std::process::id());
        let path = std::env::temp_dir().join(name);
        let _ = fs::remove_dir_all(&path);
        Self(path)
    }

    fn file(&self, name: &str) -> PathBuf {
        self.0.join("local").join(name)
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

/// The leaf of an issued chain: its serial number and the end of its validity.
fn leaf(issued: &Issued) -> (u64, u64) {
    let blocks = pem::decode("CERTIFICATE", &issued.chain_pem).unwrap();
    let fields = x509::read(&blocks[0]).unwrap();
    (serial_of(&fields).unwrap(), fields.not_after)
}

/// The lists of `crl.pem`, in their order.
fn lists(scratch: &Scratch) -> Vec<crl::List> {
    let text = fs::read_to_string(scratch.file("crl.pem")).unwrap();
    let blocks = pem::decode(crl::LABEL, &text).unwrap();
    blocks.iter().map(|der| crl::read(der, None).unwrap()).collect()
}

#[test]
fn serial_numbers_are_hexadecimal_and_never_zero() {
    assert_eq!(parse_serial("1f"), Some(0x1f));
    assert_eq!(parse_serial("FFFFFFFFFFFFFFFF"), Some(u64::MAX));
    for text in ["", "0", "0000", "12345678901234567", "xyz", "-1", "+1", "1 "] {
        assert_eq!(parse_serial(text), None, "{text}");
    }
}

#[test]
fn an_entry_is_a_file_and_leaves_when_its_certificate_has_expired() {
    let scratch = Scratch::new();
    let authority = LocalAuthority::open(&scratch.0, NOW, &[]).unwrap();
    assert_eq!(authority.revoked(NOW).unwrap(), []);
    let issued = authority.issue(&["localhost"], 3600, NOW).unwrap();
    let (serial, not_after) = leaf(&issued);
    assert!(!authority.is_revoked(serial) && !authority.chain_is_revoked(&issued.chain_pem));
    let entry = authority.revoke(serial, Some(not_after), "localhost", NOW + 5).unwrap();
    let expected =
        Revoked { serial, revoked_at: NOW + 5, drop_after: not_after, name: "localhost".into() };
    assert_eq!(entry, expected);
    assert!(authority.is_revoked(serial) && authority.chain_is_revoked(&issued.chain_pem));
    let path = scratch.file("revoked").join(format!("{serial:016x}"));
    assert_eq!(fs::metadata(&path).unwrap().permissions().mode() & 0o777, 0o600);
    // A second revocation keeps the first entry.
    assert_eq!(authority.revoke(serial, None, "other", NOW + 9).unwrap(), expected);
    // A serial that the storage does not hold stays for the longest life of a leaf,
    // and a name that is not plain text is not written.
    let unknown = authority.revoke(0xabc, None, "two words", NOW).unwrap();
    assert_eq!((unknown.drop_after, unknown.name.as_str()), (NOW + LONGEST_LEAF, "-"));
    let serials = |now| -> Vec<u64> {
        authority.revoked(now).unwrap().iter().map(|entry| entry.serial).collect()
    };
    let mut both = vec![serial, 0xabc];
    both.sort_unstable();
    assert_eq!(serials(not_after), both);
    assert_eq!(serials(not_after + 1), [0xabc]);
    assert!(!path.exists() && !authority.is_revoked(serial));
    assert_eq!(serials(NOW + LONGEST_LEAF + 1), []);
    // A file with another name is no entry.
    fs::write(scratch.file("revoked").join("notes.txt"), "1 2 x\n").unwrap();
    assert_eq!(serials(NOW), []);
}

#[test]
fn the_directory_takes_a_bounded_number_of_entries() {
    let scratch = Scratch::new();
    let authority = LocalAuthority::open(&scratch.0, NOW, &[]).unwrap();
    let directory = scratch.file("revoked");
    fs::create_dir_all(&directory).unwrap();
    for serial in 1..=MAX_REVOKED as u64 {
        let line = format!("{NOW} {} -\n", NOW + 100);
        fs::write(directory.join(format!("{serial:016x}")), line).unwrap();
    }
    let full = authority.revoke(9_999_999, None, "-", NOW).unwrap_err();
    assert_eq!((full.code, full.title), ("ACME016", "REVOCATION LIST FAILED"));
    assert!(full.message.contains("1024"), "{}", full.message);
    // An entry that is there already is still answered, and time makes room.
    assert!(authority.revoke(7, None, "-", NOW).is_ok());
    assert!(authority.revoke(9_999_999, None, "-", NOW + 101).is_ok());
    assert_eq!(authority.revoked(NOW + 101).unwrap().len(), 1);
}

#[test]
fn the_list_is_written_when_it_is_due_and_its_number_grows() {
    let scratch = Scratch::new();
    let authority = LocalAuthority::open(&scratch.0, NOW, &[]).unwrap();
    assert!(authority.refresh_crl(NOW, false).unwrap());
    assert!(!authority.refresh_crl(NOW + 10, false).unwrap());
    let first = lists(&scratch);
    assert_eq!(first.len(), 1);
    assert_eq!((first[0].this_update, first[0].next_update), (NOW - 60, NOW + CRL_LIFETIME));
    assert_eq!((first[0].number, first[0].entries.len()), (NOW, 0));
    assert_eq!(first[0].issuer, INTERMEDIATE_NAME);
    for name in ["crl.der", "crl.pem"] {
        let mode = fs::metadata(scratch.file(name)).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o644, "{name}");
    }
    let der = fs::read(authority.crl_path()).unwrap();
    assert_eq!(crl::read(&der, None).as_ref(), first.first());
    // A new entry makes the list due at once.
    authority.revoke(0x51, None, "-", NOW + 20).unwrap();
    assert!(authority.refresh_crl(NOW + 20, false).unwrap());
    let second = lists(&scratch);
    let entry = crl::Entry { serial: 0x51, revoked_at: NOW + 20 };
    assert_eq!((second[0].number, second[0].entries.as_slice()), (NOW + 20, &[entry][..]));
    // Before half of the validity nothing is written, and after it the list is.
    let half = NOW + 20 - 60 + (CRL_LIFETIME + 60) / 2;
    assert!(!authority.refresh_crl(half - 1, false).unwrap());
    assert!(authority.refresh_crl(half, false).unwrap());
    // A clock that steps back still gives a larger number, and `force` writes.
    assert!(authority.refresh_crl(NOW + 30, true).unwrap());
    assert_eq!(lists(&scratch)[0].number, half + 1);
    // A missing or damaged file is written again.
    fs::write(authority.crl_path(), b"damaged").unwrap();
    assert!(authority.refresh_crl(NOW + 30, false).unwrap());
    fs::remove_file(authority.crl_pem_path()).unwrap();
    assert!(authority.refresh_crl(NOW + 30, false).unwrap());
    assert!(!authority.refresh_crl(NOW + 30, false).unwrap());
}

#[test]
fn the_replaced_intermediate_signs_a_list_until_it_expires() {
    let scratch = Scratch::new();
    let authority = LocalAuthority::open(&scratch.0, NOW, &[]).unwrap();
    let old = authority.issue(&["old.internal"], 172_800, NOW).unwrap();
    assert!(authority.refresh_crl(NOW, false).unwrap());
    assert!(!scratch.file(PREVIOUS).exists());
    // Five days later the intermediate is replaced. The one before it is kept.
    let later = NOW + 5 * 86_400;
    let new = authority.issue(&["new.internal"], 3600, later).unwrap();
    let mode = fs::metadata(scratch.file(PREVIOUS)).unwrap().permissions().mode();
    assert_eq!(mode & 0o777, 0o600);
    authority.revoke(leaf(&old).0, None, "old.internal", later).unwrap();
    assert!(authority.refresh_crl(later, false).unwrap());
    let both = lists(&scratch);
    assert_eq!(both.len(), 2);
    let signer = |issued: &Issued| {
        let blocks = pem::decode("CERTIFICATE", &issued.chain_pem).unwrap();
        let parts = x509::parts(&blocks[1]).unwrap();
        (parts.spki.to_vec(), x509::key_id(parts.spki).to_vec())
    };
    let text = fs::read_to_string(scratch.file("crl.pem")).unwrap();
    let blocks = pem::decode(crl::LABEL, &text).unwrap();
    // The first list is that of the present intermediate, the second that of the one
    // before. Each verifies with its own signer and holds the entry.
    for (block, issued) in blocks.iter().zip([&new, &old]) {
        let (key, key_id) = signer(issued);
        let list = crl::read(block, Some(&key)).unwrap();
        assert_eq!(list.authority_key_id, key_id);
        assert_eq!(list.entries.len(), 1);
    }
    assert!(crl::read(&blocks[0], Some(&signer(&old).0)).is_none());
    assert_eq!(both[1].next_update, later + CRL_LIFETIME);
    assert_eq!(fs::read(authority.crl_path()).unwrap(), blocks[0]);
    // In its last day the list of the old intermediate ends with it.
    let last_day = NOW + INTERMEDIATE_LIFETIME - 3600;
    assert!(authority.refresh_crl(last_day, false).unwrap());
    let both = lists(&scratch);
    assert_eq!(both[0].next_update, last_day + CRL_LIFETIME);
    assert_eq!(both[1].next_update, NOW + INTERMEDIATE_LIFETIME);
    // Once the old intermediate has expired, its file and its list are gone.
    let after = NOW + INTERMEDIATE_LIFETIME + 1;
    assert!(authority.refresh_crl(after, false).unwrap());
    assert_eq!(lists(&scratch).len(), 1);
    assert!(!scratch.file(PREVIOUS).exists());
}

/// `openssl crl -verify` accepts the list with the intermediate, and `openssl verify
/// -crl_check` refuses the revoked leaf and accepts another. Skipped without `openssl`.
#[test]
fn openssl_verifies_the_list_and_refuses_the_revoked_leaf() {
    let _spawn = crate::SPAWN.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
    if crate::keygen::probe().is_err() {
        return;
    }
    let scratch = Scratch::new();
    let now =
        std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs();
    let authority = LocalAuthority::open(&scratch.0, now, &[]).unwrap();
    let revoked = authority.issue(&["gone.internal"], 3600, now).unwrap();
    let kept = authority.issue(&["kept.internal"], 3600, now).unwrap();
    let (serial, not_after) = leaf(&revoked);
    authority.revoke(serial, Some(not_after), "gone.internal", now).unwrap();
    assert!(authority.refresh_crl(now, false).unwrap());
    let file = |name: &str, text: &str| {
        let path = scratch.0.join(name);
        fs::write(&path, text).unwrap();
        path
    };
    let blocks = pem::decode("CERTIFICATE", &revoked.chain_pem).unwrap();
    let intermediate = file("int.pem", &pem::encode("CERTIFICATE", &blocks[1]));
    let said = |command: &mut Command| {
        let output = command.output().unwrap();
        let text = format!(
            "{}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        (output.status.success(), text)
    };
    for (path, form) in [(authority.crl_pem_path(), "PEM"), (authority.crl_path(), "DER")] {
        let mut command = Command::new("openssl");
        command.args(["crl", "-verify", "-noout", "-text", "-inform", form]);
        command.arg("-CAfile").arg(&intermediate).arg("-in").arg(&path);
        let (ok, text) = said(&mut command);
        assert!(ok && text.to_ascii_lowercase().contains("verify ok"), "{form}: {text}");
        assert!(text.contains("Version 2 (0x1)") && text.contains("CRL Number"), "{text}");
        let shown = format!("{serial:016X}");
        assert!(text.contains(shown.trim_start_matches('0')), "{form}: {text}");
    }
    let check = |issued: &Issued, name: &str| {
        let blocks = pem::decode("CERTIFICATE", &issued.chain_pem).unwrap();
        let leaf = file(name, &pem::encode("CERTIFICATE", &blocks[0]));
        let mut command = Command::new("openssl");
        command.args(["verify", "-x509_strict", "-crl_check"]);
        command.arg("-CAfile").arg(authority.root_path());
        command.arg("-untrusted").arg(&intermediate);
        command.arg("-CRLfile").arg(authority.crl_pem_path()).arg(&leaf);
        said(&mut command)
    };
    let (ok, text) = check(&kept, "kept.pem");
    assert!(ok, "{text}");
    let (ok, text) = check(&revoked, "gone.pem");
    assert!(!ok && text.contains("certificate revoked"), "{text}");
}
