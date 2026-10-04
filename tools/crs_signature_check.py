#!/usr/bin/env python3
"""Qualify native verification against the pinned archive and isolated GnuPG."""
import argparse
import base64
import hashlib
import json
from pathlib import Path
import subprocess
import tempfile
from urllib.request import urlopen

MAX_ARCHIVE = 8 * 1024 * 1024
SIGNED_TIME = 1791049738


def archive_bytes(directory, manifest, download):
    archive = directory / "release.tar.gz"
    if not archive.exists() and download:
        with urlopen(manifest["asset"], timeout=30) as response:
            data = response.read(MAX_ARCHIVE + 1)
        if len(data) > MAX_ARCHIVE or hashlib.sha256(data).hexdigest() != manifest["archive_sha256"]:
            raise ValueError("pinned archive download mismatch")
        archive.parent.mkdir(parents=True, exist_ok=True)
        archive.write_bytes(data)
    with archive.open("rb") as file:
        data = file.read(MAX_ARCHIVE + 1)
    if len(data) > MAX_ARCHIVE or hashlib.sha256(data).hexdigest() != manifest["archive_sha256"]:
        raise ValueError("pinned archive mismatch")
    return data


def decode_signature(source):
    lines = source.decode("ascii").splitlines()
    start = lines.index("") + 1
    encoded = "".join(line for line in lines[start:]
                      if line and not line.startswith(("=", "-----")))
    return bytearray(base64.b64decode(encoded, validate=True))


def armor_signature(data, checksum=""):
    encoded = base64.b64encode(data).decode("ascii")
    lines = "\n".join(encoded[i:i + 64] for i in range(0, len(encoded), 64))
    return ("-----BEGIN PGP SIGNATURE-----\n\n" + lines + "\n" + checksum +
            "-----END PGP SIGNATURE-----\n").encode("ascii")


def body_offset(data):
    if data[0] & 0x40:
        if data[1] < 192:
            return 2
        return 6 if data[1] == 255 else 3
    return 1 + (1, 2, 4)[data[0] & 3]


def gpg_check(home, archive, signature, fingerprint):
    subprocess.run(["gpg", "--batch", "--homedir", str(home), "--import",
                    "vendor/crs/security.asc"], check=True, capture_output=True, timeout=20)
    result = subprocess.run(["gpg", "--batch", "--homedir", str(home),
                             "--faked-system-time", str(SIGNED_TIME), "--status-fd", "1",
                             "--verify", str(signature), str(archive)],
                            check=True, capture_output=True, text=True, timeout=20)
    if "[GNUPG:] VALIDSIG " + fingerprint + " " not in result.stdout:
        raise ValueError("GnuPG did not authenticate the pinned primary signer")


def invoke(binary, directory, archive, signature, expected, error=None):
    archive_path = directory / "candidate.tar.gz"
    signature_path = directory / "candidate.asc"
    archive_path.write_bytes(archive)
    signature_path.write_bytes(signature)
    result = subprocess.run([str(binary), str(archive_path), str(signature_path), str(SIGNED_TIME)],
                            capture_output=True, text=True, timeout=20)
    if error is None:
        if result.returncode != 0 or result.stdout != expected:
            raise ValueError(f"native receipt mismatch: {result.stdout!r} {result.stderr!r}")
    elif result.returncode != 1 or result.stdout != "rejected " + error + "\n":
        raise ValueError(f"expected {error}, got {result.stdout!r} {result.stderr!r}")


def qualification(binary, directory, archive, signature, digest):
    expected = f"verified {digest} {SIGNED_TIME}\n"
    invoke(binary, directory, archive, signature, expected)
    data = decode_signature(signature)
    for crc in ("", "=malformed\n", "=AAAA\n"):
        invoke(binary, directory, archive, armor_signature(data, crc), expected)
    altered_archive = bytearray(archive)
    altered_archive[-1] ^= 1
    invoke(binary, directory, altered_archive, signature, expected, "InvalidSignature")
    # Preserve the digest prefix: this must fail full RSA padding/signature verification.
    altered_signature = data.copy()
    altered_signature[-1] ^= 1
    invoke(binary, directory, archive, armor_signature(altered_signature), expected,
           "InvalidSignature")
    offset = body_offset(data)
    weak = data.copy()
    weak[offset + 3] = 2  # SHA-1 is not an archive-authentication algorithm in this profile.
    invoke(binary, directory, archive, armor_signature(weak), expected, "UnsupportedSignature")
    wrong_issuer = data.copy()
    wrong_issuer[offset + 9] ^= 1  # First fingerprint byte in the pin's first hashed subpacket.
    invoke(binary, directory, archive, armor_signature(wrong_issuer), expected, "WrongIssuer")
    invoke(binary, directory, archive, armor_signature(data + b"\xc2\x00"), expected,
           "InvalidSignature")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", type=Path)
    parser.add_argument("--download", action="store_true")
    parser.add_argument("--source-dir", type=Path, default=Path(".zig-cache/crs-review"))
    args = parser.parse_args()
    manifest = json.loads(Path("vendor/crs/provenance.json").read_text())
    archive = archive_bytes(args.source_dir, manifest, args.download)
    signature = Path("vendor/crs/release.tar.gz.asc").read_bytes()
    signature_entry = next(row for row in manifest["files"] if row["path"] == "release.tar.gz.asc")
    if hashlib.sha256(signature).hexdigest() != signature_entry["sha256"]:
        raise ValueError("signature fixture mismatch")
    with tempfile.TemporaryDirectory(prefix="sibuna-crs-signature-") as temporary:
        directory = Path(temporary)
        home = directory / "gpg"
        home.mkdir(mode=0o700)
        original_archive = directory / "original.tar.gz"
        original_signature = directory / "original.asc"
        original_archive.write_bytes(archive)
        original_signature.write_bytes(signature)
        gpg_check(home, original_archive, original_signature, manifest["signature_fingerprint"])
        qualification(args.binary.resolve(), directory, archive, signature, manifest["archive_sha256"])
    print("Native RSA verification matches the pinned GnuPG receipt; 9 acceptance/rejection cases pass.")


if __name__ == "__main__":
    main()
