#!/usr/bin/env python3
"""Qualify the signed stock package, independent of a daemon update or activation."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import tempfile

from crs_signature_check import archive_bytes, SIGNED_TIME


def invoke(binary, directory, archive, signature, version, expected_error=None, configuration=None):
    archive_path = directory / "candidate.tar.gz"
    signature_path = directory / "candidate.asc"
    archive_path.write_bytes(archive)
    signature_path.write_bytes(signature)
    command = [str(binary), str(archive_path), str(signature_path), version, str(SIGNED_TIME)]
    if configuration is not None:
        configuration_path = directory / "operator.conf"
        configuration_path.write_text(configuration)
        command.append(str(configuration_path))
    result = subprocess.run(command, capture_output=True, text=True, timeout=60)
    if expected_error is not None:
        if result.returncode != 1 or result.stdout != "rejected " + expected_error + "\n":
            raise ValueError(f"package refusal mismatch: {result.stdout!r} {result.stderr!r}")
        return
    parts = result.stdout.split()
    conditions = "701" if configuration is None else "702"
    if result.returncode or len(parts) != 5 or parts[:3] != ["prepared", conditions, "6653"]:
        raise ValueError(f"private compilation mismatch: {result.stdout!r} {result.stderr!r}")
    if parts[3] != hashlib.sha256(archive).hexdigest() or not 0 < int(parts[4]) <= 64 * 1024 * 1024:
        raise ValueError("incorrect receipt or compiled memory bound")
    return int(parts[4])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", type=Path)
    parser.add_argument("--download", action="store_true")
    args = parser.parse_args()
    manifest = json.loads(Path("vendor/crs/provenance.json").read_text())
    archive = archive_bytes(Path(".zig-cache/crs-review"), manifest, args.download)
    signature = Path("vendor/crs/release.tar.gz.asc").read_bytes()
    with tempfile.TemporaryDirectory(prefix="sibuna-crs-package-") as temporary:
        directory = Path(temporary)
        binary = args.binary.resolve()
        used = invoke(binary, directory, archive, signature, "4.30.0")
        invoke(binary, directory, archive, signature, "4.31.0", "InvalidArchivePath")
        altered = bytearray(archive)
        altered[-1] ^= 1
        invoke(binary, directory, altered, signature, "4.30.0", "InvalidSignature")
        invoke(binary, directory, archive[:-1], signature, "4.30.0", "InvalidSignature")
        invoke(binary, directory, archive, signature, "4.30.0", configuration=
               'SecAction "id:123456,phase:1,nolog,pass,setvar:tx.operator_marker=present"')
        invoke(binary, directory, archive, signature, "4.30.0", "DuplicateId",
               'SecAction "id:901001,phase:1,pass"')
        invoke(binary, directory, archive, signature, "4.30.0", "UnknownDirective",
               'Include /etc/unreviewed.conf')
        invoke(binary, directory, archive, signature, "4.30.0", "OperatorConfigurationLimit",
               "#" * (64 * 1024 + 1))
    print(f"Signed package prepares all 701 conditions within {used} compiled bytes; "
          "staging/operator ownership and six refusal cases pass.")


if __name__ == "__main__":
    main()
