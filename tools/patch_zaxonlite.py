#!/usr/bin/env python3
"""Apply the reviewed 0.6.1 sealed-reader correction only to a generated build input."""
import difflib
import hashlib
from pathlib import Path
import sys


def patch(source, review, destination):
    original = source.read_bytes()
    expected = "dd81cb3bf63368e6ba2c2bc5380a409415c03de6dc5576f30ddae5def9889a18"
    if hashlib.sha256(original).hexdigest() != expected:
        raise SystemExit("Zaxonlite journal source changed; re-review the sealed-reader patch.")
    before = original.decode()
    old = "self.reader = segment.Reader.open("
    new = "self.reader = segment.Reader.openSealed("
    if before.count(old) != 1:
        raise SystemExit("Expected exactly one journal iterator reader.")
    after = before.replace(old, new)
    diff = "".join(difflib.unified_diff(before.splitlines(True), after.splitlines(True),
                                     fromfile="a/src/journal.zig", tofile="b/src/journal.zig"))
    if review.read_text() != diff:
        raise SystemExit("Reviewed Zaxonlite patch does not match the generated change.")
    destination.write_text(after)


if __name__ == "__main__":
    patch(*(Path(value) for value in sys.argv[1:]))
