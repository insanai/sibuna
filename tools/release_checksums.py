#!/usr/bin/env python3
"""Hash every public release artifact, without checksumming temporary metadata."""
import hashlib
from pathlib import Path
import sys

root = Path(sys.argv[1])
suffixes = ('.tar.gz', '.zip', '.deb', '.rpm', '.pkg.tar.zst', '.tgz', '.rb')
files = sorted(p for p in root.iterdir() if p.is_file() and (p.name.endswith(suffixes) or p.name == 'IMAGE-DIGEST.txt'))
if not files:
    raise SystemExit('no release artifacts')
(root / 'SHA256SUMS').write_text(''.join(f'{hashlib.sha256(p.read_bytes()).hexdigest()}  {p.name}\n' for p in files))
