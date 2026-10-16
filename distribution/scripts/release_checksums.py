#!/usr/bin/env python3
"""Write SHA256SUMS over every public release asset in a directory."""
import hashlib
from pathlib import Path
import sys

root = Path(sys.argv[1])
suffixes = ('.tar.gz', '.zip', '.deb', '.rpm', '.pkg.tar.zst', '.pkg', '.tgz', '.rb')
files = sorted(path for path in root.iterdir() if path.is_file()
               and (path.name.endswith(suffixes) or path.name == 'IMAGE-DIGEST.txt'))
if not files:
    raise SystemExit('release-checksums: no release assets')
(root / 'SHA256SUMS').write_text(
    ''.join(f'{hashlib.sha256(path.read_bytes()).hexdigest()}  {path.name}\n' for path in files))
print(f'release-checksums: {len(files)} assets')
