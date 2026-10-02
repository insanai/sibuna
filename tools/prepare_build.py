#!/usr/bin/env python3
"""Create Zig 0.16's ZIP-fetch scratch directory on a clean compiler cache."""
import json
from pathlib import Path
import re
import subprocess
import sys


def prepare(executable="zig"):
    output = subprocess.check_output([str(executable), "env"], text=True)
    quoted = re.search(r'\.global_cache_dir = ("(?:[^"\\]|\\.)*")', output).group(1)
    scratch = Path(json.loads(quoted)) / "tmp"
    scratch.mkdir(parents=True, exist_ok=True)
    print(f"zig-cache: {scratch}")


if __name__ == "__main__":
    prepare(sys.argv[1] if len(sys.argv) > 1 else "zig")
