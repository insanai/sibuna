#!/usr/bin/env python3
"""Refuse a release tag that differs from the package and embedded source offer."""
import os
from pathlib import Path
import re
import subprocess

ROOT = Path(__file__).resolve().parents[1]


def version():
    return re.search(r'\.version = "([0-9]+\.[0-9]+\.[0-9]+)"',
                     (ROOT / "build.zig.zon").read_text()).group(1)


if __name__ == "__main__":
    expected = version()
    ref = os.environ.get("GITHUB_REF", "")
    if ref.startswith("refs/tags/") and ref != f"refs/tags/v{expected}":
        raise SystemExit(f"Tag {ref} does not match version {expected}")
    shell = (ROOT / "apps/console-ui/web/shell.html").read_text()
    if f"https://github.com/insanai/sibuna/tree/v{expected}" not in shell:
        raise SystemExit("Console source offer must name the release tag")
    chart = ROOT / "distribution/helm/sibuna/Chart.yaml"
    guix = ROOT / "guix.scm"
    if guix.exists() and f'(version "{expected}")' not in guix.read_text():
        raise SystemExit("Local Guix candidate version must match the source release")
    if chart.exists():
        for field in ("version", "appVersion"):
            value = re.search(r'^' + field + r':\s*"?([^"\s]+)"?\s*$', chart.read_text(), re.MULTILINE)
            if value is None or value.group(1) != expected:
                raise SystemExit(f"Initial chart {field} must match release {expected}")
    if len(os.sys.argv) > 1 and os.sys.argv[1] != "--print-version":
        actual = subprocess.check_output([os.sys.argv[1], "--version"],
                                         stderr=subprocess.STDOUT, text=True).strip()
        if actual != f"sibuna {expected}":
            raise SystemExit(f"Binary reports {actual!r}, expected sibuna {expected}")
    print(expected if "--print-version" in os.sys.argv else f"release-version: {expected}")
