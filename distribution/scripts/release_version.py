#!/usr/bin/env python3
"""The release version, and the checks that the tag, the chart and a binary agree with it.

The version is `[workspace.package] version` in the root Cargo.toml. With `--check` the
script refuses a tag (GITHUB_REF) or a Helm chart that names another version; with
`--binary PATH` it also runs the executable's `--version`. `--print` prints the version.
"""
import argparse
import os
from pathlib import Path
import re
import subprocess
import tomllib

ROOT = Path(__file__).resolve().parents[2]
CHART = ROOT / 'distribution/helm/sibuna/Chart.yaml'


def version():
    """The workspace version, for example 1.0.0-beta.1."""
    with open(ROOT / 'Cargo.toml', 'rb') as manifest:
        return tomllib.load(manifest)['workspace']['package']['version']


def check(binary=None):
    expected = version()
    ref = os.environ.get('GITHUB_REF', '')
    if ref.startswith('refs/tags/') and ref != f'refs/tags/v{expected}':
        raise SystemExit(f'release-version: tag {ref} does not match version {expected}')
    chart = CHART.read_text()
    for field in ('version', 'appVersion'):
        value = re.search(r'^' + field + r':\s*"?([^"\s]+)"?\s*$', chart, re.MULTILINE)
        if value is None or value.group(1) != expected:
            raise SystemExit(f'release-version: chart {field} must be {expected}')
    if binary is not None:
        output = subprocess.run([str(binary), '--version'], capture_output=True, text=True,
                                check=True, timeout=30)
        reported = (output.stdout + output.stderr).strip()
        if reported != f'sibuna {expected}':
            raise SystemExit(f'release-version: binary reports {reported!r}')
    print(f'release-version: {expected}')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('--print', action='store_true', help='print the version')
    group.add_argument('--check', action='store_true', help='check tag, chart and binary')
    parser.add_argument('--binary', type=Path, help='with --check: the executable to run')
    args = parser.parse_args()
    if args.print:
        print(version())
    else:
        check(args.binary)
