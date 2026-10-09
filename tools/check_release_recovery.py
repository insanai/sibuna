#!/usr/bin/env python3
"""Requalify Homebrew without replacing source or bypassing other release gates."""
import argparse
import json
import re
import subprocess
import time

from check_release_version import ROOT, version
from release_targets import PLATFORMS


def api(path):
    return json.loads(subprocess.check_output(['gh', 'api', path]))


def require_gates(jobs, source_only=False):
    required = {'distribution-source'} if source_only else {
        'distribution-source', 'crs-conformance', 'crs-console', 'container-and-chart',
        *[f'build ({p["runner"]}, {p["package"]}, {p["target"]})' for p in PLATFORMS],
        *[f'native-packages ({p["runner"]}, {p["package"]}, {p["target"]})'
          for p in PLATFORMS if p['package'].startswith('linux-')],
    }
    for name in required:
        matches = [j for j in jobs if j['name'] == name]
        if len(matches) != 1 or matches[0]['conclusion'] != 'success':
            raise ValueError(f'successful original gate required: {name}')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('run_id')
    parser.add_argument('tag')
    parser.add_argument('--source-only', action='store_true')
    parser.add_argument('--wait', action='store_true')
    args = parser.parse_args()
    if not re.fullmatch(r'[0-9]+', args.run_id) or args.tag != f'v{version()}':
        raise SystemExit('numeric run ID and current application tag required')
    base = f'repos/insanai/sibuna/actions/runs/{args.run_id}'
    run = api(base)
    commit = subprocess.check_output(['git', 'rev-parse', f'{args.tag}^{{commit}}'],
                                     cwd=ROOT, text=True).strip()
    if (run['path'] != '.github/workflows/release.yml' or run['event'] != 'push' or
            run['head_branch'] != args.tag or run['head_sha'] != commit or
            run['head_repository']['full_name'] != 'insanai/sibuna'):
        raise SystemExit('original run must qualify this exact upstream tag/commit')
    subprocess.run(['git', 'merge-base', '--is-ancestor', commit, 'HEAD'], cwd=ROOT, check=True)
    # Only release orchestration and its documentation may change after the tag.
    allowed = {'.github/workflows/release.yml', '.github/workflows/release-recover.yml',
               '.github/workflows/distribution.yml', 'tools/check_release_recovery.py',
               'tools/test_release_recovery.py', 'docs/sid/records/0011-distribution-packages.typ',
               'distribution/README.md'}
    changed = subprocess.check_output(['git', 'diff', '--name-only', commit, 'HEAD'],
                                      cwd=ROOT, text=True).splitlines()
    if set(changed) - allowed:
        raise SystemExit('source, formula and packaging recipes must remain byte-identical')
    if args.wait:
        for _ in range(80):
            if run['status'] == 'completed':
                break
            time.sleep(30)
            run = api(base)
    if not args.source_only and run['status'] != 'completed':
        raise SystemExit('original qualification must finish before publication')
    require_gates(api(base + '/jobs?per_page=100')['jobs'], args.source_only)
    names = {'sibuna-distribution-source'} if args.source_only else {
        'sibuna-distribution-source', 'qualified-container',
        *[f'sibuna-{p["package"]}' for p in PLATFORMS],
        'sibuna-native-linux-amd64', 'sibuna-native-linux-arm64',
    }
    artifacts = api(base + '/artifacts?per_page=100')['artifacts']
    for name in names:
        matches = [a for a in artifacts if a['name'] == name and not a['expired']]
        if len(matches) != 1:
            raise SystemExit(f'unique unexpired qualified artifact required: {name}')
    print(f'qualification {args.run_id}: exact {args.tag} source {commit} and gates verified')


if __name__ == '__main__':
    main()
