#!/usr/bin/env python3
"""Permit publishing retries only from a successful identical Helm qualification."""
import json
import re
import subprocess
import sys

from check_release_version import ROOT, version

run_id = sys.argv[1]
if sys.argv[2] != f'v{version()}':
    raise SystemExit('application tag must match the current qualified chart')
if not re.fullmatch(r'[0-9]+', run_id):
    raise SystemExit('qualification run must be a numeric GitHub run ID')
base = f'repos/insanai/sibuna/actions/runs/{run_id}'
run = json.loads(subprocess.check_output(['gh', 'api', base]))
if run['path'] != '.github/workflows/helm-bootstrap.yml' or run['event'] != 'workflow_dispatch':
    raise SystemExit('not a Helm bootstrap qualification run')
commit = run['head_sha']
subprocess.run(['git', 'merge-base', '--is-ancestor', commit, 'HEAD'], cwd=ROOT, check=True)
paths = ['distribution/container', 'distribution/helm', 'SECURITY.md', 'build.zig.zon',
         'tools/check_container.py', 'tools/check_helm.py', 'tools/prepare_container.py',
         'tools/prepare_published_container.py', 'tools/package_linux.py',
         'tools/check_release_version.py', 'tools/install_distribution_tools.py']
subprocess.run(['git', 'diff', '--quiet', commit, 'HEAD', '--', *paths], cwd=ROOT, check=True)
jobs = json.loads(subprocess.check_output(['gh', 'api', base + '/jobs?per_page=100']))['jobs']
qualified = [job for job in jobs if job['name'] == 'qualify' and job['conclusion'] == 'success']
gate = 'Qualify the actual non-root image and Kubernetes install, upgrade and uninstall'
if len(qualified) != 1 or not any(step['name'] == gate and step['conclusion'] == 'success'
                                for step in qualified[0]['steps']):
    raise SystemExit('successful actual image and Kubernetes qualification required')
artifacts = json.loads(subprocess.check_output(['gh', 'api', base + '/artifacts']))['artifacts']
if not any(artifact['name'] == 'qualified-helm-bootstrap' and not artifact['expired']
           for artifact in artifacts):
    raise SystemExit('qualified artifact is missing or expired')
print(f'reusing qualification {run_id} from {commit}; recipe bytes are unchanged')
