#!/usr/bin/env python3
"""Propose a reviewed formula update to an explicitly configured upstream tap."""
import base64
import json
import os
from pathlib import Path
import re
import sys
import urllib.request


def api(path, data=None, method=None):
    request = urllib.request.Request('https://api.github.com/' + path,
        data=None if data is None else json.dumps(data).encode(), method=method,
        headers={'Authorization': 'Bearer ' + os.environ['GH_TOKEN'],
                 'Accept': 'application/vnd.github+json', 'Content-Type': 'application/json',
                 'User-Agent': 'sibuna-tap-release'})
    with urllib.request.urlopen(request, timeout=60) as response:
        return json.load(response)


repository, tag, filename = sys.argv[1:]
if not re.fullmatch(r'[\w.-]+/homebrew-[\w.-]+', repository) or not re.fullmatch(r'v\d+\.\d+\.\d+', tag):
    raise SystemExit('an explicit homebrew tap and stable tag are required')
formula = Path(filename).read_bytes()
if b'@VERSION@' in formula or b'@SHA256@' in formula:
    raise SystemExit('formula contains placeholders')
base = api(f'repos/{repository}')['default_branch']
branch = 'sibuna-' + tag
# Each release proposes one PR. Existing branches/PRs are left for human review.
refs = api(f'repos/{repository}/git/ref/heads/{base}')
update_file = True
try:
    api(f'repos/{repository}/git/ref/heads/{branch}')
except urllib.error.HTTPError as error:
    if error.code != 404:
        raise
    api(f'repos/{repository}/git/refs', {'ref': 'refs/heads/' + branch, 'sha': refs['object']['sha']})
else:
    prs = api(f'repos/{repository}/pulls?state=all&head={repository.split("/")[0]}:{branch}')
    if prs:
        print(prs[0]['html_url'])
        sys.exit(0)
    existing = api(f'repos/{repository}/contents/Formula/sibuna.rb?ref={branch}')
    if base64.b64decode(existing['content']) != formula:
        raise SystemExit('existing tap branch differs; preserve it for human review')
    update_file = False

path = f'repos/{repository}/contents/Formula/sibuna.rb'
try:
    previous = api(path + '?ref=' + branch)['sha']
except urllib.error.HTTPError as error:
    if error.code != 404:
        raise
    previous = None
identity = {'name': 'github-actions[bot]', 'email': '41898282+github-actions[bot]@users.noreply.github.com'}
payload = {'author': identity, 'committer': identity, 'message': f'sibuna {tag[1:]}', 'branch': branch, 'content': base64.b64encode(formula).decode()}
if previous:
    payload['sha'] = previous
if update_file:
    api(path, payload, 'PUT')
pr = api(f'repos/{repository}/pulls', {'title': f'sibuna {tag[1:]}', 'head': branch, 'base': base,
    'body': f'Update the source formula from the checksum-qualified Sibuna {tag} release.\n\nGenerated from upstream distribution/homebrew/sibuna.rb.in. Review before merging. AI-assisted implementation; community submissions require human review and disclosure.'})
print(pr['html_url'])
