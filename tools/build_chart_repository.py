#!/usr/bin/env python3
"""Index checksum-verified Helm assets from published GitHub releases for Pages."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import urllib.request


def fetch(url):
    request = urllib.request.Request(url, headers={'Accept': 'application/vnd.github+json', 'User-Agent': 'sibuna-chart-repository'})
    if url.startswith('https://api.github.com/') and os.environ.get('GH_TOKEN'):
        request.add_header('Authorization', 'Bearer ' + os.environ['GH_TOKEN'])
    return urllib.request.urlopen(request, timeout=120).read()


def chart_names(release):
    """Select charts without confusing canonical OpenBSD .tgz package names."""
    match = re.fullmatch(r'(helm-)?v([0-9]+\.[0-9]+\.[0-9]+)', release['tag_name'])
    if not match:
        return []
    version = match[2]
    assets = {a['name'] for a in release['assets']}
    current = f'helm-sibuna-{version}.tgz'
    legacy = f'sibuna-{version}.tgz'
    legacy_allowed = bool(match[1]) or tuple(map(int, version.split('.'))) < (0, 3, 5)
    candidates = [name for name in (current, legacy) if name in assets
                  and (name != legacy or legacy_allowed)]
    if len(candidates) > 1:
        raise ValueError(f'{release["tag_name"]}: ambiguous chart assets')
    if not candidates and (match[1] or not legacy_allowed):
        raise ValueError(f'{release["tag_name"]}: missing qualified Helm asset')
    return candidates


def build(destination, repository_id):
    if repository_id:
        import uuid
        if not re.fullmatch(r'[0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}', repository_id.strip()):
            raise ValueError('Artifact Hub repository ID must be a UUID, not an API key')
        repository_id = str(uuid.UUID(repository_id.strip()))
    destination.mkdir(parents=True, exist_ok=True)
    # Retain all published chart versions, including older app versions; never index drafts.
    page = 1
    while True:
        releases = json.loads(fetch(f'https://api.github.com/repos/insanai/sibuna/releases?per_page=100&page={page}'))
        if not releases:
            break
        for release in releases:
            if release['draft'] or release['prerelease']:
                continue
            assets = {a['name']: a['browser_download_url'] for a in release['assets']}
            charts = chart_names(release)
            if not charts:
                continue
            lines = fetch(assets['SHA256SUMS']).decode().splitlines()
            digests = {line.split()[1]: line.split()[0] for line in lines}
            for name in charts:
                data = fetch(assets[name])
                if hashlib.sha256(data).hexdigest() != digests.get(name):
                    raise ValueError(f'{release["tag_name"]}: chart digest mismatch')
                if (destination / name).exists():
                    raise ValueError(f'duplicate chart version: {name}')
                (destination / name).write_bytes(data)
        page += 1
    subprocess.run(['helm', 'repo', 'index', str(destination), '--url', 'https://insanai.github.io/sibuna/charts'], check=True)
    (destination / 'index.html').write_text(
        '<!doctype html><html lang="en"><meta charset="utf-8">'
        '<title>Sibuna Helm repository</title><h1>Sibuna Helm repository</h1>'
        '<p>Repository URL: <code>https://insanai.github.io/sibuna/charts/</code></p>'
        '<pre>helm repo add sibuna https://insanai.github.io/sibuna/charts/\n'
        'helm repo update\nhelm search repo sibuna</pre>'
        '<p><a href="index.yaml">Helm index</a> · '
        '<a href="https://github.com/insanai/sibuna/tree/main/distribution/helm/sibuna">'
        'Installation and security requirements</a></p></html>\n')
    if repository_id:
        (destination / 'artifacthub-repo.yml').write_text(f'repositoryID: {repository_id}\n')
    # Verified-publisher ID is public. No personal owner email is included.


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('destination', type=Path)
    parser.add_argument('--repository-id', default='')
    args = parser.parse_args()
    build(args.destination, args.repository_id)
