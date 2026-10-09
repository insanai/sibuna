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


def build(destination, repository_id):
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
            charts = [n for n in assets if re.fullmatch(r'sibuna-[0-9]+\.[0-9]+\.[0-9]+\.tgz', n)]
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
        import uuid
        uuid.UUID(repository_id)
        (destination / 'artifacthub-repo.yml').write_text(f'repositoryID: {repository_id}\n')
    # Verified-publisher ID is public. No personal owner email is included.


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('destination', type=Path)
    parser.add_argument('--repository-id', default='')
    args = parser.parse_args()
    build(args.destination, args.repository_id)
