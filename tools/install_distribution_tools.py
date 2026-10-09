#!/usr/bin/env python3
"""Install checksum-pinned release tools into an isolated directory (Linux x86-64)."""
import argparse
import hashlib
import os
from pathlib import Path
import tarfile
import tempfile
import urllib.request

TOOLS = {
    'buildx': ('https://github.com/docker/buildx/releases/download/v0.38.0/buildx-v0.38.0.linux-amd64', '4fe4cc38adf48169132749b6ca22a990928db0118e3407584ee553723115d287', None),
    'kind': ('https://github.com/kubernetes-sigs/kind/releases/download/v0.33.0/kind-linux-amd64', 'aee6151561422756b764a4ae28e7f44cda5af5a9eead3cc9985112b1de8d8e0d', None),
    'kubectl': ('https://dl.k8s.io/release/v1.35.8/bin/linux/amd64/kubectl', '874d5e72dbb819f43cff16bcd1e4f8bac5b7f2361fe1e55049b0a6c676fb0cbf', None),
    'nfpm': ('https://github.com/goreleaser/nfpm/releases/download/v2.47.0/nfpm_2.47.0_Linux_x86_64.tar.gz', '0660ca602b2d2d2ae4781a06c692b3eeb9d437ffea05b831d76e41f4a3188783', 'nfpm'),
    'helm': ('https://get.helm.sh/helm-v4.3.0-linux-amd64.tar.gz', '86584a54def73570558f66f5111cc53dfed56689637ae32c1201205d494f54fb', 'linux-amd64/helm'),
    'typst': ('https://github.com/typst/typst/releases/download/v0.15.1/typst-x86_64-unknown-linux-musl.tar.xz', 'a6d077d0a95eed5a2eba715b2dae06be954f624ccbf85758a03f389ded33118c', 'typst-x86_64-unknown-linux-musl/typst'),
    'actionlint': ('https://github.com/rhysd/actionlint/releases/download/v1.7.12/actionlint_1.7.12_linux_amd64.tar.gz', '8aca8db96f1b94770f1b0d72b6dddcb1ebb8123cb3712530b08cc387b349a3d8', 'actionlint'),
}


def install(destination, names):
    destination.mkdir(parents=True, exist_ok=True)
    for name in names:
        url, digest, member = TOOLS[name]
        data = urllib.request.urlopen(url, timeout=120).read()
        if hashlib.sha256(data).hexdigest() != digest:
            raise ValueError(f'{name}: download digest mismatch')
        if member is None:
            (destination / name).write_bytes(data)
            (destination / name).chmod(0o755)
            continue
        with tempfile.TemporaryFile() as stream:
            stream.write(data)
            stream.seek(0)
            with tarfile.open(fileobj=stream) as bundle:
                entry = bundle.getmember(member)
                if not entry.isfile():
                    raise ValueError(f'{name}: expected a regular executable')
                (destination / name).write_bytes(bundle.extractfile(entry).read())
                (destination / name).chmod(0o755)
    if os.environ.get('GITHUB_PATH'):
        with open(os.environ['GITHUB_PATH'], 'a') as output:
            output.write(str(destination.resolve()) + '\n')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('destination', type=Path)
    parser.add_argument('tools', nargs='+', choices=TOOLS)
    args = parser.parse_args()
    install(args.destination, args.tools)
