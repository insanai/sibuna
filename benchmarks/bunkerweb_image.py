#!/usr/bin/env python3
"""Download an official BunkerWeb image into an OCI layout for native qualification.

Use umoci to unpack it; this helper never extracts archives or installs host packages.
The manifest and every downloaded blob are SHA-256 verified. Record the resolved digest,
since a version tag alone does not identify an immutable artifact.
"""
import argparse
import hashlib
import json
from pathlib import Path
import urllib.request

REGISTRY = "https://registry-1.docker.io"
REPOSITORY = "bunkerity/bunkerweb"
MEDIA = ", ".join((
    "application/vnd.oci.image.index.v1+json",
    "application/vnd.docker.distribution.manifest.list.v2+json",
    "application/vnd.oci.image.manifest.v1+json",
    "application/vnd.docker.distribution.manifest.v2+json",
))


def digest(content):
    return "sha256:" + hashlib.sha256(content).hexdigest()


class Registry:
    def __init__(self):
        url = ("https://auth.docker.io/token?service=registry.docker.io&scope="
               f"repository:{REPOSITORY}:pull")
        with urllib.request.urlopen(url, timeout=60) as reply:
            self.token = json.load(reply)["token"]

    def open(self, kind, reference):
        request = urllib.request.Request(
            f"{REGISTRY}/v2/{REPOSITORY}/{kind}/{reference}",
            headers={"Authorization": "Bearer " + self.token, "Accept": MEDIA},
        )
        return urllib.request.urlopen(request, timeout=120)

    def manifest(self, reference):
        with self.open("manifests", reference) as reply:
            content = reply.read(4 * 1024 * 1024 + 1)
            expected = reply.headers.get("Docker-Content-Digest")
        if len(content) > 4 * 1024 * 1024 or expected != digest(content):
            raise ValueError("manifest digest or size validation failed")
        if reference.startswith("sha256:") and reference != expected:
            raise ValueError("registry returned a different manifest")
        return content

    def blob(self, descriptor, directory):
        expected = descriptor["digest"]
        if (not expected.startswith("sha256:") or len(expected) != 71
                or any(c not in "0123456789abcdef" for c in expected[7:])):
            raise ValueError("unsupported blob digest")
        if type(descriptor["size"]) is not int or descriptor["size"] < 0:
            raise ValueError("invalid blob size")
        path = directory / expected.split(":")[1]
        if path.exists() and path.stat().st_size == descriptor["size"]:
            with path.open("rb") as source:
                checksum = "sha256:" + hashlib.file_digest(source, "sha256").hexdigest()
            if checksum == expected:
                return
        temporary = path.with_suffix(".partial")
        checksum, total = hashlib.sha256(), 0
        try:
            with self.open("blobs", expected) as reply, temporary.open("wb") as output:
                while block := reply.read(1024 * 1024):
                    total += len(block)
                    if total > descriptor["size"]:
                        raise ValueError("blob exceeds declared size")
                    checksum.update(block)
                    output.write(block)
            if total != descriptor["size"] or "sha256:" + checksum.hexdigest() != expected:
                raise ValueError("blob digest or size validation failed")
            temporary.replace(path)
        finally:
            temporary.unlink(missing_ok=True)


def pull(destination, reference):
    registry = Registry()
    index_bytes = registry.manifest(reference)
    index = json.loads(index_bytes)
    platforms = [item for item in index.get("manifests", [])
                 if item.get("platform", {}).get("os") == "linux"
                 and item.get("platform", {}).get("architecture") == "amd64"]
    if len(platforms) != 1:
        raise ValueError("expected exactly one Linux amd64 image")
    manifest_bytes = registry.manifest(platforms[0]["digest"])
    manifest = json.loads(manifest_bytes)
    blobs = destination / "blobs/sha256"
    blobs.mkdir(parents=True, exist_ok=True)
    for descriptor in [manifest["config"], *manifest["layers"]]:
        print(f"Downloading {descriptor['digest']} ({descriptor['size']} bytes)", flush=True)
        registry.blob(descriptor, blobs)
    resolved = digest(manifest_bytes)
    (blobs / resolved.split(":")[1]).write_bytes(manifest_bytes)
    descriptor = {"mediaType": manifest["mediaType"], "digest": resolved,
                  "size": len(manifest_bytes),
                  "annotations": {"org.opencontainers.image.ref.name": "benchmark"}}
    (destination / "oci-layout").write_text('{"imageLayoutVersion":"1.0.0"}\n')
    (destination / "index.json").write_text(json.dumps({"schemaVersion": 2,
                                                       "manifests": [descriptor]}) + "\n")
    provenance = {"repository": REPOSITORY, "reference": reference,
                  "index_digest": digest(index_bytes), "image_digest": resolved,
                  "config_digest": manifest["config"]["digest"],
                  "layers": manifest["layers"], "platform": "linux/amd64"}
    (destination / "provenance.json").write_text(json.dumps(provenance, indent=2) + "\n")
    return provenance


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", type=Path)
    parser.add_argument("--reference", default="1.6.15")
    arguments = parser.parse_args()
    print(json.dumps(pull(arguments.directory, arguments.reference), indent=2))
