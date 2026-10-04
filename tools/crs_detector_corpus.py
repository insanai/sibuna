"""Bounded, digest-pinned libinjection test inputs; no fixture redistribution."""
import hashlib
import io
import json
from pathlib import Path
import tarfile
from urllib.request import urlopen


def inputs(directory, download):
    manifest = json.loads(Path("vendor/libinjection/provenance.json").read_text())
    pin = manifest["test_archive"]
    path = directory / "tests.tar.gz"
    limit = 8 * 1024 * 1024
    if not path.exists() and download:
        url = "https://codeload.github.com/libinjection/libinjection/tar.gz/" + manifest["commit"]
        with urlopen(url, timeout=30) as response:
            data = response.read(limit + 1)
        verify(data, pin)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
    with path.open("rb") as file:
        data = file.read(limit + 1)
    verify(data, pin)
    result = {name: [] for name in pin["categories"]}
    seen = set()
    total = 0
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as archive:
        for index, member in enumerate(archive):
            total += member.size
            if index >= 1024 or total > 32 * 1024 * 1024:
                raise ValueError("detector archive expansion limit")
            relative = Path(member.name)
            if relative.is_absolute() or ".." in relative.parts:
                raise ValueError("invalid detector archive path")
            parts = relative.parts
            if len(parts) != 3 or parts[1] != "tests":
                continue
            name = parts[2]
            category = next((key for key in result if name.startswith("test-" + key + "-")), None)
            if category is None or not name.endswith(".txt"):
                continue
            if name in seen or not member.isfile() or member.size > 64 * 1024:
                raise ValueError("invalid detector fixture")
            seen.add(name)
            content = archive.extractfile(member).read(64 * 1024 + 1)
            value = content.split(b"--INPUT--\n", 1)[1].split(b"\n--EXPECTED--\n", 1)[0]
            # Match the pinned text runner's per-line rstrip and outer strip.
            value = b"\n".join(line.rstrip() for line in value.splitlines()).strip()
            result[category].append((name, value))
    for category, expected in pin["categories"].items():
        if len(result[category]) != expected:
            raise ValueError("detector fixture count mismatch: " + category)
        result[category].sort()
    return result


def verify(data, pin):
    if len(data) != pin["bytes"] or hashlib.sha256(data).hexdigest() != pin["sha256"]:
        raise ValueError("pinned detector archive digest/size mismatch")
