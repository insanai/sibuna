#!/usr/bin/env python3
"""Build and measure primitives; all instrumentation lives outside the daemon."""
import datetime
import http.client
import hashlib
import json
import os
import pathlib
import platform
import re
import socket
import subprocess
import tempfile
import time

ROOT = pathlib.Path(__file__).resolve().parents[1]


def command(*args):
    return subprocess.check_output(args, cwd=ROOT, text=True).strip()


def free_port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def request(port, path, headers=None, method="GET", body=None):
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=3)
    try:
        conn.request(method, path, body=body, headers=headers or {})
        resp = conn.getresponse()
        return resp.status, dict(resp.getheaders()), resp.read()
    finally:
        conn.close()


def ready(proc, port, timeout=45):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if proc.poll() is not None:
            raise RuntimeError(f"daemon exited with {proc.returncode}")
        try:
            if request(port, "/__sibuna/health")[0] == 200:
                return
        except (OSError, http.client.HTTPException):
            pass
        time.sleep(0.05)
    raise TimeoutError("daemon did not become healthy")


def stop(proc):
    if proc.poll() is None:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait()


def pin_cpus(proc, count):
    """Linux worker settings count acceptors or Go schedulers, not equivalent CPU limits.
    Apply the same allowed CPU set to every startup thread before warmup. Later threads
    inherit their creator's affinity. Other platforms retain their native scheduling.
    """
    if count <= 0:
        raise ValueError("CPU budget must be positive")
    if not hasattr(os, "sched_setaffinity"):
        return None
    cpus = sorted(os.sched_getaffinity(0))[:count]
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        tasks = list(pathlib.Path(f"/proc/{proc.pid}/task").iterdir())
        for task in tasks:
            try:
                os.sched_setaffinity(int(task.name), cpus)
            except ProcessLookupError:
                pass
        tasks = list(pathlib.Path(f"/proc/{proc.pid}/task").iterdir())
        try:
            if all(os.sched_getaffinity(int(task.name)) == set(cpus) for task in tasks):
                return cpus
        except ProcessLookupError:
            pass
    raise TimeoutError("process CPU affinity did not settle before warmup")


def source_paths():
    """Track build inputs and assets without hashing generated dependencies or prior results."""
    names = subprocess.check_output(
        ["git", "ls-files", "--cached", "--others", "--exclude-standard", "-z", "--",
         "build.zig", "build.zig.zon", "build", "apps", "libs", "benchmarks", "tools", "vendor"],
        cwd=ROOT,
    )
    paths = {pathlib.Path(name.decode()) for name in names.split(b"\0") if name}
    return [ROOT / path for path in sorted(paths)
            if path.parts[:2] != ("benchmarks", "results") and (ROOT / path).is_file()]


def cpu_name():
    if platform.system() == "Darwin":
        return command("sysctl", "-n", "machdep.cpu.brand_string")
    cpu = platform.processor()
    if cpu:
        return cpu
    # Python's processor() is often empty in Linux containers. Record the kernel's
    # model instead of leaving the hardware provenance blank.
    if platform.system() == "Linux":
        try:
            for line in pathlib.Path("/proc/cpuinfo").read_text().splitlines():
                key, separator, value = line.partition(":")
                if separator and key.strip() in ("model name", "Hardware"):
                    return value.strip()
        except OSError:
            pass
    return "unknown"


def storage_provenance(manifest):
    """Original pin plus explicit compatibility source; the source hash covers vendor files."""
    if '.path = "vendor/zaxonlite"' in manifest:
        original = json.loads((ROOT / "vendor/provenance.json").read_text())["zaxonlite"]
        return {"url": original["url"], "hash": original["zig_package_hash"],
                "path": "vendor/zaxonlite", "compatibility": "Zig 0.17"}
    return {"url": re.search(r'\.url\s*=\s*"([^"]+)"', manifest).group(1),
            "hash": re.search(r'\.hash\s*=\s*"([^"]+)"', manifest).group(1)}


def metadata(binary=None):
    manifest = (ROOT / "build.zig.zon").read_text()
    artifact = pathlib.Path(binary) if binary else ROOT / "zig-out/bin/sibuna"
    source = hashlib.sha256()
    paths = source_paths()
    for path in paths:
        content = path.read_bytes()
        source.update(str(path.relative_to(ROOT)).encode() + b"\0")
        source.update(len(content).to_bytes(8, "big"))
        source.update(content)
    return {
        "zaxonlite": storage_provenance(manifest),
        "source_sha256": source.hexdigest(),
        "source_manifest_version": 3,
        "source_file_count": len(paths),
        "daemon_sha256": hashlib.sha256(artifact.read_bytes()).hexdigest(),
        "date": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "host": socket.gethostname(), "cpu": cpu_name(), "os": platform.platform(),
        "git": command("git", "rev-parse", "HEAD"),
        "dirty": bool(command("git", "status", "--porcelain")),
        "zig": command("zig", "version"),
    }


def record(data, name):
    out = ROOT / "benchmarks/results"
    out.mkdir(exist_ok=True)
    stamp = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    for path in (out / f"{name}-{stamp}.json", out / f"{name}.json"):
        path.write_text(json.dumps(data, indent=2) + "\n")
    print(f"Results: {out / (name + '.json')}", flush=True)


def main():
    subprocess.run(["zig", "build", "-j1", "wasm", "-Doptimize=fast"], cwd=ROOT, check=True)
    subprocess.run(["zig", "build", "-j1", "-Doptimize=fast"], cwd=ROOT, check=True)
    data = json.loads(command(str(ROOT / "zig-out/bin/sibuna-benchmark")))
    data["meta"].update(metadata())
    data["meta"].update({
        "binary_bytes": (ROOT / "zig-out/bin/sibuna").stat().st_size,
        "wasm_bytes": (ROOT / "zig-out/web/wasm/sibuna-pow.wasm").stat().st_size,
        "storage_compiled": True, "storage_active": False, "workers": 2,
        "timing": "7 batches, untimed reset and warmup; no per-operation clock reads",
    })
    with tempfile.TemporaryFile(mode="w+") as log:
        port = free_port()
        proc = subprocess.Popen([str(ROOT / "zig-out/bin/sibuna"), "--port", str(port),
                                 "--host", "127.0.0.1", "--workers", "2"],
                                cwd=ROOT, stdout=log, stderr=log)
        try:
            ready(proc, port)
            time.sleep(1)
            data["meta"]["idle_rss_kb"] = int(command("ps", "-o", "rss=", "-p", str(proc.pid)))
        except Exception:
            log.seek(0)
            print(log.read())
            raise
        finally:
            stop(proc)
    record(data, "latest")


if __name__ == "__main__":
    main()
