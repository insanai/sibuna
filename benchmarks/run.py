#!/usr/bin/env python3
"""Build and measure primitives; all instrumentation lives outside the daemon."""
import datetime
import http.client
import hashlib
import json
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


def metadata():
    manifest = (ROOT / "build.zig.zon").read_text()
    cpu = platform.processor()
    if platform.system() == "Darwin":
        cpu = command("sysctl", "-n", "machdep.cpu.brand_string")
    source = hashlib.sha256()
    paths = [ROOT / "build.zig", ROOT / "build.zig.zon"]
    for directory in ("apps", "libs", "benchmarks"):
        paths.extend(p for p in (ROOT / directory).rglob("*")
                     if p.suffix in {".zig", ".py", ".sh", ".js", ".html"})
    for path in sorted(paths):
        source.update(str(path.relative_to(ROOT)).encode() + b"\0")
        source.update(path.read_bytes())
    return {
        "zaxonlite": {
            "url": re.search(r'\.url\s*=\s*"([^"]+)"', manifest).group(1),
            "hash": re.search(r'\.hash\s*=\s*"([^"]+)"', manifest).group(1),
        },
        "source_sha256": source.hexdigest(),
        "daemon_sha256": hashlib.sha256((ROOT / "zig-out/bin/sibuna").read_bytes()).hexdigest(),
        "date": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "host": socket.gethostname(), "cpu": cpu, "os": platform.platform(),
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
    subprocess.run(["zig", "build", "wasm", "-Doptimize=ReleaseFast"], cwd=ROOT, check=True)
    subprocess.run(["zig", "build", "-Doptimize=ReleaseFast"], cwd=ROOT, check=True)
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
