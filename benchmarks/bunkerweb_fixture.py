#!/usr/bin/env python3
"""Run the official BunkerWeb proxy natively in a dedicated unpacked image.

The image's configuration generator and security modules are unchanged. chroot isolates
absolute image paths without emulating instructions or installing host services. A sudo
launcher drops to the calling UID before nginx starts. Never use a production filesystem.
"""
import hashlib
import json
import os
from pathlib import Path
import subprocess

ERROR_BODY = b"<!doctype html><title>Forbidden</title><p>Forbidden</p>".ljust(235, b" ")
ERROR_CONFIG = """error_page 403 /benchmark-denied.html;
location = /benchmark-denied.html {
    internal;
    root /var/www/html;
    modsecurity off;
    auth_basic off;
}
"""


def chroot(root, *command):
    wrapper = Path(__file__).with_name("bunkerweb_native.sh")
    return ["sudo", "-n", "unshare", "--mount", "--propagation", "private",
            "/bin/sh", str(wrapper), str(root), str(os.getuid()), str(os.getgid()), *command]


def configure(root, port, origin_port, workers, inspection, small_error=False, overrides=None):
    if not (root / "usr/share/bunkerweb/VERSION").is_file():
        raise ValueError("expected a dedicated unpacked BunkerWeb image")
    settings = {
        "SERVER_NAME": "benchmark.test", "HTTP_PORT": str(port),
        "HTTPS_PORT": "", "LISTEN_HTTP": "yes",
        "API_HTTP_PORT": str(port + 1), "API_LISTEN_HTTP": "no",
        "WORKER_PROCESSES": str(workers), "WORKER_CONNECTIONS": "4096",
        "WORKER_RLIMIT_NOFILE": "8192", "HTTP2": "no", "HTTP3": "no",
        "AUTO_LETS_ENCRYPT": "no", "USE_REVERSE_PROXY": "yes",
        "REVERSE_PROXY_HOST": f"http://127.0.0.1:{origin_port}",
        "REVERSE_PROXY_HTTP_VERSION": "1.1", "REVERSE_PROXY_KEEPALIVE": "yes",
        "USE_MODSECURITY": "yes" if inspection else "no",
        "USE_MODSECURITY_CRS": "yes" if inspection else "no",
        "MODSECURITY_CRS_VERSION": "4", "MODSECURITY_SEC_AUDIT_ENGINE": "Off",
        "USE_ANTIBOT": "no", "USE_BAD_BEHAVIOR": "no", "USE_BLACKLIST": "no",
        "USE_WHITELIST": "no", "USE_DNSBL": "no", "USE_LIMIT_REQ": "no",
        "USE_LIMIT_CONN": "no", "USE_BUNKERNET": "no",
        "SEND_ANONYMOUS_REPORT": "no", "USE_GZIP": "no", "USE_BROTLI": "no",
        "USE_CLIENT_CACHE": "no", "USE_REAL_IP": "no", "LOG_LEVEL": "crit",
        "ACCESS_LOG": "off", "ERROR_LOG": "/var/log/bunkerweb/benchmark-error.log",
    }
    settings.update(overrides or {})
    custom = root / "data/configs/server-http/benchmark-denied.conf"
    if small_error:
        # A URI error redirect changes POST to GET. The stock ERRORS named location
        # preserves POST, which nginx's static handler rejects with 405 instead of 403.
        # CRS still decides the denial before this internal error page is served.
        settings["INTERCEPTED_ERROR_CODES"] = "400 401 404 405 413 429 500 501 502 503 504"
        (root / "data/www/benchmark-denied.html").write_bytes(ERROR_BODY)
        custom.write_text(ERROR_CONFIG)
    else:
        custom.unlink(missing_ok=True)
    (root / "dev/shm").mkdir(parents=True, exist_ok=True)
    for filename in ("error.log", "modsec_audit.log", "access.log"):
        path = root / "var/log/bunkerweb" / filename
        if path.is_symlink():
            path.unlink()
        path.touch()
    variables = root / "etc/bunkerweb/benchmark.env"
    variables.write_text("".join(f"{key}={value}\n" for key, value in settings.items()))
    cert_command = (
        "mkdir -p /var/cache/bunkerweb/misc; "
        "test -f /var/cache/bunkerweb/misc/default-server-cert.pem || "
        "openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:secp384r1 "
        "-nodes -subj /CN=benchmark.test -days 1 "
        "-keyout /var/cache/bunkerweb/misc/default-server-cert.key "
        "-out /var/cache/bunkerweb/misc/default-server-cert.pem"
    )
    subprocess.run(chroot(root, "/bin/sh", "-c", cert_command), check=True,
                   stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    command = chroot(root, "/usr/bin/python3", "/usr/share/bunkerweb/gen/main.py",
                     "--variables", "/etc/bunkerweb/benchmark.env")
    generated = subprocess.run(command, text=True, capture_output=True, check=True)
    if "ignoring" in generated.stdout.lower() or "ignoring" in generated.stderr.lower():
        raise ValueError("configuration generator ignored a benchmark setting: "
                         + generated.stdout + generated.stderr)
    subprocess.run(chroot(root, "/usr/sbin/nginx", "-t"), check=True,
                   stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    configs = sorted((root / "etc/nginx").rglob("*"))
    checksum = hashlib.sha256()
    for path in configs:
        if path.is_file():
            checksum.update(str(path.relative_to(root)).encode() + b"\0")
            checksum.update(path.read_bytes())
    return {"settings": settings, "generated_configuration_sha256": checksum.hexdigest(),
            "custom_error_configuration": ERROR_CONFIG if small_error else None}


def start(root, cpus, log):
    # taskset precedes exec: every nginx worker inherits the same product CPU allowance.
    command = ["taskset", "-c", ",".join(map(str, cpus)),
               *chroot(root, "/usr/sbin/nginx", "-g", "daemon off;")]
    return subprocess.Popen(command, stdout=log, stderr=log, start_new_session=True)


def identity(root, image):
    versions = root / "usr/share/bunkerweb/core/modsecurity/misc/versions.json"
    return {
        "version": (root / "usr/share/bunkerweb/VERSION").read_text().strip(),
        "image": json.loads((image / "provenance.json").read_text()),
        "modsecurity_crs": json.loads(versions.read_text()),
        "nginx": subprocess.check_output(chroot(root, "/usr/sbin/nginx", "-V"),
                                         stderr=subprocess.STDOUT, text=True).strip(),
        "execution": "native Linux amd64; chroot; no Docker daemon or CPU emulation",
    }
