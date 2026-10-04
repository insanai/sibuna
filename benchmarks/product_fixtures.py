#!/usr/bin/env python3
"""Shared native product fixtures for proxy and admission comparisons.

The caller owns logs and the temporary directory. Products run one at a time and inherit
the same CPU allowance. Synthetic signing keys and trusted headers belong to this fixture.
"""
from dataclasses import dataclass
from argparse import Namespace
import hashlib
import json
import os
from pathlib import Path
import signal
import subprocess

import bunkerweb_fixture as bunker
from process_accounting import snapshot
from run import free_port, stop

BITS = 16
CLIENT_HEADERS = {"Host": "benchmark.test", "User-Agent": "Mozilla/5.0 SibunaBenchmark",
                  "Accept": "text/html", "Accept-Encoding": "gzip",
                  "X-Real-IP": "203.0.113.30", "X-Forwarded-For": "203.0.113.30"}


@dataclass(frozen=True)
class Context:
    options: Namespace
    port: int
    origin: int
    temporary: Path
    cpus: list


def sibuna_command(profile, context, protected, mode):
    options, temporary = context.options, context.temporary
    policy = {"default_action": "challenge" if protected else "allow", "rules": []}
    if protected:
        policy["rules"] = [{"name": "robots", "path": "/robots.txt", "action": "ALLOW"}]
    filename = temporary / "policy.json"
    filename.write_text(json.dumps(policy))
    command = [str(options.sibuna), "--gate" if profile == "sibuna-gate" else "--shield",
               "--mode", mode, "--host", options.listen_host, "--port", str(context.port),
               "--workers", str(options.workers), "--upstream-host", "127.0.0.1",
               "--upstream-port", str(context.origin), "--policy-file", str(filename),
               "--rate-limit", "100000000", "--idle-timeout", "15"]
    if protected:
        seed = temporary / "seed.hex"
        seed.write_text("0" * 64)
        command += ["--algorithm", "hashcash", "--difficulty", str(BITS),
                    "--secret-file", str(seed), "--trust-forwarded",
                    "--challenge-rate-limit", "100000000"]
    return command, {"policy": policy, "console_active": False, "storage_active": False}


def anubis_command(context, protected, mode, scheme):
    policy = context.temporary / "policy.yaml"
    action = "CHALLENGE" if protected else "ALLOW"
    policy.write_text("bots:\n  - name: benchmark-client\n    user_agent_regex: Mozilla\n"
                      f"    action: {action}\ndnsbl: false\nhoneypot:\n  enabled: false\n")
    target = f"http://127.0.0.1:{context.origin}" if mode == "reverse_proxy" else ""
    command = [str(context.options.anubis), "--bind",
               f"{context.options.listen_host}:{context.port}", "--metrics-bind",
               f"127.0.0.1:{free_port()}", "--target=" + target, "--difficulty", str(BITS // 4),
               "--policy-fname", str(policy), "--slog-level", "ERROR", "--cookie-secure=false"]
    if scheme == "hs512":
        command += ["--hs512-secret", "benchmark-synthetic-signing-key-" + "0" * 64]
    if not protected:
        command += ["--use-remote-address"]
    return command, {"policy": policy.read_text(), "token_scheme": scheme,
                     "upstream_keepalive": "enabled; native Go transport defaults"}


def start_product(profile, context, log, protected=False, mode="reverse_proxy",
                  scheme="default"):
    options = context.options
    if profile.startswith("bunkerweb"):
        if mode != "reverse_proxy":
            raise ValueError("this BunkerWeb fixture has no native forward-auth endpoint")
        overrides = {}
        if protected:
            overrides = {"USE_ANTIBOT": "javascript", "ANTIBOT_IGNORE_URI": "^/robots[.]txt$",
                         "USE_REAL_IP": "yes", "REAL_IP_FROM": "127.0.0.1/32 10.0.0.0/8",
                         "SESSIONS_SECRET": "0" * 64, "SESSIONS_NAME": "benchmark-session"}
        configuration = bunker.configure(options.rootfs, context.port, context.origin,
                                        options.workers, "crs" in profile,
                                        profile.endswith("small-error"), overrides)
        return bunker.start(options.rootfs, context.cpus, log), configuration
    command, configuration = (anubis_command(context, protected, mode, scheme)
                              if profile.startswith("anubis") else
                              sibuna_command(profile, context, protected, mode))
    environment = {**os.environ, "GOMAXPROCS": str(options.workers)}
    command = ["taskset", "-c", ",".join(map(str, context.cpus)), *command]
    return subprocess.Popen(command, stdout=log, stderr=log, env=environment), {
        **configuration, "command": command}


def stop_product(profile, process, rootfs):
    if not profile.startswith("bunkerweb"):
        stop(process)
        return
    pid_file = rootfs / "var/run/bunkerweb/nginx.pid"
    if process.poll() is None and pid_file.exists():
        pid = int(pid_file.read_text())
        if pid not in snapshot(process.pid)["pids"]:
            raise RuntimeError("nginx PID does not belong to this fixture")
        os.kill(pid, signal.SIGQUIT)
    process.wait(timeout=15)
    if process.returncode:
        raise RuntimeError(f"BunkerWeb stop returned {process.returncode}")


def anubis_identity(binary):
    version = subprocess.check_output([str(binary), "--version"], text=True).strip()
    checksum = hashlib.sha256(binary.read_bytes()).hexdigest()
    if (version != "Anubis v1.27.0" or checksum !=
            "43a02b1d3908d3d775fe9454140f91ac36843320bc3d3712b33b638f38e801ac"):
        raise ValueError("expected the qualified official Anubis v1.27.0 Linux amd64 binary")
    return {"version": version, "binary_sha256": checksum,
            "release": "https://github.com/TecharoHQ/anubis/releases/tag/v1.27.0",
            "archive_sha256": "092f92b1710ee2eb208f019733f6ce06cbc041884272340bea13635a4515c357"}
