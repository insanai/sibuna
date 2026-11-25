"""Measure established TCP streams through a Sibuna binary on Linux loopback."""

import argparse
import asyncio
import json
import resource
import socket
import subprocess
import tempfile
import time
from pathlib import Path


async def origin(reader, writer):
    try:
        writer.write(b"R")
        await writer.drain()
        if await reader.readexactly(1) == b"Q":
            writer.write(b"Y")
            await writer.drain()
    except (asyncio.IncompleteReadError, ConnectionError):
        pass
    finally:
        writer.close()


async def connect(port):
    reader, writer = await asyncio.open_connection("127.0.0.1", port)
    if await reader.readexactly(1) != b"R":
        raise ValueError("origin greeting changed in transit")
    return reader, writer


async def run(binary, flows, directory):
    server = await asyncio.start_server(origin, "127.0.0.1", 0)
    async with server:
        backend = server.sockets[0].getsockname()[1]
        with socket.socket() as candidate:
            candidate.bind(("127.0.0.1", 0))
            port = candidate.getsockname()[1]
        config = {
            "global": {"max_flows": flows, "admin_socket": "edge.sock"},
            "backends": {"app": {"mode": "tcp", "servers": [f"127.0.0.1:{backend}"]}},
            "frontends": {"web": {"proto": "tcp", "binds": [f"127.0.0.1:{port}"],
                                  "default_backend": "app"}},
        }
        (directory / "edge.json").write_text(json.dumps(config))
        log = directory / "edge.log"
        with log.open("w") as output:
            proc = subprocess.Popen(
                [binary, "--config-file", "edge.json"], cwd=directory, stdout=output, stderr=output
            )
            try:
                async with asyncio.timeout(10):
                    while "listeners ready" not in log.read_text():
                        if proc.poll() is not None:
                            raise RuntimeError(log.read_text())
                        await asyncio.sleep(0.05)
                await measure(binary, directory, proc.pid, port, flows)
            finally:
                proc.terminate()
                try:
                    proc.wait(timeout=8)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    proc.wait()


async def measure(binary, directory, pid, port, flows):
    clients = []
    try:
        start = time.monotonic()
        while len(clients) < flows:
            batch = min(20, flows - len(clients))
            async with asyncio.timeout(30):
                clients.extend(await asyncio.gather(*(connect(port) for _ in range(batch))))
        ramp = time.monotonic() - start
        info = subprocess.check_output([binary, "ctl", "edge.sock", "show", "info"],
                                       cwd=directory, text=True, timeout=10)
        fields = dict(line.split(": ", 1) for line in info.splitlines() if ": " in line)
        if int(fields["flows"]) != flows or int(fields["drops"]) != 0:
            raise RuntimeError(info)
        descriptors = sum(1 for _ in Path(f"/proc/{pid}/fd").iterdir())
        print(f"{flows} established in {ramp:.3f} s, {descriptors} edge descriptors", flush=True)
        await asyncio.sleep(5)
        async with asyncio.timeout(60):
            for _, writer in clients:
                writer.write(b"Q")
            for reader, _ in clients:
                if await reader.readexactly(1) != b"Y":
                    raise ValueError("origin echo changed in transit")
        print(f"{flows} echoes verified after a five-second hold, zero admission drops")
    finally:
        for _, writer in clients:
            writer.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", type=Path, help="built sibuna executable")
    parser.add_argument("--flows", type=int, default=10_000)
    args = parser.parse_args()
    first, last = map(int, Path("/proc/sys/net/ipv4/ip_local_port_range").read_text().split())
    capacity = min(1_000_000, last - first + 1)
    if not 1 <= args.flows <= capacity:
        parser.error(f"choose --flows from 1 to {capacity} for this address pair")
    soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
    need = 2 * args.flows + 512
    if hard != resource.RLIM_INFINITY and need > hard:
        parser.error(f"pilot needs {need} descriptors per process, hard limit is {hard}")
    if soft != resource.RLIM_INFINITY and soft < need:
        resource.setrlimit(resource.RLIMIT_NOFILE, (need, hard))
    with tempfile.TemporaryDirectory(prefix="sibuna-flow-") as tmp:
        asyncio.run(run(args.binary.resolve(), args.flows, Path(tmp)))


if __name__ == "__main__":
    main()
