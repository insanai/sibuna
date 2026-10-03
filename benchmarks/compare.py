#!/usr/bin/env python3
"""Real HTTP admission comparison. Third-party executables stay outside this repo."""
import argparse
import concurrent.futures
import gzip
import hashlib
import http.client
import json
import multiprocessing
import os
import pathlib
import re
import statistics
import subprocess
import tempfile
import time
import urllib.parse
from run import ROOT, free_port, metadata, pin_cpus, record, stop

API = '/.within.website/x/cmd/anubis/api/'
HEADERS = {'User-Agent': 'Mozilla/5.0 SibunaBenchmark', 'Accept': 'text/html', 'Accept-Encoding': 'gzip',
           'X-Real-IP': '203.0.113.30', 'X-Forwarded-For': '203.0.113.30'}


def exchange(conn, task):
    method, path, headers, body, expected = task
    conn.request(method, path, body=body, headers=headers)
    reply = conn.getresponse()
    payload = reply.read()
    if reply.status != expected:
        raise RuntimeError(f'{path}: expected {expected}, got {reply.status}: {payload[:200]!r}')
    return reply.getheaders(), payload


def request(port, task):
    conn = http.client.HTTPConnection('127.0.0.1', port, timeout=10)
    try:
        return exchange(conn, task)
    finally:
        conn.close()


def cookies(headers):
    """Cookie pairs from every Set-Cookie header, attributes ignored. Parsed by hand: Python's
    SimpleCookie discards a whole header when it meets an attribute it does not know (such as
    Anubis's `Partitioned`), which silently drops the verification cookie."""
    jar = {}
    for key, value in headers:
        if key.lower() != 'set-cookie':
            continue
        pair = value.split(';', 1)[0].strip()
        name, _, content = pair.partition('=')
        if name.strip():
            jar[name.strip()] = content.strip()
    return '; '.join(f'{name}={content}' for name, content in jar.items() if content)


# The solver below is fixed at two hex digits so Sibuna and Anubis do equal work. Sibuna's
# adaptive controller adds bits once the challenge issue rate passes its 50/s baseline, and
# the measured batches deliberately flood issuance, so a proof solved at 8 bits would be
# rejected and the timed batch would measure rejections rather than verifications. Issue the
# proof challenges below that baseline, and wait for the smoothed rate to decay first.
BITS = 8
ISSUE_INTERVAL = 1 / 40
CHALLENGE_BUDGET = 100_000_000


def issue(port, timeout=180):
    deadline = time.monotonic() + timeout
    while True:
        time.sleep(ISSUE_INTERVAL)
        _, body = request(port, ('GET', '/__sibuna/challenge.json?path=/private',
                                 HEADERS, None, 200))
        challenge = json.loads(body)
        if challenge['difficulty'] == BITS:
            return challenge
        if time.monotonic() >= deadline:
            raise AssertionError(f'adaptive difficulty stayed above {BITS} bits: {challenge}')
        time.sleep(1)


def solution(port, product):
    if product == 'sibuna':
        challenge = issue(port)
        prefix = challenge['id'] + ':'
        challenge_id = challenge['id']
        cookie = ''
    else:
        hdr, body = request(port, ('GET', '/private', HEADERS, None, 200))
        if any(k.lower() == 'content-encoding' and v == 'gzip' for k, v in hdr):
            body = gzip.decompress(body)
        match = re.search(rb'<script id="anubis_challenge"[^>]*>(.*?)</script>', body, re.S)
        assert match, body[:400]
        info = json.loads(match.group(1))
        assert info['rules']['difficulty'] == 2, info
        prefix = info['challenge']['randomData']
        challenge_id = info['challenge']['id']
        cookie = cookies(hdr)
    for nonce in range(1 << 24):
        digest = hashlib.sha256((prefix + str(nonce)).encode()).hexdigest()
        if digest.startswith('00'):
            break
    else:
        raise RuntimeError('solver limit exceeded')
    if product == 'sibuna':
        return ('POST', '/__sibuna/verify', HEADERS,
                json.dumps({'challenge_id': challenge_id, 'nonce': str(nonce)}), 200)
    query = urllib.parse.urlencode({'id': challenge_id, 'nonce': nonce, 'response': digest,
                                   'elapsedTime': 1000, 'redir': f'http://127.0.0.1:{port}/private'})
    return ('GET', API + 'pass-challenge?' + query, {**HEADERS, 'Cookie': cookie}, None, 302)


def batch_worker(port, groups):
    conn = http.client.HTTPConnection('127.0.0.1', port, timeout=10)
    try:
        # Establish the socket outside measurement, without consuming a proof.
        conn.connect()
        start = time.perf_counter_ns()
        for group in groups:
            for task in group:
                exchange(conn, task)
        return time.perf_counter_ns() - start
    finally:
        conn.close()


def measure(pool, port, batches):
    rates, durations = [], []
    for groups in batches:
        half = len(groups) // 2
        start = time.perf_counter_ns()
        futures = [pool.submit(batch_worker, port, part) for part in (groups[:half], groups[half:])]
        times = [f.result(timeout=60) for f in futures]
        elapsed = time.perf_counter_ns() - start
        rates.append(len(groups) * 1e9 / elapsed)
        durations.append(max(times) / half)
    return {'operations_per_second_median': statistics.median(rates),
            'operations_per_second_batches': rates,
            'slowest_client_ns_per_operation_median': statistics.median(durations),
            'batches': len(batches), 'operations_per_batch': len(batches[0]), 'clients': 2}


def run_case(binary, product, scheme, pool, rounds):
    with tempfile.TemporaryDirectory(prefix='sibuna-admission-compare-') as name:
        temp = pathlib.Path(name)
        port = free_port()
        env = dict(os.environ, GOMAXPROCS='2')
        if product == 'sibuna':
            args = [str(binary), '--gate', '--mode', 'forward_auth', '--host', '127.0.0.1',
                    '--port', str(port), '--workers', '2', '--algorithm', 'hashcash',
                    '--difficulty', '8', '--rate-limit', '100000000', '--idle-timeout', '2',
                    # Measure successful issuance/verification, retaining the limiter's
                    # check but reserving enough budget for every timed batch.
                    '--challenge-rate-limit', str(CHALLENGE_BUDGET)]
            check = '/private'
        else:
            policy = temp / 'policy.yaml'
            policy.write_text('bots:\n  - name: generic-browser\n    user_agent_regex: Mozilla\n'
                              '    action: CHALLENGE\ndnsbl: false\nhoneypot:\n  enabled: false\n')
            args = [str(binary), '--bind', f'127.0.0.1:{port}', '--metrics-bind',
                    f'127.0.0.1:{free_port()}', '--target=', '--difficulty', '2',
                    '--policy-fname', str(policy), '--slog-level', 'ERROR', '--cookie-secure=false']
            if scheme == 'hs512':
                args += ['--hs512-secret', 'sibuna-benchmark-fixed-secret-with-64-bytes-' + '0' * 32]
            check = API + 'check'
        with (temp / 'server.log').open('w+') as log:
            proc = subprocess.Popen(args, stdout=log, stderr=log, env=env, cwd=temp)
            try:
                affinity = pin_cpus(proc, 2)
                deadline = time.monotonic() + 30
                while time.monotonic() < deadline:
                    if proc.poll() is not None:
                        raise RuntimeError('server exited')
                    try:
                        request(port, ('GET', check, HEADERS, None, 401))
                        break
                    except (OSError, http.client.HTTPException):
                        time.sleep(.05)
                else:
                    raise RuntimeError('server startup timeout')
                hdr, _ = request(port, solution(port, product))
                cookie = cookies(hdr)
                assert cookie, hdr
                valid = ('GET', check, {**HEADERS, 'Cookie': cookie}, None, 200)
                request(port, valid)
                missing = ('GET', check, HEADERS, None, 401)
                if product == 'sibuna':
                    bootstrap = [('GET', '/__sibuna/challenge', HEADERS, None, 200),
                                 ('GET', '/__sibuna/challenge.json?path=/private', HEADERS, None, 200)]
                else:
                    bootstrap = [('GET', '/private', HEADERS, None, 200)]
                result = {'product': product, 'token_scheme': scheme,
                          'binary_sha256': hashlib.sha256(binary.read_bytes()).hexdigest(),
                          'binary_bytes': binary.stat().st_size, 'cpu_affinity': affinity}
                if product == 'sibuna':
                    result['challenge_rate_limit'] = CHALLENGE_BUDGET
                for label, group in [('valid_session', [valid]), ('unauthenticated_check', [missing]),
                                     ('challenge_bootstrap', bootstrap)]:
                    # Complete one untimed warmup before the measured batches.
                    for task in group:
                        request(port, task)
                    result[label] = measure(pool, port, [[group] * 200 for _ in range(rounds)])
                # Each measured verification receives a fresh valid proof.
                # Issuance and solving are outside the timed batches.
                batches = [[[solution(port, product)] for _ in range(64)] for _ in range(rounds)]
                result['proof_verification'] = measure(pool, port, batches)
                result['rss_kib_after_workload'] = int(subprocess.check_output(
                    ['ps', '-o', 'rss=', '-p', str(proc.pid)], text=True))
                return result
            except Exception:
                log.flush(); log.seek(0)
                print(log.read()[-6000:])
                raise
            finally:
                stop(proc)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--anubis', required=True, type=pathlib.Path)
    parser.add_argument('--batches', type=int, default=7)
    args = parser.parse_args()
    if args.batches < 1:
        parser.error('--batches must be positive')
    binary = args.anubis.resolve(strict=True)
    subprocess.run(['zig', 'build', '-Doptimize=fast'], cwd=ROOT, check=True)
    data = {'meta': metadata(), 'anubis_version': subprocess.check_output(
        [str(binary), '--version'], text=True).strip(), 'runs': [], 'limitations': [
        'Two clients, two Sibuna workers, GOMAXPROCS=2; loopback HTTP forward-auth, no origin or TLS.',
        'Linux pins every product thread to the same two allowed CPUs before warmup; '
        'other platforms have no enforced CPU affinity.',
        'Hashcash work matched at 8 zero bits / 2 zero hex digits; same UA and client IP.',
        'Proof challenges are issued below the 50/s adaptive baseline so the matched work '
        'holds; the bootstrap batches above it measure issuance only, which is difficulty '
        'independent.',
        'Sibuna reserves 100 million challenge operations per window for this fixture; '
        'the limiter check remains, but exhaustion and production budgets are not measured.',
        'Default Anubis Ed25519 and optional HS512 are both tested; Sibuna uses its default MAC.',
        'Bootstrap includes HTML plus JSON for Sibuna and HTML with embedded puzzle for Anubis; static assets excluded.',
        'Fresh proofs are prepared outside timed verification; browser solve and network latency are not measured.',
        'External Python/IPC costs limit throughput; sequential runs are not a universal product ranking.',
        'Downloads/builds are supplied externally and must not be committed.',
    ]}
    ctx = multiprocessing.get_context('spawn')
    with concurrent.futures.ProcessPoolExecutor(2, mp_context=ctx) as pool:
        list(pool.map(int, range(2)))
        for product, scheme, exe in [('sibuna', 'blake3', ROOT/'zig-out/bin/sibuna'),
                                     ('anubis', 'ed25519', binary), ('anubis', 'hs512', binary)]:
            print(f'Measuring {product} {scheme}', flush=True)
            data['runs'].append(run_case(exe, product, scheme, pool, args.batches))
    record(data, 'admission-comparison-latest')


if __name__ == '__main__':
    main()
