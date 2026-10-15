# Console smoke run: eight Traffic dashboards

Recorded on 2026-10-15 by `sibuna-browser dashboards` (`tools/browser`) at revision a693ab7 plus the uncommitted U8 work, on an AMD Ryzen 9 5950X (32 threads, 121 GiB) with Linux 7.0.0-28 and Chromium 155.0.8059.39. Result: PASS.

## Setup

The daemon is a release build (`cargo build --release -p sibuna`), on one SQLite node with its console:

```
sibuna console init-admin admin --data-dir <tmp>/data
sibuna --host 127.0.0.1 --port 39180 --upstream-host 127.0.0.1 --upstream-port 39100 \
  --console 127.0.0.1:39443 --data-dir <tmp>/data --trust-forwarded --workers 4 \
  --policy-file <tmp>/policy.json
sibuna-browser origin --listen 127.0.0.1:39100
sibuna-browser dashboards --url http://127.0.0.1:39443 --username admin \
  --password-file <tmp>/initial-password --new-password-file <tmp>/new-password \
  --traffic http://127.0.0.1:39180/ --out <tmp>/smoke --count 8 --duration 30 --rate 200 \
  --pid <daemon pid>
```

The policy file allows `/static/*`, `/about`, `/missing/*` and `/broken/*` and challenges everything else; the origin fixture answers `/missing/*` with 404 and `/broken/*` with 500. The generator rotates ten paths (one an SQL injection), three user agents and 500 `X-Forwarded-For` addresses from documentation networks, so the run sees admitted, challenged, denied and origin-error outcomes.

Each dashboard runs in its own Chromium with its own session. The console allows five sign-ins per minute per address and per account, and five wall-display exchanges per minute per address; so dashboards 1 to 3 are administrator sessions (the first one replaces the temporary password) showing live boot totals, and dashboards 4 to 8 are wall displays opened with codes the first one minted. Eight browser subscribers are well under the console's 64.

## Results

| Measure | Value |
| --- | --- |
| Data-plane requests | 6,000 in 30.0 s (200 per second, 4 threads, one connection per request) |
| Answered | 6,000: 200 x 1,200, 401 x 3,000, 403 x 600, 404 x 600, 500 x 600 |
| Errors (no reply) | 0 |
| Latency p50 / p90 / p99 / max | 246 / 311 / 373 / 552 us (connect included) |
| Daemon VmRSS at start | 36,152 KiB |
| Daemon VmRSS with 8 dashboards open | 38,028 KiB |
| Daemon VmRSS after the traffic | 41,496 KiB (VmHWM 41,496 KiB) |

| Dashboard | Session | `stats` deltas | Requests tile |
| --- | --- | ---: | --- |
| 1 | administrator | 139 | 16 changes, ending at 6,000 |
| 2 | administrator | 139 | 16 changes, 0 to 6,000 |
| 3 | administrator | 139 | 16 changes, 0 to 6,000 |
| 4 | wall display | 139 | 16 changes, 0 to 6,000 |
| 5 | wall display | 139 | 16 changes, 0 to 6,000 |
| 6 | wall display | 134 | 16 changes, ending at 6,000 |
| 7 | wall display | 134 | 16 changes, ending at 6,000 |
| 8 | wall display | 134 | 16 changes, ending at 6,000 |

The tiles were read every two seconds during the 30 seconds of traffic and 3 seconds after it. Every dashboard ended with the same totals (Requests 6,000, Admitted 2,400, Challenged 3,000, Policy denied 600, Origin 4xx 600, Origin 5xx 600), kept its WebSocket open, and reported no exception, console error or Content-Security-Policy violation. Dashboards 1 and 6 to 8 showed no statistics yet at the first reading, a moment after their stream opened.
