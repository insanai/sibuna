# Edge load balancer and HAProxy

Recorded by hand on 2026-11-24 at revision 4d8c244 plus the socket-pair handoff, on an AMD Ryzen 7 5800H (16 threads, 12 GiB, an LXC container) with Linux 7.0.0-38, Rust 1.100.0, HAProxy 3.0.11, wrk 4.2.0 and h2load 1.64.0. No `cargo xtask bench` harness covers the edge yet, so this file is a record of one manual run and not a repeated measurement.

## Setup

Everything runs on one host over loopback, pinned with `taskset`. Two HAProxy origins answer a two-byte body (`/small`) or a one-kilobyte body (`/`) on CPUs 0-3. The proxy under test has CPUs 4-11. The load generator has CPUs 12-15. HAProxy runs with `nbthread 8` and `balance leastconn`. Sibuna runs with `"workers": 8` and the default least-connections scheduler. Both terminate TLS with the same ECDSA P-256 certificate and forward cleartext HTTP/1.1 to the origins.

```
wrk -t4 -c<connections> -d8s --latency <url>             # tcp, http, http1k, https
h2load -t4 -c<connections> -m10 -D 8 <url>               # h2
```

`tcp` sends the same HTTP requests through a TCP frontend. `off`, `gate` and `shield` are the values of `http.surface`. Gate and shield run with an allow-all policy and `"rate_limit": "off"`, so they measure the request path and not admission. Each cell is one eight-second run.

## Requests per second

| Workload | Connections | HAProxy | Sibuna off | Sibuna gate | Sibuna shield |
| --- | ---: | ---: | ---: | ---: | ---: |
| tcp | 16 | 172,395 | 177,211 | | |
| tcp | 256 | 237,451 | 230,181 | | |
| tcp | 2,048 | 183,887 | 184,890 | | |
| http | 16 | 140,003 | 135,488 | 143,240 | 140,064 |
| http | 256 | 242,695 | 143,405 | 151,857 | 145,434 |
| http | 2,048 | 172,950 | 132,752 | 140,418 | 137,037 |
| http1k | 16 | 132,017 | 132,501 | | |
| http1k | 256 | 220,527 | 139,958 | | |
| http1k | 2,048 | 163,064 | 134,167 | | |
| https | 16 | 107,636 | 75,111 | 75,943 | 74,776 |
| https | 256 | 166,407 | 88,785 | 85,726 | 83,962 |
| https | 2,048 | 130,700 | 75,104 | 71,635 | 71,419 |
| h2 | 16 | 195,808 | 72,602 | 70,144 | 69,169 |
| h2 | 256 | 167,124 | 64,555 | 62,569 | 61,849 |
| h2 | 2,048 | 115,361 | over limit | over limit | over limit |

At 2,048 HTTP/2 connections with ten streams each, the offered 20,480 concurrent exchanges exceed `http.max_connections` (8,192). Sibuna answered about 65,000 requests per second and refused the rest with 503.

## Latency (p50 / p99)

| Workload | Connections | HAProxy | Sibuna off |
| --- | ---: | ---: | ---: |
| tcp | 256 | 0.91 ms / 2.00 ms | 0.95 ms / 2.13 ms |
| tcp | 2,048 | 10.68 ms / 20.28 ms | 10.79 ms / 16.75 ms |
| http | 256 | 1.00 ms / 2.32 ms | 0.89 ms / 16.15 ms |
| http | 2,048 | 11.54 ms / 23.86 ms | 4.95 ms / 663 ms |
| https | 256 | 1.41 ms / 4.72 ms | 2.76 ms / 6.48 ms |
| https | 2,048 | 6.99 ms / 94.30 ms | 25.31 ms / 60.45 ms |
| h2 | 16 | 0.75 ms / 6.23 ms | 2.19 ms / 8.55 ms |
| h2 | 256 | 15.00 ms / 61.31 ms | 39.35 ms / 130.26 ms |

At 2,048 plaintext HTTP connections wrk also reported 159 to 249 request timeouts against Sibuna and none against HAProxy.

## Memory and CPU

Both proxies used all eight CPUs at 256 and 2,048 connections. Resident memory at 2,048 connections: tcp 9 MiB for Sibuna and 51 MiB for HAProxy; http 298 MiB and 70 MiB; https 348 MiB and 132 MiB. At 256 plaintext HTTP connections Sibuna spent about 80% of its CPU time in the kernel and made 2.9 context switches per request.

## Reading

TCP forwarding matches HAProxy in throughput and latency and uses less memory. HTTP matches it at 16 connections. From 256 connections the firewall's thread per connection costs context switches that an event loop does not pay, and Sibuna reaches 59% to 77% of HAProxy's plaintext throughput. TLS and HTTP/2 add a handoff from the protocol runtime to a firewall thread for each connection or exchange, and reach 53% to 70% and 37% to 39%. Gate and shield cost nothing measurable over `off` on this workload.
