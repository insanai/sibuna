# Edge HTTP on event-driven workers, 2026-11-24

This record repeats the HTTP cells of `edge-haproxy-2026-11-24.md` after SID 0016 moved the HTTP firewall of edge mode from a thread per connection to event-driven workers. The host, the origins, the load generators and the CPU sets are those of that record: two origins on four CPUs, the proxy on eight, the load generator on four, all over loopback. Each cell is one run of eight seconds. It is a manual record, not a repeated measurement.

## Throughput (requests per second)

| Workload | Connections | HAProxy 3.0.11 | Sibuna threads | Sibuna workers | Workers / HAProxy |
| --- | ---: | ---: | ---: | ---: | ---: |
| http | 16 | 139,618 | 135,435 | 162,810 | 1.17 |
| http | 256 | 243,864 | 143,311 | 229,139 | 0.94 |
| http | 2,048 | 163,491 | 133,301 | 176,448 | 1.08 |
| https | 16 | 108,360 | 75,318 | 86,816 | 0.80 |
| https | 256 | 166,407 | 88,785 | 146,874 | 0.88 |
| https | 2,048 | 130,700 | 75,104 | 120,840 | 0.92 |
| h2, 10 streams | 16 | 195,808 | 72,602 | 103,903 | 0.53 |
| h2, 10 streams | 256 | 167,124 | 64,555 | 96,977 | 0.58 |

The plaintext HAProxy column is from this run. The `https` and `h2` HAProxy columns and the whole thread column are from the earlier record, on the same host and configuration. With `surface` `shield` and an allow-all policy the workers served 160,339, 226,703 and 172,949 plaintext requests per second at 16, 256 and 2,048 connections.

## Latency (p50 / p99)

| Workload | Connections | HAProxy | Sibuna threads | Sibuna workers |
| --- | ---: | ---: | ---: | ---: |
| http | 16 | 0.11 ms / 0.17 ms | | 0.09 ms / 0.15 ms |
| http | 256 | 1.00 ms / 1.47 ms | 0.89 ms / 16.15 ms | 0.96 ms / 2.60 ms |
| http | 2,048 | 11.55 ms / 30.61 ms | 4.95 ms / 663 ms | 10.95 ms / 18.03 ms |
| https | 256 | 1.41 ms / 4.72 ms | 2.76 ms / 6.48 ms | 1.54 ms / 4.38 ms |
| https | 2,048 | 6.99 ms / 94.30 ms | 25.31 ms / 60.45 ms | 14.15 ms / 56.54 ms |
| h2 | 16 | 0.75 ms / 6.23 ms | 2.19 ms / 8.55 ms | 1.52 ms / 7.06 ms |
| h2 | 256 | 15.00 ms / 61.31 ms | 39.35 ms / 130.26 ms | 26.20 ms / 114.84 ms |

## Memory

Resident memory of the proxy at 2,048 plaintext connections under load: 62 MiB with workers, 298 MiB with threads, 74 MiB for HAProxy.

A separate run opened connections without load, with `http.max_connections` 200,000.

| State | Resident memory | Threads |
| --- | ---: | ---: |
| Started | 7 MiB | 35 |
| 20,000 idle keep-alive connections | 15 MiB | 35 |
| 10,000 open WebSocket tunnels, each echoing a message three times | 27 MiB | 35 |

An idle connection therefore costs about 0.4 KiB in the process and a tunnel about 2 KiB. The kernel's socket memory is not part of these figures. All 10,000 tunnels were accepted in 0.9 s and every echo was correct.

## Processors

Plaintext HTTP at 256 connections, with the proxy confined to a CPU set.

| CPUs | Requests per second | CPU seconds in 6 s |
| ---: | ---: | ---: |
| 1 | 67,989 | 5 |
| 2 | 92,122 | 11 |
| 4 | 176,383 | 23 |
| 8 | 226,750 | 38 |

The worker count follows the CPUs the process may use. At eight CPUs the four CPUs of the load generator and the four of the origins also limit the result, as they do for HAProxy.

## Notes

- wrk reported 256 to 320 read errors per plaintext cell at 16 and 256 connections. Sibuna closes a keep-alive connection after 4,096 requests and announces it with `Connection: close`. wrk counts each such close as a read error. The count matches the request total divided by 4,096.
- The `h2` cell at 2,048 connections is omitted. The configuration still capped `http.max_connections` at 8,192, below the 20,480 concurrent streams offered.
- HTTP/2 remains the furthest from HAProxy. Each stream still crosses a socket pair between the protocol runtime and a worker.

## Three nodes

Three nodes on three hosts ran with a mesh, `surface` `shield`, a TLS frontend and three HTTP origins with HTTP health checks. A client held 300 WebSocket tunnels through each node and sent requests through each node in a loop.

| Event | Observation |
| --- | --- |
| Steady | No request failed. Each node reported the regional regime. |
| One origin stopped | 10 of about 114,000 requests failed in the four seconds around the stop. After the health check removed the origin, none failed. The tunnels to that origin closed, and the others stayed. |
| Origin returned | It received requests again after two passed probes. 90 of 90 new tunnels opened. |
| One node killed | Every tunnel through the two other nodes stayed open, and no request through them failed. |
| Reload of one node without one origin | No request failed. The node stopped using that origin. Its tunnels stayed open. |
| Reload with a broken file | The node logged `EDGE002`, kept its routes and failed no request. |
| One node stopped with SIGTERM | It closed its tunnels after the drain period. Tunnels through the remaining node stayed open. The remaining node reported the standalone regime, and the regional regime again when the others returned. |
| Rule check | A WebSocket offer with a foreign `Origin` received 403. A WebSocket over TLS opened and echoed. |

## Three proxies in one run

A later run on the same host measured HAProxy 3.0.11, Envoy 1.40.2 and Sibuna one after the other, each with eight threads on the same eight CPUs, least-connections or least-request balancing, and the same certificate. Sibuna ran with `surface` `off` and `http.max_connections` 100,000. Envoy ran with `--concurrency 8`, request ids and dynamic router statistics off, and circuit breakers raised out of the way. Requests per second:

| Workload | Connections | HAProxy | Envoy | Sibuna | Sibuna / HAProxy | Sibuna / Envoy |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| http | 16 | 143,153 | 50,624 | 161,847 | 1.13 | 3.20 |
| http | 256 | 245,317 | 69,996 | 226,782 | 0.92 | 3.24 |
| http | 2,048 | 174,563 | 59,820 | 172,319 | 0.99 | 2.88 |
| https | 16 | 107,938 | 52,497 | 86,858 | 0.80 | 1.65 |
| https | 256 | 166,343 | 63,293 | 149,456 | 0.90 | 2.36 |
| https | 2,048 | 130,514 | 51,241 | 122,280 | 0.94 | 2.39 |
| h2, 10 streams | 16 | 200,619 | 81,320 | 102,774 | 0.51 | 1.26 |
| h2, 10 streams | 256 | 167,262 | 69,054 | 97,271 | 0.58 | 1.41 |
| h2, 10 streams | 2,048 | 115,585 | 58,245 | 80,277 | 0.69 | 1.38 |

No request failed in any HTTP/2 cell. The 99th percentile at 256 connections: plaintext 1.46 ms, 5.44 ms and 2.60 ms for HAProxy, Envoy and Sibuna; TLS 5.05 ms, 5.97 ms and 4.14 ms; HTTP/2 54.86 ms, 89.71 ms and 128.86 ms. Resident memory at 2,048 plaintext connections: 72 MiB, 142 MiB and 38 MiB.

## Where the processor time goes

The kernel's per-thread counters, read before and after six seconds at 256 connections, give the CPU time per request by thread group.

| Workload | Proxy | Requests | Worker threads | TLS runtime threads | CPU per request |
| --- | --- | ---: | ---: | ---: | ---: |
| http | HAProxy | 1,500,099 | 47.6 s | | 31.7 us |
| http | Sibuna | 1,381,527 | 38.8 s | | 28.1 us |
| https | Sibuna | 937,012 | 21.0 s | 18.8 s | 42.5 us |
| h2 | Sibuna | 595,838 | 17.8 s | 27.3 s | 75.7 us |

On plaintext HTTP Sibuna spends less CPU per request than HAProxy. It serves fewer requests because its workers sleep more: they used 81% of the eight CPUs and HAProxy 99%. On TLS and HTTP/2 a second group of threads does about half of the work or more. That group terminates TLS and HTTP/2 and then writes each request as HTTP/1.1 text into a socket pair, which a worker reads and parses again. The HTX documentation of HAProxy describes the same design in its own history: its first HTTP/2 support converted HTTP/2 to HTTP/1, which "was terribly unefficient because it required two parsing passes". HAProxy now keeps one internal message form and runs TLS, HTTP/2 and the server connection of a stream on one thread.
