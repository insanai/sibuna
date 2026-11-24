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
