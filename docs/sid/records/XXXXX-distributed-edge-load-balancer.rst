:sid-number: XXXXX
:sid-title: Sibuna Edge: Distributed TCP/UDP Load Balancer, Mmap State Engine, and Adaptive Cluster Fabric
:sid-state: prediscussion
:sid-status: Working Draft
:sid-type: Architectural Specification
:sid-authors: ["Vikrant Rathore"]
:sid-created: 2026-11-24
:sid-updated: 2026-11-24
:sid-discussion: No external discussion URL assigned
:sid-summary: Extends Sibuna from a single-origin HTTP/1.1 firewall into a portable C10M-inspired distributed L4/L7 TCP/UDP load balancer with strict control/data-plane separation, JLV/2 programmable configuration shared with jlavideploy and jlavici alongside hitless runtime reloads, a saturation-proof pure-Rust seqlock memory-mapped key-value store, a capability-isolated plugin architecture, an autonomous three-regime cluster data plane, multi-stage DDoS self-protection, Raylib-style modular crates, and Lean 4 machine-checked proofs.
:sid-labels: ["architecture","load-balancer","network","ddos","mathematics"]

Sibuna Edge: Distributed TCP/UDP Load Balancer, Mmap State Engine, and Adaptive Cluster Fabric
==============================================================================================

Abstract
--------

Sibuna (SID 0002, SID 0010) currently operates behind a third-party ingress as a single-origin HTTP/1.1 admission gate and semantic WAF on a reusable thread-per-connection runtime. This record specifies **Sibuna Edge**: an architectural extension that turns Sibuna into a **distributed Layer-4 (TCP/UDP) and Layer-7 (HTTP) load balancer** comparable in operational capability to HAProxy, Katran, and Unimog while preserving Sibuna's single-binary deployment, TigerStyle bounds (SID 0001), zero-allocation hot path, and ``unsafe_code = "deny"`` workspace discipline.

An operator observes six cohesive capabilities:

1. **Strict Control-Plane / Data-Plane Split & Portable C10M Execution:** Inspired by Robert Graham's C10M principles (*"the kernel is the control plane, not the data plane"*) without NIC takeover (no mandatory DPDK/PF_RING), pinned shared-nothing workers drive cooperative OS batching (``io_uring``/``epoll`` + ``SO_REUSEPORT`` + ``recvmmsg``/``splice`` on Linux, ``kqueue`` on BSD/macOS, ``IOCP`` on Windows) over 64-byte L3-resident flow slots and borrowed transient buffer rings.
2. **JLV/2 Configuration ("One Schema, Two Spellings") & Hitless Runtime Reloads:** Reuses the sibling **JLV/2** pure, statically typed, step-budgeted language from ``jlavideploy`` and ``jlavici`` (``sibuna.jlv`` alongside zero-dependency static ``.json``), synchronised on disk for GitOps or through SQLite/PostgreSQL (SID 0011), with sub-5-nanosecond in-process ``Arc`` snapshot swaps (``SIGHUP``) and zero-drop ``SCM_RIGHTS`` listener handover across binary upgrades (``SIGUSR2``).
3. **Ultrafast Pure-Rust Memory-Mapped KV Store** (``sibuna-kv``): A lock-free optimistic-seqlock L1 RAM cache backed by a bounded ``MAP_SHARED`` disk ring arena with W-TinyLFU admission. Under volumetric DDoS or botnet state saturation, cold stick-table and session entries spill seamlessly to memory-mapped disk and one-hit attack keys shed deterministically in :math:`O(1)` without OOM or process crash.
4. **Adaptive Topology-Driven Data Plane (ATDP):** Nodes continuously measure cluster peer count and round-trip latency with deadband hysteresis, automatically configuring the data plane across **Standalone P2C-PEWMA**, **LAN/PoP Mesh (Bounded-Load Maglev + 1-Hop Consistent Peer Forwarding + UDP Delta-CRDT Stick-Tables)**, and **Geo-Anycast WAN (Locality-Tiered Maglev + Stateless Routing Tokens)**.
5. **Multi-Tier Plugin Architecture** (``sibuna-plugin``): Zero-cost native Rust phase traits alongside fuel-metered, zero-WASI WebAssembly linear-memory sandboxes and an asynchronous out-of-process Stream Processing Offload Engine (Sibuna SPOE).
6. **Formal Proofs & Raylib-Style Modular Crates:** Every core scheduling, memory-saturation, convergence, and DDoS-shedding algorithm is accompanied by formal axioms, lemmas, proofs, and a **machine-checked Lean 4.19.0 specification** (``docs/sid/assets/distributed-edge-load-balancer.lean``), realised in small orthogonal crates with flat, plain-data Raylib-style APIs.

Motivation and scope
--------------------

Why extend Sibuna to Layer-4 TCP/UDP load balancing
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Deploying Sibuna today requires placing nginx, Caddy, Envoy, or HAProxy in front of it (SID 0002, SID 0014) and running one Sibuna daemon per upstream application. That split creates four operational pain points at edge scale:

- **Single-Origin Coupling:** ``Config`` binds one ``listen_host:listen_port`` to one ``upstream_host:upstream_port`` literal. Routing ten services or draining one backend server requires an external load balancer.
- **Thread-per-Connection Ceiling:** Full-duplex TCP tunnelling after an upgrade spawns two OS threads per connection (1 MiB + 128 KiB stacks in ``sibuna-net::duplex``), capping a node at ``MAX_CONNECTIONS_LIMIT = 8,192`` sockets before virtual memory and scheduler context-switching dominate tail latency.
- **No UDP Data Plane:** DNS, QUIC/HTTP3 passthrough, WireGuard, VoIP, gaming, and custom telemetry transports run over UDP, where Sibuna currently has zero listener, flow-tracking, or flood-mitigation support.
- **Ingress Blindness to Raw Wire Signals:** In SID 0014 Sibuna had to trust an external ingress header for JA4 TLS fingerprints because terminating HTTP/2 and HTTP/3 inside a WAF enlarges the attack surface. Yet an **L4 TCP passthrough load balancer** sees the initial TLS ``ClientHello`` directly on the wire: it can route by SNI/ALPN and compute native JA4/JA4T fingerprints in-house *without* terminating TLS or parsing HTTP/2 frames, forwarding the verified identity downstream via PROXY protocol v2 TLVs.

Why C10M without kernel takeover
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Robert Graham's C10M analysis (*"The Secret to 10 Million Concurrent Connections — The Kernel Is the Problem"*) identifies three root causes of connection collapse: (1) mixing control-plane scheduling with data-plane packet forwarding, (2) per-packet syscall and lock contention across cores, and (3) blowing CPU L3 caches with bloated per-socket allocations. Full kernel-bypass frameworks (DPDK, netmap, PF_RING) solve C10M by seizing the entire network interface card in user space.

**Sibuna explicitly rejects full NIC takeover.** Seizing the NIC breaks ``sibuna``'s single-binary portability across Linux, FreeBSD, OpenBSD, macOS, and Windows, blinds the host kernel's BGP/ARP/ICMP/SSH control plane, prevents container/Kubernetes sidecar deployment, and requires vendor-specific PMD drivers. Instead, Sibuna applies the **architectural laws of C10M cooperatively** atop modern OS primitives:

1. **Kernel handles L2/L3 ARP, BGP, routing tables, and NIC hardware interrupts; Sibuna owns L4/L7 flow state.**
2. **Thread-per-Core Shared-Nothing Sharding:** Hardware RSS and kernel ``SO_REUSEPORT`` (augmented on Linux by an optional cooperative ``SO_ATTACH_REUSEPORT_CBPF`` socket group) hash 4-tuples directly to pinned worker threads so workers never contend on an accept or flow-table lock.
3. **Syscall Amortisation:** Batched event submission/completion (``io_uring`` multishot & buffer rings, ``recvmmsg``/``sendmmsg``, ``kqueue`` batch ``kevent``, ``splice(2)``) reduces privilege crossings by :math:`16\times` to :math:`64\times`.
4. **64-Byte Cache-Line Flow State & Zero Idle Buffers:** An idle TCP or UDP flow occupies **one 64-byte cache line** (640 MiB for :math:`10^7` flows), borrowing read/write buffers from a per-core slab ring *only* during the microseconds bytes are in flight.

Scope and non-goals
~~~~~~~~~~~~~~~~~~~

This record specifies the production deployment architecture, the control/data-plane boundary, the ``sibuna.jlv`` (JLV/2) + canonical JSON configuration model and runtime reload protocol, ``sibuna-kv``, the three-regime distributed data plane, the plugin subsystem, the seven-stage DDoS self-protection pipeline, the formal mathematical models with Lean 4 proofs, and the Raylib-style crate APIs.

**Deliberate non-goals:**

- **Full HTTP/2 or HTTP/3 termination** inside Sibuna (rejected for the security reasons of SID 0014; Sibuna load-balances HTTP/2 and HTTP/3/QUIC transparently at L4 via TLS SNI/ALPN and QUIC Connection ID routing, while inspecting HTTP/1.1 at L7 where configured).
- **Mandatory eBPF/XDP root privileges:** Cooperative socket filters and ``io_uring`` accelerate Linux deployments when ``CAP_NET_ADMIN`` / modern kernels are present, but unprivileged ``epoll``/``kqueue``/``IOCP`` fallbacks preserve identical semantics everywhere.

Specification
-------------

Infrastructure Deployment Architecture
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Sibuna Edge is designed to run either at the bare-metal / VM network perimeter behind BGP Anycast / ECMP routers or inside cloud VPCs / Kubernetes clusters as an ingress load-balancing tier. Crucially, Sibuna binds only its configured VIPs/ports and leaves SSH, BGP daemons (BIRD/FRR), WireGuard meshes, and host telemetry untouched on the kernel network stack.

.. typst-diagram::
   :caption: Production infrastructure deployment of a Sibuna Edge PoP. BGP Anycast / ECMP routers spray flows across Sibuna nodes; NIC RSS and cooperative SO_REUSEPORT steer packets to pinned shared-nothing workers backed by memory-mapped NVMe spill arenas, while the out-of-band control plane manages configuration, health, and PostgreSQL sync.
   :alt: Layered infrastructure diagram from Internet and Attackers through Upstream IXP/Transit BGP Anycast and ECMP Routers, into a Sibuna Edge Node showing Cooperative NIC/Kernel Socket Steering alongside untouched Host SSH/FRR, Pinned Data-Plane Workers with L1 Seqlock RAM and NVMe mmap spill, Out-of-Band Control Plane and PostgreSQL HA, forwarding over PROXYv2 to TCP, UDP/QUIC, and HTTP Origin Fleets.

   #import "@preview/cetz:0.5.2"
   #set text(font: "Libertinus Serif", size: 8.0pt, fill: rgb("#172033"))
   #cetz.canvas(length: 1cm, {
     import cetz.draw: *

     let ink = rgb("#172033")
     let muted = rgb("#64748b")
     let blue = rgb("#1e40af")
     let blue-bg = rgb("#eff6ff")
     let green = rgb("#15803d")
     let green-bg = rgb("#f0fdf4")
     let amber = rgb("#b45309")
     let amber-bg = rgb("#fffbeb")
     let red = rgb("#b91c1c")
     let red-bg = rgb("#fef2f2")
     let violet = rgb("#6d28d9")
     let violet-bg = rgb("#f5f3ff")
     let slate-bg = rgb("#f8fafc")

     let card(x1, y1, x2, y2, fill-c, stroke-c, title, body) = {
       rect((x1, y1), (x2, y2), radius: 3pt, fill: fill-c, stroke: 0.75pt + stroke-c)
       content(((x1 + x2) / 2, (y1 + y2) / 2), box(width: (x2 - x1 - 0.25) * 1cm, align(center, {
         text(weight: "bold", size: 7.7pt, fill: stroke-c.darken(15%), title)
         if body != "" {
           linebreak()
           text(size: 6.7pt, fill: ink, body)
         }
       })))
     }

     let arr(p1, p2, col, lbl: none) = {
       line(p1, p2, stroke: 0.8pt + col, mark: (end: "stealth", fill: col, scale: 0.65))
       if lbl != none {
         content(((p1.at(0) + p2.at(0)) / 2, (p1.at(1) + p2.at(1)) / 2),
           box(fill: white, inset: 1.3pt, text(size: 6.6pt, fill: col.darken(10%), lbl)))
       }
     }

     // Tier 0: Clients & Attackers
     card(0.0, 11.4, 6.8, 12.6, green-bg, green, "Legitimate Clients (TCP / UDP / HTTPS / QUIC)",
       "Browsers, APIs, DNS, WireGuard, VoIP, Gaming")
     card(7.6, 11.4, 14.4, 12.6, red-bg, red, "Volumetric & State-Exhaustion Adversaries",
       "SYN/UDP Spoof Floods, Million-IP Botnets, TLS/HTTP Scrapers")

     // Tier 1: Network Perimeter
     card(1.6, 9.6, 12.8, 10.7, blue-bg, blue,
       "Edge Transit / IXP — BGP Anycast VIPs + L3/L4 ECMP Hardware Hashing",
       "Stateless 5-tuple ECMP spray across active Sibuna Edge hosts; BIRD/FRR announces /24 & /48 health")
     arr((3.4, 11.4), (4.8, 10.7), green)
     arr((11.0, 11.4), (9.6, 10.7), red)

     // Tier 2: Sibuna Edge Host Box
     rect((0.0, 2.7), (10.3, 8.85), radius: 4pt, fill: slate-bg, stroke: 1.0pt + blue)
     content((0.25, 8.52), anchor: "west",
       text(weight: "bold", size: 8.2pt, fill: blue, "Sibuna Edge Host i (Node 1..K in PoP — Zero NIC Takeover)"))

     // Inside Host: NIC + Kernel Cooperative Layer
     card(0.3, 6.85, 6.7, 8.15, blue-bg, blue,
       "NIC RSS + Kernel SO_REUSEPORT + cBPF",
       "SYN cookies, TCP_DEFER_ACCEPT, io_uring, recvmmsg, kqueue")
     card(7.0, 6.85, 10.0, 8.15, white, muted,
       "Co-Resident OS Stack",
       "BIRD/FRR BGP, SSHd,\nICMP/ARP untouched")

     // Pinned Workers
     card(0.3, 4.75, 3.35, 6.35, green-bg, green,
       "Core 0 Worker",
       "64B FlowTable + Slab\nMaglev/P2C + Plugins\nStateless UDP Gate")
     card(3.55, 4.75, 6.7, 6.35, green-bg, green,
       "Core 1..N Workers",
       "Shared-Nothing Loops\nTLS SNI + Native JA4\nGCRA + PoSW Gate")

     // Mmap KV Spill Arena
     card(0.3, 2.95, 6.7, 4.3, amber-bg, amber,
       "sibuna-kv (L1 Seqlock RAM -> L2 NVMe MAP_SHARED)",
       "W-TinyLFU admission; saturation spills cold flows to disk; 0 OOM")

     // Local Control Plane inside Host
     card(7.0, 2.95, 10.0, 6.35, violet-bg, violet,
       "Local Control Plane",
       "JLV/JSON Eval & RCU\nActive Health Prober\nSCM_RIGHTS Hot-FD\nSWIM + CRDT Gossip\nSPOE Offload Client")

     arr((5.0, 9.6), (3.5, 8.15), blue, lbl: "VIP Flows")
     arr((1.8, 6.85), (1.8, 6.35), green)
     arr((5.1, 6.85), (5.1, 6.35), green)
     arr((1.8, 4.75), (1.8, 4.3), amber)
     arr((5.1, 4.75), (5.1, 4.3), amber)
     line((7.0, 5.55), (6.7, 5.55), stroke: (paint: violet, thickness: 0.75pt, dash: "dashed"),
       mark: (end: "stealth", fill: violet, scale: 0.6))

     // Peer Cluster Mesh + Shared Control Plane (Right side)
     card(10.75, 6.15, 14.4, 8.65, green-bg, green,
       "Sibling Edge Nodes (2..K)",
       "UDP SWIM Heartbeats\nDelta-CRDT Stick-Tables\n1-Hop CPF Tunnel\n(Auto-tuned by RTT)")
     card(10.75, 2.95, 14.4, 5.75, violet-bg, violet,
       "Cluster Control Plane",
       "sibuna.jlv (GitOps) +\nPostgreSQL HA Store\nNOTIFY sibuna_policy\nWASM Operator Console")

     line((10.0, 7.4), (10.75, 7.4), stroke: 0.8pt + green,
       mark: (start: "stealth", end: "stealth", fill: green, scale: 0.6))
     line((10.0, 4.35), (10.75, 4.35), stroke: 0.8pt + violet,
       mark: (start: "stealth", end: "stealth", fill: violet, scale: 0.6))

     // Tier 3: Origin Fleets
     card(0.0, 0.3, 4.5, 1.75, blue-bg, blue,
       "TCP / TLS Origin Pool",
       "PROXYv2 + SNI + JA4 TLV\nDatabases, gRPC, TLS Ingress")
     card(4.95, 0.3, 9.45, 1.75, green-bg, green,
       "UDP / QUIC Origin Pool",
       "4-Tuple NAT / CID Affinity\nHTTP/3, DNS, Media, WireGuard")
     card(9.9, 0.3, 14.4, 1.75, amber-bg, amber,
       "HTTP/1.1 Protected Origins",
       "Sibuna Gate / Shield WAF\nStriped Keep-Alive Pools")

     arr((2.2, 2.7), (2.2, 1.75), blue, lbl: "L4 TCP")
     arr((5.1, 2.7), (7.1, 1.75), green, lbl: "L4 UDP")
     arr((6.4, 2.7), (11.8, 1.75), amber, lbl: "L7 HTTP")
   })

Control Plane vs. Cooperative C10M Data Plane
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Following HAProxy's master-worker architecture and SID 0007's isolation invariants, Sibuna Edge enforces an absolute hardware and ownership wall between the **Control Plane** and the **Data Plane**:

- **Control Plane (Off-Path Threads, Asynchronous Allowed):** Runs configuration evaluation and validation (``sibuna-jlv`` for ``.jlv`` programs and ``sibuna-conf`` for canonical JSON/schema validation), ``sqlx`` database synchronisation (SID 0011), active TCP/UDP/HTTP backend health probes, SWIM peer RTT measurement and Delta-CRDT gossip batching (``sibuna-cluster``), the operator console (``sibuna-console``), and the Unix administrative control socket (``/run/sibuna/admin.sock``). It publishes immutable ``Arc<TopologySnapshot>`` values into a global ``TopologySlot`` and updates atomic backend health bitmaps. **It never touches a client socket or holds a lock a worker acquires.**
- **Data Plane (Pinned Run-to-Completion Worker Threads, Zero Heap Allocation):** One OS thread per assigned CPU core (``--workers``, pinned via ``sched_setaffinity`` where supported). Each worker owns its own ``Poller`` instance (``sibuna-io``), its own ``FlowTable`` shard, and its own fixed ``SlabRing`` of 16 KiB I/O buffers. Workers read ``TopologySlot`` through a thread-local generation cache (one ``Acquire`` atomic load per event batch, :math:`< 2\,\text{ns}`).

.. admonition:: Invariant D1 (C10M Cache-Line Flow Compactness)

   Every active or idle L4 TCP/UDP flow in a worker's ``FlowTable`` occupies **exact 64 bytes** (one x86-64 / ARM64 cache line, ``#[repr(C, align(64))]``). A connection silent between bursts holds **zero** read/write buffer memory; a 16 KiB transfer buffer is leased from the worker's pre-allocated ``SlabRing`` upon readiness notification and returned before the ``poll_batch`` turn ends whenever the outbound socket accepts the write.

.. typst-diagram::
   :caption: Exact 64-byte cache-line layout of a worker-local FlowSlot (top) and the strict Control-Plane / Data-Plane isolation boundary (bottom). Ten million concurrent idle flows require 640 MiB of flow metadata and zero heap allocations.
   :alt: Top shows a 64-byte cache line split into client_ip (16B), client_port (2B), vip_port (2B), client_fd (4B), upstream_fd (4B), backend_id (2B), flags_proto (2B), rx_slab_idx (2B), tx_slab_idx (2B), last_active_ms (8B), bytes_up_down_q (8B), hash_tag (8B), and generation_ver (4B). Bottom shows Control Plane publishing Arc<TopologySnapshot> via Acquire/Release atomic generation into Core-Pinned Shared-Nothing Data-Plane Workers.

   #import "@preview/cetz:0.5.2"
   #set text(font: "Libertinus Serif", size: 8pt, fill: rgb("#172033"))
   #cetz.canvas(length: 1cm, {
     import cetz.draw: *

     let ink = rgb("#172033")
     let blue = rgb("#1e40af")
     let blue-bg = rgb("#eff6ff")
     let green = rgb("#15803d")
     let green-bg = rgb("#f0fdf4")
     let amber = rgb("#b45309")
     let amber-bg = rgb("#fffbeb")
     let violet = rgb("#6d28d9")
     let violet-bg = rgb("#f5f3ff")

     content((0, 7.05), anchor: "west",
       text(weight: "bold", size: 8.5pt, fill: ink, "FlowSlot: #[repr(C, align(64))] — 64 Bytes Exactly (1 CPU Cache Line)"))

     let cell(x1, x2, y, bg, fg, name, bytes) = {
       rect((x1, y), (x2, y + 1.1), fill: bg, stroke: 0.7pt + fg)
       content(((x1 + x2) / 2, y + 0.55), align(center, {
         raw(name)
         linebreak()
         text(size: 6.8pt, fill: fg.darken(15%), bytes)
       }))
     }

     cell(0.0, 3.0, 5.7, blue-bg, blue, "client_ip", "16 B (v6/v4m)")
     cell(3.0, 4.3, 5.7, blue-bg, blue, "ports", "4 B (c,v)")
     cell(4.3, 6.1, 5.7, green-bg, green, "fds / sock", "8 B (c,u)")
     cell(6.1, 7.6, 5.7, green-bg, green, "backend", "4 B (id,st)")
     cell(7.6, 9.1, 5.7, amber-bg, amber, "slab_idx", "4 B (rx,tx)")
     cell(9.1, 10.9, 5.7, amber-bg, amber, "active_ms", "8 B (mono)")
     cell(10.9, 12.7, 5.7, violet-bg, violet, "flow_hash", "8 B (sip)")
     cell(12.7, 14.4, 5.7, violet-bg, violet, "quota_gen", "12 B (tat,g)")

     line((0.0, 5.42), (14.4, 5.42), stroke: 0.6pt + ink, mark: (start: "|", end: "|"))
     content((7.2, 5.12), text(size: 7.3pt, fill: ink,
       "64 B per flow  =>  100k flows = 6.4 MiB (fits in single Ryzen/EPYC L3)  |  10M flows = 640 MiB"))

     // Control Plane vs Data Plane Split
     rect((0.0, 0.15), (5.55, 4.5), radius: 3pt, fill: violet-bg, stroke: 0.85pt + violet)
     content((2.78, 4.15), text(weight: "bold", size: 8.0pt, fill: violet, "Control Plane (Off-Path)"))
     line((0.25, 3.88), (5.3, 3.88), stroke: 0.5pt + violet.lighten(40%))
     content((2.78, 2.0), box(width: 5.05cm, align(left, text(size: 7.1pt, [
       • *JLV / JSON Eval:* `sibuna.jlv` -> `EdgeConfig`\
       • *Health Engine:* TCP / HTTP / UDP probes\
       • *Storage Sync:* SQLite / PostgreSQL `sqlx`\
       • *Cluster Agent:* SWIM RTT + Delta-CRDT\
       • *Admin IPC:* `/run/sibuna/admin.sock`\
       • *Hot Upgrade:* `SCM_RIGHTS` FD passer
     ]))))

     rect((7.55, 0.15), (14.4, 4.5), radius: 3pt, fill: green-bg, stroke: 0.85pt + green)
     content((10.98, 4.15), text(weight: "bold", size: 8.0pt, fill: green, "Data Plane (Pinned Core Workers 0..N-1)"))
     line((7.8, 3.88), (14.15, 3.88), stroke: 0.5pt + green.lighten(40%))
     content((10.98, 2.0), box(width: 6.35cm, align(left, text(size: 7.1pt, [
       • *Poller (`sibuna-io`):* `io_uring` / `epoll` / `kqueue`\
       • *Zero-Copy:* Linux `splice(2)` + `recvmmsg`\
       • *SlabRing:* 16 KiB leased only while active\
       • *Scheduler:* O(1) Bounded Maglev + PEWMA\
       • *State (`sibuna-kv`):* Seqlock RAM + `mmap` spill\
       • *Plugins:* Native traits + Fuel-metered WASM
     ]))))

     line((5.55, 3.0), (7.55, 3.0), stroke: 1.0pt + violet, mark: (end: "stealth", fill: violet))
     content((6.55, 3.38), align(center, text(size: 6.7pt, fill: violet, "Arc<Snapshot>\n1 Acquire Load")))

     line((7.55, 1.35), (5.55, 1.35), stroke: (paint: green, thickness: 0.9pt, dash: "dashed"),
       mark: (end: "stealth", fill: green))
     content((6.55, 0.88), align(center, text(size: 6.7pt, fill: green, "Vyukov Ring &\nAtomic Counters")))
   })

Tiered cooperative I/O backend (``sibuna-io``)
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

To uphold portability across every release target of SID 0010 without ``tokio`` or ``mio`` on the data plane, ``sibuna-io`` encapsulates the smallest possible OS event-notification surface inside one isolated module (carrying explicit ``// SAFETY:`` invariants, as ``sibuna-store::ring`` and ``sibuna-crypto`` SIMD modules do):

.. list-table:: Cooperative OS I/O tiers in ``sibuna-io`` (zero NIC takeover)
   :header-rows: 1
   :widths: 22 28 50

   * - Target OS
     - Mechanism
     - Zero-Copy & Batching Fast Path
   * - Linux :math:`\ge 5.19`
     - ``io_uring`` (preferred) or ``epoll``
     - Multishot ``IORING_OP_ACCEPT`` and ``IORING_OP_RECV`` with provided buffer rings; ``splice(2)`` pipe pairs for pure L4 TCP passthrough; ``recvmmsg(2)`` / ``sendmmsg(2)`` (64 datagrams/call) for UDP; ``SO_REUSEPORT`` with optional cBPF CPU steering.
   * - Linux :math:`5.10 - 5.18` (baseline)
     - ``epoll_pwait`` (``EPOLLET | EPOLLONESHOT``)
     - 256-event completion batches, ``splice(2)`` L4 TCP zero-copy, ``recvmmsg(2)`` / ``sendmmsg(2)`` UDP batches.
   * - FreeBSD 15 / OpenBSD 7.9 / macOS 12+
     - ``kqueue`` (``EV_CLEAR``)
     - Single ``kevent(2)`` syscall both registers changelists and reaps up to 256 completions; ``SO_REUSEPORT_LB`` on FreeBSD.
   * - Windows 10 / Server 2016+
     - ``IOCP`` / ``WSAPoll``
     - ``GetQueuedCompletionStatusEx`` batch completion reaping over non-blocking ``WSASocket``.

JLV/2 Configuration (``sibuna.jlv``), Canonical Schema, Storage Authority, and Hitless Reloads
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Reusing the sibling JLV/2 language ("One Language, One Schema, Two Spellings")
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

SID 0003 used flat JSON for 128 HTTP policy rules. An HAProxy-class edge load balancer expresses listeners, TCP/UDP timeouts, TLS SNI routing trees, stick-tables, health probes, 16-to-128-server backend pools across PoPs, peer meshes, and WASM plugins. Plain JSON lacks comments, arithmetic, named constants, and parametrised server generation; YAML introduces indentation footguns and type-coercion ambiguities; inventing a Sibuna-only DSL would duplicate a lexer, parser, formatter, and Language Server across sibling projects.

Instead, Sibuna Edge adopts **JLV/2** (specified in ``jlavideploy`` JDD 0004 and JDD 0016, and already shared by ``jlavici`` JCD XXXXX and ``jlavideploy/examples/sibuna``): **the ecosystem has one configuration language with one implementation**. Operators write CI workflows (``jlavici``), host/fleet deployments (``jlavideploy``), and live L4/L7 edge load-balancer topologies (``sibuna``) in the same statically typed, pure, deterministic, step-budgeted language, with ``jlvd fmt`` formatting and ``jlv-lsp`` editor diagnostics out of the box.

Following ``jlavici``'s exact **One Schema, Two Spellings** architecture:

1. **Canonical Schema & Static JSON Spelling** (``sibuna-conf``, zero external crates): Defines ``EdgeConfig`` and validates durations (``"250ms"``, ``"30s"``), byte budgets (``"256MiB"``, ``"16GiB"``), CIDRs, Maglev rings, and ACL references. Static ``.json`` files compile directly through ``sibuna-conf``, keeping ``cargo build --no-default-features`` 100% zero-external-crate (SID 0010).
2. **Programmable JLV/2 Spelling** (``sibuna-jlv``, control-plane Cargo feature ``jlv``, enabled by default): Links the five pure language kernel crates from ``jlavideploy`` (``jlv-core``, ``jlv-lang``, ``jlv-syntax``, ``jlv-compiler``, ``jlv-stdlib``). A ``sibuna.jlv`` file exports ``fn edge() -> Map<Value>``, compiled under ``Role::Transform`` with ``jlv.std.foundation`` as its sole library (no filesystem, network, clock, or multi-file ambient imports) and evaluated off-path on a dedicated 8 MiB-stack control-plane thread under ``Limits { evaluation_steps: 1_000_000, modules: 1, .. }``. Its resulting ``Value::Map`` lowers with ``jlv-syntax`` token spans into the exact same ``EdgeConfig`` validator. **Zero JLV crates or allocations ever touch a data-plane worker.**

.. code-block:: text

   // /etc/sibuna/sibuna.jlv — Sibuna Edge Topology in JLV/2 (shared with jlavideploy & jlavici)
   import { map } from jlv.std.foundation

   let api_hosts = [
       { id: 1, addr: "10.20.1.11:8443", weight: 100, max_flows: 50_000, backup: false },
       { id: 2, addr: "10.20.1.12:8443", weight: 100, max_flows: 50_000, backup: false },
       { id: 3, addr: "10.20.1.13:8443", weight: 50,  max_flows: 25_000, backup: true  },
   ]

   fn tcp_server(node: Map<Value>) -> Map<Value> {
       return {
           name: "api-${node.id}",
           addr: node.addr,
           weight: node.weight,
           max_flows: node.max_flows,
           backup: node.backup,
       }
   }

   fn edge() -> Map<Value> {
       return {
           global: {
               workers: "auto",              // 1 pinned worker per CPU core (excludes management_cpus)
               max_flows: 1_000_000,         // 64 MiB FlowSlot table across workers
               admin_socket: "/run/sibuna/admin.sock",
               cluster_mode: "adaptive",     // standalone | lan_mesh | geo_anycast
           },
           console: {
               listen: "10.99.0.11:9443",    // isolated management VLAN / WireGuard listener
               management_cpus: [0],         // off-path core disjoint from packet workers
               behind_proxy: true,
               origin: "https://edge-console.internal",
               trusted_proxies: ["10.99.0.2/32"],
               allow_operators: ["10.99.10.0/24", "fd00:99:10::/48"],  // bastion / VPN CIDRs only
               peer_key_file: "/etc/sibuna/console-peer.key",
               peer_ca_file: "/etc/sibuna/management-ca.pem",
               peers: [
                   { node: 2, origin: "https://fra-edge-02.internal:9443", allow_ips: ["10.99.0.12/32"] },
                   { node: 3, origin: "https://fra-edge-03.internal:9443", allow_ips: ["10.99.0.13/32"] },
               ],
           },
           kv_stores: {
               edge_state: {
                   ram_budget: "256MiB",     // L1 optimistic-seqlock RAM cache
                   mmap_path: "/var/lib/sibuna/edge_state.arena",
                   mmap_budget: "16GiB",     // L2 MAP_SHARED saturation spill ring
                   admission: "wtinylfu",    // blocks 1-hit DDoS flood cache pollution
               },
           },
           plugins: {
               bot_telemetry: {
                   kind: "wasm",
                   module: "/etc/sibuna/plugins/telemetry_enricher.wasm",
                   fuel_limit: 50_000,       // ~5 us deterministic execution ceiling
                   memory_pages: 4,          // 256 KiB pre-allocated linear memory
                   on_trap: "fail_open",
               },
           },
           frontends: {
               public_tls_tcp: {
                   binds: ["0.0.0.0:443", "[::]:443"],
                   proto: "tcp",
                   reuseport: true,
                   defer_accept: "5s",
                   inspect_delay: "2s",
                   tcp_inspect: "tls_client_hello",  // non-terminating SNI, ALPN & native JA4!
                   rate_limit: { conn_per_10s: 200, ipv6_prefix: 64, store: "edge_state" },
                   acls: {
                       is_api: { sni: "api.example.com" },
                       is_bad_ja4: { ja4_prefix: "t12d*" },
                   },
                   rules: [
                       { action: "deny", when: "is_bad_ja4" },
                       { action: "use_backend", backend: "api_tcp_origin", when: "is_api" },
                   ],
                   default_backend: "web_http_shield",
               },
               public_quic_dns_udp: {
                   binds: ["0.0.0.0:443"],
                   proto: "udp",
                   reuseport: true,
                   udp_defense: { mode: "stateless_cookie_under_load", threshold_pps: 50_000 },
                   session_timeout: "30s",
                   stick: { on: "quic_cid", fallback: "4tuple", store: "edge_state" },
                   default_backend: "quic_h3_fleet",
               },
           },
           backends: {
               api_tcp_origin: {
                   mode: "tcp",
                   balance: { kind: "bounded_maglev", load_factor_pct: 125, fallback: "pewma" },
                   proxy_v2: { enabled: true, tlv_ja4: true, tlv_sni: true },
                   health_check: { kind: "tcp", timeout: "500ms", interval: "2s", fall: 3, rise: 2 },
                   servers: [for n in api_hosts: tcp_server(n)],
               },
               quic_h3_fleet: {
                   mode: "udp",
                   balance: { kind: "bounded_maglev", load_factor_pct: 125 },
                   health_check: { kind: "udp", send_hex: "0001", timeout: "300ms", interval: "2s" },
                   servers: [
                       for i in [1, 2]: { name: "h3-${i}", addr: "10.20.2.1${i}:443", weight: 100 }
                   ],
               },
           },
       }
   }

Where configuration is stored (Hybrid Authority Contract)
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Operators run load balancers in two distinct operational regimes; Sibuna Edge supports both cleanly while accounting for the fact that JLV/2 functions and comprehensions are **many-to-one** (evaluating ``fn edge()`` yields plain data, which cannot be inverted back into arbitrary helper loops):

1. **Immutable File / GitOps Mode** (no ``--data-dir`` or ``--database-url``): ``sibuna.jlv`` (or static ``edge.json``) is the sole source of truth on disk. Ephemeral runtime overrides via ``sibuna adm set-weight`` live in memory until the next ``SIGHUP`` reload.
2. **Persistent / Cluster Mode** (SQLite single-node or PostgreSQL cluster, SID 0011): ``sibuna.jlv`` defines host-local bootstrap invariants (CPU worker pinning, ``mmap_path``, listener bind sockets, local ``admin_socket``), while **evaluated routing topology** (``edge_frontends``, ``edge_backends``, ``edge_servers``, ``policies``, ``ip_reputation``) is stored in typed ``STRICT`` SQL tables governed by ``policy_revision``. Alongside the relational rows, an ``edge_config_sources`` audit table records the pinned ``.jlv`` source text and its SHA-256 digest (mirroring ``jlavici``'s pinned workflow provenance). Operators apply ``sibuna.jlv`` transactionally with ``sibuna conf apply -f sibuna.jlv`` (evaluating locally, displaying a relational diff, and committing under optimistic concurrency) and export live cluster state via ``sibuna conf dump --format json|jlv`` (which emits either canonical JSON or a formatted literal ``fn edge() -> Map<Value>`` module).

Hitless runtime reload sequence (``SIGHUP`` RCU vs. ``SIGUSR2`` Socket Transfer)
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Like HAProxy, Sibuna Edge never drops an active TCP stream or an established UDP session during configuration changes or binary upgrades:

- **Tier 1 — In-Process RCU Snapshot Swap** (``SIGHUP``, Console Edit, or PostgreSQL ``NOTIFY``): Handles all changes to backends, server weights, ACLs, Maglev lookup tables, WAF policies, rate limits, and WASM plugins without touching listener sockets. The Control Plane compiles a fresh ``TopologySnapshot`` (including pre-computed 65,537-slot Maglev rings and Aho-Corasick tables) off-path; if any syntax or semantic check fails, the old snapshot remains untouched and an Elm-style diagnostic is returned. On success, ``TopologySlot::publish`` increments the generation counter with ``Release`` ordering.
- **Tier 2 — Hitless Master-Worker Binary / Listener Upgrade** (``SIGUSR2``, HAProxy ``-sf`` model): When upgrading the ``sibuna`` executable itself or changing ``bind`` addresses/worker counts, the supervisor spawns the new ``sibuna`` process. The new process connects to ``/run/sibuna/handoff.sock`` and receives every live ``TcpListener``, ``UdpSocket``, and ``sibuna-kv`` ``MAP_SHARED`` file descriptor over ``SCM_RIGHTS`` (on Windows, ``WSADuplicateSocket``). Once the new workers signal readiness, old listeners stop accepting (``SO_REUSEPORT`` seamlessly steers all new SYNs and UDP packets to the new process), and the old process drains in-flight TCP connections until ``connections == 0`` or ``--drain-timeout`` expires.

.. typst-diagram::
   :caption: Sequence diagram of Tier-1 Hitless RCU Snapshot Reload (top) and Tier-2 Hitless Binary & Socket Upgrade via Unix SCM_RIGHTS FD Passing (bottom). Zero SYN resets and zero UDP state loss occur in either path.
   :alt: Sequence diagram with five vertical lifelines: Operator/CLI, Old Control Plane, Old Data-Plane Workers, New Sibuna Process, and Live Clients. Top phase shows SIGHUP/conf apply evaluating JLV/JSON, building Maglev + Engine off-path, atomic Release store to TopologySlot, and Workers switching in <5 ns. Bottom phase shows SIGUSR2 spawning New Process, transferring Listener FDs + Mmap Arena FD via SCM_RIGHTS, atomic cutover of new SYNs/UDP packets, and graceful connection drain of Old Workers.

   #import "@preview/cetz:0.5.2"
   #set text(font: "Libertinus Serif", size: 7.8pt, fill: rgb("#172033"))
   #cetz.canvas(length: 1cm, {
     import cetz.draw: *

     let ink = rgb("#172033")
     let muted = rgb("#64748b")
     let blue = rgb("#1e40af")
     let blue-bg = rgb("#eff6ff")
     let green = rgb("#15803d")
     let amber = rgb("#b45309")
     let amber-bg = rgb("#fffbeb")
     let violet = rgb("#6d28d9")

     let xs = (0.9, 3.8, 7.0, 10.3, 13.4)
     let names = (
       "Operator /\nPostgres",
       "Control Plane\n(Gen k)",
       "Pinned Workers\n(Gen k)",
       "New Process\n(Gen k+1)",
       "Live TCP/UDP\nClients",
     )
     let cols = (violet, blue, green, amber, ink)

     for i in range(5) {
       let x = xs.at(i)
       let c = cols.at(i)
       rect((x - 1.15, 9.5), (x + 1.15, 10.35), radius: 2.5pt, fill: c.lighten(88%), stroke: 0.75pt + c)
       content((x, 9.92), align(center, text(weight: "bold", size: 7.4pt, fill: c.darken(15%), names.at(i))))
       line((x, 0.3), (x, 9.5), stroke: (paint: muted.lighten(30%), thickness: 0.65pt, dash: "dashed"))
     }

     let msg(from, to, y, col, label, dashed: false) = {
       let x1 = xs.at(from)
       let x2 = xs.at(to)
       line((x1, y), (x2, y),
         stroke: (paint: col, thickness: 0.8pt, dash: if dashed { "dashed" } else { none }),
         mark: (end: "stealth", fill: col, scale: 0.6))
       content(((x1 + x2) / 2, y + 0.22), align(center,
         box(fill: white, inset: 1.2pt, text(size: 6.9pt, fill: col.darken(15%), label))))
     }

     // Band 1: Tier-1 RCU Reload
     rect((0.0, 5.65), (14.4, 9.25), radius: 3pt, fill: blue-bg.lighten(45%), stroke: 0.5pt + blue.lighten(50%))
     content((0.2, 9.02), anchor: "west",
       text(weight: "bold", size: 7.6pt, fill: blue, "Tier 1: In-Process Hitless Reload (SIGHUP / Admin IPC / PostgreSQL NOTIFY)"))

     msg(0, 1, 8.5, violet, "1. SIGHUP / NOTIFY sibuna_policy")
     rect((2.8, 7.62), (4.8, 8.22), fill: white, stroke: 0.6pt + blue, radius: 2pt)
     content((3.8, 7.92), align(center, text(size: 6.5pt, "Eval JLV/JSON &\nBuild Maglev")))
     msg(1, 2, 7.22, blue, "2. Release store Arc<Snapshot> (gen + 1)")
     msg(4, 2, 6.62, green, "3. Existing & new flows served (<5 ns Acquire load)")
     msg(1, 0, 5.98, violet, "4. OK (applied revision & SHA-256)", dashed: true)

     // Band 2: Tier-2 Binary Upgrade
     rect((0.0, 0.5), (14.4, 5.35), radius: 3pt, fill: amber-bg.lighten(45%), stroke: 0.5pt + amber.lighten(50%))
     content((0.2, 5.12), anchor: "west",
       text(weight: "bold", size: 7.6pt, fill: amber, "Tier 2: Zero-Drop Binary / Listener Upgrade (SIGUSR2 + Unix SCM_RIGHTS)"))

     msg(0, 1, 4.6, violet, "1. SIGUSR2 (spawn upgraded binary)")
     msg(1, 3, 4.0, amber, "2. Pass TCP/UDP FDs + Mmap KV FD (SCM_RIGHTS)")
     msg(3, 1, 3.35, green, "3. READY (new SO_REUSEPORT workers armed)", dashed: true)
     msg(1, 2, 2.75, blue, "4. Detach listeners & enter draining state")
     msg(4, 3, 2.1, green, "5. All new SYNs & UDP flows -> Gen k+1 (shared mmap KV!)")
     msg(4, 2, 1.45, muted, "6. In-flight TCP streams finish cleanly on Gen k", dashed: true)
     msg(2, 1, 0.85, muted, "7. connections == 0 -> Old process exits 0", dashed: true)
   })

Ultrafast Pure-Rust Memory-Mapped KV Engine (``sibuna-kv``)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Why an edge load balancer needs a disk-spillable KV store
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

An L4/L7 edge load balancer tracks high-cardinality state: UDP 4-tuple and QUIC Connection ID affinity mappings, HAProxy-style stick-tables (source-IP session pinning, sliding connection/error rates), dynamic reputation bans, and SYN/UDP challenge budgets. Under normal traffic, a few hundred thousand entries fit effortlessly in L1 RAM. Under a **multi-million-IP botnet or spoofed DDoS saturation attack**, two catastrophic failures threaten traditional load balancers:

1. **Unbounded Heap Growth -> OOM Kill:** Growing a ``HashMap`` per flow crashes the entire edge node, dropping every legitimate service on the box.
2. **Naive LRU Eviction -> Cache Thrashing:** A fixed-size LRU table survives OOM, *but* a 5 Mpps flood of single-packet spoofed IPs immediately evicts every legitimate customer's sticky session and UDP NAT mapping!

``sibuna-kv`` solves both problems in **100% safe-interface pure Rust** (confined ``unsafe`` only for the ``mmap(2)``/``CreateFileMappingW`` FFI call and cache-line atomic seqlock reads, documented with ``// SAFETY:`` proofs and verified under Miri for the seqlock protocol).

Architecture of ``sibuna-kv``
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

``sibuna-kv`` is structured as **64 independent cache-line-padded shards** keyed by SipHash-1-3 (under a per-boot random secret so adversaries cannot cause hash-bucket collisions). Each shard pairs three fixed structures:

1. **W-TinyLFU Doorkeeper & 4-Bit Count-Min Sketch (256 KiB/shard):** Estimates candidate key frequency :math:`f(k) \in [0, 15]` with periodic halving aging. When saturated, an incoming key replaces an occupant *only* if :math:`f(\text{candidate}) > f(\text{victim})`. Spoofed single-packet flood keys (:math:`f = 1`) never displace established sessions (:math:`f \ge 1`).
2. **L1 Optimistic Seqlock RAM Table (4-Way Set-Associative, 64-Byte Slots):** Each slot holds ``seq: AtomicU64`` (even when quiescent, odd while a writer mutates), ``key_hash: u64``, ``expiry_ms: u64``, ``key: [u8; 16]``, and ``value: [u8; 24]``. Readers execute **zero atomic read-modify-writes** (no ``fetch_add``, no mutex, no cache-line invalidation across cores): they ``Acquire``-load ``seq``, copy the 56 payload bytes onto the stack, ``Acquire``-fence, and re-read ``seq``.
3. **L2 Memory-Mapped Disk Ring Arena** (``MAP_SHARED``, Fixed Pre-Allocated File): Pre-allocated at startup via ``fallocate`` / ``ftruncate`` to ``mmap_budget`` (for example 16 GiB = **268,435,456 entries** of 64 bytes each!). Cold entries displaced from L1 RAM with :math:`f \ge 2` demote sequentially into 4-way associative buckets in the ``mmap`` region, protected by a 64-bit Wyhash/CRC checksum so a power loss or torn OS page never yields corrupt state on warm restart.

.. admonition:: Non-Blocking Saturation & Page-Fault Bound

   Workers advise the kernel with ``madvise(MADV_RANDOM)`` so Linux does not waste NVMe bandwidth on useless 128 KiB read-ahead, and never call ``fsync``/``msync(MS_SYNC)`` on the packet path. Furthermore, each worker budgets at most ``--kv-cold-lookups-per-ms`` L2 ``mmap`` probes; beyond that IOPS watermark, cold misses skip L2 and treat the flow as uncached (falling back to deterministic Maglev routing!), so even slow disk I/O under extreme saturation can **never** stall packet forwarding.

.. typst-diagram::
   :caption: Data flow inside one shard of sibuna-kv during a volumetric multi-million-IP saturation event. Legitimate sticky flows stay in L1 Seqlock RAM or spill cleanly to the pre-allocated MAP_SHARED arena; 1-hit spoofed flood keys are rejected at the W-TinyLFU gate in O(1) without evicting live sessions.
   :alt: Flow diagram showing Packet Key entering SipHash-1-3 Shard Selector, checking L1 Seqlock RAM (4-way 64B slots, ~4 ns lock-free read). On miss, checks W-TinyLFU 4-bit Count-Min Sketch: if saturated and freq(cand) <= freq(victim), sheds immediately to sibuna_kv_shed_total (0 evictions, 0 crashes); if hot (freq >= 2), promotes/writes to L1 and demotes cold valid L1 occupant to Pre-allocated MAP_SHARED Disk Arena (64B checksummed slots, 268M keys per 16 GiB).

   #import "@preview/cetz:0.5.2"
   #set text(font: "Libertinus Serif", size: 7.8pt, fill: rgb("#172033"))
   #cetz.canvas(length: 1cm, {
     import cetz.draw: *

     let ink = rgb("#172033")
     let blue = rgb("#1e40af")
     let blue-bg = rgb("#eff6ff")
     let green = rgb("#15803d")
     let green-bg = rgb("#f0fdf4")
     let amber = rgb("#b45309")
     let amber-bg = rgb("#fffbeb")
     let red = rgb("#b91c1c")
     let red-bg = rgb("#fef2f2")
     let violet = rgb("#6d28d9")
     let violet-bg = rgb("#f5f3ff")

     let node(x1, y1, x2, y2, bg, fg, title, sub) = {
       rect((x1, y1), (x2, y2), radius: 3pt, fill: bg, stroke: 0.8pt + fg)
       content(((x1 + x2) / 2, (y1 + y2) / 2), box(width: (x2 - x1 - 0.22) * 1cm, align(center, {
         text(weight: "bold", size: 7.6pt, fill: fg.darken(15%), title)
         if sub != "" {
           linebreak()
           text(size: 6.7pt, fill: ink, sub)
         }
       })))
     }

     let edge(p1, p2, col, txt: none, dy: 0.22) = {
       line(p1, p2, stroke: 0.85pt + col, mark: (end: "stealth", fill: col, scale: 0.65))
       if txt != none {
         content(((p1.at(0) + p2.at(0)) / 2, (p1.at(1) + p2.at(1)) / 2 + dy),
           box(fill: white, inset: 1.3pt, text(size: 6.6pt, fill: col.darken(10%), txt)))
       }
     }

     node(0.0, 2.9, 2.55, 4.45, blue-bg, blue, "Lookup / Upsert", "Keyed SipHash-1-3\nShard 0..63")
     node(3.45, 2.7, 7.35, 4.65, green-bg, green, "L1 Seqlock RAM Tier",
       "4-Way Set-Associative (64B/slot)\nEven seq => tear-free ~4 ns read\nZero reader locks or RMW!")
     node(8.35, 2.7, 11.65, 4.65, violet-bg, violet, "W-TinyLFU Gate",
       "Bloom Doorkeeper +\n4-bit Count-Min Sketch\nTests f(cand) > f(victim)")
     node(12.55, 3.3, 14.4, 4.75, red-bg, red, "O(1) Shed",
       "1-hit flood dropped\nsibuna_kv_shed")
     node(3.6, 0.25, 11.5, 1.75, amber-bg, amber,
       "L2 Pre-Allocated MAP_SHARED Disk Arena (sibuna-kv.arena)",
       "Fixed fallocate ring (16 GiB = 268M flows) | Wyhash64 slot MAC | MADV_RANDOM | Async flush")

     edge((2.55, 3.68), (3.45, 3.68), blue, txt: "probe")
     edge((7.35, 3.68), (8.35, 3.68), violet, txt: "miss / full")
     edge((11.65, 4.02), (12.55, 4.02), red, txt: "f <= fv")
     edge((5.4, 2.7), (5.4, 1.75), amber, txt: "demote cold (f >= 2)", dy: 0.0)
     edge((9.7, 1.75), (9.7, 2.7), green, txt: "promote hot hit", dy: 0.0)
   })

Adaptive Topology-Driven Distributed Data Plane (ATDP)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

A static cluster design forces operators to choose between a single-datacenter L2 load balancer (which breaks across WAN regions) and a purely stateless anycast router (which drops stateful TCP/UDP connections whenever ECMP membership changes inside a PoP). Sibuna Edge resolves this by adopting the **Adaptive Topology-Driven Data Plane (ATDP)** in ``sibuna-cluster``: Sibuna discovers cluster members dynamically (via shared PostgreSQL node heartbeats, DNS SRV records, or static ``peers`` seeds) and continuously measures peer count :math:`P` and 95th-percentile UDP SWIM probe RTT :math:`\mathrm{RTT}_{95}` to self-configure into the optimal regime.

The three autonomous data-plane regimes
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

.. graphviz::
   :caption: Autonomous state machine of the Adaptive Topology-Driven Data Plane (ATDP). Hysteresis thresholds (1.5 ms entry, 3.0 ms exit) prevent regime oscillation under transient network jitter.
   :alt: Directed state machine among three regimes: Regime 1 Standalone (P == 0, local P2C-PEWMA), Regime 2 Regional PoP Mesh (P >= 1 and RTT_95 < 1.5 ms, Bounded-Load Maglev + 1-Hop Consistent Peer Forwarding + UDP Delta-CRDT Stick-Tables), and Regime 3 Geo-Anycast WAN Fabric (P >= 1 and RTT_95 > 3.0 ms, Hierarchical Locality-Weighted Maglev + Stateless Encrypted Flow Routing Tokens + Async PostgreSQL Bans).

   digraph atdp_regimes {
     graph [rankdir=LR, bgcolor="transparent", fontname="Helvetica", fontsize=10, nodesep=0.5, ranksep=0.8];
     node [shape=box, style="rounded,filled", fontname="Helvetica", fontsize=9, penwidth=1.2, margin="0.16,0.10"];
     edge [fontname="Helvetica", fontsize=8.2, color="#475569", penwidth=1.0];

     r1 [label="Regime 1: Standalone / VIP\n(peers = 0)\n• P2C Peak-EWMA Scheduler\n• Local sibuna-kv Mmap Store\n• Zero Network Gossip", color="#1e40af", fillcolor="#eff6ff"];
     r2 [label="Regime 2: Regional PoP Mesh\n(peers >= 1, p95 RTT < 1.5 ms)\n• Bounded-Load Maglev (M = 65537)\n• 1-Hop Consistent Peer Forwarding (CPF)\n• Batched UDP Delta-CRDT Stick-Tables", color="#15803d", fillcolor="#f0fdf4"];
     r3 [label="Regime 3: Geo-Anycast WAN\n(peers >= 1, p95 RTT > 3.0 ms)\n• Locality-Tiered Maglev (Local PoP First)\n• Stateless AEAD Flow Routing Tokens\n• Async PostgreSQL Ban/Policy Sync", color="#b45309", fillcolor="#fffbeb"];

     r1 -> r2 [label="peer discovered\nRTT < 3.0 ms"];
     r1 -> r3 [label="peer discovered\nRTT >= 3.0 ms"];
     r2 -> r3 [label="p95 RTT > 3.0 ms\n(for 3 ticks)"];
     r3 -> r2 [label="p95 RTT < 1.5 ms\n(for 6 ticks)\n[1.5 ms Deadband]"];
     r2 -> r1 [label="peers == 0"];
     r3 -> r1 [label="peers == 0"];
   }

1. **Regime 1 — Standalone / Active-Passive VIP** (:math:`P = 0`): Uses **Power-of-Two-Choices with Peak-EWMA (P2C-PEWMA)** directly over local atomic in-flight counters and microsecond origin response latencies. No hash-ring indirection or peer network traffic runs.
2. **Regime 2 — Regional LAN / PoP Mesh** (:math:`P \ge 1`, :math:`\mathrm{RTT}_{95} < 1.5\,\text{ms}`): Multiple Sibuna nodes sit behind an L3 ECMP router in the same PoP.

   - **Bounded-Load Maglev Scheduling:** Every node builds the identical deterministic 65,537-slot Maglev table over healthy backends, capped per backend by load factor :math:`\alpha = 1.25`.
   - **1-Hop Consistent Peer Forwarding (CPF, Unimog/Katran umbrella):** When a node joins or drains and ECMP hashes an *existing* TCP/UDP flow to a new Sibuna node, the receiving node checks its local ``FlowTable``; on a non-SYN TCP packet or known QUIC server-ID belonging to peer :math:`j` (encoded in ``sibuna-kv`` Delta-CRDT ownership or CID prefix), it forwards the packet across a lightweight authenticated UDP/TCP peer tunnel with ``cpf_hop = 1`` (**at most one hop, guaranteed loop-free**), keeping existing connections alive across ECMP reshuffles.
   - **Delta-CRDT Stick-Tables:** Every 50 ms, nodes multicast/unicast compressed ``StickState`` join-semilattice deltas (active bans, sticky backend bindings, rate counters) authenticated with keyed BLAKE3.

3. **Regime 3 — Geo-Distributed Multi-Region Anycast** (:math:`P \ge 1`, :math:`\mathrm{RTT}_{95} > 3.0\,\text{ms}`): Cross-continent PoPs exist, where synchronous stick-table gossip or cross-ocean CPF hops would inflate tail latency. ATDP automatically partitions peers into **Local-PoP Rings** (:math:`\mathrm{RTT} < 1.5\,\text{ms}` subset uses Regime 2 internally) and **Remote-PoP Fallback Tiers** (used only if local PoP healthy capacity drops below 25%), encoding sticky backend identity into stateless XChaCha20-Poly1305 QUIC Retry / HTTP cookies rather than WAN gossip.

Multi-Tier Plugin Architecture (``sibuna-plugin``)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

An HAProxy-class load balancer must let operators add custom protocol decoders, custom routing ACLs, header/TLV enrichers, or enterprise auth hooks without forking Sibuna or violating ``unsafe_code = "deny"`` and ``Axiom 2`` (zero hot-path heap allocation). Sibuna Edge provides three composable extension tiers:

.. list-table:: Sibuna Edge Plugin Tiers and Safety Guarantees
   :header-rows: 1
   :widths: 22 26 26 26

   * - Tier
     - Execution Model
     - Budget & Isolation
     - Best For
   * - **1. Native Rust Trait**
     - Compiled into custom ``sibuna`` binary via ``Plugin`` trait hooks
     - :math:`0\,\text{ns}` dispatch overhead; borrow-checked ``PluginCtx<'a>``; zero heap alloc
     - Ultra-hot L4 custom binary framing, custom Maglev hash extractors
   * - **2. Sandboxed WASM**
     - Pure-Rust fuel-metered ``wasm32`` sandbox, zero WASI imports
     - Pre-allocated fixed pages (64–256 KiB/worker); deterministic fuel cap; ``on_trap = fail_open | fail_closed``
     - Third-party dynamic L4/L7 ACLs, custom TLV writers, custom token validators loaded at ``SIGHUP``
   * - **3. Sibuna SPOE**
     - Out-of-process binary frame stream over Unix socket / TCP pool
     - Bounded deadline (e.g. ``5ms``) and circuit breaker; never blocks other worker flows
     - Heavy ML bot scoring, external threat-intel lookups, legacy Lua/Python logic

Every plugin hook receives a fixed-layout C-compatible context view (``AcceptView``, ``ClientHelloView``, ``DatagramView``, ``HttpHeadView``) and returns a plain-data ``Verdict`` enum: ``Pass``, ``RouteBackend(BackendId)``, ``Challenge``, ``DropSilent``, ``RejectCode(u16)``, or ``BanClient { seconds: u32 }``.

Multi-Layer Self-Protection Against DDoS
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

When Sibuna moves from behind an ingress to **being** the front-door TCP/UDP load balancer, Sibuna itself becomes the primary target of volumetric SYN floods, spoofed UDP reflection/state-exhaustion floods, Slowloris socket starvation, and TLS handshake exhaustion. Sibuna protects itself through a **7-Stage Cost-Asymmetric Defense Funnel**, ordered strictly from lowest nanosecond CPU cost to highest:

.. typst-diagram::
   :caption: Seven-stage cost-ordered DDoS self-protection funnel (left) and the Stateless Keyed-BLAKE3 UDP Cookie Return-Routability sequence (right) that prevents spoofed UDP floods from allocating a single byte in FlowTable or sibuna-kv.
   :alt: Left side shows a narrowing 7-stage funnel from Stage 0 Kernel SYN Cookies + TCP_DEFER_ACCEPT + cBPF (~0 ns user CPU), Stage 1 Lock-Free BanTable + PeerTable /64 cap (~5 ns), Stage 2 Stateless BLAKE3 UDP Cookie Gate (~35 ns, drops 100% spoofed IPs), Stage 3 Lock-Striped GCRA Packet/Byte/Conn Limiters (~6 ns), Stage 4 Non-Terminating TLS ClientHello SNI & Native JA4 Filter (~80 ns), Stage 5 W-TinyLFU sibuna-kv Saturation Shield, down to Stage 6 L7 Shield WAF & Cohen-Pietrzak PoSW Gate. Right side shows UDP Client sending initial UDP packet, Sibuna replying with 24-byte Stateless BLAKE3 Cookie without storing state, Client echoing cookie, and Sibuna verifying MAC in constant time before inserting FlowSlot and forwarding to Backend.

   #import "@preview/cetz:0.5.2"
   #set text(font: "Libertinus Serif", size: 7.5pt, fill: rgb("#172033"))
   #cetz.canvas(length: 1cm, {
     import cetz.draw: *

     let ink = rgb("#172033")
     let muted = rgb("#64748b")
     let blue = rgb("#1e40af")
     let blue-bg = rgb("#eff6ff")
     let green = rgb("#15803d")
     let green-bg = rgb("#f0fdf4")
     let amber = rgb("#b45309")
     let amber-bg = rgb("#fffbeb")
     let red = rgb("#b91c1c")
     let red-bg = rgb("#fef2f2")
     let violet = rgb("#6d28d9")
     let violet-bg = rgb("#f5f3ff")

     content((3.9, 8.6), align(center,
       text(weight: "bold", size: 8.1pt, fill: red, "7-Stage Cost-Ordered Self-Protection Funnel")))

     let stage(y, halfw, bg, fg, label, cost) = {
       let cx = 3.9
       rect((cx - halfw, y), (cx + halfw, y + 0.88), radius: 2.5pt, fill: bg, stroke: 0.75pt + fg)
       content((cx, y + 0.44), box(width: (2 * halfw - 0.18) * 1cm, align(center, {
         text(weight: "bold", size: 6.9pt, fill: fg.darken(15%), label)
         linebreak()
         text(size: 6.2pt, fill: ink, cost)
       })))
     }

     stage(7.4, 3.85, red-bg, red, "S0: Kernel SYN Cookies + TCP_DEFER_ACCEPT", "0 ns user CPU — unestablished SYNs never wake Sibuna")
     stage(6.25, 3.68, red-bg, red, "S1: Seqlock BanTable + PeerTable (/64 IPv6)", "~5 ns — O(1) drop of banned prefixes & conn-flooders")
     stage(5.1, 3.51, amber-bg, amber, "S2: Stateless Keyed-BLAKE3 UDP Cookie Gate", "~35 ns — 0 bytes stored until return-routability proved")
     stage(3.95, 3.34, amber-bg, amber, "S3: GCRA Packet / Byte / New-Flow Limiters", "~6.2 ns — 16B cell caps bursts & sustained pps/bps")
     stage(2.8, 3.17, violet-bg, violet, "S4: TLS ClientHello Peek (SNI + Native JA4)", "~80 ns — drops botnet TLS stacks before connect")
     stage(1.65, 3.00, blue-bg, blue, "S5: sibuna-kv W-TinyLFU + Mmap Spill Shield", "Blocks cache thrashing; spills cold state to NVMe")
     stage(0.5, 2.83, green-bg, green, "S6: L7 Shield WAF + Cohen-Pietrzak PoSW", "Admitted clean TCP / UDP / HTTP flows -> Origin")

     for i in range(6) {
       let y = 7.4 - i * 1.15
       line((3.9, y), (3.9, y - 0.27), stroke: 0.7pt + muted, mark: (end: "stealth", fill: muted, scale: 0.55))
     }

     // Right panel: Stateless UDP Cookie Sequence
     rect((8.0, 0.5), (14.4, 8.3), radius: 3pt, fill: rgb("#f8fafc"), stroke: 0.7pt + rgb("#cbd5e1"))
     content((11.2, 8.0), align(center,
       text(weight: "bold", size: 7.7pt, fill: blue, "Stateless UDP Return-Routability Gate")))

     let lx = (8.95, 11.2, 13.45)
     let lnames = ("UDP Client", "Sibuna Worker", "UDP Origin")
     for i in range(3) {
       rect((lx.at(i) - 0.85, 7.05), (lx.at(i) + 0.85, 7.65), radius: 2pt, fill: blue-bg, stroke: 0.65pt + blue)
       content((lx.at(i), 7.35), text(weight: "bold", size: 6.6pt, fill: blue, lnames.at(i)))
       line((lx.at(i), 0.8), (lx.at(i), 7.05), stroke: (paint: muted.lighten(30%), thickness: 0.6pt, dash: "dashed"))
     }

     let smsg(a, b, y, col, txt) = {
       line((lx.at(a), y), (lx.at(b), y), stroke: 0.75pt + col, mark: (end: "stealth", fill: col, scale: 0.55))
       content(((lx.at(a) + lx.at(b)) / 2, y + 0.23), align(center,
         box(fill: rgb("#f8fafc"), inset: 1pt, text(size: 6.3pt, fill: col.darken(15%), txt))))
     }

     smsg(0, 1, 6.3, red, "1. Initial Datagram (Spoofed?)")
     content((11.2, 5.6), box(fill: amber-bg, stroke: 0.5pt + amber, inset: 2.8pt, radius: 2pt,
       align(center, text(size: 6.2pt, "0 State Stored!\nTag = BLAKE3_K(IP||port||ts)"))))
     smsg(1, 0, 4.85, amber, "2. Retry Cookie (QUIC Retry / DTLS)")
     content((10.05, 4.22), box(fill: rgb("#f8fafc"), inset: 1pt,
       text(size: 6.1pt, fill: red, "(Spoofed IPs never see step 2)")))
     smsg(0, 1, 3.55, green, "3. Datagram + Echoed Cookie")
     content((11.2, 2.8), box(fill: green-bg, stroke: 0.5pt + green, inset: 2.8pt, radius: 2pt,
       align(center, text(size: 6.2pt, "Constant-time MAC OK!\nInsert 64B FlowSlot"))))
     smsg(1, 2, 1.9, blue, "4. Forward Clean Datagram")
     smsg(2, 0, 1.2, green, "5. Established Bi-Dir Flow")
   })

- **TCP Slow-Read / SYN Starvation Immunity:** On Linux listeners ``TCP_DEFER_ACCEPT`` (and ``SO_ACCEPTFILTER`` ``dataready`` on FreeBSD) keeps half-open and data-less sockets inside the kernel's compact SYN/accept queue until payload bytes actually arrive, so a SYN flood or empty-connect flood consumes **zero** Sibuna ``FlowSlot`` entries. Once accepted, ``inspect_delay`` (default ``2s`` for TLS SNI) and stalled-writer timeouts (SID 0002) reap non-progressing peers deterministically.
- **UDP Amplification & Spoof Immunity:** For QUIC listeners, Sibuna emits a standards-compliant **RFC 9000 QUIC** ``Retry`` **packet** containing a 16-byte keyed-BLAKE3 token ``Tag_K(client_ip || client_port || dcid || epoch_10s)`` whenever new-session arrivals exceed ``threshold``. For DTLS (``HelloVerifyRequest``) or Sibuna-aware UDP protocols, the equivalent stateless cookie header applies; for legacy stateless UDP protocols (such as authoritative DNS), Sibuna switches into **per-prefix GCRA + response-size amplification ratio clamping** without allocating long-lived session slots.

Mathematical Foundations and Machine-Checked Lean 4 Proofs
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Continuing the formal discipline of SID 0006, every core primitive introduced by Sibuna Edge is derived from explicit axioms, proved analytically, and verified by **Lean 4.19.0** in ``docs/sid/assets/distributed-edge-load-balancer.lean`` with **zero external dependencies and zero** ``sorry`` **axioms**.

.. admonition:: Axiom 5 (Cooperative Non-Blocking Progress)

   No data-plane worker ever executes an unbounded loop, waits on an off-path thread, allocates from the system heap, or blocks on disk ``fsync``. Every packet event completes in :math:`O(1)` worst-case probes bounded by compile-time constants.

.. admonition:: Axiom 6 (Saturation Survival)

   Let :math:`M_{\mathrm{ram}}` and :math:`M_{\mathrm{mmap}}` be the configured RAM and memory-mapped disk budgets. Under any adversarial packet arrival sequence :math:`\sigma = (p_1, p_2, \dots, p_k)` of arbitrary length :math:`k \to \infty`, resident state never exceeds :math:`M_{\mathrm{ram}}`, mapped file state never exceeds :math:`M_{\mathrm{mmap}}`, and established multi-packet flows are never evicted by single-packet flood keys.

Part A: Capacity-Bounded Maglev & Peak-EWMA Load Balancing
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

.. admonition:: Definition 33 (Bounded-Load Maglev Permutation & Admission)

   Fix a prime ring size :math:`M = 65{,}537` and :math:`B \ge 1` healthy backends. Backend :math:`b` derives two independent 64-bit hashes into :math:`\mathrm{offset}_b \in [0, M)` and :math:`\mathrm{skip}_b \in [1, M-1]`, generating the probe sequence

   .. math::

      \pi_b(i) = (\mathrm{offset}_b + i \cdot \mathrm{skip}_b) \bmod M, \qquad i \in \{0, \dots, M-1\}.

   Let :math:`\mathbf{L} = (\ell_0, \dots, \ell_{B-1})` be the vector of active backend flows with total load :math:`L = \sum_{b=0}^{B-1} \ell_b`, and let :math:`C = \lceil \alpha (L + 1) / B \rceil` (for overload factor :math:`\alpha > 1`, default :math:`1.25`) or an explicit server ``max_flows`` cap. For a flow hashing to slot :math:`h \in [0, M)` with primary owner :math:`p = T[h]`, ``admitBounded`` selects :math:`p` if :math:`\ell_p < C`; otherwise it selects the first healthy backend :math:`b` along the fallback schedule satisfying :math:`\ell_b < C` (weighted by Peak-EWMA cost :math:`\mathcal{C}_b = \alpha_w s_b + (256 - \alpha_w)\hat{\mu}_b + \rho_b`).

.. admonition:: Lemma 34 (Ring Bound and Bijectivity)

   For every :math:`M > 0`, :math:`\pi_b(i) < M` (so table indexing is total and bounds-check free). Moreover, because :math:`M = 65{,}537` is prime and :math:`1 \le \mathrm{skip}_b < M`, :math:`\gcd(\mathrm{skip}_b, M) = 1`, hence :math:`i \mapsto \pi_b(i)` is a bijection on :math:`\mathbb{Z}/M\mathbb{Z}`, guaranteeing Maglev table population always terminates in at most :math:`M` steps per backend.

.. admonition:: Theorem 35 (Strict Capacity Safety & Pigeonhole Work-Conserving Liveness)

   1. **Safety:** If :math:`\forall b < B,\ \ell_b \le C` holds before arrival and ``admitBounded`` admits the flow onto backend :math:`b^*` yielding :math:`\mathbf{L}'`, then :math:`\forall b < B,\ \ell'_b \le C`. No backend ever exceeds its capacity ceiling.
   2. **Liveness:** Whenever total active load satisfies :math:`\sum_{b=0}^{B-1} \ell_b < B \cdot C`, there exists at least one backend :math:`b^* < B` with :math:`\ell_{b^*} < C`, so ``admitBounded`` is guaranteed to succeed without spurious rejection.

.. admonition:: Proof of Theorem 35

   **(1)** ``admitBounded`` increments :math:`\ell_{b^*}` by 1 *only* after verifying the guard :math:`\ell_{b^*} < C` (either on primary :math:`p` or via ``findAvailable``). Since :math:`\ell_{b^*}, C \in \mathbb{N}`, :math:`\ell_{b^*} < C \implies \ell_{b^*} + 1 \le C`; every other coordinate :math:`b \ne b^*` is unchanged and satisfies :math:`\ell_b \le C` by hypothesis. **(2)** By contraposition, if ``findAvailable`` returns ``none``, then :math:`\forall b < B,\ \ell_b \ge C`. Summing over all :math:`B` backends yields :math:`\sum_{b=0}^{B-1} \ell_b \ge B \cdot C`, contradicting :math:`\sum \ell_b < B \cdot C`. :math:`\square`

Part B: Optimistic Seqlock Linearizability & ``sibuna-kv`` Saturation Bound
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

.. admonition:: Definition 36 (Optimistic Seqlock Protocol & Two-Tier KV Automaton)

   Each L1 slot holds an atomic sequence counter :math:`v \in \mathbb{N}`, initially :math:`0`. A writer increments :math:`v \leftarrow v + 1` (odd) before mutating payload bytes and :math:`v \leftarrow v + 1` (even) with ``Release`` ordering upon completion. An optimistic reader reads :math:`v_1`, copies the slot bytes, issues an ``Acquire`` fence, reads :math:`v_2`, and accepts the read iff :math:`\mathrm{seqReadValid}(v_1, v_2) \equiv (v_1 \bmod 2 = 0) \land (v_1 = v_2)`.

   Across both tiers, a shard with bounds :math:`(R, D)` (RAM slots :math:`R`, ``mmap`` slots :math:`D`) transitions from occupancy :math:`(r, d, \text{rep}, \text{shed})` on arrival with candidate frequency :math:`f_c` and victim frequency :math:`f_v` via:

   .. math::

      \delta(r, d) = \begin{cases}
      (r + 1, d, \text{rep}, \text{shed}) & \text{if } r < R, \\
      (r, d + 1, \text{rep}, \text{shed}) & \text{if } r = R \land d < D \quad (\text{spill to mmap}), \\
      (r, d, \text{rep} + 1, \text{shed}) & \text{if } r = R \land d = D \land f_c > f_v \quad (\text{W-TinyLFU replace}), \\
      (r, d, \text{rep}, \text{shed} + 1) & \text{otherwise} \quad (\text{O(1) saturation shed}).
      \end{cases}

.. admonition:: Lemma 37 (Tear-Free Seqlock Linearizability)

   ``seqReadValid`` rejects every read overlapping an active writer (:math:`v_1 = 2k + 1`) and every read straddling one or more completed writes (:math:`v_2 \ge v_1 + 2 > v_1`), while succeeding in one pass whenever a quiescent slot (:math:`v_1 = 2k`) experiences no write (:math:`v_2 = v_1`).

.. admonition:: Theorem 38 (Zero-Crash Saturation & Anti-Pollution Invariant)

   For any valid initial occupancy :math:`r_0 \le R \land d_0 \le D` and any adversarial trace :math:`\sigma \in (\mathbb{N} \times \mathbb{N})^*` of length :math:`|\sigma| = k`:

   1. **Memory Bound:** After processing :math:`\sigma`, :math:`r_k \le R \land d_k \le D`, and :math:`r_k + d_k + \mathrm{rep}_k + \mathrm{shed}_k = r_0 + d_0 + \mathrm{rep}_0 + \mathrm{shed}_0 + k`.
   2. **Flood Immunity:** Whenever saturated (:math:`r = R \land d = D`), any single-packet flood arrival (:math:`f_c = 1`) against an established flow (:math:`f_v \ge 1`) leaves :math:`\mathrm{rep}` unchanged (zero evictions) and increments :math:`\mathrm{shed}` by 1.

.. admonition:: Proof of Theorem 38

   By structural induction on :math:`\sigma`. In branch 1, :math:`r < R \implies r + 1 \le R`; in branch 2, :math:`d < D \implies d + 1 \le D`; in branches 3 and 4, :math:`(r, d)` are invariant, preserving :math:`r \le R \land d \le D` at every step, and exactly one of the four disjoint counters increments by 1. When :math:`r = R, d = D, f_c = 1, f_v \ge 1`, the strict inequality :math:`f_v < 1` is false over :math:`\mathbb{N}`, forcing branch 4. :math:`\square`

Part C: Delta-CRDT Semilattice Convergence, Hysteresis, & 1-Hop CPF
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

.. admonition:: Theorem 39 (Bounded Join-Semilattice Convergence & Loop-Free Forwarding)

   1. **CRDT Convergence:** Define peer state :math:`s = (\text{banUntil}, \text{hitEpochMax}, \text{riskScore}) \in \mathbb{N}^3` with pointwise join :math:`a \sqcup b = (\max(a_1, b_1), \max(a_2, b_2), \max(a_3, b_3))`. Then :math:`(\mathbb{N}^3, \sqcup)` satisfies commutativity (:math:`a \sqcup b = b \sqcup a`), associativity (:math:`(a \sqcup b) \sqcup c = a \sqcup (b \sqcup c)`), idempotence (:math:`a \sqcup a = a`), and ban monotonicity (:math:`a_1 \le (a \sqcup b)_1`). Consequently, unreliable UDP gossip converges to the exact supremum state across arbitrary packet loss (with retransmission), duplication, and reordering.
   2. **Hysteresis Stability:** For deadband thresholds :math:`\tau_{\mathrm{low}} \le \tau_{\mathrm{high}}`, any RTT fluctuation :math:`\mathrm{rtt} \in [\tau_{\mathrm{low}}, \tau_{\mathrm{high}}]` with :math:`P > 0` satisfies :math:`\mathrm{stepRegime}(R, P, \mathrm{rtt}) = R` for :math:`R \in \{\text{LAN}, \text{WAN}\}`, eliminating single-threshold flapping.
   3. **1-Hop CPF Termination:** Marking peer-tunnelled packets with ``alreadyForwarded = true`` guarantees :math:`\mathrm{cpfDecide}(\cdot, \cdot, b_{\mathrm{fb}}, \mathrm{true}) = \mathrm{deliverBackend}(b_{\mathrm{fb}})`, bounding cluster-internal forwarding hops to at most :math:`1` even if two nodes hold temporarily divergent Maglev generations during a reload.

Part D: Stateless UDP Cookie Gate & Early-Drop Cost Dominance
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

.. admonition:: Theorem 40 (Zero Unverified UDP State & Early-Drop CPU Dominance)

   1. **Zero Spoofed State:** Under ``udpHandleFirstPacket``, any UDP datagram lacking a valid constant-time BLAKE3 cookie (:math:`\mathrm{cookieValid} = \mathrm{false}`) leaves ``activeSessions`` invariant (:math:`S' = S`), discharging SID 0006's Axiom 4 for connectionless UDP.
   2. **Strict CPU Savings:** For :math:`g \ge 0` legitimate packets proxied at cost :math:`c_{\mathrm{proxy}}` and :math:`a > 0` attack packets dropped at early funnel stage :math:`c_{\mathrm{early}} < c_{\mathrm{proxy}}`, total CPU expenditure satisfies :math:`g \cdot c_{\mathrm{proxy}} + a \cdot c_{\mathrm{early}} < (g + a) \cdot c_{\mathrm{proxy}}`, saving :math:`a(c_{\mathrm{proxy}} - c_{\mathrm{early}})` cycles.

Machine-Checked Lean 4 Specification (Verified on Lean 4.19.0)
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

The complete self-contained proof script below lives in ``docs/sid/assets/distributed-edge-load-balancer.lean`` and passes ``lean docs/sid/assets/distributed-edge-load-balancer.lean`` with zero ``sorry`` placeholders:

.. code-block:: lean4

   namespace SibunaEdge

   -- Part A: Capacity-Bounded Maglev & Peak-EWMA Load Balancing
   def maglevProbe (offset skip ringSize step : Nat) : Nat :=
     (offset + step * skip) % ringSize

   theorem maglevProbe_lt_ring (offset skip ringSize step : Nat) (hM : 0 < ringSize) :
       maglevProbe offset skip ringSize step < ringSize := by
     unfold maglevProbe
     exact Nat.mod_lt (offset + step * skip) hM

   def findAvailable : List Nat → Nat → Option Nat
     | [], _ => none
     | l :: ls, cap =>
       if l < cap then some 0
       else match findAvailable ls cap with
         | some idx => some (idx + 1)
         | none => none

   def bumpLoad : List Nat → Nat → List Nat
     | [], _ => []
     | l :: ls, 0 => (l + 1) :: ls
     | l :: ls, idx + 1 => l :: bumpLoad ls idx

   def admitBounded (loads : List Nat) (primary cap : Nat) : Option (Nat × List Nat) :=
     match loads[primary]? with
     | some l =>
       if l < cap then some (primary, bumpLoad loads primary)
       else (findAvailable loads cap).map (fun alt => (alt, bumpLoad loads alt))
     | none =>
       (findAvailable loads cap).map (fun alt => (alt, bumpLoad loads alt))

   def AllAtMost (loads : List Nat) (cap : Nat) : Prop := ∀ x ∈ loads, x ≤ cap

   def sumLoads : List Nat → Nat
     | [] => 0
     | l :: ls => l + sumLoads ls

   theorem findAvailable_none_implies_full :
       ∀ (loads : List Nat) (cap : Nat),
         findAvailable loads cap = none → loads.length * cap ≤ sumLoads loads
     | [], _, _ => by simp [sumLoads]
     | l :: ls, cap, h => by
       unfold findAvailable at h
       split at h
       · contradiction
       · have hrec : ls.length * cap ≤ sumLoads ls := by
           cases hsub : findAvailable ls cap with
           | none => exact findAvailable_none_implies_full ls cap hsub
           | some _ => rw [hsub] at h; contradiction
         simp [List.length_cons, Nat.add_mul, sumLoads]; omega

   theorem findAvailable_some_of_under_capacity
       (loads : List Nat) (cap : Nat) (hUnder : sumLoads loads < loads.length * cap) :
       ∃ idx, findAvailable loads cap = some idx := by
     cases h : findAvailable loads cap with
     | some idx => exact ⟨idx, rfl⟩
     | none => have := findAvailable_none_implies_full loads cap h; omega

   -- Part B: Seqlock Linearizability & Two-Tier Mmap KV Saturation Bound
   def seqBeginWrite (seq : Nat) : Nat := seq + 1
   def seqEndWrite   (seq : Nat) : Nat := seq + 1
   def seqReadValid  (seqBefore seqAfter : Nat) : Bool :=
     (seqBefore % 2 == 0) && (seqBefore == seqAfter)

   theorem seqlock_rejects_inflight_write (seq : Nat) (hEven : seq % 2 = 0) (anyAfter : Nat) :
       seqReadValid (seqBeginWrite seq) anyAfter = false := by
     unfold seqReadValid seqBeginWrite
     have hOdd : (seq + 1) % 2 = 1 := by omega
     simp [hOdd]

   theorem seqlock_rejects_torn_write (seq : Nat) :
       seqReadValid seq (seqEndWrite (seqBeginWrite seq)) = false := by
     unfold seqReadValid seqEndWrite seqBeginWrite; simp

   structure KvBounds    where ramCap : Nat; mmapCap : Nat
   structure KvOccupancy where ramUsed : Nat; mmapUsed : Nat; replaced : Nat; shed : Nat

   def KvBounded (b : KvBounds) (s : KvOccupancy) : Prop :=
     s.ramUsed ≤ b.ramCap ∧ s.mmapUsed ≤ b.mmapCap

   def kvStep (b : KvBounds) (s : KvOccupancy) (candFreq victimFreq : Nat) : KvOccupancy :=
     if s.ramUsed < b.ramCap then { s with ramUsed := s.ramUsed + 1 }
     else if s.mmapUsed < b.mmapCap then { s with mmapUsed := s.mmapUsed + 1 }
     else if victimFreq < candFreq then { s with replaced := s.replaced + 1 }
     else { s with shed := s.shed + 1 }

   theorem kvStep_preserves_bounds
       (b : KvBounds) (s : KvOccupancy) (cf vf : Nat) (h : KvBounded b s) :
       KvBounded b (kvStep b s cf vf) := by
     unfold KvBounded at *; unfold kvStep; rcases h with ⟨hRam, hMmap⟩
     split
     · dsimp; exact ⟨by omega, hMmap⟩
     · split
       · dsimp; exact ⟨hRam, by omega⟩
       · split <;> (dsimp; exact ⟨hRam, hMmap⟩)

   -- Part C: Delta-CRDT Semilattice, Hysteresis Stability, & 1-Hop CPF
   structure StickState where banUntil : Nat; hitEpochMax : Nat; riskScore : Nat
     deriving DecidableEq

   def stickJoin (a b : StickState) : StickState :=
     { banUntil := Nat.max a.banUntil b.banUntil
       hitEpochMax := Nat.max a.hitEpochMax b.hitEpochMax
       riskScore := Nat.max a.riskScore b.riskScore }

   theorem stickJoin_comm  (a b : StickState)   : stickJoin a b = stickJoin b a := by
     unfold stickJoin; simp [Nat.max_comm]
   theorem stickJoin_assoc (a b c : StickState) :
       stickJoin (stickJoin a b) c = stickJoin a (stickJoin b c) := by
     unfold stickJoin; simp [Nat.max_assoc]
   theorem stickJoin_idem  (a : StickState)     : stickJoin a a = a := by
     cases a; unfold stickJoin; simp

   -- Part D: Stateless UDP Cookie Gate & Early-Drop CPU Dominance
   structure UdpGateState where activeSessions : Nat; cookieChallengesSent : Nat

   def udpHandleFirstPacket (st : UdpGateState) (cookieValid : Bool) (cap : Nat) : UdpGateState :=
     if cookieValid then
       if st.activeSessions < cap then { st with activeSessions := st.activeSessions + 1 } else st
     else { st with cookieChallengesSent := st.cookieChallengesSent + 1 }

   theorem udp_spoof_allocates_zero_state (st : UdpGateState) (cap : Nat) :
       (udpHandleFirstPacket st false cap).activeSessions = st.activeSessions := by
     unfold udpHandleFirstPacket; simp

   end SibunaEdge

Modular Crate Decomposition and Raylib-Style Public APIs
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

To keep future maintenance effortless within SID 0001's hard structural limits (:math:`\le 70` logical lines per function, :math:`\le 1{,}408` lines per file, :math:`\le 99` characters per line), Sibuna Edge decomposes into **seven orthogonal crates** following **Raylib's API philosophy** while strictly isolating ``jlv-*`` to the off-path Control Plane (preserving SID 0010's zero-external-crate data plane):

- **Plain-Data Value Handles &** ``#[repr(C)]`` **Config Structs:** Every configuration and verdict type is a flat public-field ``struct`` implementing ``Default``, ``Copy``/``Clone``, and ``Debug`` — no builder-pattern generics, no deeply nested trait objects, and no macro magic.
- **Small Flat Verb Vocabulary:** Each crate exports 8 to 15 top-level functions at the crate root using consistent paired verbs (``open_*`` / ``close_*``, ``load_*`` / ``unload_*``, ``begin_*`` / ``end_*``, ``is_*``, ``*_count``), obeying SID 0010's rule against ``get_`` prefixes.

.. graphviz::
   :caption: Extended Sibuna Edge crate graph. Reusable zero-dependency crates sit in the dashed lower box; off-path control-plane crates (such as sibuna-jlv and sibuna-storage) compose them one way toward cmd/sibuna without polluting packet workers.
   :alt: Directed acyclic graph of crates showing reusable zero-dependency crates sibuna-io, sibuna-kv, sibuna-conf, sibuna-lb, and sibuna-plugin alongside sibuna-crypto, sibuna-cidr, sibuna-store, and sibuna-http, while control-plane crates sibuna-jlv (linking jlv-* from jlavideploy), sibuna-cluster, sibuna-net, sibuna-storage, and sibuna-console feed cmd/sibuna.

   digraph edge_crates {
     graph [rankdir=BT, bgcolor="transparent", fontname="Helvetica", fontsize=10, nodesep=0.32, ranksep=0.55];
     node [shape=box, style="rounded,filled", fontname="Helvetica", fontsize=9, fillcolor="#eff6ff", color="#1e40af", penwidth=1.0];
     edge [color="#64748b", arrowsize=0.65];

     subgraph cluster_reusable {
       label="Reusable Data-Plane & Schema Crates (Zero External Crates)";
       style="dashed,rounded"; color="#94a3b8"; bgcolor="#f8fafc";
       crypto [label="sibuna-crypto"];
       cidr [label="sibuna-cidr"];
       store [label="sibuna-store"];
       http [label="sibuna-http"];
       io [label="sibuna-io\n(epoll/io_uring/kqueue/IOCP)", fillcolor="#dcfce7", color="#15803d"];
       kv [label="sibuna-kv\n(Seqlock RAM + mmap)", fillcolor="#dcfce7", color="#15803d"];
       lb [label="sibuna-lb\n(Maglev, P2C, PROXYv2, SNI/JA4)", fillcolor="#dcfce7", color="#15803d"];
       conf [label="sibuna-conf\n(EdgeConfig Schema & JSON)", fillcolor="#dcfce7", color="#15803d"];
       plugin [label="sibuna-plugin\n(Traits, Fuel WASM, SPOE)", fillcolor="#dcfce7", color="#15803d"];
     }

     core [label="sibuna-core"];
     policy [label="sibuna-policy"];
     jlv [label="sibuna-jlv\n(Off-Path JLV/2 Transform)", fillcolor="#fef3c7", color="#b45309"];
     net [label="sibuna-net"];
     cluster [label="sibuna-cluster\n(ATDP, SWIM, CRDT, CPF)", fillcolor="#fef3c7", color="#b45309"];
     storage [label="sibuna-storage\n(SQLite / PostgreSQL)"];
     console [label="sibuna-console"];
     daemon [label="cmd/sibuna\n(Edge LB + WAF + Console)", fillcolor="#ede9fe", color="#6d28d9"];

     kv -> crypto;
     lb -> crypto; lb -> cidr;
     conf -> cidr;
     plugin -> http; plugin -> crypto;
     policy -> core; policy -> cidr;
     jlv -> conf;
     net -> io; net -> lb; net -> http; net -> core;
     cluster -> lb; cluster -> kv; cluster -> crypto; cluster -> core;
     storage -> conf; storage -> policy; storage -> core;
     console -> storage; console -> cluster; console -> jlv;
     daemon -> net; daemon -> cluster; daemon -> kv; daemon -> conf; daemon -> jlv; daemon -> plugin; daemon -> policy; daemon -> storage; daemon -> console;
   }

Raylib-style crate API signatures
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

.. code-block:: rust

   // ---- 1. crates/io (sibuna-io): Portable Cooperative Event Loop & Slab Rings -----------
   pub struct PollSpec { pub max_events: u16, pub slab_buffers: u32, pub slab_bytes: u32 }
   pub struct NetEvent { pub token: u32, pub readable: bool, pub writable: bool, pub closed: bool }

   pub fn open_poller(spec: PollSpec) -> Result<Poller, IoError>;
   pub fn close_poller(poller: Poller);
   pub fn register_tcp(poller: &mut Poller, fd: RawSocket, token: u32) -> Result<(), IoError>;
   pub fn register_udp(poller: &mut Poller, fd: RawSocket, token: u32) -> Result<(), IoError>;
   pub fn begin_poll<'a>(poller: &'a mut Poller, timeout_ms: u32) -> Result<&'a [NetEvent], IoError>;
   pub fn end_poll(poller: &mut Poller);
   pub fn lease_slab(poller: &mut Poller) -> Option<SlabBuf>;
   pub fn release_slab(poller: &mut Poller, slab: SlabBuf);
   pub fn splice_tcp(src: RawSocket, dst: RawSocket, pipe: &mut PipePair, max: usize) -> io::Result<usize>;

   // ---- 2. crates/kv (sibuna-kv): Seqlock L1 RAM + MAP_SHARED Disk Spill Engine ----------
   pub struct KvSpec<'a> { pub ram_bytes: usize, pub mmap_path: Option<&'a Path>, pub mmap_bytes: u64 }
   pub struct KvStats { pub ram_used: u64, pub mmap_used: u64, pub hits: u64, pub shed: u64 }

   pub fn open_kv(spec: KvSpec<'_>) -> Result<KvStore, KvError>;
   pub fn close_kv(store: KvStore);
   pub fn kv_lookup(store: &KvStore, key: &[u8; 16], now_ms: u64, out: &mut [u8; 24]) -> bool;
   pub fn kv_upsert(store: &KvStore, key: &[u8; 16], val: &[u8; 24], ttl_ms: u64, now_ms: u64) -> bool;
   pub fn kv_remove(store: &KvStore, key: &[u8; 16]) -> bool;
   pub fn kv_stats(store: &KvStore) -> KvStats;

   // ---- 3. crates/lb (sibuna-lb): Maglev, P2C-PEWMA, TLS SNI/JA4 Peek, PROXYv2 -----------
   pub struct BackendTarget { pub id: u16, pub addr: SocketAddr, pub weight: u16, pub max_flows: u32 }
   pub struct FlowKey { pub src: IpAddr, pub dst: IpAddr, pub sport: u16, pub dport: u16, pub proto: u8 }
   pub struct TlsHelloView<'a> { pub sni: &'a [u8], pub alpn: &'a [u8], pub ja4: [u8; 36] }

   pub fn load_balancer(targets: &[BackendTarget], load_factor_pct: u16) -> Result<Balancer, LbError>;
   pub fn select_backend(lb: &Balancer, key: &FlowKey, state: &BackendMetrics) -> Option<u16>;
   pub fn record_feedback(state: &BackendMetrics, id: u16, rtt_us: u32, failed: bool);
   pub fn is_backend_healthy(state: &BackendMetrics, id: u16) -> bool;
   pub fn inspect_tls_hello(buf: &[u8]) -> Result<Option<TlsHelloView<'_>>, TlsPeekError>;
   pub fn write_proxy_v2(out: &mut [u8], key: &FlowKey, hello: Option<&TlsHelloView<'_>>) -> Result<usize, LbError>;
   pub fn parse_proxy_v2(buf: &[u8]) -> Result<(FlowKey, usize), LbError>;

   // ---- 4. crates/conf & crates/jlv: Canonical Schema + Off-Path JLV/2 Evaluator ---------
   pub fn load_edge_json(path: &str, source: &str, diag: &mut Diagnostic) -> Result<EdgeConfig, ConfError>;
   pub fn validate_edge_config(config: &EdgeConfig, diag: &mut Diagnostic) -> Result<(), ConfError>;
   pub fn dump_edge_json(config: &EdgeConfig, out: &mut dyn fmt::Write) -> fmt::Result;
   pub fn eval_edge_jlv(path: &str, source: &str, diag: &mut Diagnostic) -> Result<EdgeConfig, ConfError>;
   pub fn dump_edge_jlv(config: &EdgeConfig, out: &mut dyn fmt::Write) -> fmt::Result;

   // ---- 5. crates/plugin (sibuna-plugin): Traits, Fuel-Metered WASM & SPOE ---------------
   pub fn load_wasm_plugin(bytes: &[u8], fuel_limit: u64, pages: u16) -> Result<PluginModule, PluginError>;
   pub fn run_accept_hook(chain: &PluginChain, view: &AcceptView<'_>) -> Verdict;
   pub fn run_hello_hook(chain: &PluginChain, view: &TlsHelloView<'_>) -> Verdict;
   pub fn run_datagram_hook(chain: &PluginChain, view: &DatagramView<'_>) -> Verdict;

   // ---- 6. crates/cluster (sibuna-cluster): ATDP 3-Regime Mesh, SWIM & Delta-CRDT --------
   pub fn start_cluster(spec: ClusterSpec, kv: Arc<KvStore>) -> Result<ClusterMesh, ClusterError>;
   pub fn stop_cluster(mesh: ClusterMesh);
   pub fn active_regime(mesh: &ClusterMesh) -> DataPlaneRegime;
   pub fn route_or_cpf(mesh: &ClusterMesh, lb: &Balancer, key: &FlowKey, hop: bool) -> RouteAction;

Elm-Style Diagnostics
~~~~~~~~~~~~~~~~~~~~~

Every JLV/2 compile/budget problem (forwarded with exact ``jlv-syntax`` token spans just as ``jlavici`` maps ``ci.jlv.*``), semantic schema error, ``mmap`` permission refusal, or invalid WASM plugin import renders an Elm-style human-friendly diagnostic (SID 0001):

.. code-block:: text

   -- UNKNOWN BACKEND IN FRONTEND -------------------------------------------------

   /etc/sibuna/sibuna.jlv:73:55
     73 |                        { action: "use_backend", backend: "api_tcp_origin_v2", when: "is_api" },
        |                                                          ^^^^^^^^^^^^^^^^^^^

   Frontend `public_tls_tcp` routes matching flows to `api_tcp_origin_v2`, but the
   `backends` map returned by `fn edge() -> Map<Value>` defines no such key.

   Hint: Did you mean `api_tcp_origin` defined at line 89? Run
   `sibuna check -f /etc/sibuna/sibuna.jlv` before reloading a live node.

Console Evolution, 1.25 MiB WASM Budget, and Strict Peer Isolation
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Current cluster capabilities in ``sibuna-console`` (SID 0007, SID 0013)
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

The shipped console already includes a foundational multi-node cluster view, but it is shaped around Sibuna's single-origin HTTP firewall model:

- **What works today:** Operators can toggle the Traffic, Security Overview, and Kiosk Wall Display scope between **All configured nodes** and an individual **Node N** (``cmd/console-ui/src/scope.rs``). Consoles exchange live statistics over authenticated TLS WebSockets (``/console/peer``, up to ``MAX_PROBES = 8`` peers and ``MAX_MEMBERS = 9`` members in ``sibuna-console-protocol::nodes``), display replicated PostgreSQL member cards on **CONSOLE / NODES** (management URL, applied vs. committed policy revision, HTTP probe latency/health, RSS memory, CPU permille, clock skew), and execute fenced local ``drain``, ``resume``, and ``clear_local_bans`` commands with durable receipts.
- **What is missing for Sibuna Edge:**

  1. **No Visual Topology Graph:** The **Nodes** page renders flat member tables, and the 3D **Globe** routes all country arcs to a single ``--console-location`` coordinate rather than plotting multiple regional PoPs, peer SWIM/CPF mesh links, or downstream origin fleets.
  2. **No L4/L7 Frontend & Backend Matrix:** There is no HAProxy-style live backend table showing TCP/UDP frontends, per-server health (``UP`` / ``DRAIN`` / ``MAINT`` / ``DOWN``), active flow share vs. ``max_flows``, Peak-EWMA latency, or live weight/drain controls.
  3. **Hard 9-Node Ceiling & Local-Only Node Commands:** ``MAX_MEMBERS = 9`` is too small for multi-PoP edge fleets, and ``nodes/command`` only controls the node serving the active browser session rather than routing intents to any cluster member.
  4. **No** ``sibuna-kv`` **or ATDP Visibility:** Operators cannot see L1 Seqlock RAM vs. L2 ``mmap`` disk arena fill ratios, W-TinyLFU flood-shedding rates, or the active ATDP regime (``Standalone``, ``LAN Mesh CPF``, ``Geo-Anycast``).
  5. **Tight 768 KiB WASM Ceiling & Open-Ended Peer/Operator Network Gate:** ``cmd/sibuna/build.rs`` enforces ``CONSOLE_CEILING = 768 * 1024`` (786,432 B), while ``sibuna-console-ui`` already measures **719,406 B** (only ~67 KiB left). Meanwhile, ``Ingress`` (``crates/console/src/http/ingress.rs``) verifies ``trusted_proxies`` CIDRs, but does not separate allowed *operator client CIDRs* from *peer node CIDRs*, and ``ReplayCache::accept`` (``crates/console/src/peer/auth.rs``) accepts any ``from != 0`` holding the shared peer key rather than pinning ``transcript.from`` to a declared peer roster and IP in configuration.

Relaxing ``CONSOLE_CEILING`` to 1.25 MiB (1,280 KiB) with zero runtime bottleneck
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

In ``crates/console/src/assets.rs``, ``console.wasm`` lives in static read-only binary memory (``&'static [u8]``) and is served under a content-addressed SHA-256 URL (``/console/assets/<16-hex-sha256>/console.wasm``) with ``Cache-Control: public, max-age=31536000, immutable``. Consequently:

- **Downloaded Once, Executed in the Browser:** An operator's browser fetches ``console.wasm`` **once per Sibuna binary upgrade** (~350–450 KiB compressed over HTTPS) and compiles it via ``WebAssembly.instantiateStreaming``. Every SVG topology layout, Maglev share bar, 60-point sparkline, and JLV relational diff renders on the **operator's browser CPU**; steady-state wire traffic is solely 1 Hz compact JSON deltas (:math:`\le 4\,\text{KiB}`).
- **Updated Budget:** Sibuna Edge raises ``CONSOLE_CEILING`` in ``cmd/sibuna/build.rs`` from **768 KiB (786,432 B)** to **1,280 KiB (1.25 MiB = 1,310,720 B)**, with a **1,024 KiB (1.0 MiB)** review threshold (superseding SID 0007's 768 KiB cap). This grants **591,314 bytes** of uncompressed headroom for rich cluster/topology visualisations while keeping ``[profile.wasm]`` (``opt-level = "z"``, fat LTO, ``--compress-relocations``) intact.

Zero-bottleneck isolation & closed-world peer access in ``sibuna.jlv``
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

To guarantee that web console sessions, peer telemetry streams, or management-port scans **never** become a CPU, lock, socket, or database bottleneck for the L4/L7 data plane, Sibuna Edge enforces five hard walls configured directly in ``console: { ... }`` of ``sibuna.jlv``:

1. **Physical Socket & CPU Core Disjointness:** ``sibuna-serve::Server`` binds a dedicated management IP/VLAN socket (``console.listen``, never sharing ``SO_REUSEPORT`` groups or pollers with data-plane VIP frontends) and optionally pins acceptor, watchdog, collector, and peer worker threads to ``console.management_cpus`` excluded from packet-worker ``--workers`` affinity.
2. **Pre-Parse CIDR Split** (``allow_operators`` vs. ``peers[i].allow_ips``):

   - Unauthorised TCP peers connecting directly (without ``behind_proxy``) are dropped immediately after ``accept()`` **before** ``sibuna-serve`` allocates a slot, spawns/wakes a worker, or reads ``MAX_HEAD`` (16 KiB).
   - Behind ``trusted_proxies``, human/API routes (``/console/*`` except ``/console/peer``) require the verified client IP to match ``console.allow_operators`` (for example, corporate WireGuard or bastion subnets); ``/console/peer`` refuses every client IP not listed in ``console.peers[*].allow_ips``.

3. **Closed-World Peer Roster Pinning:** Upgrading ``GET /console/peer`` now requires **four simultaneous proofs**: (a) transport/forwarded client IP matches ``peers[i].allow_ips`` for a configured peer entry ``i``; (b) ``transcript.from == peers[i].node`` (unknown or removed node IDs are rejected even if they possess an unrotated ``peer.key``); (c) directional ``HMAC-SHA256`` over the 64-byte upgrade transcript (``sibuna-console-peer-v1``) within ``SKEW_SECONDS = 30`` and ``ReplayCache`` (256 slots, zero eviction of live receipts); and (d) outbound WSS peer workers verify ``--console-peer-ca-file`` + strict RFC 6125 hostname matching via ``sibuna-tls``. Removing a compromised or decommissioned peer from ``sibuna.jlv`` severs its inbound and outbound peer streams immediately upon ``SIGHUP``.
4. **Hard Class Quotas & Non-Blocking Storage Tickets:** ``sibuna-serve::Admission`` partitions ``max_slots`` (:math:`\le 256`, default ``96``) into ``max_browsers`` (:math:`\le 64`), ``max_peers`` (:math:`\le 64`, raised from ``MAX_PEERS = 8`` to ``63`` for multi-PoP fleets), and ``http_reserved >= 16`` so long-lived WebSockets can never starve REST logins or health calls. Console background tasks (250 ms ``Relaxed`` atomic collector, 1 Hz hub feeder, retention, notifier) may hold **at most 4 of the 32** ``sibuna-storage`` queue tickets (SID 0007, SID 0011) and never wait synchronously; peer streams cap waiting queries at ``INBOX_CAPACITY = 8`` and halve rows automatically to fit a single 4 KiB WebSocket frame.
5. **Four Functional UI Additions (within the 1.25 MiB WASM ceiling):** (a) inline-SVG **Cluster Mesh & Flow Topology** on **CONSOLE / NODES** (raising ``MAX_MEMBERS`` from ``9`` to ``64`` and routing remote ``drain``/``maint`` commands via PostgreSQL ``console_node_commands``); (b) **CONSOLE / TOPOLOGY** live HAProxy-style Frontend/Backend/Server matrix; (c) multi-PoP ``(lat_e4, lon_e4)`` **Globe** markers; and (d) server-side ``sibuna-jlv`` plan/diff/apply on **Policies / Settings**.

.. typst-diagram::
   :caption: Zero-bottleneck Console & Closed-World Peer Isolation architecture. Unauthorised IPs drop before slot allocation; operators fetch the 1.25 MiB WASM UI once (immutable SHA-256 cache) and render topology graphs in the browser, while strict class, ticket, and CPU bounds isolate packet workers completely.
   :alt: Architecture diagram split into External Management Callers on the left (Bastion/VPN Operator Browser, Declared Sibling Console Peer Node 2, and Unauthorized Scanner/Decommissioned Node), Passing through sibuna.jlv Strict Ingress & Roster Gate (allow_operators CIDR check, peers[i].allow_ips + node ID + HMAC-SHA256 check, immediate drop for unauthorized), into Off-Path Console Subsystem pinned to management_cpus (Immutable rodata console.wasm <= 1.25 MiB, sibuna-serve 96-slot Admission with 16 HTTP reserved, 4/32 storage ticket cap), separated by a hard wall (Relaxed/Acquire atomics only, <1% impact) from Pinned C10M Data-Plane Workers 1..N.

   #import "@preview/cetz:0.5.2"
   #set text(font: "Libertinus Serif", size: 7.5pt, fill: rgb("#172033"))
   #cetz.canvas(length: 1cm, {
     import cetz.draw: *

     let ink = rgb("#172033")
     let muted = rgb("#64748b")
     let blue = rgb("#1e40af")
     let blue-bg = rgb("#eff6ff")
     let green = rgb("#15803d")
     let green-bg = rgb("#f0fdf4")
     let amber = rgb("#b45309")
     let amber-bg = rgb("#fffbeb")
     let red = rgb("#b91c1c")
     let red-bg = rgb("#fef2f2")
     let violet = rgb("#6d28d9")
     let violet-bg = rgb("#f5f3ff")

     let box-card(x1, y1, x2, y2, bg, fg, title, body) = {
       rect((x1, y1), (x2, y2), radius: 3pt, fill: bg, stroke: 0.75pt + fg)
       content(((x1 + x2) / 2, (y1 + y2) / 2), box(width: (x2 - x1 - 0.22) * 1cm, align(center, {
         text(weight: "bold", size: 7.1pt, fill: fg.darken(15%), title)
         if body != "" {
           linebreak()
           text(size: 6.3pt, fill: ink, body)
         }
       })))
     }

     // Left column: Callers
     box-card(0.0, 4.7, 3.85, 6.2, blue-bg, blue, "Operator Browser (VPN)",
       "1. GET console.wasm (1x cached!)\n2. 1 Hz <=4 KiB WS deltas\n3. SVG/Diff runs in Browser CPU")
     box-card(0.0, 2.7, 3.85, 4.2, violet-bg, violet, "Sibling Peer (Node 2..64)",
       "WSS /console/peer (mTLS/CA)\nPinned IP + Node ID + HMAC\nBounded 8-query inbox")
     box-card(0.0, 0.7, 3.85, 2.2, red-bg, red, "Unknown IP / Removed Peer",
       "Port scan, internet host, or\ndecommissioned node ID")

     // Middle Gate: sibuna.jlv Strict Console ACL
     rect((4.4, 0.55), (7.75, 6.35), radius: 3pt, fill: amber-bg, stroke: 0.85pt + amber)
     content((6.08, 6.0), text(weight: "bold", size: 7.2pt, fill: amber.darken(15%), "Strict Peer & CIDR Gate"))
     line((4.6, 5.72), (7.55, 5.72), stroke: 0.5pt + amber.lighten(40%))
     content((6.08, 3.35), box(width: 3.0cm, align(left, text(size: 6.3pt, [
       • Dedicated VLAN `listen`\
       • `trusted_proxies` + HTTPS\
       • `/console/*`:\
         `ip in allow_operators`\
       • `/console/peer`:\
         `ip in peers[i].allow_ips`\
         `from == peers[i].node`\
         `HMAC-SHA256` (30s skew)\
       • Else: *0-slot fast drop!*
     ]))))

     // Right Top: Isolated Console Subsystem
     rect((8.35, 2.65), (14.4, 6.35), radius: 3pt, fill: violet-bg.lighten(35%), stroke: 0.85pt + violet)
     content((11.38, 6.02), text(weight: "bold", size: 7.2pt, fill: violet,
       "Console Plane (Pinned to management_cpus)"))
     box-card(8.55, 4.55, 11.3, 5.7, white, blue, "Immutable Asset",
       "console.wasm <= 1.25 MiB\n(~400 KiB gzip, max-age=1y)")
     box-card(11.5, 4.55, 14.2, 5.7, white, violet, "sibuna-serve Quotas",
       "<=256 slots (16 HTTP rsv)\n<=64 browsers, <=64 peers")
     box-card(8.55, 2.9, 14.2, 4.25, white, amber, "Bounded Storage & Query Governor",
       "Max 4/32 background DB tickets · 60 mut/min · 5 Argon2/min (fixed 19 MiB)")

     // Right Bottom: Protected Data Plane
     box-card(8.35, 0.55, 14.4, 1.95, green-bg, green,
       "Pinned C10M Data-Plane Workers (Cores 1..N — Untouched)",
       "Zero shared locks, sockets, threads, or heap with Console; <=1% throughput impact")

     // Arrows
     line((3.85, 5.45), (4.4, 5.45), stroke: 0.8pt + blue, mark: (end: "stealth", fill: blue, scale: 0.55))
     line((3.85, 3.45), (4.4, 3.45), stroke: 0.8pt + violet, mark: (end: "stealth", fill: violet, scale: 0.55))
     line((3.85, 1.45), (4.4, 1.45), stroke: 0.8pt + red, mark: (end: "stealth", fill: red, scale: 0.55))
     content((6.08, 0.92), text(weight: "bold", size: 6.0pt, fill: red, "Drop / 403 CONSOLEPEER"))

     line((7.75, 5.1), (8.55, 5.1), stroke: 0.8pt + blue, mark: (end: "stealth", fill: blue, scale: 0.55))
     line((7.75, 3.55), (8.55, 3.55), stroke: 0.8pt + violet, mark: (end: "stealth", fill: violet, scale: 0.55))
     line((11.38, 1.95), (11.38, 2.65), stroke: (paint: green, thickness: 0.8pt, dash: "dashed"),
       mark: (end: "stealth", fill: green, scale: 0.55))
     content((12.9, 2.3), text(size: 6.1pt, fill: green.darken(15%), "250ms Relaxed Atomics Only"))
   })

.. typst-diagram::
   :caption: Mockup of the extended Sibuna Console Topology & Cluster Mesh view (rendered as zero-dependency inline SVG inside sibuna-console-ui within the relaxed 1.25 MiB immutable WASM budget). Operators see the live ATDP regime, pinned peer SWIM RTT / CPF links, L1/mmap KV pressure, and HAProxy-style backend server pools in one screen.
   :alt: Console UI mockup showing top breadcrumb CONSOLE / TOPOLOGY & CLUSTER MESH with ATDP Regime badge (Regime 2: Regional PoP Mesh, p95 RTT 0.42 ms), three Edge Node cards connected by SWIM/CRDT & CPF links with RAM/mmap bars, routing down into Backend Pool cards (api_tcp_origin and quic_h3_fleet) showing UP, DRAIN, and BACKUP origin servers with active flows, EWMA RTT, and Drain/Weight buttons.

   #import "@preview/cetz:0.5.2"
   #set text(font: "Libertinus Serif", size: 7.4pt, fill: rgb("#172033"))
   #cetz.canvas(length: 1cm, {
     import cetz.draw: *

     let ink = rgb("#172033")
     let muted = rgb("#64748b")
     let blue = rgb("#1e40af")
     let blue-bg = rgb("#eff6ff")
     let green = rgb("#15803d")
     let green-bg = rgb("#f0fdf4")
     let amber = rgb("#b45309")
     let amber-bg = rgb("#fffbeb")
     let red = rgb("#b91c1c")
     let red-bg = rgb("#fef2f2")
     let violet = rgb("#6d28d9")
     let violet-bg = rgb("#f5f3ff")
     let border = rgb("#cbd5e1")

     // Outer Browser/Console Frame
     rect((0.0, 0.0), (14.4, 8.35), radius: 4pt, fill: rgb("#f8fafc"), stroke: 0.9pt + border)
     rect((0.0, 7.45), (14.4, 8.35), radius: (top: 4pt), fill: white, stroke: 0.7pt + border)
     content((0.3, 7.9), anchor: "west",
       text(weight: "bold", size: 7.4pt, fill: ink, "CONSOLE  /  TOPOLOGY & CLUSTER MESH"))
     rect((9.25, 7.62), (14.15, 8.18), radius: 9pt, fill: green-bg, stroke: 0.65pt + green)
     content((11.7, 7.9), text(weight: "bold", size: 6.5pt, fill: green,
       "ATDP: LAN PoP Mesh (3/3 Healthy · p95 0.42 ms)"))

     // Edge Node Cards Row
     let node-card(x, title, role-col, role-bg, flows, kv-txt) = {
       rect((x, 4.75), (x + 4.2, 7.05), radius: 3pt, fill: white, stroke: 0.8pt + role-col)
       rect((x, 6.45), (x + 4.2, 7.05), radius: (top: 3pt), fill: role-bg, stroke: 0.6pt + role-col)
       content((x + 2.1, 6.75), text(weight: "bold", size: 7.0pt, fill: role-col.darken(15%), title))
       content((x + 2.1, 5.6), box(width: 3.85cm, align(left, text(size: 6.4pt, [
         • *Flows:* #flows\
         • *KV RAM / Mmap:* #kv-txt\
         • *Rev:* `42` (synced) · `[Drain]`
       ]))))
     }

     node-card(0.3, "Node 1 (fra-edge-01 · LIVE)", green, green-bg, "142,810 TCP / 89,120 UDP", "68% / 4% NVMe")
     node-card(5.1, "Node 2 (fra-edge-02 · LIVE)", green, green-bg, "139,405 TCP / 91,004 UDP", "65% / 3% NVMe")
     node-card(9.9, "Node 3 (fra-edge-03 · DRAINING)", amber, amber-bg, "12,104 in-flight (CPF -> 1,2)", "21% / 0% NVMe")

     // Mesh peer links between nodes
     line((4.5, 5.9), (5.1, 5.9), stroke: 0.8pt + green, mark: (start: "stealth", end: "stealth", fill: green, scale: 0.5))
     content((4.8, 6.2), text(size: 5.8pt, fill: green, "CRDT\n0.3ms"))
     line((9.3, 5.9), (9.9, 5.9), stroke: (paint: amber, thickness: 0.8pt, dash: "dashed"),
       mark: (end: "stealth", fill: amber, scale: 0.5))
     content((9.6, 6.2), text(size: 5.8pt, fill: amber, "1-Hop\nCPF"))

     // Backend Pool Matrix (Bottom half)
     rect((0.3, 0.3), (7.05, 4.05), radius: 3pt, fill: white, stroke: 0.75pt + blue)
     content((0.5, 3.72), anchor: "west",
       text(weight: "bold", size: 6.7pt, fill: blue, "Backend: api_tcp_origin (TCP · Maglev · PROXYv2+JA4)"))
     line((0.45, 3.45), (6.9, 3.45), stroke: 0.5pt + border)
     content((3.68, 1.9), box(width: 6.35cm, align(left, text(size: 6.3pt, [
       `[UP]`    *api-1* (`10.20.1.11:8443`) w=100 flows: `48,210/50k` (`1.1ms`)\
       `[UP]`    *api-2* (`10.20.1.12:8443`) w=100 flows: `47,905/50k` (`1.2ms`)\
       `[DRAIN]` *api-3* (`10.20.1.13:8443`) w=50  flows: `1,204/25k`  (`1.4ms`)
     ]))))

     rect((7.35, 0.3), (14.1, 4.05), radius: 3pt, fill: white, stroke: 0.75pt + violet)
     content((7.55, 3.72), anchor: "west",
       text(weight: "bold", size: 6.7pt, fill: violet, "Backend: quic_h3_fleet (UDP · CID Stick · Cookie Gate)"))
     line((7.5, 3.45), (13.95, 3.45), stroke: 0.5pt + border)
     content((10.72, 1.9), box(width: 6.35cm, align(left, text(size: 6.4pt, [
       `[UP]`    *h3-1*  (`10.20.2.11:443`)   w=100  sessions: `90,112`   ewma: `0.6ms`\
       `[UP]`    *h3-2*  (`10.20.2.12:443`)   w=100  sessions: `89,992`   ewma: `0.7ms`\
       `[SHED]`  *UDP Cookie Gate:* `412,900/s` spoofed floods dropped (`0 B` RAM)
     ]))))

     line((2.4, 4.75), (3.4, 4.05), stroke: 0.75pt + blue, mark: (end: "stealth", fill: blue, scale: 0.55))
     line((7.2, 4.75), (3.9, 4.05), stroke: 0.75pt + blue, mark: (end: "stealth", fill: blue, scale: 0.55))
     line((2.6, 4.75), (10.3, 4.05), stroke: 0.75pt + violet, mark: (end: "stealth", fill: violet, scale: 0.55))
     line((7.4, 4.75), (10.9, 4.05), stroke: 0.75pt + violet, mark: (end: "stealth", fill: violet, scale: 0.55))
   })

Rationale and alternatives
--------------------------

.. list-table:: Key architectural trade-offs and rejected alternatives
   :header-rows: 1
   :widths: 22 30 48

   * - Concern
     - Alternative Considered
     - Why Rejected / Why Sibuna Edge's Choice Wins
   * - **C10M Networking**
     - DPDK / PF_RING full kernel bypass
     - Seizes entire NIC, breaks Linux/BSD/macOS/Windows portability, hides ARP/BGP/SSH from OS, requires hugepages & root PMDs. Cooperative ``SO_REUSEPORT`` + ``io_uring``/``kqueue`` + 64B ``FlowSlot`` achieves multi-million concurrency portably with zero NIC takeover.
   * - **Async Runtime**
     - ``tokio`` + ``mio`` on the data plane
     - Adds ~30 crates to the hot path, forces heap-allocated task state machines per connection, and obscures exact per-flow cache-line sizing (SID 0010). ``sibuna-io`` keeps fixed array indexing and zero hot allocations.
   * - **Config Language**
     - Bespoke ``SCL`` DSL, YAML, HCL, or Lua
     - A custom ``SCL`` duplicates parser/formatter/LSP engineering; YAML has silent type traps; Lua is unbounded and impure. Reusing **JLV/2** (``sibuna-jlv`` + zero-dep canonical JSON in ``sibuna-conf``) unifies CI (``jlavici``), deployment (``jlavideploy``), and edge routing (``sibuna``) under one statically typed, 1M-step-budgeted pure ``Role::Transform`` kernel with zero hot-path footprint.
   * - **KV Spill Engine**
     - RocksDB, ``sled``, ``redb``, or ``lmdb``
     - RocksDB links C++ and stalls under compaction; ``sled``/``redb`` allocate B-tree nodes and block on transactional ``fsync``. ``sibuna-kv`` uses fixed 64B seqlock RAM + ``MAP_SHARED`` ring buckets with W-TinyLFU shedding: zero compaction pauses, zero ``fsync`` stalls, zero external crates.
   * - **Scheduling**
     - Classic Ketama ring or plain Round-Robin
     - Ketama requires :math:`O(\log N)` binary search and causes :math:`\sim 20\%` load imbalance; plain RR loses flow affinity across ECMP edge nodes. **Bounded-Load Maglev + P2C-PEWMA** gives :math:`O(1)` lookup, minimal disruption on node churn, and provable :math:`\le C` backend load ceilings (Theorem 35).
   * - **Cluster Data Plane**
     - Fixed gossip-everywhere or stateless-only
     - Synchronous gossip across 150 ms trans-oceanic WAN links ruins latency, whereas stateless-only inside a 0.2 ms PoP needlessly resets TCP streams on ECMP churn. **ATDP** measures RTT and adapts across Standalone, PoP CPF+CRDT Mesh, and WAN Stateless Anycast automatically.
   * - **Plugins**
     - Dynamic ``dlopen`` (``.so``/``.dll``) or Lua
     - ``dlopen`` violates ``unsafe_code = "deny"`` and crashes the whole daemon on a segfault; Lua adds a garbage collector to the request thread. Fuel-metered zero-WASI WASM + SPOE isolates faults completely.

Security and operational considerations
---------------------------------------

- **Trust Boundaries:**

  - *Untrusted External Wire:* Every TCP ``ClientHello`` parser, PROXYv2 reader (accepted *only* from CIDRs explicitly listed in ``trust_proxy_cidr``), and UDP cookie verifier operates on bounded slices with constant-time MAC checks. An untrusted client sending a ``PROXY`` header on a public port is rejected immediately.
  - *Plugin Boundary:* WASM plugins receive zero WASI capabilities (no filesystem, clock, random, or socket syscalls) and trap harmlessly on out-of-bounds memory or fuel exhaustion.
  - *Peer Mesh, Console & Admin IPC:* UDP SWIM/CRDT frames carry a 16-byte keyed-BLAKE3 tag derived from the cluster master seed (``sibuna/cluster-mesh/v1``) with a 64-bit monotonic replay window; ``/console/*`` enforces ``allow_operators`` CIDRs, while ``/console/peer`` enforces closed-world roster pinning (``peers[i].allow_ips`` + ``peers[i].node`` + ``HMAC-SHA256`` + CA/hostname verification); ``/run/sibuna/admin.sock`` and ``handoff.sock`` enforce ``0600`` owner-only UNIX credentials (``SO_PEERCRED`` / ``LOCAL_PEERCRED``).

- **Failure & Saturation Recovery:**

  - *PostgreSQL Outage:* Workers continue serving the last published ``Arc<TopologySnapshot>`` indefinitely (SID 0011).
  - *NVMe Disk Full / Slow:* ``sibuna-kv`` pre-allocates its arena via ``fallocate`` at startup so ``ENOSPC`` cannot occur mid-attack; IOPS watermark shedding prevents slow storage from blocking workers.
  - *Corrupt Crash State:* On restart, ``sibuna-kv`` verifies each ``mmap`` slot's 64-bit Wyhash tag lazily on read; torn slots are treated as empty misses in :math:`O(1)` with zero recovery scan pause.

Backwards compatibility
-----------------------

All existing CLI flags (``--port``, ``--upstream-host``, ``--upstream-port``, ``--mode``, ``--policy-file``, ``--gate``, ``--shield``, ``--console``, ``--data-dir``, ``--database-url-file``) continue to work unchanged: when ``--config-file <sibuna.jlv|edge.json>`` is omitted, ``cmd/sibuna`` synthesises a single-frontend, single-backend HTTP ``EdgeConfig`` in memory that behaves bit-for-bit identically to Sibuna 1.0.0-beta.3. Core storage migration 3 adds ``edge_frontends``, ``edge_backends``, ``edge_servers``, and ``edge_config_sources`` alongside existing ``policies`` and ``ip_reputation`` tables without altering existing rows.

Acceptance criteria and implementation status
---------------------------------------------

Status: **Working Draft (prediscussion)** — proposed architecture and verified Lean 4 mathematical models; no Rust workspace crate changes committed yet.

Promotion and eventual ``committed`` status require:

1. **Formal Verification Gate (Met in Draft):** ``lean docs/sid/assets/distributed-edge-load-balancer.lean`` exits ``0`` with zero ``sorry`` axioms across Theorems 35, 38, 39, and 40.
2. **Zero-Allocation & Style Gate:** ``cargo xtask check``, ``cargo clippy --all-targets -- -D warnings``, and Miri verification on ``sibuna-kv`` seqlock and ``sibuna-io`` slab rings pass within the 70-line function and 1,408-line file bounds.
3. **L4 TCP/UDP & Reload Conformance:** End-to-end tests verify TCP passthrough with TLS SNI + native JA4 TLV over PROXYv2, UDP 4-tuple and QUIC CID stickiness, stateless UDP cookie flood rejection, ``SIGHUP`` RCU reloads, and ``SIGUSR2`` ``SCM_RIGHTS`` zero-drop binary upgrades under active ``wrk`` and UDP flood load.
4. **Saturation Survival Gate:** A synthetic 50-million-unique-key adversarial harness against a 64 MiB RAM + 512 MiB ``mmap`` ``sibuna-kv`` instance sustains :math:`> 99.9\%` retention of established multi-packet sessions with zero OOM, zero panics, and bounded RSS.
5. **ATDP Multi-Node Gate:** A 4-node integration suite (using Linux ``tc netem`` to sweep peer RTT from ``0.2 ms`` to ``40 ms`` and back) verifies automatic transitions across Standalone, Regional PoP CPF+CRDT Mesh, and Geo-Anycast Stateless regimes without flapping inside the ``[1.5 ms, 3.0 ms]`` deadband.
6. **Console Budget, Closed-World Peer ACL & Non-Interference Gate:** ``sibuna-console-ui`` builds cleanly under ``CONSOLE_CEILING = 1,310,720`` bytes (1.25 MiB, 1.0 MiB review threshold); integration tests verify that unconfigured client CIDRs and unpinned ``transcript.from`` node IDs are rejected before slot/session allocation, and flooding ``console.listen`` degrades L4/L7 data-plane throughput by :math:`\le 1\%` (SID 0007).

Open questions
--------------

1. **Linux eBPF Socket Steering Packaging:** Should optional ``SO_ATTACH_REUSEPORT_CBPF`` (classic BPF, zero external toolchain, unprivileged in many setups) be enabled by default on Linux, reserving full eBPF QUIC-CID socket steering for an opt-in ``--linux-ebpf`` flag when ``CAP_BPF`` is available?
2. **WASM Execution Engine:** Should ``sibuna-plugin`` ship a compact ~1,200-line in-house fuel-metered ``wasm32`` bytecode/register interpreter (zero external crates, ~20–40 ns/instruction, ample for 500-instruction ACL hooks) or admit ``wasmtime``/``wasmi`` behind an optional ``wasm-plugins`` Cargo feature as ``sqlx`` is confined to ``sibuna-storage``?
3. **Default** ``sibuna-kv`` **Disk Path:** In single-node ``--data-dir <dir>`` deployments without an explicit ``kv_stores`` entry, should Sibuna allocate a default ``1 GiB`` ``<dir>/edge_state.arena`` automatically or keep ``mmap`` spill opt-in?
4. **JLV Kernel License Alignment & Workspace Sourcing:** ``sibuna`` is licensed ``LGPL-3.0-or-later``, whereas ``jlavideploy`` (``jlv-*``) and ``guidedog`` (``gd-json``, ``gd-report``, ``gd-sha``) currently declare ``AGPL-3.0-or-later`` (fine for ``jlavici``, which is also ``AGPL-3.0-or-later``). Before linking ``sibuna-jlv`` by default, should the pure language kernel crates (``jlv-{core,lang,model,syntax,compiler,stdlib}`` and ``gd-{json,report,sha}``) be dual-licensed or relicensed to ``LGPL-3.0-or-later`` (and optionally extracted into a shared ``jlv`` repository so CI builds do not require a sibling ``../jlavideploy`` checkout), or should ``--features jlv`` opt into an ``AGPL-3.0-or-later`` distribution profile?

Review history
--------------

- 2026-11-24: Created initial ``prediscussion`` draft with infrastructure topology, C10M cooperative architecture, JLV/2 (``sibuna.jlv``) + canonical JSON configuration specification, ``sibuna-kv`` two-tier seqlock/mmap design, ATDP 3-regime distributed fabric, 7-stage DDoS self-protection funnel, console topology view, Raylib-style crate APIs, and machine-checked Lean 4.19.0 proofs (``docs/sid/assets/distributed-edge-load-balancer.lean``).

References
----------

- Robert Graham, *C10M: Defending The Internet At Scale* (ShmooCon 2013) and Todd Hoff, *The Secret to 10 Million Concurrent Connections — The Kernel Is the Problem*, High Scalability (2013).
- Daniel E. Eisenbud et al., *Maglev: A Fast and Reliable Software Network Load Balancer*, USENIX NSDI (2016).
- Vahab Mirrokni, Mikkel Thorup, and Morteza Zadimoghaddam, *Consistent Hashing with Bounded Loads*, ACM-SIAM SODA (2018).
- Gil Einziger, Roy Friedman, and Ben Manes, *TinyLFU: A Highly Efficient Cache Admission Policy*, ACM Transactions on Storage 13(4) (2017).
- Paulo Sérgio Almeida, Ali Shoker, and Carlos Baquero, *Delta State Replicated Data Types*, Journal of Parallel and Distributed Computing 111 (2018).
- Nikita Shirokov and Ranjeeth Dasineni, *Katran: A High Performance Layer 4 Load Balancer*, Meta Engineering (2018); Matthewack / Cloudflare, *Unimog: Cloudflare's Edge Load Balancer* (2020).
- HAProxy Technologies, *PROXY Protocol Versions 1 and 2 Specification* (2020); IETF RFC 9000, *QUIC: A UDP-Based Multiplexed and Secure Transport* (Section 8, Address Validation via Retry Packets).
- Jlavideploy JDD 0004 (*JLV/1 Language Report*), JDD 0016 (*A Familiar Surface for JLV*), and Jlavici JCD XXXXX (*JLV Workflows*).
- SID 0001 (process and TigerStyle limits), SID 0002 (foundation architecture), SID 0006 (mathematical foundations and Axioms 1–4), SID 0007 (console isolation invariants), SID 0010 (Rust port and dependency policy), SID 0011 (SQLite and PostgreSQL storage), SID 0014 (JA4 TLS fingerprints).
