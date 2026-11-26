:sid-number: 0035
:sid-title: Post-Quantum Key Exchange
:sid-state: discussion
:sid-status: Open for Discussion
:sid-type: Architectural Specification
:sid-authors: ["Vikrant Rathore"]
:sid-created: 2026-11-26
:sid-updated: 2026-11-26
:sid-discussion: No external discussion URL assigned
:sid-summary: Every TLS connection that Sibuna ends or opens offers and accepts the hybrid key exchange X25519MLKEM768, which combines X25519 with ML-KEM-768 (FIPS 203). A recording of the traffic today then stays secret against a quantum computer of tomorrow. We add the group beside the ring provider of rustls 0.23, in the shape of the hybrid combinator of rustls 0.24, with ML-KEM from a pure Rust crate.
:sid-labels: ["architecture","tls","security","cryptography"]

Post-Quantum Key Exchange
=========================

Abstract
--------

The key of a TLS 1.3 session comes from an elliptic-curve Diffie-Hellman exchange. Shor's algorithm computes discrete logarithms on a quantum computer, so an adversary who records a session today can read it once such a computer exists. This is called "harvest now, decrypt later". Signatures do not have this problem: a forged signature is useful only at the time of the handshake.

The defence is a key exchange that a quantum computer cannot break. ML-KEM, standardised by NIST as FIPS 203, is such a key encapsulation mechanism. The IETF draft ``draft-ietf-tls-ecdhe-mlkem`` defines the group X25519MLKEM768 (code point ``0x11EC``), which runs ML-KEM-768 and X25519 together and feeds both secrets to the key schedule. The session stays secret as long as either of the two holds. Chrome, Firefox, Safari, Edge, OpenSSL 3.5, Go and Cloudflare offer this group by default.

We make Sibuna offer and accept X25519MLKEM768 on every TLS connection it ends (HTTPS and HTTP/3 listeners, TLS on the workers) and every one it opens (servers behind ``tls`` pools, the console's outbound connections). Clients and servers without the group keep using X25519 or the NIST curves, with no extra round trip.

Motivation and scope
--------------------

Sibuna's own tokens were already safe against a quantum adversary. Shield's session cookies and the challenge records of the gate are sealed with keyed BLAKE3, against which Grover's algorithm gives only a quadratic speedup (SID 0006), and the proof of sequential work is secure in the quantum random oracle model. The transport was not: every cookie, request and response crossed a TLS session whose key came from X25519 or P-256 alone.

rustls, the TLS library of Sibuna, supports X25519MLKEM768 only with its aws-lc-rs provider. Sibuna uses the ring provider:

- rustls 0.23 implements the group in ``crypto::aws_lc_rs::pq`` and enables it with the ``aws_lc_rs`` feature. The ``prefer-post-quantum`` feature moves it to the front.
- rustls 0.24 (in development, 0.24.0-dev.3) moves the providers into their own crates. ``rustls-aws-lc-rs`` has the hybrid groups; ``rustls-ring`` has X25519, P-256 and P-384 only. The core crate gains a public ``Hybrid`` combinator with a ``HybridLayout``, so that any provider can pair a classical group with a post-quantum one.
- ``rustls-post-quantum`` was the experimental home of ML-KEM before rustls 0.23.22. It is now the aws-lc-rs provider plus three experimental ML-DSA signature algorithms.

This record covers the key exchange of every TLS connection of the ``sibuna`` binary. It does not cover certificates and signatures (see Rationale), the TLS of PostgreSQL connections, which sqlx builds itself, or the inner protocol of the agent and WebAssembly hooks.

Specification
-------------

Invariants
~~~~~~~~~~

#. *Either secret suffices.* The secret that enters the TLS 1.3 key schedule is the ML-KEM shared secret followed by the X25519 shared secret, 64 bytes, as the draft specifies. Each half can be recovered from the whole, so an adversary who learns the whole has broken both components.
#. *No client is refused for it.* A peer that does not offer the hybrid group negotiates exactly the group it negotiated before. Adding the group never turns a successful handshake into a failure.
#. *TLS 1.3 only.* The hybrid group is never selected for TLS 1.2, which has no way to carry a key encapsulation.
#. *Strict lengths.* A client share has exactly 1,216 bytes (an ML-KEM-768 encapsulation key of 1,184 bytes, then an X25519 key of 32). A server share has exactly 1,120 bytes (a ciphertext of 1,088 bytes, then 32). Any other length, or an encapsulation key that fails the modulus check of FIPS 203, ends the handshake with ``illegal_parameter``.
#. *One provider.* Every TLS configuration of the binary is built from one function, so no connection is left with the classical groups alone.

The group
~~~~~~~~~

The crate ``sibuna-tls`` gains a module ``kx`` with three parts.

- ``Hybrid`` pairs a classical ``SupportedKxGroup`` with a post-quantum one under one ``NamedGroup``, and ``HybridLayout`` states the share lengths and which half comes first. Its fields and behaviour are those of the combinator in rustls 0.24, so that a move to 0.24 deletes our copy and keeps the call sites.
- ``MlKem768`` is a ``SupportedKxGroup`` for the post-quantum half. A client's ``start`` draws a 64-byte seed and derives the decapsulation key from it (``DecapsulationKey::from_seed``). A server's ``start_and_complete`` checks the client's encapsulation key, draws the 32-byte message and encapsulates (``encapsulate_deterministic``, the FIPS 203 algorithm with explicit randomness). All randomness comes from ring's ``SystemRandom``, the source of every other key in rustls.
- ``X25519MLKEM768`` is ``Hybrid { classical: X25519 of ring, post_quantum: MlKem768, name: X25519MLKEM768, layout: post-quantum first }``.

The ML-KEM arithmetic comes from the RustCrypto crate ``ml-kem`` 0.3, which is pure Rust, runs in constant time for secret data, and is tested against the Wycheproof and NIST vectors.

A client that starts a hybrid exchange also offers its X25519 key alone, through ``hybrid_component``. A server without the hybrid group then picks X25519 and the client completes with the same X25519 key, without a ``HelloRetryRequest``. This is what browsers do, and what rustls does for its own hybrid groups.

The provider
~~~~~~~~~~~~

``sibuna_tls::provider()`` returns the ring provider of rustls with the key exchange groups

#. X25519MLKEM768,
#. X25519,
#. P-256 (``secp256r1``),
#. P-384 (``secp384r1``).

The cipher suites, signature algorithms and randomness stay those of ring. Every place that built ``rustls::crypto::ring::default_provider()`` calls ``provider()`` instead: the listeners' server configuration (and through it HTTP/3 and the workers), the client configuration of pools, the console's ``Connector``, and the automatic HTTPS driver.

A TLS 1.3 server picks the first group in the client's list that it supports, so the client's order decides. Browsers list X25519MLKEM768 first. Our client lists it first too, and sends key shares for X25519MLKEM768 and X25519.

There is no setting. An operator gains nothing by turning the group off: a peer without it negotiates as before, and a peer with it gains forward secrecy against a quantum adversary.

Costs
~~~~~

A ClientHello grows by 1,216 bytes and a ServerHello by 1,120. The ClientHello of a browser was already larger than a 1,500-byte packet, and the bound of the ClientHello that the workers read is 16 KiB (SID 0024), so nothing changes there. The inspection of TCP frontends reads at most ``inspect_bytes`` (SID 0032); a hybrid ClientHello of about 1,800 bytes fits the default. A QUIC Initial of our own HTTP/3 client now spans two packets, which QUIC allows.

The CPU cost is measured below.

The model
~~~~~~~~~

``docs/sid/assets/post-quantum-key-exchange.lean`` models the selection of a group and the layout of the shares in core Lean 4.

- ``split_concat``: splitting a share built by ``concat`` returns the two halves (invariant 1), and ``split_wrong_length``: a share of any other length is refused (invariant 4).
- ``secret_reveals_halves``: whoever knows the combined secret knows each half, so learning it requires breaking both components (invariant 1).
- ``selected_is_mutual`` and ``never_hybrid_on_tls12``: the selected group is offered by the client, supported by the server and usable for the version (invariant 3).
- ``classical_client_unchanged``: for a client that does not offer the hybrid group, adding it to the server changes no selection (invariant 2), and ``adding_keeps_success``: a selection that succeeded still succeeds.
- ``hybrid_first_wins``: a TLS 1.3 client that lists the hybrid group first gets it from a server that supports it.
- ``component_completes``: when the server picks the hybrid's classical component, the client completes with its X25519 key.

Rationale and alternatives
--------------------------

*The aws-lc-rs provider.* It is rustls's own answer and has the hybrid groups. It is a binding to AWS-LC, a C and assembly library built by a C compiler and, on some targets, CMake and NASM. We release static builds for musl on two architectures, macOS on two and Windows with the MSVC runtime. Each would need its own build check, and the release workflow is the first place the Windows build would run. Enabling rustls's ``aws_lc_rs`` feature beside ``ring`` also stops rustls from choosing a process-wide provider by itself, which sqlx relies on for PostgreSQL TLS. We may move to aws-lc-rs later for other reasons. This record does not need it.

*rustls 0.24.* It has the combinator, but no ML-KEM for ring, and quinn 0.11, tokio-rustls 0.26 and sqlx require rustls 0.23. We copy the shape of its combinator instead.

*ML-KEM written in-house.* Sibuna writes small things itself, and its crypto crate carries Ed25519, ChaCha20-Poly1305 and Argon2. ML-KEM is larger: number-theoretic transforms, sampling, compression whose division must not depend on secrets (the "KyberSlash" timing faults of 2024), and implicit rejection in constant time. A fault there breaks the confidentiality of every session silently. We take the RustCrypto crate, which is maintained, audited in the open and tested against the published vectors, and record the reason in ``Cargo.toml``.

*Pure ML-KEM without X25519.* The groups ``MLKEM768`` and ``MLKEM1024`` exist. ML-KEM is young, and the hybrid keeps the classical guarantee should a flaw be found in it. Browsers do not offer pure ML-KEM.

*SecP256r1MLKEM768.* It serves deployments that must use NIST curves only. Browsers do not offer it, so it would cost code and tests for no peer we know. It can be added with one more ``Hybrid`` value.

*ML-DSA certificates.* ``rustls-post-quantum`` offers ML-DSA signatures with aws-lc-rs as an experiment. No public certificate authority issues ML-DSA certificates and no browser accepts them. A signature also protects only the handshake in which it is made, so it is not exposed to recording. We keep ECDSA and RSA certificates.

Security and operational considerations
---------------------------------------

The group adds no setting, port or file. The JA4 fingerprint of a client counts its groups only through the extensions, so a fingerprint does not change when Sibuna adds the group. The access log's TLS field names the version and the cipher suite. It does not name the group.

The handshake does more work on the server: one ML-KEM encapsulation besides the X25519 operation. A flood of handshakes is limited by the admission controls of the listener, as before.

Backwards compatibility
-----------------------

None is broken. Old clients do not list the group and negotiate as before. A client that sends only a hybrid share and lists X25519 as well gets the hybrid group. Servers behind pools that do not know the group answer with X25519, which our client completes with the key it already sent.

Acceptance criteria and implementation status
---------------------------------------------

.. list-table::
   :header-rows: 1
   :widths: 46 54

   * - Criterion
     - Evidence
   * - A Sibuna client and a Sibuna server negotiate X25519MLKEM768
     - Planned.
   * - OpenSSL 3.5 negotiates the group with a Sibuna listener, and a Sibuna client with ``openssl s_server``
     - Planned.
   * - A peer without the group negotiates X25519 with no ``HelloRetryRequest``
     - Planned.
   * - Wrong share lengths and invalid keys are refused; the group is not offered for TLS 1.2
     - Planned.
   * - Every TLS configuration uses ``provider()``
     - Planned.
   * - The Lean model checks
     - Planned.

Open questions
--------------

#. Should the access log name the negotiated group, so that an operator can count post-quantum sessions?

Review history
--------------

- 2026-11-26. Initial draft.

References
----------

- NIST FIPS 203, *Module-Lattice-Based Key-Encapsulation Mechanism Standard*, August 2024.
- K. Kwiatkowski, P. Kampanakis, B. Westerbaan and D. Stebila, *Post-quantum hybrid ECDHE-MLKEM Key Agreement for TLSv1.3*, ``draft-ietf-tls-ecdhe-mlkem``.
- D. Stebila, S. Fluhrer and S. Gueron, *Hybrid key exchange in TLS 1.3*, ``draft-ietf-tls-hybrid-design``.
- rustls: ``rustls/src/crypto/aws_lc_rs/pq`` (0.23), ``rustls/src/crypto/kx`` and ``rustls-ring`` (0.24.0-dev.3), ``rustls-post-quantum``.
- D. J. Bernstein et al., *KyberSlash: Exploiting secret-dependent division timings in Kyber implementations*, 2024.
- SID 0006, mathematical foundations; SID 0012, console TLS; SID 0021, automatic HTTPS; SID 0024, TLS on the workers; SID 0032, staged admission.
