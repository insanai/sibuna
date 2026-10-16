:sid-number: XXXXX
:sid-title: Trusted JA4 Fingerprints From the Ingress
:sid-state: prediscussion
:sid-status: Working Draft
:sid-type: Architectural Specification
:sid-authors: ["Vikrant Rathore"]
:sid-created: 2026-10-16
:sid-updated: 2026-10-16
:sid-discussion: No external discussion URL assigned
:sid-summary: Sibuna reads a JA4 TLS fingerprint that a trusted ingress computes and forwards in a request header, validates it, and lets policy rules, incidents and the console use it; it never terminates TLS itself.
:sid-labels: ["security","bots","policy"]

Trusted JA4 Fingerprints From the Ingress
=========================================

Abstract
--------

A JA4 fingerprint summarises how a client opens a TLS connection: protocol, version, cipher suites, extensions and the first ALPN value. Browsers, libraries and bots differ in it, and a client cannot change it from inside its HTTP requests, which makes it one of the strongest signals for telling automation from browsers. Sibuna runs behind a TLS ingress and never sees the TLS handshake, so it cannot compute JA4 itself. We let an ingress that does compute it forward the value in a request header. Sibuna reads that header only from a trusted forwarder, checks its format, and makes the fingerprint available to policy rules, incident records and the console. An operator observes a new option, ``--ja4-header``, a new rule field, ``ja4``, and the fingerprint beside each recorded incident.

Motivation and scope
--------------------

Hosted edges use JA4 for bot management: Cloudflare exposes JA3 and JA4 to Enterprise customers with Bot Management and can send ``cf-ja4`` to the origin. Sibuna's User-Agent and header signatures are easy to forge; a TLS fingerprint is not, because it is fixed by the client's TLS library before any HTTP byte is sent.

Computing JA4 requires the ClientHello, so the component that terminates TLS must compute it. We considered making Sibuna that component and rejected it (see Rationale): the front door that browsers reach must speak HTTP/2 and HTTP/3, which Sibuna does not. Several ingresses already compute JA4 and pass it on:

- Cloudflare: the managed transform "Add bot protection headers" sends ``cf-ja4`` (Enterprise plan with Bot Management).
- Apache Traffic Server: the ``ja4_fingerprint`` plugin adds a ``ja4`` request header.
- nginx: the ``ja4-nginx-module`` of FoxIO exposes ``$http_ssl_ja4`` (it needs a ClientHello capture patch, nginx 1.26 or later); ``proxy_set_header X-JA4 $http_ssl_ja4;`` forwards it.
- HAProxy: a community Lua plugin.

No official Caddy or Envoy support was found when this record was written. This record covers JA4 only; JA4H (HTTP), JA4T (TCP) and the other JA4+ fingerprints are out of scope.

Specification
-------------

- **Option.** ``--ja4-header <name>`` names the request header that carries the fingerprint (for example ``cf-ja4``, ``ja4`` or ``x-ja4``). It is off by default. The name must be a valid header token of at most 64 bytes, must not be a field Sibuna itself sets (``X-Forwarded-*``, ``X-Real-IP``, ``X-Sibuna-*``), and is matched case-insensitively.
- **Trust.** The header is read only when the request's forwarded headers are trusted, by the same decision that governs ``X-Forwarded-For`` (``--trust-forwarded``, ``--trusted-hops``, and forward-auth mode; SID 0002). From an untrusted peer the header is ignored. In reverse-proxy mode Sibuna removes the configured header from the request it sends to the origin when the header was not trusted, so a client cannot hand the origin a forged value under Sibuna's name; a trusted value is passed on unchanged.
- **Validation.** A value is accepted only if it has the JA4 form ``a_b_c``: ``a`` is ten characters (one of ``t``, ``q`` or ``d``; a two-character version; ``d`` or ``i``; a two-digit cipher count; a two-digit extension count; a two-character ALPN code of ASCII letters and digits), and ``b`` and ``c`` are twelve lowercase hexadecimal characters each. Anything else, including a repeated header, is treated as absent and counted in ``sibuna_ja4_invalid_total``. Accepted values are counted in ``sibuna_ja4_present_total``.
- **Policy.** A rule may carry ``"ja4": "<value>"`` (exact match) or ``"ja4": "<prefix>*"`` (prefix match; for example ``"t13d*"`` for TLS 1.3 over TCP with SNI). A request without a fingerprint never matches a ``ja4`` rule. The loader refuses a pattern that cannot match a valid JA4 value. Matching is a byte comparison on the request path and allocates nothing.
- **Records.** A recorded incident stores the fingerprint when one was accepted (a nullable text column of at most 36 bytes in ``security_incidents`` on both backends, SID 0011). The console shows it in the incident evidence, where SID 0007 shows "JA4 fingerprint: Not recorded" today, and the Events filters accept it.
- **No reputation keyed by JA4.** Bans and reputation stay keyed by address. A JA4 value names a client library, which many legitimate clients share, so banning by it would be too broad; rules decide what to do with it.

Rationale and alternatives
--------------------------

- **Native TLS termination in Sibuna** (with rustls, which the console already admits, SID 0012) would let Sibuna compute JA4 itself, but it would make Sibuna the front door. Browsers there negotiate HTTP/2 and HTTP/3; a front door that offers only HTTP/1.1 costs asset-heavy sites their multiplexing. Rejected.
- **HTTP/2 in Sibuna** would remove that objection but adds a binary protocol with a record of severe denial-of-service and inspection-bypass bugs (Rapid Reset, CVE-2023-44487; CONTINUATION floods; HTTP/2 to HTTP/1.1 downgrade smuggling; CVE-2026-13763, where a WAF behind a load balancer inspected only part of a body split across HTTP/2 frames). The established deployments, including AWS WAF behind CloudFront or a load balancer and Coraza inside Envoy or Caddy, keep HTTP/2 in the terminating proxy and inspect the decoded request. Rejected.
- **Reading the ClientHello in a TCP pass-through in front of the ingress** would need a way to attach the fingerprint to the decrypted requests downstream (for example PROXY protocol extensions the ingress forwards as headers), which common ingresses do not offer. Rejected.

Security and operational considerations
---------------------------------------

The fingerprint is only as trustworthy as the trust boundary: the configured header is honoured only from forwarders Sibuna already trusts, and an operator who enables ``--ja4-header`` must make the ingress overwrite any client-supplied copy of that header. A JA4 value identifies a TLS library and configuration, not a person or a device; it is stored with incidents under the same retention as the other incident fields. Clients can imitate a browser's ClientHello with specialised libraries, so JA4 raises the cost of automation rather than proving identity, and rules should combine it with other signals.

Backwards compatibility
-----------------------

The option is off by default, so behaviour does not change until an operator sets it. The incident table gains one nullable column; databases created before this change are migrated by adding it.

Acceptance criteria and implementation status
---------------------------------------------

1. With ``--ja4-header`` set and forwarding trusted, a ``ja4`` rule matches a request whose header carries a valid fingerprint, exactly and by prefix.
2. The same header from an untrusted peer is ignored and, in reverse-proxy mode, removed from the request sent to the origin.
3. Malformed and repeated values are ignored and counted.
4. Incidents record the fingerprint on SQLite and PostgreSQL, and the console shows and filters it.
5. A warm request still makes no heap allocation (``cmd/sibuna/tests/steady_state.rs``).
6. The book gives recipes for Cloudflare, nginx and Apache Traffic Server.

Status: draft for review; planned for the release after 1.0.0-beta.1.

Open questions
--------------

- Should the forwarded header name default to ``cf-ja4`` when the operator writes ``--ja4-header`` without a value, or always be explicit (proposed: explicit)?
- Should a rule be able to match a set of fingerprints from a file (an allow list of known clients), or is one value or prefix per rule enough for a first version (proposed: one per rule)?

Review history
--------------

- 2026-10-16: drafted for the maintainer's review after deciding not to terminate TLS or HTTP/2 in Sibuna.

References
----------

- FoxIO, JA4+ network fingerprinting: https://github.com/FoxIO-LLC/ja4
- FoxIO, ja4-nginx-module: https://github.com/FoxIO-LLC/ja4-nginx-module
- Cloudflare, JA3/JA4 fingerprint: https://developers.cloudflare.com/bots/additional-configurations/ja3-ja4-fingerprint/
- Cloudflare, managed transforms: https://developers.cloudflare.com/rules/transform/managed-transforms/reference/
- Apache Traffic Server, JA4 fingerprint plugin: https://docs.trafficserver.apache.org/admin-guide/plugins/ja4_fingerprint.en.html
- CVE-2023-44487 (HTTP/2 Rapid Reset); CVE-2026-13763 (AWS ALB with WAF, HTTP/2 body inspection)
- SID 0002 (forwarded identity), SID 0003 (policy schema), SID 0007 (console evidence), SID 0011 (storage), SID 0012 (rustls)
