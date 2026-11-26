:sid-number: 0036
:sid-title: Host Wildcards and PROXY Header Repairs
:sid-state: discussion
:sid-status: Open for Discussion
:sid-type: Architectural Specification
:sid-authors: ["Vikrant Rathore"]
:sid-created: 2026-11-26
:sid-updated: 2026-11-26
:sid-discussion: No external discussion URL assigned
:sid-summary: Lets an HTTP route name a wildcard host such as *.example.org or a list of hosts, and lets a TLS inspection rule name a wildcard server name. Refuses a route, a rule or a host that an earlier wildcard hides. Repairs three edges of the PROXY protocol: a header for a client and a listener of different address families, the probes of a pool that sends headers, and the health checks of a load balancer in front of a frontend that reads them.
:sid-labels: ["architecture","edge","routing","proxy-protocol"]

Host Wildcards and PROXY Header Repairs
=======================================

Abstract
--------

An HTTP route of the edge names one exact host, and a TLS inspection rule names one exact server name. A frontend that serves every name under a domain can only send them all to its default pool. We let a route name ``*.example.org``, which matches every name under ``example.org`` and not ``example.org`` itself, and a list of names. We let an SNI rule name a wildcard in the same way. A route, a rule or a single host of a route that an earlier one hides can never match, so the configuration refuses it when a wildcard is involved.

We also repair three edges of the PROXY protocol support of SID 0015 and SID 0020. A TCP pool with ``proxy_v2`` closed a connection whose client and listener addresses were of different families, because a version 2 header names both addresses in one family. The usual case is a dual-stack listener behind an IPv4 load balancer. The health probes of such a pool sent no header. The book did not say how the health checks of a load balancer in front of a ``proxy_protocol`` frontend get through.

Motivation and scope
--------------------

Sibuna already accepts wildcards where certificates are concerned. A certificate file may hold ``*.example.org`` and is chosen after exact names (``crates/ingress/src/certs.rs``), and ``tls.auto`` obtains a wildcard certificate over DNS-01 (SID 0021). Routing stops short of it. ``Rule::matches`` compares the request host with one name (``crates/lb/src/http.rs``), and ``Match::Sni`` compares the server name of a ClientHello with one name (``crates/lb/src/rules.rs``). A host with a ``*`` is refused as invalid. A service with a name per customer, or a group of subdomains that needs its own pool, its own firewall setting or its own policy (SID 0019), cannot be configured.

HAProxy matches hosts by suffix (``hdr_end(host)``, ``req.ssl_sni -m end``), by a domain map and by regular expression. nginx names servers by an exact name, a leading or trailing wildcard and a regular expression. Host names are dot-separated labels, and almost every rule we have seen is a suffix. We add leading wildcards and lists, and no regular expressions (see Rationale).

The PROXY repairs came out of a review of the PROXY support against AWS, Google Cloud and nginx. ``proxy::prefix`` returns nothing when the client and the listener differ in family, ``start_flow`` and the inspection path then close the connection, and the flow log calls it ``no_server``. The mismatch is reachable in three ways:

- A dual-stack listener (``[::]``) with ``proxy_protocol`` reads an IPv4 client from the header, while the local address of the socket is IPv4-mapped IPv6. This is the setup behind an IPv4 network load balancer.
- An IPv4 listener reads an IPv6 client from the header.
- A client that connects to a dual-stack listener over IPv4, without a PROXY header, has a mapped peer and a mapped local address. Its header was written in the IPv6 family with mapped addresses, which receivers log as ``::ffff:a.b.c.d``.

Sibuna's own PROXY parser keeps a mapped source as written, so a chain of two Sibuna nodes logs the mapped form too.

This record does not add a PROXY header to the connections of HTTP pools. Sibuna sends the client to HTTP servers in ``X-Forwarded-For`` and ``X-Real-IP``, as the HTTP load balancers of AWS and Google Cloud do, and a header per connection would end the sharing of server connections between clients. It does not add regular expressions, a wildcard in the last label (``www.example.*``), or wildcards on the hosts of the daemon. It does not change the two other host grammars of the edge: the managed names of automatic HTTPS (``tls.auto``) and the ``on_demand`` suffixes (SID 0021).

Specification
-------------

Invariants
~~~~~~~~~~

#. *A wildcard leaves its domain out.* ``*.example.org`` matches a host that ends in ``.example.org`` after at least one more character. It never matches ``example.org``.
#. *A label boundary.* A wildcard matches only at a dot: ``*.example.org`` does not match ``badexample.org``.
#. *First match.* Routes and SNI rules are tried in the order of the file, as before, and the first that matches decides. A wildcard does not reorder them.
#. *Nothing hidden by a wildcard.* The configuration refuses a route, a host of a route or an SNI rule that the coverage check below finds hidden by an earlier one, when a wildcard is on either side. The check is syntactic and compares one earlier route at a time.
#. *Per request.* A route is chosen for each request from its host, also for each request of a keep-alive connection and for each stream of an HTTP/2 or HTTP/3 connection. A connection that a browser shares between names under one wildcard certificate is routed by request, never by its first name.
#. *A header can always be written.* A ``proxy_v2`` pool writes a header for every connection, whatever the families of the client and the listener. An extension that cannot be written is left out of the header; the connection is not closed for it.
#. *The header keeps the addresses.* An IPv4 address, written as IPv4 or as IPv4-mapped IPv6, is written as IPv4 when the other address is IPv4 too, and as IPv4-mapped IPv6 otherwise. A receiver that maps IPv4 reads back the client and the listener. Sibuna's parser is such a receiver.
#. *Probes speak first.* A probe of a ``proxy_v2`` pool begins with a version 2 header with the ``LOCAL`` command.

Host patterns
~~~~~~~~~~~~~

A host pattern is a host name or a wildcard. A host name is as today: labels of 1 to 63 letters, digits and hyphens, no hyphen at either end, at most 253 characters, no trailing dot. An internationalised name is written in its ASCII form (``xn--``). A wildcard is ``*.`` followed by such a name, 253 characters in all with the ``*.``. Patterns are stored in lower case, also in SNI ACLs, which kept their case until now, and compared without ASCII case. The request host loses its port and a trailing dot first, as today. A server name that ends in a dot is invalid in a ClientHello and meets no rule, as today.

A wildcard is refused when:

- the ``*`` is not the whole first label (``api.*.example.org``, ``*api.example.org``, ``**.example.org``). The message suggests ``*.`` followed by the labels after the last label that holds a ``*``, when that is a valid name: "Did you mean ``*.example.org``?";
- it is ``*`` alone. The hint says that a route without ``host`` matches every host and that the default pool of a frontend takes every server name;
- its last label is all digits, which no top-level domain is (RFC 3696). A wildcard therefore never matches an IPv4 literal. An exact IPv4 host stays allowed.

``*.org`` and ``*.internal`` are allowed on purpose: a frontend may serve a private top-level domain. An empty host, the host of a request without one, and an IPv6 literal match no pattern.

The implementation keeps a wildcard as its suffix with the dot, ``.example.org``, and matches a host that is longer than the suffix and ends with it. ``matchesWild_iff`` proves that this computation is the definition. One module of the load balancer crate, ``host_pattern``, holds the grammar, the matcher and the coverage relation for routes and SNI rules.

Routes
~~~~~~

A route of an HTTP frontend gives ``host`` or ``hosts``, a ``path_prefix``, or a host and a prefix, as today.

.. code-block:: text

   routes: [
     { host: "admin.example.org", backend: "admin" },
     { hosts: ["*.example.org", "example.org"], backend: "app" },
     { host: "*.customers.example.net", path_prefix: "/api/", backend: "api" },
   ]

- ``host`` is one pattern. ``hosts`` is a list of 1 to 16 patterns. A route gives at most one of the two.
- A route matches a request when one of its patterns matches the host and its prefix covers the path.
- The policy of a request (SID 0019), its firewall setting and its WebSocket rule are those of the first matching route, so a wildcard route carries them to every name it matches.
- A request looks the routes up several times: for the firewall, for the policy, for the WebSocket rule and for the pool. With 128 routes of 16 patterns, a request that matches none compares its host with 2,048 patterns in each lookup, about 3 microseconds (see Measurement).

Two other matchers of the edge read host names and keep their own rules. Automatic HTTPS answers ACME HTTP-01 and redirects to HTTPS for a name that a managed name or a managed wildcard of one label covers (``Automatic::port_of``). It follows certificates, because the redirect is only useful where a certificate exists. The ``on_demand`` suffixes of the local authority stay suffixes. Neither is a route.

The coverage check
~~~~~~~~~~~~~~~~~~

*Patterns.* An exact name covers the same name. A wildcard ``*.s`` covers an exact name under ``s``, and a wildcard ``*.t`` where ``t`` is ``s`` or lies under ``s``. An exact name covers no wildcard.

*Hosts.* A route without ``host`` covers every pattern. A route with patterns covers a pattern when one of its patterns does.

*Prefixes.* A route without ``path_prefix`` covers every prefix and no prefix at all. A prefix ``p`` covers a prefix ``q`` when ``q``, read as a path, lies under ``p``. A prefix covers no route without prefix, also ``/``, although ``/`` matches every path that a request can carry; the check stays syntactic.

At load, each pattern of each route is compared with the routes before it. A pattern is refused, with the earlier route and pattern named, when:

- an earlier route covers it and the earlier route's prefix covers this route's prefix, and the pattern, the covering pattern or both are wildcards, or the earlier route has no ``host`` and the pattern is a wildcard; or
- another pattern of the same route covers it, and one of the two is a wildcard. Two equal patterns in one list are refused in any case.

A route whose patterns one earlier route hides all is reported once, as a route that can never match. When several earlier routes share the work, the first hidden pattern is reported, so that the hint names a move that helps:

.. code-block:: text

   frontends.web.routes[2] can never match: routes[1] (host "*.example.org") comes first and matches every request it would.
   Hint: move routes[2] above routes[1], or remove it.

   frontends.web.routes[2].hosts[0] "*.example.org" can never bring a request to this route: routes[1] (host "*.example.org") comes first.
   Hint: remove it from this route, or move the route above routes[1].

``covered_never_chosen`` and ``hidden_pattern_never_chosen`` prove that what the check refuses could never decide a request. The check costs at most 8,128 pairs of routes of 16 times 16 pattern comparisons, once per load. It finds what one earlier route hides. A route hidden only by several earlier routes together is not found (see Known gaps). Old files hold no wildcard and no ``hosts``, so the check refuses nothing that loaded before; an exact name that an earlier exact route covers still loads.

The messages carry their own hint, as ``global.sticky_entries`` does. A refused file fails with ``EDGE001`` ("invalid configuration"), which adds its general hint to run ``sibuna check``.

SNI rules
~~~~~~~~~

An ACL of a TCP frontend with ``tcp_inspect`` may give ``sni: "*.example.org"``. The ClientHello's server name is compared by the same matcher. The rules are checked as routes are, with one pattern per rule: a rule whose SNI ACL is covered by the SNI ACL of an earlier rule, where either is a wildcard, is refused. The action of either rule plays no part, since an earlier match decides whatever it does, and rules with ALPN or JA4 ACLs between them are skipped. An ACL that two rules name is covered by itself, so a wildcard ACL named twice is refused and an exact one still loads.

The family of a PROXY header
~~~~~~~~~~~~~~~~~~~~~~~~~~~~

``proxy::prefix`` writes the address block from the client and the listener address (or the address that the client reached at another node, SID 0026):

#. Each address is made canonical with ``IpAddr::to_canonical``: ``::ffff:a.b.c.d`` becomes ``a.b.c.d``.
#. When both are IPv4, the block is ``TCP over IPv4`` (``0x11``) with 12 bytes.
#. Otherwise it is ``TCP over IPv6`` (``0x21``) with 36 bytes, and an IPv4 address is written as ``::ffff:a.b.c.d``.

The ports stay. The address block can always be written. The extensions are written when they can be: the JA4 extension is left out when the fingerprint cannot be computed, and an extension that would make the header longer than its length field allows is left out. ``prefix`` then always returns a header, and the branches that closed the connection are gone. ``encode_keeps`` proves that a receiver reads back the canonical client and listener, and ``ipv4_pairs_stay_ipv4`` that an IPv4 pair is written as IPv4 in every form.

Sibuna's parser makes the source of a header canonical too, so a mapped source that another sender writes reaches the log, ``X-Forwarded-For`` and the rate limits as IPv4. The trusted-proxy checks are unchanged, since address ranges already compare mapped addresses as IPv4. Forwarded flows between nodes were canonical already.

Probes of a pool that sends headers
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

A ``health::Spec`` gains a flag, set when its pool has ``proxy_v2``. The flag is part of the key of a probe, so two pools that share a server and differ in ``proxy_v2`` probe it separately, and a server added through the admin socket gets the flag of its pool. With the flag, a probe writes 16 bytes after it connects, within the probe timeout: the version 2 signature, ``0x20`` (version 2, ``LOCAL``), ``0x00`` (no family) and a length of zero. The protocol text requires a receiver to accept ``LOCAL`` and to use the real endpoints of the connection, which is what a health check is.

A written header shows only that the kernel took the bytes. The probe then reads for at most 100 milliseconds or the rest of the timeout, whichever is shorter. An end of stream or a reset fails the probe: the receiver refused the header. Bytes from a server that speaks first, or no answer within the wait, pass it. The probes of all pools take turns on four threads, so each probe of a silent ``proxy_v2`` server adds up to 100 milliseconds to the round of its thread. A node with hundreds of such servers checks each one less often than its ``interval``, and the book says so. Before this record such a probe sent nothing, and a receiver that requires headers, such as HAProxy with ``accept-proxy``, logged a broken header for every probe. ``proxy_v2`` requires a TCP pool and HTTP probes require an HTTP pool, so only ``tcp`` probes carry the header.

A probe of a pool whose servers are Sibuna frontends with ``proxy_protocol`` is now accepted there. The header names no client, so that frontend keeps the socket peer, the probing node, and opens a flow to its own pool for each probe, which ends when the probe closes.

Load balancers in front of a PROXY frontend
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

A frontend with ``proxy_protocol: true`` closes a connection from outside ``trusted_proxies`` and a connection without a whole header in its first packet. A TCP health check of a load balancer in front passes anyway, because it judges the completed connect. An HTTP health check fails unless it is arranged for. The book gains a section with two ways:

- Point the health check at the separate listener ``observability.listen`` and its ``/ready`` route. That listener reads no PROXY header and applies no address list; its address is its access control. Readiness answers 503 from the start of a shutdown, which is what the load balancer should see. This works for every load balancer.
- Check ``/__sibuna/ready`` on the frontend with an HTTP health check that sends a header. A Google Cloud HTTP health check can send a version 1 header (``proxyHeader: PROXY_V1``). The networks of the checkers then belong in ``trusted_proxies``, for the header, and in ``internal_allow``, for the route.

AWS does not document whether the health checks of a Network Load Balancer carry the version 2 header of their target group, so the book sends them to the separate listener. The section also lists what the load balancers in front send: an AWS Network Load Balancer sends version 2 when its target group enables it, Google's TCP and SSL proxy load balancers send version 1, and Private Service Connect sends version 2. Sibuna accepts both versions and skips the extensions.

Rationale and alternatives
--------------------------

*Regular expressions.* They would need a regular expression engine, a new crate against the dependency rule of the project. An unanchored expression such as ``example\.com`` also matches ``example.com.evil.net``, and a route can turn the firewall off. What an expression adds beyond suffixes and lists, such as ``api-[0-9]+``, is rare in host names. The policy engine's ``*_regex`` fields are exact, prefix and substring patterns for the same reasons.

*A wildcard of one label, as in certificates.* RFC 6125 lets ``*.example.org`` in a certificate cover ``a.example.org`` and not ``a.b.example.org``. nginx and HAProxy's ``hdr_end`` match any depth in routing, and an operator who routes the names of customers expects ``a.b.example.org`` to follow. We match any depth and say in the book that a certificate covers one label, so ``a.b.example.org`` needs its own certificate or ``*.b.example.org``.

*Most specific first.* nginx tries exact names, then the longest leading wildcard, then the trailing one, then expressions in order. Sibuna's routes also carry path prefixes and are already ordered by the file. One rule, the first match, is easier to reason about, and the coverage check catches the order mistakes that wildcards make easy.

*Refusing every covered route.* A route that an exact route covers cannot match either, and the check could refuse it. A file with such a dead route loads today, and refusing it would stop a node from starting after an upgrade. Such a route is a mistake that wildcards make likely and exact names make rare, so we check where wildcards are involved.

*A warning instead of a refusal.* The edge has no channel for warnings of a valid file at load other than the log, which an operator may not read during ``sibuna check``. A hidden route can hide a route with the firewall on behind one with it off.

*Matching once per request.* The several lookups of one request could share one match. The measurement shows about 12 microseconds per request in the largest file the configuration allows, and a lookup of 139 nanoseconds, mostly the reservation, in a file of three routes, so we keep the lookups separate.

*Dropping a mixed-family connection on purpose.* Some receivers would see an IPv4-mapped address where they expect IPv4. HAProxy itself maps IPv4 into IPv6 when the families differ, and a forwarded connection with a mapped address is better than a closed one.

*A version 1 header for probes.* Version 1 has ``PROXY UNKNOWN``, and the pools send version 2. A receiver that requires version 2 may refuse version 1, so the probe speaks the version of the pool.

*A probe that only writes.* It would pass against a server that refuses the header, since the kernel takes the bytes before the server reads them. The short read costs at most 100 milliseconds per probe of such a pool and tells a refusal from an acceptance.

Security and operational considerations
---------------------------------------

A wildcard route matches every name under its domain, also names that nobody configured in DNS. A client can send any ``Host``. A wildcard route that turns the firewall off therefore turns it off for every such name, and the book says so. The coverage check ensures that an exact route below such a wildcard cannot be meant to keep the firewall on for one name.

The matcher reads the host of a request that the HTTP parser already bounded, and compares at most 16 patterns per route. A request with a long host costs no more than one with a short host beyond the comparison of its end.

A PROXY header of the IPv6 family is 24 bytes longer than one of the IPv4 family. Receivers that check the length against the family, as Sibuna's parser does, accept both.

A ``LOCAL`` probe header tells the server nothing about a client. A server that refuses ``LOCAL``, against the protocol text, closes the probe connection, and the probe fails; the book says to check the pool's health once after enabling ``proxy_v2``.

Backwards compatibility
-----------------------

Files that loaded before load unchanged and route the same. ``hosts`` and wildcards are new spellings that older versions refuse, so in a cluster that distributes its file (SID 0023) every node is upgraded before a file uses them; an older node keeps its revision and logs ``EDGE002``. SNI ACLs are now compared in lower case, which matched before too, since the comparison ignored case.

The headers of a ``proxy_v2`` pool change for connections accepted by the node itself; forwarded flows were canonical already. A connection that was closed for a family mismatch is now forwarded. An IPv4 client on a dual-stack listener is now written as IPv4, where it was written as an IPv4-mapped IPv6 address, and a server that logs the client logs ``192.0.2.7`` instead of ``::ffff:192.0.2.7``. A connection whose JA4 could not be computed now reaches its server without the JA4 extension.

The probes of a ``proxy_v2`` pool now write 16 bytes and wait up to 100 milliseconds. A server that accepts the protocol accepts them.

Acceptance criteria and implementation status
---------------------------------------------

.. list-table::
   :header-rows: 1
   :widths: 46 54

   * - Criterion
     - Evidence
   * - A wildcard matches names under its domain at any depth, without case, and neither the domain, a name that only ends in its text, an empty host nor an IP literal
     - ``a_wildcard_matches_names_under_its_domain_at_any_depth_and_not_the_domain`` (``crates/lb/src/host_pattern.rs``); ``wildcard_and_listed_hosts_route_every_name_under_their_domain`` (``crates/lb/tests/http.rs``).
   * - ``hosts`` matches any of its patterns; ``host`` and ``hosts`` together, an empty list, repeats and more than 16 are refused
     - ``a_host_list_refuses_repeats_and_patterns_its_wildcards_cover``; ``a_malformed_host_pattern_is_refused_with_a_hint``.
   * - A malformed wildcard is refused with a hint, and ``*api.example.org`` and ``api.*.example.org`` get "Did you mean ``*.example.org``?"
     - ``malformed_wildcards_are_refused_with_a_hint_and_a_suggestion``; ``a_malformed_host_pattern_is_refused_with_a_hint``.
   * - A route, a host of a route or an SNI rule that an earlier one hides, with a wildcard on either side, is refused with the messages above; a route that an earlier exact-name route covers still loads
     - ``a_route_or_a_host_that_an_earlier_wildcard_hides_is_refused``; ``an_sni_rule_that_an_earlier_wildcard_hides_is_refused`` (``crates/lb/tests/inspect.rs``); ``coverage_follows_the_definition``; ``hiding_needs_a_wildcard_on_one_side``.
   * - Requests of one HTTP/1.1 connection for different names under a wildcard reach the pools of their routes
     - ``wildcard_routes_choose_a_pool_for_each_request_of_one_connection`` (``cmd/sibuna/tests/edge.rs``, through the binary).
   * - A TLS inspection rule with a wildcard SNI sends matching handshakes to its pool, and others to the default
     - ``a_wildcard_server_name_routes_every_name_under_its_domain``.
   * - A dual-stack PROXY frontend that reads an IPv4 client, and an IPv4 frontend that reads an IPv6 client, forward to a ``proxy_v2`` pool; IPv4 pairs are written as IPv4; the parser makes a mapped source canonical
     - ``a_dual_stack_listener_passes_an_ipv4_client_on_as_ipv4``; ``a_client_of_the_other_family_is_passed_on_in_an_ipv6_block`` (``crates/lb/tests/proxy_frontend.rs``); ``ipv4_pairs_are_written_as_ipv4_in_every_form``; ``mixed_families_are_written_as_ipv6_with_ipv4_mapped``; ``an_extension_that_does_not_fit_is_left_out`` (``crates/lb/src/proxy.rs``); ``an_ipv4_mapped_source_is_read_as_ipv4``.
   * - A probe of a ``proxy_v2`` pool writes the ``LOCAL`` header, passes against a server that accepts it, and fails against one that closes
     - ``a_probe_of_a_proxy_pool_begins_with_a_local_header_and_passes_when_it_is_taken``; ``a_server_that_closes_after_the_header_fails_the_probe``; ``a_server_that_speaks_first_passes_and_a_plain_probe_sends_nothing``; ``pools_that_share_a_server_and_differ_in_proxy_headers_probe_it_apart`` (``crates/lb/src/health.rs``); ``a_server_added_to_a_proxy_pool_is_probed_with_a_local_header`` (``crates/lb/tests/runtime.rs``).
   * - The book explains wildcard routes and the health checks of a load balancer in front of a PROXY frontend
     - ``docs/book/operations.rst``: *HTTP routing by name and path*, *TCP inspection and PROXY v2*, *Load balancers in front*, and the HAProxy table.
   * - The Lean model checks
     - ``docs/sid/assets/host-wildcards.lean``: ``wild_not_apex``, ``wild_label_boundary``, ``matchesWild_iff``, ``under_trans``, ``covers_sound``, ``underPath_trans``, ``hostsCover_sound``, ``pathCover_sound``, ``route_covers_sound``, ``covered_never_chosen``, ``hidden_pattern_never_chosen``, ``canonical_idem``, ``canonical_v6_of_v4``, ``canonical_valid``, ``decode_asV6``, ``encode_keeps``, ``ipv4_pairs_stay_ipv4``.

Measurement
-----------

Release build, one thread of an AMD Ryzen 9 5950X (``cost_of_a_lookup_with_the_most_routes``, ``crates/lb/tests/http.rs``). The file has 128 routes of 16 patterns each, half wildcards. A request whose host matches none is looked up 100,000 times:

- One lookup compares the host with 2,048 patterns and takes 3.0 to 3.1 microseconds, the reservation of the default pool included.
- Loading the file, with the coverage check over every pair of routes, takes 3.3 to 3.4 milliseconds.
- In a file of three routes with one host each, one of them a wildcard, one lookup takes 139 nanoseconds, most of it the reservation of the pool.

A request looks the routes up for the firewall, the policy, the WebSocket rule and the pool, so a request that matches nothing in the largest file spends about 12 microseconds on routes. In files of the usual size the scan is a small part of the lookup. We keep the separate lookups.

Known gaps
----------

#. The coverage check finds what one earlier route hides. A route hidden only by several earlier routes together, or by ``path_prefix: "/"`` above a route without prefix, is not found.
#. A route that an exact earlier route covers still loads, as before.
#. A certificate wildcard covers one label and a route wildcard any depth. The book states the difference; the configuration does not check that a certificate exists for each name a route can match.
#. The probes of ``proxy_v2`` servers wait up to 100 milliseconds each on threads shared with every pool. Hundreds of such servers stretch the round of a thread beyond its ``interval``.
#. A PROXY frontend keeps only the source of a header. The header that a ``proxy_v2`` pool sends names Sibuna's listener as the destination, not the destination that the load balancer in front received.

Open questions
--------------

#. Should the access log name the route that matched, so that an operator can see which wildcard served a request?

Review history
--------------

- 2026-11-26. Review after the implementation. The length of a wildcard is now bounded with its ``*.``, and the suggestion of a malformed one is skipped when it would be refused itself. The message of a route that several earlier routes hide names the first hidden host. The cost of a probe of a silent ``proxy_v2`` server on the shared probe threads is stated, in the book too. Tests now cover separate probes for pools that share a server and the probe of a server added through the admin socket. The lookups were measured.
- 2026-11-26. Review before the implementation. The family mismatch gained its most common case, a dual-stack listener behind an IPv4 load balancer, and the parser now makes a mapped source canonical. Invariant 6 holds for the whole header: an extension that cannot be written is left out. The coverage check works on single hosts as well as routes, so a wildcard inside a list cannot hide behind an earlier route, with a second theorem. The tcp probe reads briefly after the header, because a write alone would pass against a server that refuses it, and its flag is part of the probe key. The book section separates TCP and HTTP health checks and no longer claims what AWS does not document. The grammar states case, A-labels, trailing dots, empty hosts and one-label suffixes, and the other host matchers of the edge are named. The cost of the route lookups is to be measured, not estimated.
- 2026-11-26. Initial draft.

References
----------

- W. Tarreau, *The PROXY protocol, versions 1 and 2*, ``doc/proxy-protocol.txt`` of HAProxy.
- P. Saint-Andre and J. Hodges, RFC 6125, *Representation and Verification of Domain-Based Application Service Identity within Internet Public Key Infrastructure Using X.509 (PKIX) Certificates in the Context of Transport Layer Security (TLS)*, section 6.4.3.
- J. Klensin, RFC 3696, *Application Techniques for Checking and Transformation of Names*, section 2.
- nginx, ``server_name`` directive; HAProxy configuration manual, ``hdr_end`` and ``req.ssl_sni``.
- AWS, *Network Load Balancer target group attributes*, ``proxy_protocol_v2.enabled``; Google Cloud, *Proxy Network Load Balancer overview* and the ``proxyHeader`` of target proxies and health checks.
- SID 0015, distributed edge load balancer; SID 0019, traffic policy; SID 0020, edge observability and client identity; SID 0021, automatic HTTPS; SID 0023, cluster configuration; SID 0026, peer forwarding; SID 0032, staged admission.
