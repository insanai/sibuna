:sid-number: 0021
:sid-title: Automatic HTTPS
:sid-state: discussion
:sid-status: Open for Discussion
:sid-type: Architectural Specification
:sid-authors: ["Vikrant Rathore"]
:sid-created: 2026-11-24
:sid-updated: 2026-11-24
:sid-discussion: No external discussion URL assigned
:sid-summary: Obtains and renews the certificates of an edge frontend through ACME when the operator names the hosts, answers HTTP-01 and TLS-ALPN-01 challenges in the daemon, installs each certificate for new handshakes without a reload, and redirects HTTP to HTTPS for the managed names.
:sid-labels: ["architecture","load-balancer","tls","operations"]

Automatic HTTPS
===============

Abstract
--------

We make the edge of SID 0015 obtain its own certificates. The operator names the hosts of a frontend. The daemon registers an account with an ACME certificate authority (RFC 8555), proves control of each name, stores the certificate, serves it, and renews it before it expires. No certificate file is managed by hand.

An operator observes four things. A frontend with ``tls: { auto: ["example.org"] }`` serves a trusted certificate a few seconds after the first start. A plain HTTP request for ``example.org`` is redirected to HTTPS. ``sibuna ctl SOCKET show certs`` lists each name with its issuer, its expiry and the time of its next renewal. A failure of the authority or of the network is logged with a hint and retried later, and the listener keeps serving.

Motivation and scope
--------------------

SID 0015 loads certificates from PEM files, as HAProxy does. The operator runs a separate ACME client, joins chain and key into one file, and reloads the daemon after each renewal. Caddy showed that a server can do this work itself, and that operators then stop making the mistakes of this work: an expired certificate, a renewal hook that was never tested, a key with open permissions.

The owner asked for the experience of Caddy's automatic HTTPS, expressed in the patterns of Sibuna. We took the page https://caddyserver.com/docs/automatic-https as the checklist. The section "Comparison with Caddy" states what is the same, what differs and what is missing.

This record covers the edge mode of the daemon. It adds one key to the ``tls`` object of an HTTP frontend, an optional ``acme`` object under ``global``, options of ``sibuna lb``, an ACME client crate, the two challenge answers, a certificate store on disk, and one admin command. It does not add the DNS-01 challenge, wildcard certificates, a local certificate authority for internal names, issuance on demand during a handshake, external account binding, or a second authority to fall back to.

Specification
-------------

Invariants
~~~~~~~~~~

#. Automatic HTTPS never stops a listener. Every failure after the configuration was accepted is reported, counted and retried. It is never a reason to exit.
#. A handshake and a request never wait for the certificate authority. All traffic to the authority runs on one thread of its own. The request path and the handshake read shared tables and do nothing else.
#. A certificate that is being served is replaced only by a certificate that was issued for the same name, that matches its private key, and that expires later. A failed order replaces nothing.
#. A renewal is due strictly before the certificate expires, and never before it was issued.
#. The delay after a failure grows with the number of consecutive failures and has an upper bound. Two attempts for one name are never closer than the first delay.
#. Every order ends. It sends a bounded number of requests, each with a time limit, and the whole order has a time limit.
#. Everything read from the authority has a bound: the size of a response, the length of a URL, a nonce and a token, and the number of authorizations and challenges of an order.
#. A private key is written with mode 0600 into a directory with mode 0700. It is never logged and never sent.
#. Internal names are never sent to a public authority. The configuration is rejected with a message that says what to do instead.
#. Nodes that share the storage directory hold a lock for a name while they order its certificate. One node orders. The others load the result.
#. The ACME client performs no I/O. It turns responses into requests. A test drives it without a network.

Configuration
~~~~~~~~~~~~~

The smallest useful file names the hosts and nothing else.

.. code-block:: text

   fn edge() -> Map<Value> {
       return {
           frontends: {
               web: { binds: ["0.0.0.0:443"], tls: { auto: ["example.org", "www.example.org"] } },
               plain: { binds: ["0.0.0.0:80"] },
           },
           backends: { app: { servers: ["10.0.0.1:8080", "10.0.0.2:8080"] } },
       }
   }

The frontend ``web`` terminates TLS with certificates that the daemon obtains. The frontend ``plain`` answers the HTTP-01 challenge and redirects every other request for the two names to HTTPS. Requests for other names on ``plain`` are balanced as before.

.. list-table:: The new ``tls`` key of an HTTP frontend
   :header-rows: 1
   :widths: 16 14 70

   * - Key
     - Default
     - Meaning
   * - ``auto``
     - none
     - One host name, or a list of 1 to 64 host names. The daemon obtains one certificate for each name. With ``auto`` the keys ``crt`` and ``cert_file`` become optional. A certificate from a file serves a managed name until the first automatic certificate for that name exists.

A name is written in lower or upper case and stored in lower case. It is a DNS name of at most 253 bytes. An IP address is refused. A wildcard is refused, because the two challenges of this record cannot prove a wildcard. One name may appear on several frontends. It is ordered once.

.. list-table:: The ``global.acme`` object
   :header-rows: 1
   :widths: 16 26 58

   * - Key
     - Default
     - Meaning
   * - ``directory``
     - ``"letsencrypt"``
     - The authority. ``"letsencrypt"`` is the production directory of Let's Encrypt. ``"letsencrypt-staging"`` is its staging directory, for tests. Any other value is the URL of an ACME directory, with the scheme ``https``. The scheme ``http`` is accepted for a loopback address only.
   * - ``email``
     - none
     - The contact address of the account. The authority may send expiry warnings to it.
   * - ``storage``
     - ``"/var/lib/sibuna/acme"``
     - The directory of the account key, the certificates and the locks.
   * - ``challenge``
     - ``"auto"``
     - ``"http-01"``, ``"tls-alpn-01"`` or ``"auto"``. ``"auto"`` starts with HTTP-01 when the file has a plain HTTP frontend and with TLS-ALPN-01 otherwise. After a failed attempt it tries the other type.
   * - ``ca_file``
     - the system trust store
     - A PEM file of the roots that sign the certificate of the directory server. A private authority and the tests need it.
   * - ``redirect``
     - ``true``
     - Redirect plain HTTP requests for managed names to HTTPS.

Every key has a default, and the object may be absent. ``global.acme`` without an ``auto`` name is rejected, because it would have no effect.

Using the authority means accepting its terms of service. The daemon sends ``termsOfServiceAgreed`` with the registration, as Caddy does. The book says so.

Public and internal names
~~~~~~~~~~~~~~~~~~~~~~~~~

A name is *internal* when a public authority cannot or must not validate it: ``localhost``, a name that ends in ``.localhost``, ``.local``, ``.internal``, ``.home.arpa``, ``.test``, ``.example`` or ``.invalid``, ``.lan``, and a name of one label. With ``"letsencrypt"`` or ``"letsencrypt-staging"`` an internal name in ``auto`` is rejected when the file is checked.

.. code-block:: text

   -- NAME NOT PUBLIC (EDGE001) -----------------------------------------------

   edge.jlv: tls.auto: `intranet.local` is an internal name; a public certificate authority cannot validate it.

   Hint: A public certificate authority validates a name over the Internet. Use a public DNS name, or serve this name with `crt` and a certificate of your own, or set `global.acme.directory` to an authority of your own.

The failure belongs to the file, so it carries the code ``EDGE001`` of every startup failure, with a title and a hint of its own. With a directory URL of the operator's own, every well-formed name is accepted. The operator's authority decides what it validates. Caddy issues certificates for internal names from a local authority of its own. We leave that out and say so in the message and under "Known gaps".

The quick start
~~~~~~~~~~~~~~~

.. code-block:: text

   sibuna lb --tls auto --domain example.org [--domain www.example.org]...
             --server ADDR [--server ADDR]...
             [--bind ADDR]... [--http ADDR|off]
             [--acme-directory NAME|URL] [--acme-email ADDRESS] [--acme-storage DIR]

``--tls auto`` needs at least one ``--domain``. Without ``--bind`` the TLS frontend listens on ``0.0.0.0:443``. ``--http`` names the plain frontend for the challenge and the redirect. Its default is port 80 on each address of ``--bind``, and ``off`` leaves it out. ``--print-config`` prints the module shown above. The quick start still passes through ``Config::parse`` (SID 0018).

The ACME client
~~~~~~~~~~~~~~~

The crate ``sibuna-acme`` (``crates/acme``) holds the protocol and no I/O. It depends on ``ring`` for ECDSA P-256, on ``sibuna-json``, ``sibuna-encoding`` and ``sibuna-crypto``, and on nothing of the application.

.. list-table:: Parts of ``sibuna-acme``
   :header-rows: 1
   :widths: 22 78

   * - Module
     - Contents
   * - ``key``
     - A P-256 key pair: generate, load from PKCS#8, sign for JWS and for X.509, write as PEM.
   * - ``jws``
     - The JSON Web Key, its thumbprint (RFC 7638) and the flattened JWS with ES256 (RFC 7515).
   * - ``der``
     - A DER writer and a bounded DER reader.
   * - ``csr``
     - The PKCS#10 request with a subjectAltName extension.
   * - ``x509``
     - Reading notBefore, notAfter, the issuer and the DNS names of a certificate. Writing the self-signed certificate of TLS-ALPN-01 (RFC 8737).
   * - ``order``
     - The order state machine.
   * - ``schedule``
     - The renewal time and the retry delay.
   * - ``store``
     - The layout of the storage directory, file modes and the lock.

The state machine is the algorithm of this record. The caller gives it the response to the last request, and it returns the next action.

.. code-block:: text

   Directory -> Nonce -> Account -> NewOrder -> Authorization -> Present
                                                                   |
        Done <- Download <- PollOrder <- Finalize <- PollAuthorization <- Respond

.. list-table:: Actions of the order
   :header-rows: 1
   :widths: 20 80

   * - Action
     - Meaning for the caller
   * - ``Send(request)``
     - Send this request and give the response to ``advance``.
   * - ``Present(challenge)``
     - Publish the answer to this challenge, then call ``presented``.
   * - ``Wait(seconds)``
     - The authority is still working. Call ``resume`` after this time.
   * - ``Done(issued)``
     - The certificate chain and its private key.
   * - ``Failed(error)``
     - The order ended without a certificate.

A phase moves forward only. A phase that polls stays where it is while the authority answers ``pending`` or ``processing``. An authorization that the authority already holds as valid skips from ``Authorization`` to ``Finalize``. We order one name, so an order has one authorization. Any other number is an unexpected answer. A wait that the authority asks for with ``Retry-After`` is clamped to 1 to 30 seconds. Without the header the waits are 1, 2, 4 and then 8 seconds. Every request takes one unit from a budget of 48 requests, and an order without budget fails. A response with the error ``badNonce`` is repeated with the fresh nonce and takes budget like any request. The account is registered with ``newAccount`` once in the life of the process. The authority answers with the existing account when the key is known to it.

The caller owns the clock, the sockets and the files. The driver in ``crates/ingress`` sends the requests with hyper over rustls, with a limit of 10 seconds to connect, 30 seconds for one exchange, 128 KiB for one response, and five minutes for one order.

Challenges
~~~~~~~~~~

*HTTP-01.* The authority requests ``/.well-known/acme-challenge/TOKEN`` on port 80. Every request path of the daemon passes through one dispatch function. Before the firewall decides anything, that function looks the token up in a table that the driver fills, and answers with the key authorization. The lookup is a read of a small map under a read lock. A request whose token is unknown, and whose ``Host`` is not a managed name, passes on to the routes, so a server behind the edge may still run an ACME client of its own.

The key authorization of a token is the token, a dot, and the thumbprint of the account key. Nodes that share the storage directory share the account key. A node therefore answers a well-formed token for a managed name even when another node placed the order. This makes HTTP-01 work behind a DNS name that resolves to several nodes.

*TLS-ALPN-01.* The authority opens a TLS connection to port 443 with the protocol ``acme-tls/1`` and the name under validation. The certificate resolver of the listener sees that protocol in the ClientHello and presents the self-signed certificate that carries the digest of the key authorization. The connection is closed after the handshake. No request is served on it. A listener offers ``acme-tls/1`` only when it has an ``auto`` name. This challenge needs the node that placed the order, so a name served by several nodes uses HTTP-01.

Either challenge is enough. The operator opens port 80, port 443, or both.

The challenge is answered on every HTTP frontend, with and without TLS, and before the redirect. An authority that follows a redirect from port 80 to port 443 still finds the answer. The driver removes the answer of a challenge from its table when the order ends, however it ends.

Storage and the lock
~~~~~~~~~~~~~~~~~~~~

.. code-block:: text

   /var/lib/sibuna/acme/                         mode 0700
     acme-v02.api.letsencrypt.org-directory/     one directory per authority
       account.key                               mode 0600, PKCS#8 PEM
       certs/example.org/cert.pem                the chain, leaf first
       certs/example.org/key.pem                 mode 0600
       certs/example.org/retry                   the failure count and the next attempt
       locks/example.org.lock

A file is written under a temporary name in its directory and renamed, so a reader never sees half a file. The key is written before the certificate. A reader that finds a certificate without a matching key ignores both.

Before a node orders a certificate it creates the lock file of the name with ``O_EXCL``. When the file exists, another node is at work. The node waits 15 seconds and reads the storage again. It finds the new certificate there, or it finds the lock gone. A lock older than 15 minutes is stale, because an order ends within five. A stale lock is removed and taken. The account key is written under a temporary name and linked into place only when no key is there, so two nodes that start together register one account.

The lock file names its writer: the host name, the process number, and the moment the process first took a lock. A daemon that stops in the middle of an order leaves its lock behind. The next start on the same host sees that the writer is gone and takes the lock at once. On another host, or without ``/proc``, the age of the lock decides.

A takeover with ``global.reuse_port`` runs two processes on one storage directory for a short time. They are two nodes in the sense of this section. The new process loads what the old one stored. When the old one is in the middle of an order, the new one waits for the lock and then loads the result.

At a start the daemon loads every stored certificate of its names before it orders anything. A restart therefore sends nothing to the authority while the certificates are fresh.

Renewal and retry
~~~~~~~~~~~~~~~~~

A certificate that is valid from :math:`b` to :math:`e` is renewed at :math:`b + \lfloor 2(e-b)/3 \rfloor`, that is when one third of its life remains. This is Caddy's rule. A certificate of 90 days is renewed after 60. The driver sleeps until the earliest due time, at most one hour.

After :math:`n` consecutive failures for a name the next attempt is :math:`\min(120 \cdot 2^{n-1}, 86400)` seconds later: two minutes, four, eight, and from the eleventh failure on one day. When the authority answers 429 with ``Retry-After``, the delay is the larger of the two, still at most one day. The first hour holds at most five attempts for a name, which is the limit of Let's Encrypt for failed validations. Orders run one at a time, with at least one second between two orders.

The failure count and the time of the next attempt are written to the file ``retry`` of the name. A daemon that restarts reads it and waits. Without this file a daemon in a restart loop would order at every start and exhaust the limits of the authority. A success removes the file.

While a renewal fails, the old certificate keeps serving, also after it expired. An expired certificate is the authority's and the client's matter to refuse. A listener without it would refuse everybody.

Installing a certificate
~~~~~~~~~~~~~~~~~~~~~~~~

The driver owns a table from name to certificate. The resolver of each listener holds a reference to that table and the set of its own ``auto`` names. A handshake for a managed name reads the table. Installing a certificate is one write to the table. No listener is rebuilt, and no reload happens.

A reload (SIGHUP, ``reload``, the watcher) builds new resolvers that refer to the same table. A reload may add and remove ``auto`` names. Changing ``global.acme``, and adding the first ``auto`` name to a node that had none, take a restart, like every other change of a TLS listener (SID 0015).

A managed name without a certificate of its own is treated like an unknown name. A handshake without a server name, or for an unknown name, receives the first certificate from a file, or else the certificate of the first ``auto`` name, unless ``strict_sni`` refuses it. When neither exists the handshake fails with a TLS alert. The names of a host are checked in ``sibuna-lb`` (``crates/lb/src/acme.rs``), which reads the file. The client crate takes the names as given.

The daemon places no order before its listeners serve. ``Automatic::start`` starts the thread, which loads the stored certificates. ``Automatic::allow_orders`` lets it order, and the daemon calls it after the line ``Sibuna edge listeners ready``. A daemon that fails to start has then asked the authority for nothing.

The redirect
~~~~~~~~~~~~

A request that arrives without TLS, whose ``Host`` is a managed name, and that is no challenge, is answered ``308 Permanent Redirect`` to ``https://HOST/PATH?QUERY``. The port of the TLS frontend is added when it is not 443. The redirect is decided before the firewall, as the challenge answer is. ``global.acme.redirect: false`` turns it off.

The challenge answer and the redirect are one hook at the top of the request routing (``cmd/sibuna/src/acme.rs``, called from ``route`` in ``dispatch.rs``), so every request path passes it: the thread path, the event-driven workers, and HTTP/2 and HTTP/3. Both answers are written through the writer of the request, so the access log and the counters of SID 0020 record them with their status, 200 and 308. The challenge path is not under ``/__sibuna/``, so the allow-list of the internal routes does not apply to it.

SID 0019 has a redirect of its own, the member ``redirect_https`` of a cleartext frontend or route. The two compose by three rules. First, the challenge is answered before either redirect, so a frontend with ``redirect_https: true`` does not redirect the validation request of the authority. Second, where the operator states ``redirect_https`` for the frontend or route of a request, that statement decides: ``false`` keeps the request on HTTP, and a redirect is answered by the traffic policy with its own status and port. ``RoutePolicy::keeps_http`` records the stated ``false``, which the parsed value alone cannot tell from an absent member. Third, where nothing is stated, the automatic redirect answers a managed name, and it writes its answer with the function of the traffic policy (``traffic::redirect``), so both redirects are the same bytes: status 308, ``Location``, an empty body, and a connection that closes when the request has a body. A request is therefore redirected once. With ``global.acme.redirect: false`` only the stated redirects remain.

The admin command
~~~~~~~~~~~~~~~~~

.. code-block:: text

   $ sibuna ctl /run/sibuna/edge.sock show certs
   name            issuer  expires               renews                state  error
   example.org     R11     2027-02-22T10:00:00Z  2027-01-23T10:00:00Z  ready  -
   www.example.org -       -                     2026-11-24T10:04:00Z  retry  AUTHORITY REFUSED (ACME003)

``state`` is ``ready`` with a served certificate that is not due, ``ordering`` during an order, ``waiting`` for the lock of another node, ``retry`` after a failure, and ``pending`` before the first attempt. ``renews`` is the time of the next attempt. The command changes nothing and is not logged. Without an ``auto`` name it answers with the header alone. A space in the name of an issuer is written as an underscore, so a script can split a line at spaces.

``show stats`` and the metrics routes of SID 0020 carry four series: ``sibuna_edge_acme_certificates_managed``, ``sibuna_edge_acme_certificates_served``, ``sibuna_edge_acme_failures_total``, and ``sibuna_edge_acme_nearest_expiry_seconds``, which is absent while no certificate is served.

Failures
~~~~~~~~

Every failure is a diagnostic on standard error with a code, a title, the name, what happened and a hint.

.. list-table:: Failures
   :header-rows: 1
   :widths: 12 24 64

   * - Code
     - Title
     - Cause and hint
   * - ``ACME001``
     - STORAGE NOT WRITABLE
     - The storage directory cannot be created, read or written. The hint names ``global.acme.storage`` and the user of the daemon.
   * - ``ACME002``
     - AUTHORITY UNREACHABLE
     - A connection, a TLS handshake or an exchange with the authority failed or took too long. The hint names the directory URL and ``ca_file``.
   * - ``ACME003``
     - AUTHORITY REFUSED
     - The authority answered with a problem document. The message quotes its type and detail.
   * - ``ACME004``
     - RATE LIMITED
     - The authority answered 429 or ``rateLimited``. The hint names the staging directory for tests.
   * - ``ACME005``
     - VALIDATION FAILED
     - The authority could not validate the name. The message quotes the authority's reason. The hint says to point the DNS record at this node and to open port 80 or 443.
   * - ``ACME006``
     - UNEXPECTED ANSWER
     - A response broke the protocol or a bound, or the order ran out of budget or time.
   * - ``ACME007``
     - NAME NOT PUBLIC
     - Not used. An internal name with a public authority is a failure of the file. It is reported when the file is checked, as ``NAME NOT PUBLIC (EDGE001)``.
   * - ``ACME008``
     - CERTIFICATE REJECTED
     - The issued certificate does not name the host, does not match the key, or is not valid now.

A success is one line: ``ACME000: certificate for example.org obtained, valid until 2027-02-22T10:00:00Z``. The verb is ``renewed`` for a renewal and ``loaded from storage`` after a start.

Comparison with Caddy
~~~~~~~~~~~~~~~~~~~~~

.. list-table:: The Caddy page, point by point
   :header-rows: 1
   :widths: 36 12 52

   * - Caddy
     - Here
     - Note
   * - A site named by host name gets a certificate.
     - same
     - ``tls: { auto: [...] }`` or ``sibuna lb --tls auto --domain``.
   * - HTTPS is on by default for every site.
     - differs
     - The operator writes ``auto``. A topology of SID 0015 binds addresses, not names, so a name must be stated somewhere.
   * - Certificates are renewed automatically.
     - same
     - At two thirds of the lifetime.
   * - HTTP is redirected to HTTPS.
     - same
     - 308, for managed names, when the file has a plain frontend. ``redirect: false`` turns it off.
   * - HTTP-01 and TLS-ALPN-01 are solved by the server.
     - same
     - Either is enough.
   * - With both enabled, one is picked at random and the successful one is preferred.
     - differs
     - A fixed first choice, and the other type after a failure.
   * - DNS challenge and wildcard certificates.
     - missing
     - No DNS provider interface exists.
   * - Local HTTPS: a local authority for ``localhost`` and internal names.
     - missing
     - Internal names are rejected with a hint to use ``crt``.
   * - On-demand TLS.
     - missing
     - Names come from the file.
   * - Storage on disk, reused across restarts.
     - same
     - ``global.acme.storage``.
   * - Instances that share storage coordinate.
     - same
     - A lock file per name. HTTP-01 is answered by every node.
   * - Errors are retried, with exponential backoff up to one day.
     - same
     - Caddy stops after 30 days. We continue while the name is configured.
   * - After a failure the next challenge type is tried.
     - same
     - With ``challenge: "auto"``.
   * - A second issuer (ZeroSSL) is tried.
     - missing
     - One authority.
   * - A failing Let's Encrypt order is retried against staging.
     - missing
     - We respect the limits by the backoff instead.
   * - Staging is selected for tests.
     - same
     - ``directory: "letsencrypt-staging"``.
   * - Certificate management runs in the background and does not block startup.
     - same
     - The listener is ready before the first order.
   * - A configuration change aborts running ACME transactions.
     - differs
     - A reload leaves a running order alone.
   * - Manually loaded certificates turn management off for their names.
     - differs
     - ``auto`` wins once it has a certificate. The file serves until then.
   * - Encrypted ClientHello, Tailscale names.
     - missing
     - Out of scope.

Worked example
--------------

A node has the public address 203.0.113.10. The DNS records of ``example.org`` and ``www.example.org`` point at it. The operator writes the file of the section "Configuration" and starts the daemon.

#. The listeners are ready. The driver creates ``/var/lib/sibuna/acme`` and an account key.
#. For ``example.org`` the driver takes the lock, fetches the directory and a nonce, registers the account and places the order.
#. The authority offers the challenges. The file has a plain frontend, so the driver publishes the HTTP-01 answer and tells the authority.
#. The authority requests ``http://example.org/.well-known/acme-challenge/TOKEN``. The dispatch function answers from the table.
#. The driver polls the authorization, sends the certificate request, polls the order and downloads the chain.
#. The driver checks the chain against the key and the name, writes both files, installs the certificate and removes the lock. The log has one line. The next handshake for ``example.org`` receives the certificate.
#. One second later the same happens for ``www.example.org``.
#. Sixty days later the driver wakes, takes the lock and renews.

Rationale and alternatives
--------------------------

*A crate without I/O.* An ACME client is mostly a conversation with strict rules. Rules are tested best without a network. The driver that performs the I/O is small, and the end-to-end tests cover it.

*In-house JWS, CSR and certificate code.* The house rule admits an external crate for a genuinely large problem. A flattened JWS is a few lines of JSON and one signature. A CSR with one extension is forty lines of DER. The signature itself comes from ``ring``, which the build already contains through rustls.

*One certificate per name.* One certificate with every name would take one order. One failing name would then block all names, and adding a name would reissue for all. Caddy made the same choice.

*A table behind the resolver, not a reload.* ``Ingress::reload`` installs new identities. Using it for a renewal would make the driver depend on the edge worker and would rebuild every listener for one certificate. A shared table is one write.

*Stateless HTTP-01 on every node.* Caddy stores the challenge token in the shared storage. Answering from the shared account key needs no write and no read of a file on the request path.

*No fallback to a self-signed certificate.* A browser would show a warning that looks like an attack. A failed handshake and a clear log line are more honest.

*The redirect before the firewall.* A redirect costs nothing and reveals nothing. Deciding it early keeps the challenge answer and the redirect in one place, on every request path.

Security and operational considerations
---------------------------------------

The account key signs every order. Whoever reads it can order certificates for names that point at the node, and can revoke. It has the protection of a private key file: mode 0600, directory 0700.

The answer to an HTTP-01 request reflects the token of the request. The token is limited to the base64url alphabet and to 128 bytes, and the response has the type ``text/plain`` and ``X-Content-Type-Options: nosniff``. The stateless answer contains the thumbprint of the account key, which is public information of the account.

The authority is trusted to return a certificate. We still check that the leaf names the host and matches the key that we generated. URLs in responses of the authority must have the scheme of the directory.

A TLS-ALPN-01 handshake is offered to any client. It reveals a self-signed certificate that holds a digest. It serves no request.

A handshake for an unknown name never starts an order. An attacker cannot make the node order certificates.

Backwards compatibility
-----------------------

Files without ``auto`` keep their meaning. ``sibuna lb --tls PEM`` keeps its meaning. The word ``auto`` after ``--tls`` was a file name before. A file of that name is now written ``./auto``.

Acceptance criteria and implementation status
---------------------------------------------

The record is implemented on the branch ``sid-0021-automatic-https``. The table lists the evidence.

.. list-table:: Evidence
   :header-rows: 1
   :widths: 40 60

   * - Criterion
     - Evidence
   * - JWS, thumbprint and CSR are correct.
     - ``crates/acme/src/jws.rs`` and ``csr.rs``: unit tests with the vectors of RFC 7638 and RFC 7515, and ``openssl req -verify`` on the CSR when ``openssl`` is installed.
   * - The order machine follows RFC 8555 and ends.
     - ``crates/acme/src/order/tests.rs``: 14 tests that drive the machine with scripted responses, including ``badNonce``, ``orderNotReady``, an authorization that is already valid, an invalid authorization, a rate limit, answers that break a bound and an exhausted budget. The Lean model.
   * - Renewal precedes expiry. The delay is bounded and monotone.
     - ``crates/acme/src/schedule.rs`` and the Lean model.
   * - Storage is private, atomic and shared.
     - ``crates/acme/src/store.rs``: modes, a reload of what was saved, the retry state, one holder of a lock, a stale lock, and the lock of a process that is gone.
   * - The configuration has defaults and refuses what cannot work.
     - ``crates/lb/src/acme.rs`` and ``crates/lb/src/quick.rs``; ``cmd/sibuna/src/edge/quick.rs`` for ``--tls auto``; ``cmd/sibuna/src/edge/failure.rs`` for the internal name.
   * - Only a sound chain is served, and the tables answer challenges and the redirect.
     - ``crates/ingress/src/auto.rs`` and ``auto/driver.rs``; ``cmd/sibuna/src/acme.rs`` for the ``Location`` header, the table of ``show certs`` and header injection.
   * - A certificate is obtained and served without a restart, by both challenges.
     - ``cmd/sibuna/tests/edge_acme.rs`` with the authority of ``tests/support/acme_authority.rs``. It runs the ``sibuna`` binary. The authority validates by connecting back, with HTTP-01 in the first test and TLS-ALPN-01 in the second, and rejects the first nonce.
   * - A renewal installs the new certificate.
     - The first test: a lifetime of 12 seconds, and a TLS client that sees a second certificate with no restart and no reload.
   * - A failure keeps the listener and the old certificate.
     - The first test: a reload adds a name that the authority refuses. ``show certs`` reports ``retry`` with the code, the log has the hint, and the first name keeps its certificate.
   * - The two redirects compose.
     - The third test: the authority validates with HTTP-01 over a frontend that has ``redirect_https: 301``; the managed name is redirected once with 301; a route with ``redirect_https: false`` stays on HTTP.
   * - Redirect, access log, metrics, file modes.
     - The first test: 308 with the port of the TLS frontend, another host served as before, both answers in the access log, the series in ``show stats``, keys with mode 0600.
   * - A restart reuses the stored certificate.
     - The second test: the same certificate after a restart, one order in all, the line ``loaded from storage``.
   * - The client works with a real ACME server.
     - Two runs against Pebble 2.10.3, recorded under "Interoperation with Pebble".

Known gaps
~~~~~~~~~~

#. No DNS-01 challenge and no wildcard certificate.
#. No local authority for internal names.
#. No issuance on demand.
#. One authority, no external account binding.
#. No ACME Renewal Information (RFC 9773), no revocation, no OCSP stapling for automatic certificates.
#. Keys are ECDSA P-256 only.
#. A changed ``email`` does not update an existing account.
#. The lock compares the modification time of a file with the clock of the node. Nodes whose clocks differ by more than ten minutes may order twice. Two containers with one host name and separate process tables may also order twice, because each takes the other's process for gone. A double order costs one certificate and corrupts nothing.
#. One certificate per name. A frontend with many names of one registered domain spends the weekly limit of Let's Encrypt for that domain faster than one certificate with many names would.
#. The certificate thread is not supervised. If it panics, the served certificates stay and nothing is renewed until a restart. ``show certs`` then shows a renewal time in the past.
#. A stored certificate that has expired is not served after a restart. A running daemon keeps serving the certificate it has, also past its expiry.
#. ``sibuna lb`` has no flag for ``ca_file``, ``challenge`` and ``redirect``. A private authority needs a file.
#. The answers of automatic HTTPS have the verdict ``-`` in the access log. They have no verdict word of their own.
#. With TLS-ALPN-01 and several nodes, the authority must reach the node that placed the order. Only HTTP-01 is answered by every node.
#. The translated catalogs of the book do not have the new section yet.

Formal model
~~~~~~~~~~~~

``docs/sid/assets/automatic-https.lean`` models four things with Lean 4.19.0. The order machine is a phase and a budget. An answer is good, a repetition, a skip over the challenge, or bad. We prove that a step never moves a phase backwards, that every step of a live order takes budget or ends the order, that an order of budget :math:`n` is over after :math:`n + 1` steps whatever the authority answers, and that ``Done`` is entered only from ``Download``. For the schedule we prove that the renewal time lies in :math:`[b, e)` for :math:`b < e`. For the retry delay we prove that it is at least the first delay, at most one day, and monotone in the number of failures. For the table we prove that a failed order leaves the served certificate unchanged, that a served name never loses its certificate, and that the expiry of a served certificate never decreases. The JSON, the signatures, the sockets and the files are outside the model. Tests cover them.

Interoperation with Pebble
~~~~~~~~~~~~~~~~~~~~~~~~~~

We ran the ``sibuna`` binary of this branch against Pebble 2.10.3, the test authority of Let's Encrypt, on the loopback addresses of one machine on 2026-11-24. Pebble was built in a scratch ``GOPATH`` outside the repository. Nothing left the machine and no real authority was contacted.

Pebble ran with ``PEBBLE_VA_ALWAYS_VALID=0``, so it validated every name itself, with ``PEBBLE_VA_NOSLEEP=1``, and with ``PEBBLE_WFE_NONCEREJECT=30``, so it rejected about three good nonces in ten. Its configuration listened on ``127.0.0.1:24000``, validated HTTP-01 on port 25002 and TLS-ALPN-01 on port 25001, and gave the default profile a ``validityPeriod`` of 30 seconds, which makes a renewal due after 20. The edge ran from a JLV file with ``directory: "https://localhost:24000/dir"``, ``ca_file`` set to ``test/certs/pebble.minica.pem`` of the Pebble source, an ``email``, and the names ``sibuna-a.localhost`` and ``sibuna-b.localhost``, which the resolver of the machine maps to the loopback addresses. The TLS frontend bound ``127.0.0.1:25001`` and ``[::1]:25001``.

.. list-table:: Two runs of 46 seconds each
   :header-rows: 1
   :widths: 22 39 39

   * - Observation
     - ``challenge: "http-01"``, plain frontend on port 25002
     - ``challenge: "tls-alpn-01"``, no plain frontend
   * - First certificates
     - Both names ``ready`` within 14 seconds.
     - Both names ``ready`` within 14 seconds.
   * - Served chain
     - ``openssl s_client -CAfile`` with the root of Pebble's management port: ``Verify return code: 0 (ok)`` for both names.
     - The same.
   * - Renewal
     - Each name served a new serial 30 seconds later, with no restart and no reload. The log has ``renewed`` for both.
     - The same. One name was renewed twice.
   * - Certificates issued by Pebble
     - 5
     - 5
   * - ``badNonce`` retries
     - 8 requests to the challenge, finalize and certificate endpoints for 5 certificates.
     - 5 requests to ``newAccount`` for one account, 9 to finalize for 5 certificates.
   * - Redirect
     - ``308 Permanent Redirect`` on port 25002.
     - Not applicable.
   * - Failures
     - ``sibuna_edge_acme_failures_total 0``
     - ``sibuna_edge_acme_failures_total 0``

The first attempt at this run found two defects, which the implementation review below records: an order placed by a daemon that then failed to start, and the lock file that this daemon left behind.

Open questions
--------------

#. Should a DNS provider interface be added for wildcards?
#. Should a local authority serve internal names, as in Caddy?
#. Should ``show certs`` have a command that renews a name at once?

Review history
--------------

- 2026-11-24. Initial draft: ``tls.auto`` and ``global.acme``, a client crate without I/O, both challenges, storage with a lock, renewal at two thirds, exponential retry, a table behind the resolver.
- 2026-11-24. Author's review of the design. It found six faults and changed the record for each. The retry delay lived in memory only, so a daemon in a restart loop would have ordered at every start and exhausted the limits of the authority; the failure count and the next attempt are now stored beside the certificate. The draft answered the challenge on plain frontends only; an authority that follows a redirect to port 443 would have missed it, so every HTTP frontend answers, before the redirect. The draft did not say when a challenge answer leaves the table; it now leaves when the order ends. The machine had no path for an authorization that is already valid, which Pebble and Let's Encrypt both return; it now skips to ``Finalize``, and the Lean model has that step. A ``Retry-After`` of the authority was taken as it came, so the authority could park an order; it is now clamped to 30 seconds. The number of authorizations of an order was unbounded; it is now exactly one. The review also recorded two gaps: a changed e-mail address, and the lock's dependence on the clocks of the nodes.

- 2026-11-24. Author's review of the implementation, with the tests and the Pebble run as instruments. It found seven defects and fixed each. (1) The time limit of an order was built outside the runtime of the thread, so the thread panicked at its first order; the binary test found it, and the limit is now built inside. (2) The thread ordered as soon as it started, before the listeners were bound. A daemon whose start failed for another reason had already asked the authority, so a unit that restarts every five seconds would have spent the limits of the authority; the Pebble run found it, and orders now wait for ``Automatic::allow_orders``. (3) The same daemon left its lock file, and the next start would have waited 15 minutes for it to age; the lock now names its writer, and a writer that is gone on this host loses the lock at once. (4) The record said that a managed name without a certificate fails the handshake. The code serves the default certificate as for any unknown name, which is what SID 0015 does without ``strict_sni``; the record now says so. (5) The TLS library checks a certificate it is given, and refuses the critical extension of the TLS-ALPN-01 certificate; that certificate is now handed over without the check, and a unit test covers it. (6) The diagnostic of a failure ran two sentences together when the reason of the authority had no full stop. (7) ``ACME007`` was a code of the client for a failure that only the file can have; it is now a failure of the file with a title and a hint of its own. The review also added the seven gaps that end the list above.
- 2026-11-24. Merge with ``main`` after SID 0020, the takeover of ``global.reuse_port`` and the bound on TLS connections per client. Three files conflicted, all by adjacent additions, and both sides were kept: ``crates/lb/src/config.rs`` (the ``acme`` field beside ``reuse_port`` and ``observe``), and the two index files of the records. A validation connection of TLS-ALPN-01 takes a place under the client bound like any TLS connection and gives it back when the handshake ends; it is refused only when the address of the authority already holds ``max_connections_per_ip`` connections. The record gained the sections on the access log, the metrics and the takeover.
- 2026-11-24. Second merge with ``main``, after the client certificate field, the takeover of HTTP/3 and the per-client bound on QUIC connections. Three files conflicted and both sides were kept. In ``crates/ingress/src/lib.rs`` the TLS-ALPN-01 handshake ends before the fingerprint of a client certificate is taken, and the choice between HTTP/2 and HTTP/1.1 follows as on ``main``. In ``cmd/sibuna/src/edge/http.rs`` both branches had moved the limits of the TLS front into a function ``ingress_limits``; the one of ``main`` stays, with its ``share_address``. ``Cargo.lock`` lists the dependencies of both. The QUIC listener of a frontend with ``auto`` names uses the same resolver, so HTTP/3 serves the automatic certificate too.
- 2026-11-24. Third merge with ``main``, after SID 0019. One file conflicted, ``crates/lb/src/lib.rs``, by adjacent lines: the export of ``QuickAutomatic`` and the new module ``route`` both stay. The merge also joined the two redirects as the section "The redirect" describes: ``RoutePolicy`` gained ``keeps_http`` and ``redirect_to``, ``traffic::redirect`` became visible to the crate, the automatic redirect lost its own writer, and the status 308 that this record had added to ``sibuna-http`` was dropped again. A third binary test covers a frontend with ``redirect_https: 301``, a route with ``redirect_https: false`` and a managed name together.

References
----------

- SID 0015, SID 0016, SID 0017 and SID 0018.
- Caddy, "Automatic HTTPS", https://caddyserver.com/docs/automatic-https
- RFC 8555, "Automatic Certificate Management Environment (ACME)".
- RFC 8737, "ACME TLS Application-Layer Protocol Negotiation (ALPN) Challenge Extension".
- RFC 7515, "JSON Web Signature", RFC 7518, "JSON Web Algorithms", and RFC 7638, "JSON Web Key Thumbprint".
- RFC 2986, "PKCS #10: Certification Request Syntax Specification".
- Let's Encrypt, "Rate Limits", https://letsencrypt.org/docs/rate-limits/

.. rubric:: Lifecycle event

::

   2026-11-24: prediscussion -> discussion. First draft by the author; open
   for discussion before implementation
   2026-11-24: implemented on the branch sid-0021-automatic-https; the record
   stays in discussion until the branch is reviewed and merged
