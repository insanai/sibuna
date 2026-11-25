:sid-number: 0021
:sid-title: Automatic HTTPS
:sid-state: discussion
:sid-status: Open for Discussion
:sid-type: Architectural Specification
:sid-authors: ["Vikrant Rathore"]
:sid-created: 2026-11-24
:sid-updated: 2026-11-25
:sid-discussion: No external discussion URL assigned
:sid-summary: Obtains and renews the certificates of an edge frontend through ACME when the operator names the hosts, answers HTTP-01, TLS-ALPN-01 and DNS-01 challenges in the daemon, issues for internal names and IP addresses from a local authority, installs each certificate for new handshakes without a reload, and redirects HTTP to HTTPS for the managed names.
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
     - same
     - ``auto: ["*.example.org"]`` with ``global.acme.dns``. Caddy needs a build with a provider module. We run a hook program or send an RFC 2136 update, and have no vendor module.
   * - The DNS challenge checks propagation, with a timeout, a delay, resolvers and an override domain.
     - differs
     - ``check``, ``timeout``, ``wait``, ``resolver`` and ``servers``. We follow a CNAME delegation in the check. We have no ``dns_challenge_override_domain``: the provider receives the name of the challenge.
   * - Local HTTPS: a local authority for ``localhost``, internal names and IP addresses, chosen by the name.
     - same
     - ``auto: ["localhost"]`` needs no other setting. A root of 10 years, an intermediate of 7 days and leaves of 12 hours, as in Caddy.
   * - ``tls internal`` forces the local authority.
     - same
     - ``tls: { auto: [...], issuer: "internal" }``.
   * - The root is installed into the system trust store at the first start, and ``caddy trust`` and ``caddy untrust`` do it by hand.
     - differs
     - We never touch a trust store. ``sibuna ctl SOCKET show ca`` prints the root, and the book shows the command of each system.
   * - The local authority is an ACME server for other machines (``acme_server``).
     - missing
     - The local authority issues for this daemon only.
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

DNS-01, wildcards and the local authority
-----------------------------------------

This section extends the record. It closes the first two known gaps of the first part: a wildcard name, which needs the DNS-01 challenge, and an internal name, which no public authority validates.

The issuer of a name
~~~~~~~~~~~~~~~~~~~~

Every ``auto`` name has one issuer. The daemon chooses it from the name, as Caddy does.

.. code-block:: text

   name under auto          tls.issuer absent          "acme"                  "internal"
   -----------------------  -------------------------  ----------------------  ---------------
   public DNS name          ACME authority             ACME authority          local authority
   internal DNS name        local authority  [1]       ACME, or refused  [2]   local authority
   IP address               local authority            refused                 local authority

   [1] With a directory of the operator's own, an internal name goes to that directory,
       as in the first part. The operator's authority decides what it validates.
   [2] Refused with a public directory (Let's Encrypt). Accepted with the operator's own.

``tls.issuer`` is a member of the ``tls`` object beside ``auto``. Absent, the table's first column applies, and this is the form we teach: ``tls: { auto: ["localhost"] }`` works with no other setting. ``"internal"`` forces the local authority for every name of the frontend, also for a public-looking one. ``"acme"`` forces the ACME authority. An internal name with ``"acme"`` and a public directory is refused when the file is checked, with the title ``NAME NOT PUBLIC`` and a hint that names ``issuer: "internal"``. An IP address with ``"acme"`` is refused in the same way. One name on two frontends must have one issuer.

An internal name is defined as in the first part. An IP address is internal whatever its range: Let's Encrypt issues for no IP address through this client, and a certificate for a public address from the local authority is still useful to clients that trust it.

Wildcards
~~~~~~~~~

``auto`` accepts ``*.example.org``: one label ``*`` followed by a DNS name. The certificate serves ``a.example.org``. It does not serve ``a.b.example.org`` and it does not serve ``example.org``. An exact ``auto`` name wins over a wildcard, and a wildcard ``auto`` name wins over a certificate from a file, once its certificate exists. The redirect and the HTTP-01 answer treat a host that a wildcard covers as a managed name.

One certificate still has one name. ``example.org`` and ``*.example.org`` are two orders. Both use the record ``_acme-challenge.example.org`` when both use DNS-01. Orders run one at a time, each presents its own value and removes only that value, so the two never need two values at once. We keep this and say so, instead of ordering both names in one certificate.

A wildcard that goes to an ACME authority needs DNS-01, so it needs ``global.acme.dns``. Without it the file is refused with the title ``WILDCARD NEEDS DNS`` and a hint that shows the two providers. A wildcard for the local authority needs nothing.

The DNS-01 challenge
~~~~~~~~~~~~~~~~~~~~

The authority looks up the TXT record ``_acme-challenge.NAME``, where NAME is the name without ``*.``. Its value is the base64url SHA-256 digest of the key authorization (RFC 8555, section 8.4). We write the record through a *provider*, wait until the authoritative servers show it, tell the authority, and remove the record when the order ends.

.. code-block:: text

   Present(dns-01)
     |  write "presented" file  (owner, value)        so a crash can be cleaned up
     |  provider present owner value
     |  wait `wait` seconds
     |  check: every authoritative server shows the value   (at most `timeout` seconds)
     v
   Respond ... order ends, with or without a certificate
     |  provider cleanup owner value
     |  remove "presented" file

``global.acme.challenge`` gains the value ``"dns-01"``. It then applies to every ACME name, also to names without a wildcard. This serves hosts with no open port 80 or 443. With ``"auto"``, a wildcard uses DNS-01 and every other name uses HTTP-01 or TLS-ALPN-01 as before. With ``"http-01"`` or ``"tls-alpn-01"`` a wildcard still uses DNS-01, because nothing else can prove it.

.. list-table:: The ``global.acme.dns`` object
   :header-rows: 1
   :widths: 18 18 64

   * - Key
     - Default
     - Meaning
   * - ``hook``
     - none
     - The path of a program that writes and removes the record. One of ``hook`` and ``rfc2136`` is required.
   * - ``rfc2136``
     - none
     - An object: ``server`` (``"IP:PORT"``, required), ``key_name`` and ``key_file`` (the TSIG key, both or neither), ``zone`` (the zone to update; found from the SOA record when absent).
   * - ``check``
     - ``true``
     - Wait until every authoritative server of the zone shows the record. ``false`` skips the check, for a zone whose public servers we cannot reach (split horizon).
   * - ``timeout``
     - ``120``
     - The longest wait for the check, in seconds, from 1 to 3600.
   * - ``wait``
     - ``0``
     - Seconds to wait after the provider returned and before the check, from 0 to 3600. With ``check: false`` this is the whole wait.
   * - ``resolver``
     - the first ``nameserver`` of ``/etc/resolv.conf``
     - ``"IP:PORT"`` of the recursive resolver that finds the zone and its servers.
   * - ``servers``
     - the servers of the NS records
     - A list of 1 to 8 ``"IP:PORT"``: the authoritative servers to ask, in place of the search. This serves a hidden primary, a split horizon with a reachable inner server, and a test.

The smallest forms are these.

.. code-block:: text

   global: { acme: { dns: { hook: "/etc/sibuna/dns-hook" } } },
   global: { acme: { dns: { rfc2136: { server: "192.0.2.53:53", key_name: "sibuna.", key_file: "/etc/sibuna/tsig.key" } } } },

**The hook program.** We run the program directly, with no shell, as ``HOOK present RECORD VALUE`` and ``HOOK cleanup RECORD VALUE``. RECORD is the owner of the record with a final dot, for example ``_acme-challenge.example.org.``, and VALUE is the text of the TXT record. These are the arguments of the ``exec`` provider of lego in its default mode, so an existing script for it works unchanged, and a wrapper of three lines adapts a hook of acme.sh or certbot. The same three values are in the environment as ``SIBUNA_ACME_ACTION``, ``SIBUNA_ACME_RECORD`` and ``SIBUNA_ACME_VALUE``, with ``SIBUNA_ACME_NAME`` for the ``auto`` name. The program inherits the environment of the daemon, which is where it finds its credentials. Standard input is closed. Exit status 0 means done. Any other status, or a signal, fails the attempt. We wait at most 60 seconds and then kill the program. We keep the last 1024 bytes that it wrote to standard output and the last 1024 bytes that it wrote to standard error, and show them, made printable, in the diagnostic. We stop the program itself. A child that the program started may live on, and we do not wait for its output. The value of a TXT record is public, so nothing secret reaches the log through us. What the script prints is the operator's own.

**RFC 2136.** We send a dynamic update to ``server``: add one TXT record with a TTL of 60 seconds, or delete exactly that record. A delete names the record data, so the value of another order stays. With a TSIG key the update is signed with HMAC-SHA256 (RFC 8945) and the MAC of the answer is checked. ``key_file`` holds the secret in base64 on one line. The secret is never in the topology. Without a key the update is sent unsigned, for a server that trusts our address. The update goes over UDP, and over TCP when the answer is truncated or the message exceeds 1232 bytes. Each try waits 5 seconds, and we try three times. This covers BIND, Knot, PowerDNS and the hosted services that speak RFC 2136, without one vendor interface.

We add no built-in provider for a vendor's HTTP interface. Each one is a format of its own, with its own failures, and the hook reaches all of them on the first day. A vendor provider can be added later behind the same two operations without changing this record's shape.

**The check.** A recursive resolver answers from its cache and from one server. The authority asks the authoritative servers. So we ask them too.

#. Follow CNAME records from ``_acme-challenge.NAME``, at most 8, through the resolver. The last owner is where the record must be. This is the delegation of validation to another zone. The provider is still called with the first owner, the one in the challenge: a hook that follows the delegation itself must resolve it itself, and with ``rfc2136`` we set ``zone`` and write into the delegated zone only when the first owner lies in it. We say so under the gaps.
#. Find the zone: ask the resolver for the SOA record of the owner, then of each parent, until one answers with a SOA record for the asked name.
#. Ask the resolver for the NS records of the zone and for the addresses of each server. We use at most 8 servers and 4 addresses of each.
#. Ask each address for the TXT record, without recursion, over UDP and over TCP when truncated.
#. The record is visible when every server that answers shows the value, and at least one answers.
#. Repeat every 2 seconds until ``timeout``.

When the time is over, the attempt fails with ``ACME010`` and the usual retry delay. The diagnostic names the servers that did not show the value.

Every DNS message we read is bounded: at most 65535 bytes over TCP and 4096 over UDP, at most 64 records read from a message, at most 16 compression pointers followed in a name, names of at most 255 bytes. A message that breaks a bound or the format is an answer we did not get. Nothing in a message can make the daemon panic or loop. The identifier and the question of an answer must be those of our query.

**Cleanup.** Before the provider is called, the daemon writes the file ``certs/NAME/dns`` with the owner and the value. It removes the file after ``cleanup`` succeeded. When an order ends, with or without a certificate, cleanup runs. When the daemon starts and finds the file, it runs cleanup first: the process died in between. A cleanup that fails is reported with ``ACME009`` and does not fail the order, and the file stays, so the next attempt for the name cleans up again.

.. list-table:: New failures
   :header-rows: 1
   :widths: 12 24 64

   * - Code
     - Title
     - Cause and hint
   * - ``ACME009``
     - DNS PROVIDER FAILED
     - The hook exited with a status other than 0 or ran too long, or the server refused the update. The message has the status, or the response code, and the end of the output. The hint says to run the hook by hand with the same arguments, or to check the TSIG key and the update policy of the zone.
   * - ``ACME010``
     - RECORD NOT VISIBLE
     - The authoritative servers did not all show the record in time. The hint says to raise ``timeout``, or to set ``check: false`` when the public servers of the zone cannot be reached from this node.
   * - ``ACME011``
     - LOCAL AUTHORITY FAILED
     - The root or the intermediate of the local authority could not be created, read or used. The hint names the storage directory.

The local authority
~~~~~~~~~~~~~~~~~~~

The local authority is a certificate authority that the daemon creates and keeps in its storage directory. It has a root and an intermediate, as Caddy's internal issuer has.

.. code-block:: text

   STORAGE/local/
     root.pem            the root certificate and its key, mode 0600, valid 10 years
     root.crt            the root certificate alone, the file to install in clients
     intermediate.pem    the intermediate and its key, mode 0600, valid 7 days
     certs/NAME/...      leaves, as for an ACME authority
     locks/NAME.lock

.. list-table:: The certificates of the local authority
   :header-rows: 1
   :widths: 16 16 68

   * - Certificate
     - Lifetime
     - Contents
   * - Root
     - 10 years
     - ``Sibuna Local Authority - Root``. basicConstraints CA with path length 1, critical. keyUsage keyCertSign and cRLSign, critical. Subject key identifier.
   * - Intermediate
     - 7 days
     - ``Sibuna Local Authority - Intermediate``. basicConstraints CA with path length 0, critical. keyUsage as the root. Subject and authority key identifiers.
   * - Leaf
     - 12 hours
     - The name as common name. subjectAltName with dNSName or iPAddress entries. keyUsage digitalSignature, critical. extendedKeyUsage serverAuth. Authority key identifier. The served chain is the leaf and the intermediate.

Keys are ECDSA P-256. A serial number is 8 bytes from the random source of the system. A validity starts one minute before the time of issue, for clients whose clock is a little behind. A leaf with a lifetime under two minutes starts half its lifetime early instead, so that its renewal time lies ahead. A leaf never outlives the intermediate that signed it.

The root is created once, under a temporary name, and linked into place only when no root is there. Two nodes that start together on shared storage therefore end with one root, as with the account key. The intermediate is replaced when two thirds of its life have passed, or when it would end before a new leaf. A replacement is one rename. A leaf carries the intermediate that signed it, so a leaf of the old intermediate stays valid.

Leaves are issued and renewed by the same thread, with the same schedule, lock and retry as ACME certificates: renewal at two thirds of the lifetime, which is every 8 hours, and an install with no reload. Issuing needs no network. ``global.acme.internal: { lifetime: SECONDS }`` changes the lifetime of a leaf, from 10 seconds to 2 days. The default is 43200.

We add no name constraints to the root. A constraint to the configured names would have to change with every reload, and clients differ in how they treat constraints on a root. The cost is stated under Security: whoever reads ``root.pem`` can issue for any name to the clients that trust this root.

**IP addresses.** ``auto`` accepts an IPv4 or IPv6 address. A client that connects to an address sends no server name. A handshake without a server name therefore receives, in this order: the certificate of the first IP address under ``auto`` of the listener, the first certificate from a file, the certificate of the first ``auto`` name. A leaf for an IP address lists every IP address that the daemon manages, so one listener with several addresses serves all of them without a server name. When a reload adds an address, the leaves of the addresses are issued again at once.

**Trust.** A client trusts a leaf when the root is in its trust store. The daemon never touches a trust store. ``sibuna ctl SOCKET show ca`` prints the path of ``root.crt``, the validity and the PEM text. The book shows how to install the file on Linux, macOS and Windows, and how to pass it to curl. We leave automatic installation out: it needs the rights of an administrator, differs per system, and must never happen silently.

**Security.** ``root.pem`` and ``intermediate.pem`` have mode 0600 in a directory of mode 0700. A reader of the root key can impersonate any site to every client that installed the root. The root is therefore for machines we control, which is the purpose of an internal name. A node that needs no internal name creates no authority: the files appear with the first internal name.

``show certs`` gains the column ``via``: ``http-01``, ``tls-alpn-01``, ``dns-01`` or ``local``. The issuer column shows the issuer of the served certificate, which is the intermediate of the local authority or that of the ACME authority.

The quick start gains ``--acme-dns-hook PROGRAM``. ``sibuna lb --tls auto --domain localhost --server ADDR`` needs no flag: the name is internal. The RFC 2136 provider needs a file.

On demand, more authorities, stapling and the closed gaps
---------------------------------------------------------

This part closes gaps of the first two parts. It adds issuance on demand, a list of authorities with external account binding and renewal information, OCSP stapling, a Cloudflare provider, and changes to the local authority, the hook, the update, the keys and the thread.

.. list-table:: The new keys
   :header-rows: 1
   :widths: 30 16 54

   * - Key
     - Default
     - Meaning
   * - ``tls.on_demand``
     - ``false``
     - The frontend obtains a certificate at the first handshake for a name that it does not serve yet. It needs ``global.acme.on_demand`` with a guard.
   * - ``global.acme.on_demand.ask``
     - none
     - An ``http`` or ``https`` URL. We send ``GET URL?domain=NAME``. A status from 200 to 299 allows the name.
   * - ``global.acme.on_demand.allow``
     - none
     - One to 64 suffixes. ``example.org`` allows that name and every name below it.
   * - ``global.acme.on_demand.rate``
     - 10
     - New certificates per hour, 1 to 1000.
   * - ``global.acme.on_demand.names``
     - 100
     - The most names held at once, 1 to 10000.
   * - ``global.acme.on_demand.wait``
     - 20
     - The longest wait of a handshake in seconds, 1 to 120.
   * - ``global.acme.eab``
     - none
     - ``{ kid, key_file }``: the external account binding of the first authority. The file holds the base64url key.
   * - ``global.acme.fallback``
     - none
     - One to three more authorities, each ``{ directory, email, ca_file, eab }``.
   * - ``global.acme.ari``
     - ``true``
     - Ask the authority when to renew (RFC 9773).
   * - ``global.acme.ocsp``
     - ``true``
     - Staple an OCSP response when the certificate names a responder.
   * - ``global.acme.key``
     - ``"p256"``
     - The key of new certificates: ``"p256"`` or ``"p384"``.
   * - ``global.acme.dns.cloudflare``
     - none
     - ``{ token_file, zone }``: the third provider. ``zone`` is optional.
   * - ``global.acme.dns.follow_cname``
     - ``true``
     - Write the record at the target of a CNAME delegation.
   * - ``global.acme.dns.rfc2136.unsigned``
     - ``false``
     - Allow an update without a TSIG key to a server that is not on a loopback address.
   * - ``global.acme.internal.constraints``
     - none
     - Name suffixes and address ranges that the root of the local authority may issue for.

Issuance on demand
~~~~~~~~~~~~~~~~~~

A frontend with ``on_demand: true`` may have an empty ``auto`` list. A handshake that names a host for which the frontend has no certificate, neither automatic nor from a file, asks for one and waits.

::

   handshake (edge-tls)                      thread edge-acme
   --------------------                      ----------------
   read ClientHello, name N
   N served already?  -- yes --> continue
   N admissible?      -- no  --> continue (default certificate or alert)
   request(N), wait at most `wait`  ----->   stored certificate? load it
                                             ask(N)?  no: deny N for 60 s
                                             token?   no: deny N until one is back
                                             order or issue, install
   woken or timed out  <-----------------    wake the waiters
   continue with the usual choice

The daemon refuses a file that turns ``on_demand`` on without ``ask`` and without ``allow``. This is the refusal by default: without a guard, anybody who can reach the listener could make us order certificates for any name that points at us, and spend the limits of the authority.

The handshake applies the cheap guards itself, and never talks to a network. The name is admissible when it is a host name of at most 253 bytes, not an address and not a wildcard, when a suffix of ``allow`` covers it if the list exists, when it is not denied at the moment, and when the table of held names and the queue have room. The queue holds at most 64 names. A name that is not admissible is not queued. The handshake continues at once with the choice of SID 0015: the default certificate, or the alert under ``strict_sni``.

The thread applies the guards that cost time. It first looks into the storage: a certificate that an earlier run or another node obtained is loaded and costs nothing. Else it asks the ``ask`` URL, with a limit of 5 seconds and one try. A failure to ask denies the name. Then it takes a token. The bucket holds ``rate`` tokens and gains one every :math:`3600 / rate` seconds. An empty bucket denies the name until the next token. Only then it orders, with the issuer that the name and ``tls.issuer`` select, as for a listed name. A denied name is remembered for 60 seconds, in a table of at most 1024 names, so a flood of handshakes for one name asks once.

A held name is a managed name: it has a line in ``show certs``, with ``on-demand`` in a new column ``origin``, and it is renewed in the background. When its renewal is due and no handshake named it since the certificate was obtained, it is released instead: the name leaves the table and the certificate stays in the storage until it expires. So the table holds names that clients use, and its bound ``names`` is a bound on the renewals too. A name that fails is released after its first failure and denied for the retry delay of that failure count.

The wait is bounded by ``wait`` and by the handshake deadline of the listener. A handshake that times out continues with the usual choice. The order goes on, and a later handshake finds the certificate. One order runs at a time, as before, so a burst of new names is served in sequence and some handshakes time out. QUIC handshakes do not wait: the QUIC library asks the resolver without a place to wait. They use the certificate once a TCP handshake has obtained it.

Authorities, the binding and renewal information
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The keys ``directory``, ``email``, ``ca_file`` and ``eab`` describe the first authority. ``fallback`` lists up to three more. One attempt for a name asks the authorities in order and stops at the first certificate. Each failure is logged with the authority. The attempt fails when all fail, and the retry delay then counts one failure. Each authority has its own account and its own directory in the storage. The lock, the retry state and the DNS record of a name live in the directory of the first authority, so two nodes never order one name at two authorities at once. A stored certificate of any listed authority is served; the one that expires last wins. A name is public for the choice of the issuer when any listed authority is one of the public directories.

With ``eab`` the registration carries ``externalAccountBinding`` (RFC 8555, section 7.3.4): a JWS with ``alg`` HS256, the ``kid`` of the binding and the URL of ``newAccount`` in its header, the account key as its payload, and an HMAC-SHA256 with the decoded key. A directory whose ``meta`` says ``externalAccountRequired`` and that has no ``eab`` fails with a hint before any request is signed.

With ``ari`` the thread asks the ``renewalInfo`` URL of the directory for each served certificate of that authority. The identifier is the base64url of the authority key identifier, a dot, and the base64url of the serial (RFC 9773, section 4.1). The answer has a window. We pick the time :math:`s + (h \bmod (e - s))` in the window :math:`[s, e)`, where :math:`h` is a hash of the serial. The pick is therefore the same after a restart and on every node. The renewal time is the pick, and never later than four fifths of the lifetime: an authority cannot park a certificate until it expires. A window in the past renews at once. We ask again after the ``Retry-After`` of the answer, clamped to between one hour and one day, six hours without it. A failure to ask keeps the last answer, or the rule of two thirds. An order that replaces a certificate names it in ``replaces``.

OCSP stapling
~~~~~~~~~~~~~

When the leaf names an OCSP responder with an ``http`` URL in its authority information access, the thread asks it after the certificate is installed. The request is a POST of an OCSP request with one SHA-1 certificate identifier and no nonce. The response is accepted when it is at most 64 KiB, successful, names our certificate with the status ``good``, has :math:`thisUpdate \le now < nextUpdate`, and carries a signature that verifies with the key of the issuer, or with a certificate inside the response that the issuer signed and that has the OCSP signing purpose. An accepted response is stored beside the certificate and stapled to new handshakes. It is asked again at half of its validity, and after a failure with the retry delays. A response that expires is removed from the handshakes. The status ``revoked`` is logged, staples nothing and makes the renewal due at once. A certificate without a responder gets nothing. Let's Encrypt names none since 2025. A responder is contacted only when a certificate names it.

Cloudflare and the delegation
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

``dns: { cloudflare: { token_file: "/etc/sibuna/cf.token" } }`` writes the record through the API of Cloudflare, version 4, with a scoped token. We find the zone by asking ``GET /zones?name=Z`` for the owner without its first label, then without two, and so on, or take ``zone``. We create the record with ``POST /zones/ID/dns_records`` (type TXT, a TTL of 120). The cleanup lists the TXT records of the owner with our value and deletes each. Every call sends ``Authorization: Bearer`` and has a limit of 30 seconds. The token is read from the file at each use and never logged. A key ``api`` replaces the base URL for tests. It accepts an ``http`` URL on a loopback address and nothing else, so a file cannot send the token to another host.

With ``follow_cname`` every provider receives the final name of the record: we follow CNAME records from ``_acme-challenge.NAME`` with the resolver, at most 8 steps, before ``present``. The hook gets the target as ``RECORD`` and the first owner in ``SIBUNA_ACME_CHALLENGE``. The stored record names the target, so the cleanup removes what was written. A resolver that does not answer fails the attempt with ACME010.

The local authority
~~~~~~~~~~~~~~~~~~~

**Name constraints.** ``internal.constraints`` lists DNS suffixes and address ranges. They are written into the root as a critical name constraints extension with permitted subtrees, when the root is created. We put them on the root and not on the intermediate: both keys lie in one directory, so a constraint on the intermediate stops nobody who holds that directory, while a constraint on the root protects every machine that trusts it. A stolen root key then cannot issue for a bank. The default is no constraint, because ``issuer: "internal"`` may name any host. A root that exists is not rewritten. When its constraints differ from the list, the local authority fails with ACME011 and a hint, and ``sibuna check`` refuses a local name outside the list.

**Revocation.** We publish no revocation list. A leaf lives 12 hours and is renewed at 8. A list would have to be fetched by the clients, and the clients of a private authority (browsers, curl, language runtimes) do not fetch lists unless told to, each in its own way. Its ``nextUpdate`` would be as long as the life of a leaf. Removing the name from the file stops the daemon from serving and renewing it. A stolen leaf key is useful for at most the lifetime, which ``internal.lifetime`` shortens. A stolen intermediate key ends with the intermediate, after at most 7 days. A stolen root key needs a new root, with or without a list.

**The root file.** ``root.crt`` has mode 0644 and the directory ``local`` has mode 0755. The keys keep 0600 and the directories ``certs`` and ``locks`` keep 0700. Whether another user reaches the file depends on the storage directory, which we create with 0700 and never change afterwards.

**A lost root.** A stored leaf whose chain does not end at the present root is not served. It is replaced at the start.

**No ACME server.** The local authority does not answer ACME requests of other machines. That needs a server for the directory, nonces, accounts, orders, authorizations with outbound validation, and certificates, with the verification of every JWS: a second product. Nodes that share the storage share the root already.

Smaller changes
~~~~~~~~~~~~~~~

- The hook runs in a process group of its own. After the timeout the whole group is killed.
- An RFC 2136 server that is not on a loopback address needs a TSIG key, or ``unsigned: true``.
- The record of a name that left the file is cleaned in the same round, and at the start for every record that the storage remembers.
- ``sibuna lb`` gains ``--acme-issuer acme|internal`` and ``--acme-on-demand-ask URL``.
- ``key: "p384"`` makes certificate keys on P-384. The account key stays P-256. RSA keys are not offered: the cryptography of the tree (``ring``) signs with an RSA key and cannot make one.
- The certificate thread is supervised. A panic is logged, the thread starts again after 5 seconds, then 10, up to 5 minutes, and reads its state from the storage as after a restart.

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
     - Three runs against Pebble 2.10.3, recorded under "Interoperation with Pebble".
   * - DNS messages are written and read with bounds.
     - ``crates/acme/src/dns/wire.rs``: a query, an answer with compression pointers, addresses, truncation, every prefix and 6 values at every byte of an answer, pointer loops, forward pointers, a chain of 17 pointers, reserved label types, a name over 255 bytes, a message that claims 196605 records.
   * - TSIG and the update are those of another implementation.
     - ``crates/acme/src/dns/tsig.rs`` and ``update.rs``: the unsigned update, the signed update, its MAC and the signed answer are compared byte by byte with messages produced by miekg/dns 1.1.62, the library of CoreDNS and of Pebble. RFC 8945 has no test vector. A wrong secret, a wrong key name, a changed response code, a late answer, an unsigned answer and the error BADKEY are refused.
   * - The hook contract holds.
     - ``crates/acme/src/dns/tests.rs``: three arguments and four variables, closed standard input, a status of 3 with the end of 400 lines of output and no control character, a program stopped after its timeout, a program that does not exist.
   * - The record is remembered until its cleanup succeeded.
     - ``the_solver_remembers_the_record_until_its_cleanup_succeeded``: a failed cleanup keeps the file, a failed present keeps it, a new process removes the record of a dead one.
   * - The check asks the authoritative servers.
     - ``crates/acme/src/dns/tests.rs`` with the server of ``dns/server.rs``: the zone by SOA, the servers by NS and A, a CNAME delegation into another zone, a loop of aliases, another value of the same owner, the fall to TCP, one server of two without the record, a silent server, an answer to another question, and the failure that names the servers.
   * - A wildcard is obtained with DNS-01 and serves one label.
     - ``cmd/sibuna/tests/edge_acme.rs``: the binary with a hook and with a signed update against a DNS server and an authority inside the test, which validates by asking that server. A name and its wildcard share one record. ``a.apex`` gets the wildcard, ``apex`` its own certificate, ``a.b.apex`` not the wildcard. No record is left.
   * - Provider failures have a code and a hint.
     - ``a_failing_provider_and_an_invisible_record_are_reported_with_hints``: ACME009 with the status and the output, ACME010 with the server, the cleanup after both, and no validation asked of the authority.
   * - The local authority writes correct certificates.
     - ``crates/acme/src/local.rs``: ``openssl verify -x509_strict -purpose sslserver`` accepts the chain with the root, for a host name and for an IP address, and refuses it for another name and without the intermediate. File modes, one root for two openers, the replacement of the intermediate, a leaf that ends with its issuer, a damaged root that is reported and kept.
   * - Internal names and addresses are served with no setting.
     - ``internal_names_and_addresses_are_served_from_the_local_authority``: a rustls client that trusts only the root of ``show ca`` accepts ``localhost``, ``127.0.0.1`` without a server name and a host under ``*.corp.internal``; it refuses another name and another root. No ACME directory exists in the storage. A second node on the same storage and a restart serve the same root and the same leaf.
   * - Local renewal, a new address, both issuers, the override.
     - The two tests after it: a leaf of 12 seconds is replaced with no restart; a reload adds ``127.0.0.2`` and the certificate without a server name lists both; one frontend serves a name of the test authority and an address of the local one; ``issuer: "internal"`` serves ``www.example.org`` from the local root.
   * - The check refuses what cannot work.
     - ``the_check_refuses_an_internal_name_for_acme_and_a_wildcard_without_dns`` runs ``sibuna check``: NAME NOT PUBLIC and WILDCARD NEEDS DNS, each with its hint.

Known gaps
~~~~~~~~~~

#. DNS-01 has two providers, the hook and RFC 2136. No vendor interface is built in.
#. The provider is called with the owner of the challenge, not with the target of a CNAME delegation. The check follows the delegation. A hook must resolve it itself, and ``rfc2136`` writes the first owner into ``zone``.
#. The search for the zone and its servers is tested inside the crate only, with a server on a loopback port. The tests through the binary and the run against Pebble name the servers with ``servers``, because the search asks port 53.
#. The check asks every address of every name server, also an IPv6 address on a node without IPv6. Such a server does not answer and is left out. A zone whose servers all fail to answer fails the check.
#. A hook that runs too long is stopped. A process that the hook started is not.
#. An unsigned RFC 2136 update trusts the answer by the address and the identifier only. Use a TSIG key outside a loopback or a trusted link.
#. A record that was presented for a name is cleaned at the start and at the next attempt for that name. When the name leaves the file before that, the record stays.
#. The local authority has no name constraints, no revocation and no automatic installation of its root.
#. A leaf of the local authority that was stored under another root, because the storage lost ``root.pem``, is served until its renewal, at most 8 hours with the default lifetime.
#. ``root.crt`` has mode 0600 like every file of the storage. ``show ca`` prints it for a user who may use the admin socket.
#. The local authority is not an ACME server for other machines.
#. ``sibuna lb`` has ``--acme-dns-hook`` only. The RFC 2136 provider, ``issuer`` and the check settings need a file.
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

``docs/sid/assets/automatic-https.lean`` models seven things with Lean 4.19.0. The order machine is a phase and a budget. An answer is good, a repetition, a skip over the challenge, or bad. We prove that a step never moves a phase backwards, that every step of a live order takes budget or ends the order, that an order of budget :math:`n` is over after :math:`n + 1` steps whatever the authority answers, and that ``Done`` is entered only from ``Download``. For the schedule we prove that the renewal time lies in :math:`[b, e)` for :math:`b < e`. For the retry delay we prove that it is at least the first delay, at most one day, and monotone in the number of failures. For the table we prove that a failed order leaves the served certificate unchanged, that a served name never loses its certificate, and that the expiry of a served certificate never decreases. For the issuer we prove that no name is refused when the frontend states no issuer, that a public authority receives public names only, that no ACME authority is asked for an address, and that ``internal`` always means the local authority. For wildcards, with a host as its list of labels, we prove that ``*.parent`` covers a host of one more label, that it covers neither the parent nor a host of two more labels, that a covered host has exactly one label more, and that the choice among an exact certificate, a wildcard and a file takes them in this order. For the propagation check we prove that it asks at most :math:`\lfloor t / p \rfloor + 1` times for a timeout :math:`t` and a pause :math:`p`, that its pauses sum to at most :math:`t`, that a record which shows in a round the check reaches is found, and that a record which never shows fails the check. The JSON, the DNS messages, the signatures, the sockets and the files are outside the model. Tests cover them.

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

A third run on the same day used DNS-01. ``pebble-challtestsrv`` of the same Pebble release was the DNS server, on ``127.0.0.1:25053``, with its management interface on ``127.0.0.1:25055``, and Pebble resolved through it (``-dnsserver``). The hook of the run was a script of the scratch directory that posts ``set-txt`` and ``clear-txt`` to the management interface. The file named ``challenge: "dns-01"``, the hook, ``servers: ["127.0.0.1:25053"]`` and the names ``*.wild.example.com``, ``wild.example.com`` and ``127.0.0.1``. The test server does not answer SOA and NS questions, so the search for the zone was not part of this run.

.. list-table:: One run of 50 seconds with DNS-01
   :header-rows: 1
   :widths: 30 70

   * - Observation
     - Result
   * - First certificates
     - All three names ``ready`` within 16 seconds: two with ``dns-01`` from ``Pebble Intermediate CA``, the address with ``local``.
   * - Served chains
     - ``openssl s_client -CAfile`` with Pebble's root and ``-verify_hostname``: ``Verify return code: 0 (ok)`` for ``a.wild.example.com``, which received the certificate of ``*.wild.example.com``, and for ``wild.example.com``. With the root of ``show ca``, no server name and ``-verify_ip 127.0.0.1``: 0 (ok). ``curl --cacert`` with that root verified the address too.
   * - The record
     - The hook ran ``present`` and ``cleanup`` once for each order, both for ``_acme-challenge.wild.example.com.``.
   * - Renewal
     - With a lifetime of 40 seconds both ACME names were renewed with new serials, with no restart. Pebble validated with ``dns-01`` four times and issued four certificates.
   * - Failures
     - None.

Open questions
--------------

#. Should the root of the local authority be installed by a command of ours?
#. Should a vendor provider for DNS be built in?
#. Should ``show certs`` have a command that renews a name at once?

Review history
--------------

- 2026-11-24. Initial draft: ``tls.auto`` and ``global.acme``, a client crate without I/O, both challenges, storage with a lock, renewal at two thirds, exponential retry, a table behind the resolver.
- 2026-11-24. Author's review of the design. It found six faults and changed the record for each. The retry delay lived in memory only, so a daemon in a restart loop would have ordered at every start and exhausted the limits of the authority; the failure count and the next attempt are now stored beside the certificate. The draft answered the challenge on plain frontends only; an authority that follows a redirect to port 443 would have missed it, so every HTTP frontend answers, before the redirect. The draft did not say when a challenge answer leaves the table; it now leaves when the order ends. The machine had no path for an authorization that is already valid, which Pebble and Let's Encrypt both return; it now skips to ``Finalize``, and the Lean model has that step. A ``Retry-After`` of the authority was taken as it came, so the authority could park an order; it is now clamped to 30 seconds. The number of authorizations of an order was unbounded; it is now exactly one. The review also recorded two gaps: a changed e-mail address, and the lock's dependence on the clocks of the nodes.

- 2026-11-24. Author's review of the implementation, with the tests and the Pebble run as instruments. It found seven defects and fixed each. (1) The time limit of an order was built outside the runtime of the thread, so the thread panicked at its first order; the binary test found it, and the limit is now built inside. (2) The thread ordered as soon as it started, before the listeners were bound. A daemon whose start failed for another reason had already asked the authority, so a unit that restarts every five seconds would have spent the limits of the authority; the Pebble run found it, and orders now wait for ``Automatic::allow_orders``. (3) The same daemon left its lock file, and the next start would have waited 15 minutes for it to age; the lock now names its writer, and a writer that is gone on this host loses the lock at once. (4) The record said that a managed name without a certificate fails the handshake. The code serves the default certificate as for any unknown name, which is what SID 0015 does without ``strict_sni``; the record now says so. (5) The TLS library checks a certificate it is given, and refuses the critical extension of the TLS-ALPN-01 certificate; that certificate is now handed over without the check, and a unit test covers it. (6) The diagnostic of a failure ran two sentences together when the reason of the authority had no full stop. (7) ``ACME007`` was a code of the client for a failure that only the file can have; it is now a failure of the file with a title and a hint of its own. The review also added the seven gaps that end the list above.
- 2026-11-24. Merge with ``main`` after SID 0020, the takeover of ``global.reuse_port`` and the bound on TLS connections per client. Three files conflicted, all by adjacent additions, and both sides were kept: ``crates/lb/src/config.rs`` (the ``acme`` field beside ``reuse_port`` and ``observe``), and the two index files of the records. A validation connection of TLS-ALPN-01 takes a place under the client bound like any TLS connection and gives it back when the handshake ends; it is refused only when the address of the authority already holds ``max_connections_per_ip`` connections. The record gained the sections on the access log, the metrics and the takeover.
- 2026-11-24. Second merge with ``main``, after the client certificate field, the takeover of HTTP/3 and the per-client bound on QUIC connections. Three files conflicted and both sides were kept. In ``crates/ingress/src/lib.rs`` the TLS-ALPN-01 handshake ends before the fingerprint of a client certificate is taken, and the choice between HTTP/2 and HTTP/1.1 follows as on ``main``. In ``cmd/sibuna/src/edge/http.rs`` both branches had moved the limits of the TLS front into a function ``ingress_limits``; the one of ``main`` stays, with its ``share_address``. ``Cargo.lock`` lists the dependencies of both. The QUIC listener of a frontend with ``auto`` names uses the same resolver, so HTTP/3 serves the automatic certificate too.
- 2026-11-24. Third merge with ``main``, after SID 0019. One file conflicted, ``crates/lb/src/lib.rs``, by adjacent lines: the export of ``QuickAutomatic`` and the new module ``route`` both stay. The merge also joined the two redirects as the section "The redirect" describes: ``RoutePolicy`` gained ``keeps_http`` and ``redirect_to``, ``traffic::redirect`` became visible to the crate, the automatic redirect lost its own writer, and the status 308 that this record had added to ``sibuna-http`` was dropped again. A third binary test covers a frontend with ``redirect_https: 301``, a route with ``redirect_https: false`` and a managed name together.

- 2026-11-24. Second part, first draft: ``tls.issuer``, wildcards, DNS-01 with a hook and RFC 2136, the check at the authoritative servers, the local authority.
- 2026-11-24. Author's review of the second part before implementation. It found seven faults and changed the draft for each. The draft ordered ``example.org`` and ``*.example.org`` in one certificate, which needs two values on one record at once and a provider that can hold both; one certificate per name with a delete that names the value needs neither. The draft cleaned up only at the end of an order; a daemon killed in between would have left a record for ever, so the presented record is written to the storage first and cleaned at the next start. The draft trusted the answer of an RFC 2136 server by its response code; a forged answer could have reported success, so the MAC of the answer is checked. The draft asked the recursive resolver for the TXT record; its cache would have hidden a record that is not there yet, or shown one that only one server has, so every authoritative server is asked. The draft gave the leaf of the local authority 12 hours and the intermediate 7 days with no rule between them; a leaf signed in the last hours would have outlived its issuer, so a leaf ends with the intermediate and the intermediate is replaced early. The draft let a handshake without a server name fall to the first file certificate; a frontend that names an IP address would never have served it, so the IP certificate comes first and lists all managed addresses. The draft printed the root through a new subcommand that read the storage directory; that needs the rights of the daemon's user anyway, so the admin socket answers it and no second path to the key directory exists.
- 2026-11-24. Author's review of the implementation of the second part, with the tests and the Pebble run as instruments. It found nine defects and fixed each. (1) A name that could not be written left its first labels in the message; ``write_name`` now removes them, and a test compares the buffer. (2) The end of the hook's output was cut where it mattered: both streams were joined and the end was dropped; each stream now keeps its own last 1024 bytes, standard output first. (3) The tests of the hook failed now and then with "Text file busy", because a program started by one test thread held the script of another for a moment; the tests that write a script or start a program take one lock. (4) The certificate of a leaf with a short lifetime was due before it was issued, because the validity started a minute early; a short leaf now starts half its lifetime early. (5) The daemon announced "from Let's Encrypt" for names that all go to the local authority; the line now names each source with its count, and a node with internal names only opens no ACME account. (6) A record whose cleanup had failed was forgotten by the next order, which stores its own record in the same file; the next attempt now cleans first. (7) The cleanup of a leftover record ran without the lock of the name, so on shared storage it could have removed the record of another node's running order; it now takes the lock and leaves the record when it cannot. (8) The check of the test that trusts "another root" used the intermediate, which a verifier accepts as an anchor; it now uses a root of another authority. (9) The hint of a failed validation named ports only; it now names the TXT record for DNS-01. The review also recorded the gaps 3 to 12 above.
- 2026-11-24. Fourth merge with ``main``, after SID 0022 and the function ``note`` for the lines of the running edge. No file conflicted. The new diagnostic of a failed cleanup is written through ``note``, like the other lines of the certificate thread.
- 2026-11-24. Fifth merge with ``main``, after the ``local`` word of ``set server``. One file conflicted, ``cmd/sibuna/src/edge/control.rs``, in the usage text: the line ``show ca`` and the new form of ``set server`` both stay.
- 2026-11-25. Third part, first draft, after a fast-forward to ``main`` with SID 0019, 0020 and 0022: issuance on demand, a list of authorities, the binding, renewal information, stapling, Cloudflare, constraints, and the smaller changes.
- 2026-11-25. Author's review of the third part before implementation. It found nine faults and changed the draft for each. The draft asked the ``ask`` URL from the handshake; a slow answer would have held a worker of the TLS runtime, so the handshake applies only guards that read memory and the thread asks. The draft counted handshakes against the rate; a client that repeats one name would have spent it, so a token is taken per order, after the storage and ``ask`` had their say. The draft asked ``ask`` again for every handshake of a denied name; a denial is now remembered for 60 seconds in a bounded table. The draft renewed every held name for ever, so the table would have filled with names that nobody uses; a name without a handshake since its certificate is released at its renewal. The draft picked a random time in the window of the authority; each restart would have picked again and moved the renewal, so the pick is a function of the serial. The draft took the window as it came; an authority could have moved a renewal past the expiry, so the pick is capped at four fifths of the lifetime. The draft gave every authority its own lock; two nodes could then have ordered one name at two authorities, so the lock is that of the first authority. The draft put the name constraints on the intermediate; the root key lies beside it, so they are on the root. The draft let the file set the base URL of the Cloudflare API; a wrong or hostile file would have sent the token anywhere, so only a loopback ``http`` URL is accepted.

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
