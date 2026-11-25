:sid-number: 0021
:sid-title: Automatic HTTPS
:sid-state: discussion
:sid-status: Open for Discussion
:sid-type: Architectural Specification
:sid-authors: ["Vikrant Rathore"]
:sid-created: 2026-11-24
:sid-updated: 2026-11-25
:sid-discussion: No external discussion URL assigned
:sid-summary: Obtains and renews the certificates of an edge frontend through ACME when the operator names the hosts, answers HTTP-01, TLS-ALPN-01 and DNS-01 challenges in the daemon, issues for internal names and IP addresses from a local authority, obtains a certificate at the first handshake for a guarded name on demand, installs each certificate for new handshakes without a reload, and redirects HTTP to HTTPS for the managed names.
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
     - ``auto: ["*.example.org"]`` with ``global.acme.dns``. Caddy needs a build with a provider module. We run a hook program, send an RFC 2136 update or call the API of Cloudflare. Other vendors go through the hook.
   * - The DNS challenge checks propagation, with a timeout, a delay, resolvers and an override domain.
     - differs
     - ``check``, ``timeout``, ``wait``, ``resolver`` and ``servers``. With ``follow_cname`` the provider writes at the target of a CNAME delegation and the check looks there. We have no ``dns_challenge_override_domain``: the delegation is read from the DNS, not from the file.
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
     - Not built: it is a second product. See "The local authority" in the third part.
   * - The local root may sign for any name.
     - differs
     - The same by default. ``internal.constraints`` limits the root.
   * - ``key_type`` offers ECDSA and RSA keys.
     - differs
     - ``key``: P-256 or P-384. No RSA.
   * - On-demand TLS with an ``ask`` endpoint.
     - same
     - ``tls: { on_demand: true }`` and ``global.acme.on_demand``, with the same ``ask`` contract. We refuse a file without a guard, where Caddy warns. A suffix list, a rate, a bound on the names and a bound on the wait are added.
   * - An on-demand certificate is renewed during a handshake.
     - differs
     - It is renewed in the background while handshakes name it, and released otherwise. HTTP/3 handshakes do not wait.
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
     - differs
     - ``fallback`` lists up to three more authorities, asked in order in one attempt. None is listed by default. ``eab`` binds an account where the authority wants it.
   * - The renewal time follows the renewal information of the authority.
     - same
     - ``ari``, on by default, with a cap at four fifths of the lifetime.
   * - OCSP responses are stapled, and a revoked certificate is replaced.
     - same
     - ``ocsp``, on by default. A response is stapled while its window is open. ``revoked`` renews at once. Caddy also staples for certificates from files. We staple for automatic certificates only.
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

#. Follow CNAME records from ``_acme-challenge.NAME``, at most 8, through the resolver. The last owner is where the record must be. This is the delegation of validation to another zone. Since the third part the provider is called with this last owner. The section "Cloudflare and the delegation" says how.
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
   * - ``ACME012``
     - ACCOUNT NOT BOUND
     - The authority registers accounts only with an external account binding and the file has none, or the authority refused the binding, or the key file cannot be read. The hint names ``eab``.

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
     - ``{ token_file, zone, api }``: the third provider. ``zone`` is optional. ``api`` is for tests and takes an ``http`` URL on a loopback address only.
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

The thread applies the guards that cost time. It first looks into the storage: a certificate that an earlier run or another node obtained is loaded and costs nothing. Else it asks the ``ask`` URL, with a limit of 5 seconds and one try. Any other status denies the name, and so does no answer. Then it takes a token. The bucket holds ``rate`` tokens and gains one every :math:`3600 / rate` seconds. An empty bucket denies the name until the next token. Only then it orders, with the issuer that the name and ``tls.issuer`` select, as for a listed name. A denied name is remembered for 60 seconds, in a table of at most 1024 names, so a flood of handshakes for one name asks once.

A held name is a managed name: it has a line in ``show certs``, with ``on-demand`` in a new column ``origin`` before the column ``error``, and it is renewed in the background. When its renewal is due, the thread decides again. When no handshake named it since the certificate was obtained, it is released instead: the name leaves the table and the certificate stays in the storage until it expires. When the ``ask`` URL answers with a refusal, it is released too. When the URL does not answer, the certificate stays and the renewal waits for the first retry delay: silence does not take a certificate away. So the table holds names that clients use and that are still allowed, and its bound ``names`` is a bound on the renewals too. A release is logged with its reason. A held name that has no certificate and whose next attempt lies ahead is released and denied until that attempt: its order failed, now or in an earlier run, or another node holds its lock. A failed renewal does not release the name, because its certificate still serves. The held names, the denials and the bucket live in memory. A restart starts with none, a full bucket, and the certificates of the storage.

The wait is bounded by ``wait``. It stands between two deadlines of 15 seconds each, one for reading the ClientHello and one for the rest of the handshake, so a handshake on a frontend with ``on_demand`` ends within :math:`30 + wait` seconds. Only such a frontend reads the ClientHello before it chooses its configuration. Every other frontend runs the handshake as before. A handshake that times out continues with the usual choice. The order goes on, and a later handshake finds the certificate. One order runs at a time, as before, so a burst of new names is served in sequence and some handshakes time out. QUIC handshakes do not wait: the QUIC library asks the resolver without a place to wait. They use the certificate once a TCP handshake has obtained it.

Authorities, the binding and renewal information
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The keys ``directory``, ``email``, ``ca_file`` and ``eab`` describe the first authority. ``fallback`` lists up to three more. One attempt for a name asks the authorities in order and stops at the first certificate. Each failure is logged with the authority. A failure that another authority follows is logged with both directories. The attempt fails when all fail, with the failure of the last one, and the retry delay then counts one failure. Each authority has its own account and its own directory in the storage, and all accounts use one key, the one in the directory of the first authority. A node that shares the storage therefore answers an HTTP-01 challenge of any authority from the thumbprint of that key. The lock, the retry state and the DNS record of a name live in the directory of the first authority, so two nodes never order one name at two authorities at once. Every listed authority is opened at the start. A fallback whose trust roots or binding key cannot be read is reported then, and not on the day it is needed. A stored certificate of any listed authority is served; the one that expires last wins. A name is public for the choice of the issuer when any listed authority is one of the public directories.

With ``eab`` the registration carries ``externalAccountBinding`` (RFC 8555, section 7.3.4): a JWS with ``alg`` HS256, the ``kid`` of the binding and the URL of ``newAccount`` in its header, the account key as its payload, and an HMAC-SHA256 with the decoded key. The key file holds the key in base64url, with or without padding. A directory whose ``meta`` says ``externalAccountRequired`` and that has no ``eab`` fails with ``ACME012`` and a hint before any request is signed. A registration with a binding that the authority refuses fails with the same code and the reason of the authority. The key is in no message.

With ``ari`` the thread asks the ``renewalInfo`` URL of the directory for each served certificate of that authority. The identifier is the base64url of the authority key identifier, a dot, and the base64url of the serial (RFC 9773, section 4.1). The answer has a window. We pick the time :math:`s + (h \bmod (e - s))` in the window :math:`[s, e)`, where :math:`h` is a hash of the serial. The pick is therefore the same after a restart and on every node. The renewal time is the pick, and never later than four fifths of the lifetime: an authority cannot park a certificate until it expires. A window in the past renews a certificate that was loaded from the storage at once. A certificate that this process obtained has a floor: it is not renewed in its first two minutes, or in the first tenth of its lifetime when that is shorter. Without the floor an authority that always answers with a past window would make us order in a loop. We ask again after the ``Retry-After`` of the answer, clamped to between one hour and one day, six hours without it, and at least every tenth of the lifetime, so a certificate of minutes is asked about more than once. A failure to ask keeps the last answer, or the rule of two thirds, and is not logged. An authority whose directory has no ``renewalInfo`` is not asked. A name in a retry delay keeps that delay. An order that replaces a certificate of the same authority names it in ``replaces``, when the directory has ``renewalInfo``. When the authority refuses that order, we place it once more without the member: the certificate may have been replaced before, by another node.

OCSP stapling
~~~~~~~~~~~~~

When the leaf names an OCSP responder with an ``http`` URL in its authority information access, the thread asks it after the certificate is installed. The request is a POST of an OCSP request with one SHA-1 certificate identifier and no nonce. The response is accepted when it is at most 64 KiB, successful, names our certificate with the status ``good``, has :math:`thisUpdate \le now < nextUpdate`, and carries a signature that verifies with the key of the issuer, or with a certificate inside the response that the issuer signed and that has the OCSP signing purpose. An accepted response is stored beside the certificate and stapled to new handshakes. It is asked again at half of its validity, and after a failure with the retry delays. A response that expires is removed from the handshakes. The status ``revoked`` is logged, staples nothing and makes the renewal due at once. A certificate without a responder gets nothing. Let's Encrypt names none since 2025. A responder is contacted only when a certificate names it.

The implementation fixes what the paragraph above leaves open, and differs from it in two places. The response lies in ``certs/NAME/ocsp.pem`` with the label ``OCSP RESPONSE``. At a start it is stapled again when it still passes every check, and the responder is then asked at the usual time and not at once. The next question is due at the middle of the window. When a response is taken after its middle, the question is due at half of the time that is left, so it always lies after now and inside the window. A response is ``good`` and signed by an ECDSA P-256 or P-384 key or by an RSA key with PKCS#1 and SHA-256, SHA-384 or SHA-512. A delegated certificate must be inside its own validity. The first difference: a revoked certificate that this process obtained is renewed at its floor, the same floor that bounds renewal information, and not before. A responder that keeps saying ``revoked`` then cannot make us order in a loop. A renewal answer of the authority does not move a renewal that a revocation made due. The second difference: the status ``unknown`` is a failure with the retry delays, and it does not renew. ``show certs`` has a column ``ocsp``: ``good`` while a response is stapled, ``revoked``, and ``-`` otherwise. A failure is logged as NO OCSP RESPONSE (ACME013) with the time of the next question. It never changes the state of the name, because the certificate serves without a staple. The responder is asked through the HTTP client of the first authority, with a limit of 15 seconds.

Cloudflare and the delegation
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

``dns: { cloudflare: { token_file: "/etc/sibuna/cf.token" } }`` writes the record through the API of Cloudflare, version 4, with a scoped token. We find the zone by asking ``GET /zones?name=Z`` for the owner, then for the owner without its first label, then without two, and so on down to two labels, or take ``zone``. The first zone that the account has is the longest one. We create the record with ``POST /zones/ID/dns_records`` (type TXT, a TTL of 120). The cleanup lists the TXT records of the owner, and deletes each that has our value. Every call sends ``Authorization: Bearer``. The token is read from the file at each use and never logged. A key ``api`` replaces the base URL for tests. It accepts an ``http`` URL on a loopback address and nothing else, so a file cannot send the token to another host.

The implementation differs from the first draft of this section in four places. The search starts with the owner itself, because the target of a delegation may be the apex of a zone. It asks about 8 names at most, and a deeper owner needs ``zone``. A call has a limit of 10 seconds and not 30, so that writing one record takes 90 seconds at most, which is inside the time that an order allows for its provider. The cleanup asks for the records by type and name and compares the content itself, because the API holds the content of a TXT record inside quotes. A record that exists already, code 81058 of the API, counts as written. An answer with ``success: false`` fails with ACME009. The diagnostic carries the status, up to four messages of ``errors`` with their codes, and a hint that names the token file and the two rights that the token needs. Text of the API that repeats the token is replaced before it is shown. An answer is read up to 256 KiB.

``crates/acme`` builds each request and reads each answer without I/O. ``crates/ingress`` sends them with its HTTPS client and the trust roots of the system. The provider runs inside the conversation of an order, which runs on the current-thread runtime of the certificate thread, and a runtime cannot block on a second future from inside itself. So each call runs on a scoped thread with a small runtime of its own, and the caller waits for it. The client follows no redirect, so the token goes to the host of the URL only.

With ``follow_cname`` every provider receives the final name of the record: we follow CNAME records from ``_acme-challenge.NAME`` with the resolver, at most 8 steps, before ``present``. The hook gets the target as ``RECORD`` and the first owner in ``SIBUNA_ACME_CHALLENGE``. The stored record names the target, so the cleanup removes what was written. A resolver that does not answer fails the attempt with ACME010, before any provider runs. An answer without a CNAME record, also a negative one, means that there is no delegation. The target comes out of a DNS answer and a hook may hand it to a shell, so a target that is not a host name, with labels of letters, digits, ``-`` and ``_``, fails the attempt with ACME009. The hook has ``SIBUNA_ACME_CHALLENGE`` in every run, equal to ``RECORD`` without a delegation. The check that follows ``present`` looks at the same target. The time of an order grows by ``timeout`` once more for the walk.

The local authority
~~~~~~~~~~~~~~~~~~~

**Name constraints.** ``internal.constraints`` lists DNS suffixes and address ranges, at most 32. They are written into the root as a critical name constraints extension, when the root is created. We put them on the root and not on the intermediate: both keys lie in one directory, so a constraint on the intermediate stops nobody who holds that directory, while a constraint on the root protects every machine that trusts it. A stolen root key then cannot issue for a bank. The default is no constraint, because ``issuer: "internal"`` may name any host. A root that exists is not rewritten. When its constraints differ from the list, the local authority fails with ACME011 and a hint, and ``sibuna check`` refuses a local name outside the list with the diagnostic NAME OUTSIDE CONSTRAINTS. A name on demand outside the list is not asked for.

The list means "these names and nothing else". X.509 constrains each kind of name by itself, so a root with DNS subtrees only could still sign any address. We therefore close a kind that has no entry. Addresses are closed by the excluded subtrees ``0.0.0.0/0`` and ``::/0``. Host names are closed by the single permitted subtree ``invalid``, the top-level name that RFC 6761 reserves. An excluded empty name would say the same, and verifiers do not agree on it. A verifier takes a common name that looks like a host name for one and holds it against the DNS subtrees, so the common name of a leaf for an address is ``address 10.0.0.1`` and not the bare address. The entries are stored sorted and without repetitions, a suffix in lower case without a leading dot, a range with the bits after its prefix cleared, so that two spellings of one list give one extension. The local authority does not compare a name with the list when it signs. The check of the file does, and a client refuses what slips through.

**Revocation.** We publish no revocation list. A leaf lives 12 hours and is renewed at 8. A list would have to be fetched by the clients, and the clients of a private authority (browsers, curl, language runtimes) do not fetch lists unless told to, each in its own way. Its ``nextUpdate`` would be as long as the life of a leaf. Removing the name from the file stops the daemon from serving and renewing it. A stolen leaf key is useful for at most the lifetime, which ``internal.lifetime`` shortens. A stolen intermediate key ends with the intermediate, after at most 7 days. A stolen root key needs a new root, with or without a list.

**The root file.** ``root.crt`` has mode 0644 and the directory ``local`` has mode 0755. Both modes are set at every open, so a storage of an earlier version is opened up too. The keys keep 0600 and the directories ``certs`` and ``locks`` keep 0700. Whether another user reaches the file depends on the storage directory, which we create with 0700 and never change afterwards.

**A lost root.** A stored leaf whose chain does not end at the present root is not served. It is replaced at the start. The chain ends at the root when the authority key identifier of its last certificate is the key identifier of the root. An intermediate of another root is replaced by the same rule.

**No ACME server.** The local authority does not answer ACME requests of other machines. That needs a server for the directory, nonces, accounts, orders, authorizations with outbound validation, and certificates, with the verification of every JWS: a second product. Nodes that share the storage share the root already.

Smaller changes
~~~~~~~~~~~~~~~

- The hook runs in a process group of its own. After the timeout the whole group is killed with ``kill(2)``, which is the one foreign call of the client crate, in a module of its own: the standard library starts a process in a new group and cannot signal a group. A process that left the group is not reached. A hook that ends in time leaves what it started alone.
- An RFC 2136 server that is not on a loopback address needs a TSIG key, or ``unsigned: true``. The file is refused otherwise, with the diagnostic UPDATE NOT SIGNED. ``unsigned`` beside a key is refused as a contradiction.
- The record of a name that left the file is cleaned in the same round, and at the start for every record that the storage remembers. The thread lists the remembered records when it starts and whenever the names change, and cleans those of names that it does not manage, each under the lock of its name. A cleanup that fails is tried again after two minutes. The listing happens when the ACME source is open, which needs one name of an ACME authority.
- ``sibuna lb`` gains ``--acme-issuer acme|internal`` and ``--acme-on-demand-ask URL``. The second turns ``on_demand`` on for the frontend, beside the names of ``--domain``. The RFC 2136 provider has no flags: it needs a server, a key name, a key file and often a zone, which is a file's worth.
- ``key: "p384"`` makes certificate keys on P-384, for both sources. The request is signed with ECDSA and SHA-384. The account key and the keys of the local authority stay on P-256. A stored key of either curve loads, so a change of ``key`` takes effect at each renewal. RSA keys are not offered: the cryptography of the tree (``ring`` 0.17.14) signs with an RSA key and has no function that makes one, and no authority we know requires RSA.
- The certificate thread is supervised. A panic is caught, logged as ``ACME014`` with its message, and the work starts again after 5 seconds, then 10, up to 5 minutes, with a new state that it reads from the storage as after a restart. The challenge answers of the order that died are withdrawn. The served certificates stay. A state that ran an hour without a panic counts as healthy, and the next panic waits 5 seconds again.

RSA keys, the revocation list and the ACME server
-------------------------------------------------

This part builds the three things that the third part left out: RSA keys for certificates, a revocation list of the local authority, and an ACME server in front of the local authority. Where this part and an earlier part disagree, this part holds.

.. list-table:: The new keys and the new command
   :header-rows: 1
   :widths: 34 14 52

   * - Key or command
     - Default
     - Meaning
   * - ``global.acme.key``
     - ``"p256"``
     - Gains ``"rsa2048"``, ``"rsa3072"`` and ``"rsa4096"``.
   * - ``global.acme.internal.server``
     - none
     - ``{ url, allow, http_port }``: the local authority answers ACME clients at ``url``.
   * - ``global.acme.internal.server.url``
     - required
     - The base URL of the server, for example ``"https://ca.corp.internal/acme"``. The scheme ``http`` is accepted for a loopback address only.
   * - ``global.acme.internal.server.allow``
     - required
     - One to 32 DNS suffixes and address ranges, at least one of each kind. A client may order a name that a suffix covers. The validation connects only to an address inside a range.
   * - ``global.acme.internal.server.http_port``
     - ``80``
     - The port that the HTTP-01 validation connects to. Another port serves a test and a network that maps the port.
   * - ``revoke cert NAME|SERIAL``
     -
     - The admin command that revokes a certificate of the local authority.

RSA keys
~~~~~~~~

``key`` selects the key of a new leaf certificate, from an ACME authority and from the local authority. The values ``"rsa2048"``, ``"rsa3072"`` and ``"rsa4096"`` make an RSA key of that many bits. The certificate request is signed with that key, with PKCS#1 version 1.5 and SHA-256. The account key stays on P-256. The root and the intermediate of the local authority stay on P-256 too: only leaves change. A client that needs an RSA leaf still verifies an ECDSA signature on it, so the setting serves clients that need an RSA key exchange or an RSA server key, and not clients that know no ECDSA at all.

``ring`` signs with an RSA key and cannot make one. We do not write RSA key generation ourselves, and we add no crate. The daemon runs the installed program ``openssl``:

.. code-block:: text

   openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:N -outform PEM

We run the program directly, with no shell, with standard input closed, and we read the key from its standard output. We read at most 16 KiB, wait at most 120 seconds, and kill the program after that time. The key is never in a file before the store writes it with mode 0600. The program is found through the ``PATH`` of the daemon. The key that it wrote must load as an RSA key of the asked size, or the attempt fails.

A file with an RSA ``key`` needs the program on the day it is checked, and not on the day a certificate is due. ``sibuna check`` and the start of the daemon run ``openssl version``. When that fails, both stop with the diagnostic KEY TOOL FAILED (ACME015) and a hint that names the two ways out: install OpenSSL, or choose an ECDSA key. A reload runs the same check. A key that cannot be made later, because the program vanished or ran too long, fails the attempt for the name with the same code and the usual retry delay. A stored key of any of the five kinds loads, so a change of ``key`` takes effect at each renewal.

.. list-table:: New failures of this part
   :header-rows: 1
   :widths: 12 24 64

   * - Code
     - Title
     - Cause and hint
   * - ``ACME015``
     - KEY TOOL FAILED
     - The program ``openssl`` could not be started, ran too long, ended with a failure, or wrote something that is no RSA key of the asked size. The hint says to install OpenSSL into the ``PATH`` of the daemon, or to set ``key`` to ``"p256"`` or ``"p384"``.
   * - ``ACME016``
     - REVOCATION LIST FAILED
     - The revoked entries or the revocation list could not be read or written, or the list of revoked entries is full. The hint names the directory ``local`` of the storage.
   * - ``ADM013``
     - NOT REVOKED
     - ``revoke cert`` named nothing that the local authority can revoke: the daemon has no local authority, the name has no certificate of it, or the word is neither a managed name nor a serial number.

The revocation list
~~~~~~~~~~~~~~~~~~~

The local authority publishes a certificate revocation list (RFC 5280, version 2) and the operator revokes a certificate with an admin command.

.. code-block:: text

   STORAGE/local/
     revoked/SERIAL              one file per revoked certificate, mode 0600
     intermediate.previous.pem   the intermediate before the present one, mode 0600
     crl.der                     the list of the present intermediate, DER, mode 0644
     crl.pem                     the lists of every living intermediate, PEM, mode 0644

**The entries.** A revoked certificate is one file in ``revoked``. Its name is the serial number in 16 lower-case hexadecimal digits. Its one line holds the time of the revocation, the time after which the entry may be dropped, and the name. A file per entry needs no lock: creating one is one rename, removing one is one unlink, and two nodes that share the storage never rewrite a common file. The directory holds at most 1024 entries. A revocation that would exceed the bound fails with ACME016 after the entries that may be dropped were removed. An entry may be dropped when its certificate has expired. When the serial is not that of a stored certificate, the entry stays for the longest life of a leaf, two days and one minute.

**The list.** A revocation list must be signed by the issuer of the certificates it lists. The intermediate is replaced every few days, and a leaf of the replaced intermediate may still be valid. So the authority keeps the intermediate that it replaces as ``intermediate.previous.pem`` until that one expires, and it signs one list with each living intermediate. An intermediate is replaced after two thirds of its seven days, and a leaf lives two days at most, so two intermediates are enough: when the second replacement comes, the leaves of the first are gone. Every list holds every entry. A serial is 64 random bits, so an entry that belongs to the other intermediate matches nothing there. The list carries the authority key identifier of its signer and a list number, which is the time of its writing and at least one more than the number of the list it replaces. ``thisUpdate`` is one minute before the writing. ``nextUpdate`` is 24 hours after it, and not after the end of the signing intermediate.

``crl.der`` holds the list of the present intermediate. ``crl.pem`` holds that list and, while the previous intermediate lives, its list as a second block. A verifier that reads PEM takes both. Both files are written under a temporary name and renamed.

**The schedule.** The list is written again when it is missing, when the present intermediate is not its signer, when the entries are not the ones it lists, and when half of its validity has passed. The certificate thread looks at every round, so at least once an hour, and the thread of the ACME server looks once a minute. A list is therefore replaced at least eleven hours before its ``nextUpdate``. The admin command writes the list at once. A node that shares the storage sees the entry of another node at its next look.

**The command.** ``sibuna ctl SOCKET revoke cert NAME`` revokes the certificate that the local authority issued for the managed name and that the storage holds. ``revoke cert SERIAL`` takes 1 to 16 hexadecimal digits, the serial as ``show certs`` and ``openssl x509 -serial`` print it, and also revokes a certificate that the storage no longer holds, for example one that the ACME server issued to another machine. A word that is both a managed name and hexadecimal is taken as the name. The command writes the entry and the list, and wakes the certificate thread. The thread treats a served certificate whose serial is revoked as due, so the name gets a new certificate with a new key in the same round. A stored leaf whose serial is revoked is not loaded at a start. The command is logged. It answers with the serial and the name.

**What the list is for.** The file on disk is the product. A verifier is given the file: ``openssl verify -crl_check``, ``ssl_crl`` of nginx, ``SSLCARevocationFile`` of Apache. We put no distribution point into a leaf: by RFC 5280 it would have to be an ``http`` URL that every client can reach, and the daemon has no such address of its own. When the ACME server is on, it also answers ``GET URL/crl`` with ``crl.der``, for a job that fetches the file.

The ACME server
~~~~~~~~~~~~~~~

With ``internal.server`` the local authority answers ACME clients (RFC 8555), so that another machine of the internal network obtains a certificate with certbot, lego, acme.sh or a second Sibuna.

.. code-block:: text

   global: { acme: { internal: { server: {
       url: "https://ca.corp.internal/acme",
       allow: ["corp.internal", "10.0.0.0/8"],
   } } } },

**Where it listens.** The server has no listener of its own. It answers the requests whose ``Host`` is the host of ``url`` and whose path begins with the path of ``url``, on the HTTP frontends of the daemon, in the hook that already answers the HTTP-01 challenge. A URL with ``https`` is answered on TLS frontends only. A URL with ``http`` is accepted for a loopback address only and is answered on plain frontends. We chose this over a dedicated bind because it adds no socket, no second TLS stack and no second HTTP parser: the frontend terminates TLS, with a certificate that the local authority itself issues when the host is an ``auto`` name, and the access log and the counters see every request. The cost is that a request body must fit the read buffer of the connection. The server refuses a body over 32 KiB, and a request is at most a certificate request with its signature.

.. list-table:: The resources, relative to ``url``
   :header-rows: 1
   :widths: 30 70

   * - Path
     - Meaning
   * - ``GET /directory``
     - The directory: ``newNonce``, ``newAccount``, ``newOrder``.
   * - ``HEAD`` or ``GET /new-nonce``
     - A fresh nonce in ``Replay-Nonce``.
   * - ``POST /new-account``
     - Returns the account URL of the key of the request.
   * - ``POST /account/KEY``
     - The account object.
   * - ``POST /new-order``
     - A new order for 1 to 16 DNS names.
   * - ``POST /order/ID``
     - The order.
   * - ``POST /authz/ID``
     - One authorization of an order, with its HTTP-01 challenge.
   * - ``POST /chall/ID``
     - Asks the server to validate.
   * - ``POST /finalize/ID``
     - Takes the certificate request.
   * - ``POST /cert/ID``
     - The chain as PEM: the leaf and the intermediate.
   * - ``GET /crl``
     - The revocation list of the present intermediate, DER.

**Requests.** Every POST is a flattened JWS. The protected header has ``alg``, ``nonce``, ``url`` and exactly one of ``jwk`` and ``kid``. ``alg`` is ES256 with a P-256 key, or RS256 with an RSA key of 2048 to 8192 bits, which is the default of certbot. ``url`` must be the URL of the resource. The signature is verified first, and then the nonce is taken out of the table, so a nonce is accepted once. A failure is a problem document (RFC 7807) with an ACME error type, and every answer to a POST carries a new nonce.

**Accounts keep no state.** The account URL is ``URL/account/`` followed by the base64url of the canonical JWK of the account key. A request with ``kid`` is verified with the key inside its ``kid``. The server therefore has no table of accounts, an account survives a restart, and every node that serves the URL knows it. Anybody who reaches the server may register, so a table would have decided nothing. The owner of an order is the thumbprint of the account key. The server sends no terms of service, takes no external account binding and ignores contacts. An account cannot be deactivated and its key cannot be rolled over.

**Orders.** An order has 1 to 16 DNS names in lower case. A wildcard and an IP address are refused, because HTTP-01 proves neither here. Every name must be covered by a suffix of ``allow`` and, when the root has name constraints, be permitted by them. Each name gets one authorization with one HTTP-01 challenge and a token of 128 random bits. Authorizations are not reused between orders.

.. code-block:: text

   pending --all authorizations valid--> ready --finalize--> processing --issued--> valid
      |                                                           |
      +--an authorization invalid--> invalid <--not issued--------+

   Every order is removed one hour after it was created, whatever its state.

**Validation.** When the client answers a challenge, the challenge becomes ``processing`` and a task enters a queue. One thread, ``edge-acme-server``, works the queue, so the request path never waits for a network. The thread resolves the name with the resolver of the system and takes the first address that lies inside a range of ``allow``. A name without such an address is not contacted. It connects to that address and ``http_port``, with 5 seconds to connect and 10 seconds in all, sends ``GET /.well-known/acme-challenge/TOKEN`` with the name as ``Host``, and reads at most 8 KiB of header and 1 KiB of body. The status must be 200. A redirect is a failure: we follow none, so the client of the server cannot send the daemon to another host. The body, without white space at its ends, must be the token, a dot and the thumbprint of the account key. One try is made. A failure makes the challenge, the authorization and the order ``invalid`` and is stored as the ``error`` of the challenge.

The allow list is what keeps the server from being a tool for request forgery. The daemon connects only where the operator said that validation targets live, it connects to the address that it checked and not to the name again, it sends one fixed request, and it returns nothing of the response to the client but a short reason.

**Finalize.** The order must be ``ready``. The certificate request is at most 8 KiB of DER. Its signature must verify with the key it carries: P-256, P-384, or RSA with SHA-256, SHA-384 or SHA-512. Its names must be exactly the names of the order, as dNSName entries. The order becomes ``processing`` and a task enters the same queue. The thread signs the leaf with the present intermediate, for the client's key, with the lifetime ``internal.lifetime`` and the extensions of every local leaf. The order becomes ``valid`` and names the certificate URL.

**Bounds.** Everything that a client can make grow has a bound, and reaching a bound is an answer and never a panic.

.. list-table:: Bounds of the server
   :header-rows: 1
   :widths: 40 20 40

   * - Thing
     - Bound
     - At the bound
   * - Body of a request
     - 32 KiB
     - ``malformed``, status 413
   * - Path of a request
     - 2048 bytes
     - status 404
   * - Nonces
     - 4096, one hour each
     - The oldest nonce is dropped. Its holder receives ``badNonce`` and a new one.
   * - Orders
     - 1024, one hour each
     - ``rateLimited``, status 429, ``Retry-After: 60``
   * - Orders of one account
     - 16
     - ``rateLimited``
   * - Names of an order
     - 16
     - ``malformed``
   * - Queued validations and signings
     - 64
     - ``rateLimited``; the challenge stays ``pending``
   * - Certificate request
     - 8 KiB, 16 names
     - ``badCSR``
   * - Validation response
     - 8 KiB header, 1 KiB body, 10 seconds
     - The challenge is ``invalid``.

**State.** Nonces, orders, authorizations and issued chains live in memory. Accounts are in no table at all. The consequence: a restart forgets the orders that were on their way and the chains that were not downloaded yet. A client then receives ``malformed`` for the order URL it remembers, and its next run starts a new order, which takes a few seconds. Nothing that was issued is lost to the client that already holds it. Nodes that share the storage share the authority and not the orders, so a client must reach one node for the minutes of one order. We chose memory because an order lives minutes, and a table of orders in the storage would add writes to shared files for something that a retry replaces.

**What it does not do.** No ``revokeCert`` and no ``keyChange``: the directory does not name them, and the operator revokes with the admin command. No DNS-01 and no TLS-ALPN-01, so no wildcards. No IP identifiers. No external account binding, no renewal information. The lifetime of a certificate is ``internal.lifetime``, 12 hours by default and two days at most, so a client must renew often. This is the choice of the local authority, and a client that cannot renew daily is better served by the leaf lifetime than by a longer one that no revocation would reach.

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
   * - The guards, the bucket and the tables of issuance on demand keep their bounds.
     - ``crates/ingress/src/auto/demand.rs``: the bucket starts full, gains one token per period, never holds more than its capacity, admits 179 of 7200 tries at 60 per hour, and survives a clock that steps back; a name is queued once; the held names and the queue share ``names``; the queue stops at 64; the denied table stops at 1024 and drops the denial that ends first; a name counts as used only by a handshake after its certificate; a waiter returns when woken and settled, or after ``wait``. ``crates/lb/src/acme/demand.rs``: suffixes, plain host names, the ``ask`` URL, every range.
   * - The first handshake for a guarded name is served its new certificate.
     - ``cmd/sibuna/tests/edge_acme_demand.rs``, the binary against the authority and an ``ask`` server inside the test: one handshake for a name that is not in the file returns the certificate of the authority, with one order and one question; the second handshake asks nothing; ``show certs`` has ``ready on-demand``.
   * - A refused name costs no order and ends the handshake at once.
     - The same test: a name that ``ask`` refuses, twice (one question, the alert within the time of no wait, the log line with the reason), and two names outside ``allow`` (no question). The order count stays 1. With a certificate from a file on the frontend, a refused name gets that certificate and the name of the file asks for nothing.
   * - The rate and the bound on names hold through the binary.
     - ``the_rate_stops_the_next_new_name``: with ``rate: 2`` the third name gets no order and is denied. ``the_bound_on_held_names_...``: with ``names: 1`` a second name is not queued; a name whose order the authority refuses leaves no line and frees its place.
   * - A restart costs no order.
     - The first test restarts the daemon on the same storage: the handshake gets the same certificate, the log says ``loaded from storage``, and neither the authority nor ``ask`` is asked.
   * - A used name is renewed, an unused or withdrawn name is released.
     - ``a_used_name_is_renewed_and_an_unused_one_is_released`` with certificates of 9 seconds: three orders for two names, the line of the unused name leaves, its next handshake orders again. ``a_name_that_ask_no_longer_allows_is_released_at_its_renewal``: the second question is refused, no second order, the handshake then fails.
   * - On demand works with TLS-ALPN-01 and with the local authority.
     - ``a_name_on_demand_is_proved_with_tls_alpn_01_...`` and ``an_internal_name_on_demand_comes_from_the_local_authority``, where a client that trusts only the root of ``show ca`` is served ``app.localhost`` and no ACME directory exists in the storage.
   * - The binding is a correct JWS and is sent when wanted.
     - ``crates/acme/src/order/tests.rs``: the scripted authority checks the header (HS256, the key identifier, the URL of ``newAccount``, no nonce), the payload (the account key) and the MAC, which it computes with ``ring`` and not with our HMAC. A wrong key fails with ACME012 and the reason of the authority, a required binding that is missing fails after the directory alone, and the debug form of a binding hides the key.
   * - A renewal names what it replaces.
     - The same file: ``replaces`` is sent when the directory has ``renewalInfo``, left out when it has none, and the order is placed again without it when the authority answers ``alreadyReplaced``.
   * - Renewal information is read with bounds.
     - ``crates/acme/src/ari.rs``: the identifier of the example certificate of RFC 9773, section 4.1, the example answer of section 4.2, six malformed answers, an answer over 16 KiB, a URL that leaves ``https``, 200 serials whose picks lie in the window and spread, the cap, the floor and the clamp of the pause. ``crates/acme/src/time.rs`` reads RFC 3339 times with fractions and zones and refuses ten malformed ones.
   * - The next authority issues when the first fails.
     - ``cmd/sibuna/tests/edge_acme_issuers.rs`` with two authorities inside the test: the first works and the second receives no signed request; the first refuses and the second issues in the same attempt, with no failure counted, the certificate under the second directory, and a restart that loads it with no order; both refuse and the name is in ``retry`` once. A first authority on a port that nobody listens on is followed by the second.
   * - The binding works through the binary.
     - ``an_account_is_bound_with_the_key_of_the_authority``: no binding and no signed request at all; another key and no order; a file without a key, named in the log; the right key and a certificate. The key and its base64url form are not in the log.
   * - The authority moves the renewal.
     - ``the_authority_moves_the_renewal_...``: a certificate of 60 seconds, due after 40 by our rule, is renewed after its floor of 6 seconds because the first answer lies in the past; the order names the first certificate in ``replaces``; the second answer lies a day ahead and nothing is ordered for 8 seconds; after a restart a past window renews the loaded certificate within 6 seconds. With ``ari: false`` the authority is not asked and ``replaces`` is not sent.
   * - A file without a guard is refused.
     - ``the_check_refuses_on_demand_without_a_guard`` runs ``sibuna check``: ON DEMAND NEEDS A GUARD with its hint, with no ``on_demand`` object and with one that has only a rate.
   * - An OCSP response is checked without I/O and with bounds.
     - ``crates/acme/src/ocsp/tests.rs``, 7 tests with responses that the crate builds: good, revoked and unknown; a window that is not open yet or over; another serial; a signature of another key; a delegate with and without the OCSP signing purpose, outside its validity, and signed by another issuer; three failure statuses of a responder; an empty response and one over 64 KiB; every prefix of a direct and of a delegated response, and six bit patterns flipped at every byte of each, none of which is accepted. ``openssl ocsp`` answers our request with an RSA and with a P-384 key, and we accept its responses, when ``openssl`` is installed.
   * - A response is stapled, refreshed, kept through a restart and removed.
     - ``cmd/sibuna/tests/edge_acme_ocsp.rs`` with a responder inside the test, 4 tests. A client reads the stapled response from the handshake and checks it as a client would. ``openssl s_client -status`` shows it as successful and good. With a validity of 8 seconds a later handshake carries another response. After a restart the stored response is stapled before the responder is asked. A delegated signer is accepted. A responder that answers 503 gives NO OCSP RESPONSE (ACME013) in the log, and the name stays ``ready``.
   * - A revoked certificate staples nothing and is renewed once.
     - ``a_revoked_certificate_gets_no_staple_and_is_renewed``: the column ``ocsp`` says ``revoked``, the handshake has no response, one more order replaces the certificate, and no further order follows while the responder keeps its answer.
   * - Nobody is asked without a responder or with ``ocsp: false``.
     - ``nobody_is_asked_without_a_responder_or_with_ocsp_off``: a leaf without a responder gets no staple and no log line about OCSP, and with ``ocsp: false`` the responder that the leaf names counts no question.
   * - The Cloudflare calls are built and read without I/O.
     - ``crates/acme/src/dns/cloudflare/tests.rs``, 6 tests against answers inside the test: the zone search from the owner upwards and its bound of 8, a named zone asked alone, the body of the create call, the bearer field on every call, a cleanup that deletes the records with our value and no other, a record that exists, a refusal with its code that ends the search, an account without the zone, six bodies that cannot be used, an identifier that could not stand in a URL, a client that fails, and a token that the API repeats, which is not shown. ``crates/acme/src/dns/tests.rs`` reads the token file at each use.
   * - A wildcard is proved through the Cloudflare provider.
     - ``cmd/sibuna/tests/edge_acme_cloudflare.rs`` with an API, a DNS server and an authority inside the test: the nine calls of one order in their order, a certificate for ``*.cf.example.test``, no record left at the API or in the zone, and no token in the log. With another token in the file: DNS PROVIDER FAILED (ACME009) with the message and the code of the API and the hint, and neither token in the log. With ``zone`` only that zone is asked about.
   * - Every provider writes at the target of a delegation.
     - ``a_delegated_challenge_is_written_at_its_target_by_the_hook_and_by_the_update`` in the same file: the hook gets the target as its record and the first owner in ``SIBUNA_ACME_CHALLENGE``, at ``present`` and at ``cleanup``; the update without ``zone`` adds and deletes the record at the target in the other zone; both names get their certificates; with ``follow_cname: false`` the hook gets the first owner. The crate test of the same name also covers a target that is no host name. A resolver on a port where nobody listens gives RECORD NOT VISIBLE (ACME010), and the hook does not run.
   * - ``check`` refuses an ``api`` outside the loopback.
     - ``check_refuses_an_api_that_is_not_http_on_a_loopback_address`` runs ``sibuna check`` with five such URLs. ``crates/lb/src/acme.rs`` refuses eleven, among them a URL with user information and a host name that starts with ``127.0.0.1``.
   * - No test asks the resolver of the system.
     - Every topology with ``dns`` in ``edge_acme.rs`` and ``edge_acme_cloudflare.rs`` sets ``resolver`` to the DNS server of the test.
   * - The constraints are written as verifiers read them.
     - ``crates/acme/src/constraints.rs`` and ``local.rs``: the bytes of a range and its mask, the closing of a kind without an entry, malformed entries. ``openssl verify -x509_strict`` accepts leaves inside a list of both kinds, of suffixes only and of ranges only, for IPv4 and IPv6, and refuses a name outside, a second name outside beside one inside, ``evilcorp.internal`` under ``corp.internal``, and every name of the closed kind. A root is opened with its own list only, and is never rewritten.
   * - The check and the daemon keep the constraints.
     - ``crates/lb/src/acme/internal.rs`` and ``acme.rs``: the stored form of an entry, the label boundary, ranges of both families, the refusal of listed names, of the override and of a name on demand. ``the_root_keeps_its_constraints_and_a_lost_root_is_replaced_at_the_start`` in ``edge_acme.rs``: a rustls client that trusts the root accepts a name and an address inside; a rustls verifier refuses leaves for ``bank.example`` and ``10.0.0.1`` that the keys of the storage signed; ``sibuna check`` prints NAME OUTSIDE CONSTRAINTS; a start with another list logs ACME011 and serves nothing new.
   * - The root file is readable and a lost root is replaced.
     - The same test: ``root.crt`` 0644, ``local`` 0755, ``root.pem`` 0600, ``certs`` 0700. After ``root.pem``, ``root.crt`` and ``intermediate.pem`` are removed, the next start serves leaves that verify with the new root and not with the old one, loads nothing from the storage and issues once for each name. ``a_leaf_of_a_lost_root_is_not_ours`` and the test of the modes cover the same inside the crate, with a storage of the earlier modes.
   * - What a stopped hook started is stopped.
     - ``what_a_stopped_hook_started_is_stopped_with_it``: a background program of the hook that would write a file one second after the timeout writes nothing; the same program of a hook that ends in time writes it. The foreign call refuses the groups 0 and 1.
   * - An update without a key is a decision.
     - ``crates/lb/src/acme.rs``: a remote server without a key is refused, a loopback server of either family and ``unsigned: true`` are accepted, ``unsigned`` beside a key is refused. The diagnostic UPDATE NOT SIGNED has a unit test.
   * - The record of a name that left is cleaned.
     - ``the_record_of_a_name_that_left_the_file_is_cleaned_at_once_and_at_the_start``: a hook that fails leaves the record remembered; after the hook works, a reload that drops the name and, in a second storage, a restart without the name each run ``cleanup`` once for the record and forget it. ``the_presented_records_of_the_store_are_listed`` covers the listing.
   * - A key on P-384 is requested, issued, stored and served.
     - ``crates/acme``: the signature of a P-384 key verifies with SHA-384, the key survives its PEM form, ``openssl req -verify`` accepts the request of either curve and names the curve and the signature, ``openssl verify -x509_strict`` accepts a local chain with a P-384 leaf. ``a_certificate_key_on_p384_is_ordered_issued_stored_and_served``: with ``key: "p384"`` a rustls client completes the handshake with a P-384 leaf of the test authority and of the local authority, and after a restart with the stored keys, with one order in all.
   * - The thread starts again after a panic.
     - ``crates/ingress/src/auto/supervise.rs``: a thread that panics once reports the panic with a restart in 5 seconds, waits them, and then issues the certificate of the name; the delays are 5, 10, 20, 40, 80, 160 and 300 seconds. The panic is made by a flag that exists in the test build of the crate only. The line ``ACME014`` of the daemon was not seen through the binary, which has no way to make the thread panic.
   * - The quick start names the issuer.
     - ``crates/lb/src/quick.rs`` and ``cmd/sibuna/src/edge/quick.rs``: ``--acme-issuer internal`` writes ``issuer: "internal"`` and sends a public name to the local authority; another word is refused.
   * - The binary tests do not race for a port.
     - The DNS server of the tests binds TCP first, then UDP, and tries 64 ports. Each of the five suites ran three times, and all five ran together once, with no failure.

Known gaps
~~~~~~~~~~

#. DNS-01 has three providers: the hook, RFC 2136 and Cloudflare. Every other vendor goes through the hook. One daemon has one provider for all its names.
#. The Cloudflare provider was never run against Cloudflare. Its requests and the answers it expects follow the documentation of the API, version 4, and are tested against a server inside the test only.
#. The Cloudflare provider reads the first page of each list: a cleanup deletes at most 16 records with our value. The zone search asks about 8 names at most, and a deeper owner needs ``zone``. Each call opens a connection and a thread of its own. ``sibuna lb`` has no flag for it.
#. The delegation is read from the resolver without DNSSEC. Whoever can forge its answers moves the record to another name that the provider can write. An answer with an error code and no CNAME record counts as no delegation, and only silence fails the attempt. Without ``resolver`` the first resolver of the system is asked.
#. The search for the zone and its servers is tested inside the crate only, with a server on a loopback port. The tests through the binary and the run against Pebble name the servers with ``servers``, because the search asks port 53.
#. The check asks every address of every name server, also an IPv6 address on a node without IPv6. Such a server does not answer and is left out. A zone whose servers all fail to answer fails the check.
#. A hook that runs too long is stopped with its process group. A process that left the group, as a daemon does, is not reached. On a system without process groups the hook alone is stopped.
#. An unsigned RFC 2136 update trusts the answer by the address and the identifier only. It is accepted for a loopback server, and elsewhere only with ``unsigned: true``.
#. The record of a name that left the file is cleaned while the ACME source is open. A daemon whose last name of an ACME authority left before a restart does not open that source, and the record stays until such a name returns.
#. The local authority publishes no revocation list and never installs its root. The section "The local authority" of the third part says why short lifetimes stand in for the list.
#. ``root.crt`` is readable by everyone, and the storage directory above it is not, unless the operator opens it. ``show ca`` prints the root for a user who may use the admin socket.
#. The local authority is not an ACME server for other machines. Not built: it needs a server for the directory, nonces, accounts, orders, authorizations with outbound validation and certificates, with the verification of every JWS.
#. The name constraints belong to the root. A changed list needs a new root, which every client installs again. The local authority does not compare a name with the list when it signs; the check of the file and the clients do. A name under ``invalid`` passes a root whose list has ranges only, and no host has such a name.
#. The constraints were verified with OpenSSL 3 and with the verifier of rustls. No browser and no other library was tried.
#. ``sibuna lb`` has ``--acme-dns-hook``, ``--acme-issuer`` and ``--acme-on-demand-ask``. The RFC 2136 provider, Cloudflare, the constraints, ``key`` and the check settings need a file.
#. On demand: a QUIC handshake does not wait. HTTP/3 uses a certificate once a TCP handshake has obtained it.
#. On demand: one order runs at a time. Of many new names at once, the later handshakes time out and find their certificates at the next try.
#. On demand: the held names, the denials and the bucket are not stored. Each start has a full bucket, so a daemon in a restart loop may order ``rate`` new names per start. A denial that an earlier failure earned is kept through the retry file of the name.
#. On demand: no bound per client. Whoever can choose names that the guards allow, for example below a suffix of ``allow`` without ``ask``, spends the rate and fills the table until the unused names are released at their renewal. A flood of distinct names that pass the suffixes fills the queue of 64, and a new name is not queued meanwhile.
#. On demand: the guards cannot change in a reload. A held name is served on every frontend with ``on_demand``, with the issuer that the first asking frontend selected. The certificate of a released name stays in the storage until somebody removes it.
#. On demand: ``ask`` is a plain GET with no credentials, one try and no cache of an allowance beyond the life of the certificate. It was not run against Pebble, and not with DNS-01.
#. No revocation by us. A certificate from a file gets no staple.
#. Stapling: nodes that share the storage each ask the responder. A node finds the response of another only when it loads the certificate.
#. Stapling: a response with ``thisUpdate`` after our clock is refused, with no tolerance. A responder whose clock is ahead is asked again after the retry delay.
#. Stapling: only ``http`` responders, one question per certificate, no nonce. The responder is reached through the client of the first authority.
#. Stapling: the end of the window of a stapled response and the status ``unknown`` are tested inside the crate and not through the binary. Stapling was not run against Pebble.
#. Every attempt starts with the first authority. An authority that has failed for days is still asked first, and each attempt waits for its failure before the next one is asked.
#. The challenge type of ``auto`` alternates with the failed attempts of a name, not per authority.
#. All authorities share one account key. A key that one authority bans is banned for that authority only, but we have no key of another kind to offer.
#. A changed binding does not update an account that exists. An account that was registered without a binding stays unbound.
#. The answers about a renewal are not stored. After a restart the rule of two thirds holds until the first answer, which is asked for at once.
#. A failure to ask about a renewal is silent. ``show certs`` then shows the time of the last answer, or of the rule of two thirds.
#. The certificate identifier needs the authority key identifier in the leaf. A certificate without that extension is not asked about.
#. ``sibuna lb`` has no flag for ``fallback``, ``eab`` and ``ari``.
#. Certificate keys are ECDSA on P-256 or P-384. No RSA keys: ``ring`` cannot make one. The account key and the keys of the local authority are on P-256 with no setting.
#. A changed ``email`` does not update an existing account.
#. The lock compares the modification time of a file with the clock of the node. Nodes whose clocks differ by more than ten minutes may order twice. Two containers with one host name and separate process tables may also order twice, because each takes the other's process for gone. A double order costs one certificate and corrupts nothing.
#. One certificate per name. A frontend with many names of one registered domain spends the weekly limit of Let's Encrypt for that domain faster than one certificate with many names would.
#. The supervisor catches a panic of the certificate thread. It does not notice a thread that hangs: every step of the thread has a time limit of its own, and nothing watches them from outside. The restart was tested inside the crate, not through the binary.
#. A stored certificate that has expired is not served after a restart. A running daemon keeps serving the certificate it has, also past its expiry.
#. ``sibuna lb`` has no flag for ``ca_file``, ``challenge`` and ``redirect``. A private authority needs a file.
#. The answers of automatic HTTPS have the verdict ``-`` in the access log. They have no verdict word of their own.
#. With TLS-ALPN-01 and several nodes, the authority must reach the node that placed the order. Only HTTP-01 is answered by every node.
#. The translated catalogs of the book do not have the new section yet.

Formal model
~~~~~~~~~~~~

``docs/sid/assets/automatic-https.lean`` models fourteen things with Lean 4.19.0. The order machine is a phase and a budget. An answer is good, a repetition, a skip over the challenge, or bad. We prove that a step never moves a phase backwards, that every step of a live order takes budget or ends the order, that an order of budget :math:`n` is over after :math:`n + 1` steps whatever the authority answers, and that ``Done`` is entered only from ``Download``. For the schedule we prove that the renewal time lies in :math:`[b, e)` for :math:`b < e`. For the retry delay we prove that it is at least the first delay, at most one day, and monotone in the number of failures. For the table we prove that a failed order leaves the served certificate unchanged, that a served name never loses its certificate, and that the expiry of a served certificate never decreases. For the issuer we prove that no name is refused when the frontend states no issuer, that a public authority receives public names only, that no ACME authority is asked for an address, and that ``internal`` always means the local authority. For wildcards, with a host as its list of labels, we prove that ``*.parent`` covers a host of one more label, that it covers neither the parent nor a host of two more labels, that a covered host has exactly one label more, and that the choice among an exact certificate, a wildcard and a file takes them in this order. For the propagation check we prove that it asks at most :math:`\lfloor t / p \rfloor + 1` times for a timeout :math:`t` and a pause :math:`p`, that its pauses sum to at most :math:`t`, that a record which shows in a round the check reaches is found, and that a record which never shows fails the check. For issuance on demand the bucket is a capacity and a count of tokens, and a run is a list of gains, one before each name that asks. We prove that a refill never exceeds the capacity, that an empty bucket admits nothing, that a step conserves tokens, and that a run admits at most the tokens at its start plus the gains, which is the capacity plus the refills for a bucket that starts full. The decision takes the answers of the seven guards. We prove that a name is ordered only when the file has a guard and every guard passes, that a file without a guard orders nothing, and that a refusal of ``ask`` or an empty bucket orders nothing. The tables are two counts with four events. We prove that no event takes the held names and the queue together over the bound, and that any run of events holds at most ``names`` names. For the authorities, an attempt is a function from the index of an authority to whether it issues. We prove that an attempt over :math:`n` authorities asks at most :math:`n`, that the authority which issued is a listed one, that every authority before it failed and none after it was asked, that the attempt fails after :math:`n` questions when none issues, and that it succeeds when one issues. For the renewal information we prove that the pick lies in :math:`[s, e)`, that the renewal time is at most four fifths of the lifetime and so before the expiry for every answer, that a past window makes a certificate without a floor due, that a floor below the cap is respected, and that an answer inside both bounds is taken as it is. For stapling, an answer is a status and a window :math:`[t, n)`. We prove that a response is stapled only when it says good and :math:`t \le now < n`, that ``revoked`` and ``unknown`` never staple, that the next question lies after now, that it lies inside the window, and that it comes before the end when two seconds are left. For the zone search a name is its list of labels and the account is a predicate on names. We prove that the search asks at most ``limit`` questions and fewer than the owner has labels, that every name it asks about ends the owner and has two labels at least, that a zone it finds is one of the account, that no name of the account among those asked is longer than the zone it finds, and that a search which finds nothing asked only about names that the account does not have. For the constraints of the local root, with a host as its labels from the top-level label down and an address as a number, we prove that the empty list permits every name, that a list permits exactly the names that an entry covers, that a suffix covers itself and every name below a name it covers, that a covered name is never shorter than the suffix, that the cover compares whole labels, and that a list of suffixes permits no address and a list of ranges no host. For the restart of the thread we prove that the delay is at least 5 seconds, at most 300, and never shrinks with the number of panics. The JSON, the DNS messages, the signatures, the sockets and the files are outside the model. Tests cover them.

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

A fourth run, on 2026-11-25, used the list of authorities, the binding and the renewal information. Pebble ran with ``externalAccountBindingRequired``, one MAC key under ``externalAccountMACKeys``, no nonce rejection and a ``validityPeriod`` of 60 seconds. Its directory offers ``renewalInfo``. The file named ``https://127.0.0.1:24999/dir`` first, a port that nobody listened on, and Pebble under ``fallback`` with its ``ca_file`` and ``eab``. The name was ``sibuna-a.localhost`` with HTTP-01.

.. list-table:: Three runs with the binding
   :header-rows: 1
   :widths: 30 70

   * - Observation
     - Result
   * - The fallback
     - Each attempt logged AUTHORITY UNREACHABLE for the first directory with "The daemon asks https://localhost:24000/dir now", and Pebble issued. ``sibuna_edge_acme_failures_total 0``.
   * - The binding
     - Pebble registered the account and issued. ``openssl s_client -CAfile`` with Pebble's root: ``Verify return code: 0 (ok)``.
   * - Renewal information
     - The daemon asked ``renewalInfo`` every 5 to 6 seconds, ten times in the run. The certificate was renewed 30 seconds after its issue, where the rule of two thirds says 40. Pebble logged that the new order "is a replacement of" the first and marked the first as replaced.
   * - A wrong key
     - A second run with another key in the file: ACCOUNT NOT BOUND (ACME012) with Pebble's reason, "external account binding JWS verification error". No certificate.
   * - No binding
     - A third run without ``eab``: ACCOUNT NOT BOUND (ACME012) "registers an account only with an external account binding". Pebble's log has no request to ``newNonce``, ``newAccount`` or ``newOrder``.

The storage of the first run held the account key under the first directory and the certificate under ``localhost-24000-dir``.

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
- 2026-11-25. Author's review of the implementation of on-demand issuance. It found eight defects, five while the code was read against this record before its first run and three afterwards, and fixed each. (1) The thread took the queued names out of the queue and decided them afterwards; a handshake that looked in between saw a name that was neither queued nor held and stopped waiting. A name now stays queued until it is held or denied. (2) The waiting handshakes were woken after the pause of one second that follows every order; they are now woken before it. (3) This record said that a name which fails is released. A failed renewal would then have taken a serving certificate away. Only a name without a certificate is released. (4) This record bounded the wait by the handshake deadline, which is 15 seconds; the default wait of 20 would never have been reached. The wait now stands between two deadlines, and the record states the sum. (5) A name that was held again after a restart, with a retry file that puts its next attempt ahead, would have sat in the table with no order while every handshake for it waited the full time. It is released and denied until that attempt. (6) The renewal of a held name never asked ``ask`` again, so a name that the operator had withdrawn was renewed for as long as a client named it. The renewal now asks. A refusal releases the name, and silence keeps the certificate. A binary test covers it. (7) A release left no trace. It is logged with its reason. (8) The book still ended its section with a paragraph that denied the local authority, DNS-01 and issuance on demand. It is gone. The tests found no failure of their own: all eight binary tests passed at their first run and in three further runs. The review recorded the six gaps that start with "On demand".
- 2026-11-25. Author's review of the implementation of the authorities, the binding and the renewal information, with the tests and a fourth Pebble run as instruments. The binary tests and the Pebble run passed at their first run; the review found five defects of the draft and of the code by reading both against each other, and fixed each. (1) A certificate that was installed asked for its renewal information "at once" by a time of zero, also a certificate of the local authority, which is never asked; the thread would have woken every second for ever on a node with a local name. A local certificate now has no question time, and a unit test covers the times. (2) An answer of the authority set the next attempt to the renewal time as it came. A certificate whose cap lies in the past when it is issued, or an authority that always answers with a past window, would have been ordered again at every round; the floor of a certificate that this process obtained now bounds the next attempt too. (3) The pause between two questions had a lower bound of one hour, so a certificate that lives minutes was asked about once; the pause is now at most a tenth of the lifetime. (4) The draft gave each authority an account key of its own. A node that shares the storage answers an HTTP-01 challenge of another node from one thumbprint, and would have answered wrongly for a fallback authority; all accounts now use the key of the first authority, and the record says so. (5) An order with ``replaces`` that the authority refuses would have failed the renewal for as long as the authority remembers the certificate as replaced; the order is now placed once more without the member. The design text gained the floor, the pause of short certificates, the shared key, the second order without ``replaces``, the code ACME012 and the opening of every authority at the start. The line at the start of the daemon names the number of fallback authorities. The review recorded eight gaps.
- 2026-11-25. Author's review of the implementation of OCSP stapling. It found six defects and fixed each. (1) The certificates inside a response were read under a wrapper of any tag. The test that flips every bit of a response found a flipped tag that still verified. The wrapper must now be a SEQUENCE. (2) The next question was computed as half of the remaining time from now, which for a fresh response lies after the middle of the window. It is now the middle, and half of the rest only when the middle has passed. The Lean model has the function and its three bounds. (3) A renewal answer of the authority that arrived after a ``revoked`` moved the renewal back into the future. The answer now leaves a renewal alone that a revocation made due. (4) The new column of ``show certs`` moved the error column, and three test files and one unit test read the old position. One commit went in with such a failing expectation and was amended before anything followed it. (5) The test with ``openssl`` read the clock before the response was made, so the response began in the future by our strict rule. The clock is read afterwards. (6) Two tests of the store, one of them new, shared a scratch directory and failed when they ran together. The record differs from the first draft where the section "OCSP stapling" says so. The four binary tests passed in three consecutive runs.
- 2026-11-25. Author's review of the implementation of the Cloudflare provider and of the delegation. It found four defects and fixed each. (1) The DNS tests through the binary set ``servers`` and no ``resolver``. With the walk before ``present`` they would have asked the resolver of this machine for names of the tests. Each topology now names the DNS server of the test as its resolver, and the check looked for further ones and found none. (2) The search asked about 16 names with 30 seconds each. One record could then have taken eight minutes inside an order that allows its provider two. The bound is 8 names and 10 seconds, and the time of an order includes the walk. (3) The target of the delegation went from a DNS answer to the arguments of the hook as it came. A label may hold any byte, and a hook is often a shell script. A target that is not a host name now fails the attempt, and a crate test presents one with a command substitution. (4) A failure of the API carried the hint of the hook. It has a hint of its own that names the token file and the rights. The design changed in the places that the section "Cloudflare and the delegation" lists. The check after ``present`` stays lenient about a silent resolver, because the servers of the zone may still answer. The five binary tests passed at their first run.
- 2026-11-25. Sixth and seventh merge with ``main``, after the cluster work of SID 0023 and the second round of SID 0020. One file conflicted, ``crates/ingress/src/lib.rs``, by adjacent additions: the ``Listener`` of issuance on demand and the type ``Refusals`` of ``main`` both stay.
- 2026-11-25. A test of ``main`` once failed with "address in use" in ``edge_acme.rs``. The line was the start of the DNS server of the tests, which bound a UDP port and then the same TCP port, 16 times at most. Tests that run beside it take and release TCP ports all the time, so the TCP port was the one that was taken. The server now binds TCP first and then UDP, and tries 64 ports. The start of the daemon in the five suites already chose new ports after a failed start, and already waited for the line "listeners ready" and not for the word "ready".
- 2026-11-25. Author's review of the implementation of the last part: the local authority and the smaller changes. It found seven defects and changed the code or this record for each. (1) The draft closed nothing: a list of suffixes left every address open, because X.509 constrains each kind of name by itself. A kind without an entry is now closed, and OpenSSL and rustls both refuse the other kind. (2) The first test with OpenSSL refused a leaf for ``10.1.2.3`` under a list of ranges: the common name of the leaf was the address, and OpenSSL holds a common name that looks like a host name against the DNS subtrees. The common name of an address leaf is now ``address 10.1.2.3``. (3) The draft said "a stored leaf whose chain does not end at the present root is replaced" and the code would have kept the intermediate of the lost root, which has the right name and a valid life; a new leaf would then have been signed by it and refused by every client of the new root. An intermediate is now ours only when the present root signed it. (4) The gap list said that a panic of the thread leaves the daemon without renewals. That was right, and the same list did not say that the challenge answers of the dead order stayed in the tables; the supervisor withdraws them. (5) The cleanup of a name that left the file was first written to run once per change of the names. A provider that is down at that moment would have left the record for ever, so a failed cleanup is tried again after two minutes. (6) The draft offered ``unsigned: true`` beside a key without saying what it means. It is refused. (7) The kill of the process group takes the number of the hook as the group. The numbers 0 and 1 would name our own group and every process; the foreign call refuses them, with a test. The design text of the third part changed where the list above says so. Not built, with the reasons in the text: a revocation list, an ACME server, RSA keys, and flags of ``sibuna lb`` for RFC 2136. The new binary tests passed at their first run; the crate test with OpenSSL found defect 2.
- 2026-11-25. Eighth merge with ``main``, after the last round of SID 0019. No file conflicted. The full test suite ran on the tree of this merge.
- 2026-11-25. Fourth part, first draft, on the branch ``sid-0021-local-authority``: RSA keys through the ``openssl`` program, a revocation list of the local authority with an admin command, and an ACME server in front of the local authority.
- 2026-11-25. Author's review of the fourth part before implementation. It found eight faults and changed the draft for each. (1) The draft made an RSA key when a certificate was due and found a missing ``openssl`` then, hours after the start; the check of the file and the start now run the program once. (2) The draft signed one list with the present intermediate. A leaf of the replaced intermediate would have had no list that its issuer signed, and a verifier that checks lists refuses such a leaf; the replaced intermediate is now kept until it expires and signs a list of its own. (3) The draft kept the revoked entries in one file. The admin thread, the certificate thread and a second node would have rewritten it, and one of two revocations at the same moment would have been lost; an entry is now a file of its own. (4) The draft revoked by serial only what the storage holds. A certificate that the ACME server issued is in no storage, so a serial that is unknown is now revoked too, for the longest life of a leaf. (5) The draft gave the ACME server a listener of its own, which needs a TLS stack and a certificate beside the frontends; the server now answers on the frontends. (6) The draft kept a table of accounts in memory. Every restart would have forgotten the accounts, and no common client registers again by itself; the account URL now carries the key, and no table exists. (7) The draft resolved the name and then connected by name. A name that resolves differently the second time would have led the daemon outside ``allow``; the validation connects to the address that it checked. (8) The draft gave the server a lifetime key of its own, up to the life of the intermediate. Leaves of more than two days would have outlived two replacements of the intermediate and so the lists; the server uses ``internal.lifetime``.

References
----------

- SID 0015, SID 0016, SID 0017 and SID 0018.
- Caddy, "Automatic HTTPS", https://caddyserver.com/docs/automatic-https
- RFC 8555, "Automatic Certificate Management Environment (ACME)".
- RFC 8737, "ACME TLS Application-Layer Protocol Negotiation (ALPN) Challenge Extension".
- RFC 9773, "ACME Renewal Information (ARI) Extension".
- RFC 7515, "JSON Web Signature", RFC 7518, "JSON Web Algorithms", and RFC 7638, "JSON Web Key Thumbprint".
- RFC 2986, "PKCS #10: Certification Request Syntax Specification".
- Let's Encrypt, "Rate Limits", https://letsencrypt.org/docs/rate-limits/

.. rubric:: Lifecycle event

::

   2026-11-24: prediscussion -> discussion. First draft by the author; open
   for discussion before implementation
   2026-11-24: implemented on the branch sid-0021-automatic-https; the record
   stays in discussion until the branch is reviewed and merged
