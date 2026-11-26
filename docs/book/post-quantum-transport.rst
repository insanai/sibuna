Migrating a website to post-quantum transport
=============================================

A customer books a hospital appointment on a website whose records must stay confidential for years. Someone who records the encrypted request today might be able to read it later by breaking the classical key exchange. We can keep the website's public name and point it at Sibuna. The customer's browser and Sibuna can then agree a hybrid key. From Sibuna to the hospital application, we choose how to protect a second connection.

What the change protects
------------------------

In TLS 1.3, X25519MLKEM768 combines X25519 with ML-KEM-768. When the endpoints negotiate this group, a recording of that connection stays confidential while either component remains secure. The certificate still authenticates the handshake with a classical signature. A client that offers only X25519 can still connect. A TCP passthrough listener leaves TLS negotiation to the origin. If a CDN terminates TLS first, the CDN controls the browser's handshake. See `RFC 10024`_.

Deadlines at a glance
---------------------

The OpenSSL survey is a starting point. We match each service to its owner, jurisdiction and contract before choosing a deadline. These examples were checked on 26 November 2026. See the `OpenSSL survey`_.

.. typst-diagram:: diagrams/pq-deadlines.typ
   :caption: Selected milestones for the systems covered below.
   :alt: The EU roadmap starts in 2026. Singapore calls for plans in 2027. US and EU milestones follow in 2030, US and Singapore milestones in 2031, and EU and Singapore targets in 2035.

.. list-table::
   :header-rows: 1
   :widths: 22 78

   * - Milestones
     - Systems covered
   * - 2030, 2031
     - **United States.** Executive Order 14412 directs federal agencies to migrate designated high-value assets and high-impact systems to post-quantum key establishment by 31 December 2030 and digital signatures by 31 December 2031. National Security Systems follow separate requirements. A supplier checks the clauses in its contract. See `EO 14412`_ and `OMB M-26-15`_.
   * - 2026, 2030, 2035
     - **European Union.** The NIS Cooperation Group roadmap recommends that Member States start the transition by the end of 2026. It targets high-risk uses by the end of 2030, medium-risk uses by the end of 2035 and as many low-risk uses as feasible by then. We identify the risk class and the national or sector rules for our service. See the `EU roadmap`_.
   * - 2027, 2031, 2035
     - **Singapore.** CSA expects designated Critical Information Infrastructure owners to submit plans by 31 March 2027 and complete migration by 31 December 2031. Its public advisory encourages other exposed organisations to plan by the end of 2027 and migrate by 2035. We record which category applies to the system. See the `CSA advisory`_ and `CSA CII guidance`_.

From a deadline to a deployment
-------------------------------

We start with a service covered by the policy and follow one request from its client to the application. We record who owns each TLS endpoint and how long the request must stay confidential. The first example changes the public connection. The second also authenticates the connection to the website. In the third, an older device initiates the request and Sibuna protects its outgoing traffic.

Three deployments
-----------------

The examples use HTTP/1.1 to make both connections easy to inspect. We run each file separately from the directory containing its policy and certificates. The policy permits the diagnostic path and challenges other requests. We substitute our application policy before deployment.

.. literalinclude:: examples/pq/probe-policy.json
   :language: json

A website with a local HTTP origin
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

We save this file as ``website.jlv`` and the policy above as ``probe-policy.json``. The file ``edge.pem`` contains the certificate chain for ``edge.example.test`` and its private key. Our HTTP application answers ``/status`` on port 29443. Plaintext stays on loopback. For a remote device we place the gateway on its host or identify and protect the private link separately.

.. typst-diagram:: diagrams/pq-website.typ
   :caption: A customer reaches a website that serves HTTP on the same host as Sibuna.
   :alt: The browser negotiates hybrid TLS with Sibuna. Sibuna forwards the request locally and sends the response through the browser's encrypted connection.

The frontend's ``tls.crt`` makes Sibuna the TLS endpoint. The ``default_backend`` selects the pool named ``app``. Its loopback address keeps the HTTP request on this host. For public service we bind the frontend to the public interface and provision a certificate for the site's actual name.

.. literalinclude:: examples/pq/website.jlv
   :language: text

.. code-block:: sh

   sibuna check -f website.jlv
   sibuna --config-file website.jlv

An organisation with an HTTPS origin
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

We save this file as ``secure-origin.jlv``. The origin serves HTTPS on port 29443. Its certificate names ``origin.example.test``, and ``ca.pem`` contains the issuing CA certificate. Sibuna verifies the origin and negotiates a separate key exchange. An older origin can use X25519 while the public connection uses the hybrid group. Once the origin supports the hybrid group, the same configuration can protect both connections.

.. typst-diagram:: diagrams/pq-secure-origin.typ
   :caption: Sibuna accepts the customer's TLS connection and opens another to the website.
   :alt: After the browser connects, Sibuna negotiates TLS with the website and verifies its identity before forwarding the request. The two connections can negotiate different groups.

In the backend, ``servers`` gives the address to dial, ``tls.sni`` gives the name to authenticate and ``tls.ca_file`` supplies the trust anchor. These settings let us route to an IP address while verifying the certificate against a DNS name.

.. literalinclude:: examples/pq/secure-origin.jlv
   :language: text

An older device that makes requests
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Here the device is the client. We save the file as ``device-gateway.jlv`` and run Sibuna beside it. The device sends HTTP to the loopback listener. Sibuna opens authenticated TLS to the central service. Only that outgoing connection can negotiate the hybrid group. The listener must stay reachable only by the intended client. If the device already supports classical HTTPS, the preceding configuration also accepts it on the client side.

.. typst-diagram:: diagrams/pq-device.typ
   :caption: A device uses its local gateway to call a central service.
   :alt: The device sends local HTTP to Sibuna. Sibuna verifies the central service and uses a hybrid connection for the network leg. The reply returns to the device over local HTTP.

.. literalinclude:: examples/pq/device-gateway.jlv
   :language: text

Verify the negotiated group
---------------------------

We use OpenSSL 3.5 or later to make a fresh connection to the website. Here ``ca.pem`` also trusts the issuer of the public test certificate. Restricting the probe to one group makes the result unambiguous. We check the certificate verification, the negotiated group and the HTTP response.

.. code-block:: sh

   printf 'GET /status HTTP/1.1\r\nHost: edge.example.test\r\nConnection: close\r\n\r\n' |
     openssl s_client -connect 127.0.0.1:28443 -servername edge.example.test \
       -verify_hostname edge.example.test -CAfile ca.pem -verify_return_error \
       -tls1_3 -groups X25519MLKEM768 -alpn http/1.1 -brief -ign_eof

Certificate verification checks the frontend's identity. The negotiated group tells us which key exchange protected this session. We check the response body for the application's expected status. To collect equivalent evidence for the backend, we observe the connection made by Sibuna at the origin. An independent probe to the origin only shows what that probe could negotiate.

With RC6 and OpenSSL 3.5.7, we restricted the test origin to one group at a time. The table records the results. A classical client or origin can complete a request even when only the other connection uses hybrid keys.

.. list-table:: Observations for one request to ``/status``
   :header-rows: 1
   :widths: 32 36 32

   * - Client to Sibuna
     - Sibuna to application
     - HTTP result
   * - ``X25519MLKEM768``
     - HTTP on loopback
     - ``200``
   * - ``X25519MLKEM768``
     - ``X25519``
     - ``200``
   * - ``X25519MLKEM768``
     - ``X25519MLKEM768``
     - ``200``
   * - ``X25519``
     - ``X25519MLKEM768``
     - ``200``
   * - HTTP on loopback
     - ``X25519MLKEM768``
     - ``200``
   * - ``X25519MLKEM768``
     - Origin name mismatch
     - ``502``

We record the date, endpoints, certificate identities, negotiated groups and any plaintext segments for each service. Offering the group permits classical fallback. A policy that requires hybrid-only sessions needs enforcement and evidence on every covered connection. Post-quantum signatures, FIPS 140 module validation and SQLx database TLS each need separate evidence. An edge handshake establishes one item in that inventory.

.. _RFC 10024: https://www.rfc-editor.org/rfc/rfc10024.html
.. _OpenSSL survey: https://openssl-corporation.org/blog/post-quantum-cryptography-now-has-deadlines.html
.. _EO 14412: https://www.federalregister.gov/documents/2026/06/25/2026-12909/securing-the-nation-against-advanced-cryptographic-attacks
.. _OMB M-26-15: https://www.whitehouse.gov/wp-content/uploads/2026/06/M-26-15-Execution-of-the-Migration-to-Post-Quantum-Cryptography.pdf
.. _EU roadmap: https://digital-strategy.ec.europa.eu/en/library/coordinated-implementation-roadmap-transition-post-quantum-cryptography
.. _CSA advisory: https://www.csa.gov.sg/alerts-and-advisories/advisories/advisory-on-quantum-safe-migration-for-organisations/
.. _CSA CII guidance: https://isomer-user-content.by.gov.sg/36/226284f1-4fbd-4a0f-9ec3-4cc0700cb6b0/Annex%20A%20-%20Guidance%20on%20Quantum-safe%20Requirements%20and%20Migration%20Plan%20Outline.pdf
