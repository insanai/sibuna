What is Sibuna?
===============

A passenger opens a railway timetable and asks for the next departure. We run two copies of the timetable application so that one can answer while the other restarts. We give passengers one public address. Sibuna listens at that address, receives the request and chooses where it goes. In this role it is a load balancer. It can also examine web requests and decide which ones may reach the application. In that role it is a web application firewall.

One request through the edge
----------------------------

The browser opens an encrypted connection to the timetable's public name. Sibuna presents a certificate for that name. If the browser trusts the certificate, the two establish a secure connection. Sibuna can obtain and renew public certificates through Let's Encrypt. For an internal service, it can issue a certificate from a local authority whose root we install on the clients.

The address where Sibuna accepts traffic is a frontend. Once Sibuna has received the HTTP request, it can read the host and path. A route sends timetable requests to a pool containing our two application servers. These servers are the origins. For an admitted request, Sibuna chooses a healthy origin from the pool, forwards the request and returns its answer to the passenger.

.. code-block:: text

   Browser -- HTTPS --> Sibuna --+-- HTTP/1.1 --> A
                                 |
                                 +-- HTTP/1.1 --> B

The two connections can use different protocols. A browser might speak HTTP/3 to Sibuna while the timetable application speaks HTTP/1.1. An internal gRPC client needs an HTTP/2 route to a compatible service. A plain TCP stream or UDP datagram can also go to a pool. In those cases Sibuna can forward traffic without reading a web page or applying rules to an HTTP path.

Who gets through?
-----------------

Suppose a script asks for the timetable faster than the application can compute it. Adding a second origin spreads the work across two machines. A firewall rule can instead refuse a request or ask the browser to solve a puzzle before either origin does the work. After Sibuna verifies the answer, it issues a signed session that the browser can present on later visits.

Gate handles admission and local rate limits. Shield also inspects HTTP requests for patterns such as an attempted injection. We can apply the shield to the passenger website and give a machine client its own route. That client then uses the authentication required by its service.

From one node to a cluster
--------------------------

If one timetable server goes down and its health check fails, the edge can send new requests to the other server. If the edge itself goes down, the surviving origin cannot answer through that edge. We can put a second Sibuna node behind the same public name and arrange for the network to direct clients to the available node.

The nodes each forward their own traffic. Through a mesh they can exchange routing configurations, bans and information about which origin a client previously used. A passenger's next connection may reach a different edge. This is why the cluster chapters ask which decisions a node can make alone and which facts its peers need to know.

Before we turn the page, suppose both timetable servers are healthy and a passenger receives a browser challenge. Which component made that decision? Now suppose the passenger is admitted but one server has failed its health check. Which decision changes? These are the two questions we will follow through the book.
