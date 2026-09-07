#import "theme.typ": *
#import "figures.typ": *

#part_page("VIII", [Production Operations & Integration Playbook], [
  We detail deployment topologies, forward-auth integration recipes for Nginx, Caddy, and
  Traefik, container packaging, and live operational tuning under attack.
])

= Deployment Topologies

#objectives([
  By the end of this chapter, you should be able to deploy Sibuna as an autonomous reverse proxy,
  configure it as a forward-auth subrequest validator behind enterprise ingress controllers,
  and write production Nginx, Caddy, and Traefik routing specifications.
])

== Mode 1: Autonomous Reverse Proxy

In Autonomous Reverse Proxy mode, Sibuna sits directly at the network perimeter, terminates
incoming HTTP/1.1 connections on its listening port, enforces bot policies and PoW challenges,
and transparently streams authorized traffic to an internal upstream application server.

#book_figure([Request routing in Autonomous Reverse Proxy mode], pipeline_flow())

```bash
# Launch Sibuna as a reverse proxy on port 80 forwarding to port 3000
sibuna --port 80 --host 0.0.0.0 --upstream-host 127.0.0.1 --upstream-port 3000 --difficulty 4
```

== Mode 2: Forward-Auth Subrequest Validator

In modern cloud architectures, organizations frequently standardize on centralized ingress
controllers (such as Nginx, Caddy, Traefik, or Envoy) to handle TLS certificates, HTTP/2, and
global routing.

Sibuna supports *Forward-Auth Mode* (`--mode forward_auth`), acting as a subrequest validation
engine. In this topology:
1. Ingress receives the client request.
2. Ingress sends a lightweight internal subrequest to Sibuna.
3. If the request carries a valid `__sibuna_token` cookie or matches an allowlisted policy,
   Sibuna responds with `HTTP 200 OK`. Ingress forwards the original request to upstream.
4. If authentication fails, Sibuna responds with `HTTP 401 Unauthorized`. Ingress intercepts
   this response and displays Sibuna's interstitial challenge page.

=== Nginx Configuration (`auth_request`)

```nginx
server {
    listen 443 ssl;
    server_name example.com;

    location / {
        auth_request /__sibuna_auth;
        auth_request_set $auth_cookie $upstream_http_set_cookie;
        add_header Set-Cookie $auth_cookie;

        error_page 401 = @sibuna_challenge;
        proxy_pass http://127.0.0.1:3000;
    }

    location = /__sibuna_auth {
        internal;
        proxy_pass http://127.0.0.1:8080/;
        proxy_pass_request_body off;
        proxy_set_header Content-Length "";
        proxy_set_header X-Original-URI $request_uri;
        proxy_set_header X-Real-IP $remote_addr;
    }

    location @sibuna_challenge {
        proxy_pass http://127.0.0.1:8080;
    }
}
```

=== Caddy Configuration (`forward_auth`)

```caddyfile
example.com {
    forward_auth localhost:8080 {
        uri /
        header_up X-Real-IP {remote_host}
    }
    reverse_proxy localhost:3000
}
```

#v(4mm)

= Production Hardening and Operational Tuning

#objectives([
  Package Sibuna as a minimal scratch container, construct a robust systemd service unit,
  and establish operational procedures for adjusting Proof-of-Work difficulty during active
  distributed crawler attacks.
])

== Systemd Service Unit

Deploying Sibuna on bare-metal or virtual private servers is accomplished via a lightweight
systemd service unit:

```ini
[Unit]
Description=Sibuna Web AI Firewall Daemon
After=network.target

[Service]
Type=simple
User=sibuna
Group=sibuna
ExecStart=/usr/local/bin/sibuna --port 8080 --upstream-port 3000 --difficulty 4
Restart=always
RestartSec=2
LimitNOFILE=65535
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true

[Install]
WantedBy=multi-user.target
```

== Ultra-Lean Docker Containerization

Because Sibuna is compiled with pure Zig as a statically linked binary with zero C library
dependencies, it can be containerized inside an empty `scratch` image:

```dockerfile
FROM alpine:latest AS builder
RUN apk add --no-cache zig
WORKDIR /build
COPY . .
RUN zig build -Doptimize=ReleaseFast

FROM scratch
COPY --from=builder /build/zig-out/bin/sibuna /sibuna
EXPOSE 8080
ENTRYPOINT ["/sibuna"]
CMD ["--port", "8080", "--upstream-host", "upstream", "--upstream-port", "3000"]
```

The resulting container image weighs *less than 5 Megabytes*, starts in under *2 milliseconds*,
and consumes zero virtual memory for container runtimes.

== Dynamic Difficulty Tuning Under Attack

During ordinary operation, a difficulty setting of $D = 4$ ($65,536$ expected hashes) provides
the optimal balance between rapid browser solving ($approx 100$ to $150$ ms) and effective crawler
deterrence.

However, during aggressive, distributed scraping floods, administrators may dynamically scale
the difficulty:

#table(
  columns: (1fr, 1.2fr, 1.8fr),
  table.header([*Threat Level*], [*Difficulty ($D$)*], [*Operational Guidance*]),
  [Normal],
  [$D = 4$],
  [Default posture. Browser solves in $100$ to $150$ ms. Human users experience zero friction.],

  [Elevated Flood],
  [$D = 5$],
  [Imposes $1,048,576$ hashes per challenge. Solves in $1.2$ seconds. Throttles high-rate bots.],

  [Severe DDoS Attack],
  [$D = 6$],
  [Imposes $16,777,216$ hashes per challenge. Solves in $20$ seconds. Renders mass extraction completely cost-prohibitive.],
)

== Declarative Policy Configuration (`--policy-file`)

Sibuna supports declarative rule policies in JSON, achieving full functional parity with
`TecharoHQ/anubis` (`botPolicies.yaml`). Administrators can declare rules by passing
`--policy-file <path>` (or `-P <path>`):

```json
{
  "default_action": "ALLOW",
  "rules": [
    {
      "name": "block-cloudflare-workers",
      "headers": { "CF-Worker": ".*" },
      "action": "DENY"
    },
    {
      "name": "deny-amazonbot",
      "user_agent": "Amazonbot",
      "action": "DENY"
    },
    {
      "name": "protect-checkout",
      "path": "/api/checkout/*",
      "action": "CHALLENGE",
      "challenge": {
        "difficulty": 6,
        "algorithm": "sha256"
      }
    },
    {
      "name": "allow-internal-vpc",
      "remote_addresses": ["10.0.0.0/8", "192.168.0.0/16"],
      "action": "ALLOW"
    }
  ]
}
```

When evaluated, rules are checked in declaration order on the zero-allocation request hot path.
Matching rules immediately trigger their configured action (`ALLOW`, `DENY`, `CHALLENGE`, or `WEIGH`).

