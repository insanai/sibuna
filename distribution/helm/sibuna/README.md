# Sibuna

A single-node admission proxy. This chart requires a pre-existing stable admission
Secret and runs one writer with `Recreate` upgrades. The default service is
ClusterIP, console and ingress are absent, and NetworkPolicy denies ingress and
egress until the operator allows trusted clients and the origin.

## Install after the chart and image are published

Create an operator-owned 32-byte random seed file with mode 0600, then:

```sh
kubectl create namespace sibuna
kubectl -n sibuna create secret generic sibuna-admission --from-file=admission.seed=/private/path/admission.seed
helm repo add sibuna https://insanai.github.io/sibuna/charts
helm repo update
helm install gateway sibuna/sibuna --namespace sibuna --set secret.existingSecret=sibuna-admission -f operator-values.yaml
```

Supply an IPv4 literal origin with `upstream.host` and `upstream.port` and trusted
`networkPolicy.ingressFrom`/`egressTo` selectors or IP blocks in your values file.
The daemon currently cannot resolve a Service DNS name. A loopback origin is
useful only when an operator supplies an origin in the same Pod; this chart
creates no sidecar. Choose a stable origin IP and account for changing Pod IPs.
Do not expose the default loopback example as a working origin deployment.

The release image is `ghcr.io/insanai/sibuna:APP_VERSION`, for x86-64 and ARM64.
Prefer `image.digest: sha256:...` from the release's `IMAGE-DIGEST.txt`; digest takes
precedence over `image.tag`. The container has CA certificates but no shell or
build utilities. A group-readable 0440 Secret projection and fsGroup 65532 allow
non-root access; no seed appears in values, chart templates or release artifacts.

`persistence.enabled` defaults to true and creates a ReadWriteOnce PVC. Specify
`persistence.existingClaim` for operator-managed storage. Single writer access is
mandatory: do not share a PVC between releases, increase replicas, add HPA, or
change to overlapping rolling updates. Back up before upgrade. The PVC is
retained on uninstall, as is the independently created Secret. Erasure is an
explicit retirement operation. Disabling persistence is for disposable tests.
The image filesystem is read-only; `/tmp` and the state volume remain writable.

Probes call `/__sibuna/health`, which checks the listener rather than origin
reachability or storage durability. `/__sibuna/metrics` and other internal routes
share the proxy port and bypass normal policy handling: protect them at ingress.
ClusterIP alone does not provide route-level authorization. Your CNI must enforce
NetworkPolicy. TLS termination belongs to the operator. No console administrator,
console listener, public ingress, cluster membership or TLS certificate is created.

See upstream `SECURITY.md` for private reporting and `distribution/README.md` for
publishing setup. This chart's metadata contains no personal security contacts.
