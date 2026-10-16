# Sibuna

Sibuna is a web firewall and anti-crawler proxy. This chart runs one Sibuna Pod in front of an origin. It requires a pre-existing admission Secret and runs one writer with `Recreate` upgrades. The Service is ClusterIP, there is no console and no ingress, and the NetworkPolicy denies ingress and egress until the operator allows trusted clients and the origin.

## Install

Create an admission seed of 64 hexadecimal digits (32 random bytes) in a private file, store it in a Secret, and install the chart from the release asset:

```sh
umask 077; od -An -tx1 -N32 /dev/urandom | tr -d ' \n' > admission.seed
kubectl create namespace sibuna
kubectl -n sibuna create secret generic sibuna-admission --from-file=admission.seed=admission.seed
helm install gateway ./helm-sibuna-1.0.0-beta.1.tgz --namespace sibuna \
  --set secret.existingSecret=sibuna-admission -f operator-values.yaml
```

Set the origin with `upstream.host` and `upstream.port`. The daemon connects to an IP literal (IPv4 or IPv6); it does not resolve a Service name, so choose a stable origin address, such as a Service's ClusterIP. A loopback origin works only when the operator adds an origin container to the same Pod; this chart creates none. Allow trusted clients and the origin with `networkPolicy.ingressFrom` and `networkPolicy.egressTo`.

Further daemon options go in `extraArgs`, one word per item, for example `["--mode", "forward_auth", "--difficulty", "18"]`. Run `sibuna --help` for the list.

## Image

The release image is `ghcr.io/insanai/sibuna:<version>` for x86-64 and ARM64. Prefer `image.digest: sha256:...` from the release's `IMAGE-DIGEST.txt`; a digest takes precedence over `image.tag`. The image holds the static executable, CA certificates and license notices, but no shell or package manager.

## Storage

`persistence.enabled` defaults to true and creates a ReadWriteOnce PVC; `persistence.existingClaim` names an operator-managed claim instead. Sibuna keeps its SQLite database in `/var/lib/sibuna/data`, a directory it creates inside the volume with mode 0700 as UID 65532. The fsGroup 65532 lets it do so without a privileged init container. An existing claim must let UID or GID 65532 create that directory, or already contain it owned by UID 65532.

Only one writer may use the volume: do not share a PVC between releases, raise `replicaCount`, add an autoscaler, or switch to rolling updates. Back up the volume before upgrading. The PVC and the Secret are kept on uninstall; erasing them is an explicit retirement step. With `persistence.enabled: false` the state lives in an emptyDir and is lost with the Pod, which suits tests only.

The root filesystem is read-only; `/tmp` and the state volume are writable. The Secret is projected with mode 0440.

## Health and exposure

The probes call `/__sibuna/health`, which reports that the listener answers, not that the origin is reachable or the storage durable. `/__sibuna/metrics` and the other internal routes share the proxy port: protect them at the ingress. ClusterIP alone is not route-level authorization, and your CNI must enforce NetworkPolicy for the policy to have effect. TLS termination belongs to the operator.

## Upgrades

Chart version and app version are the Sibuna release version, which selects the image tag of the same version. Read the release notes, keep the Secret and the PVC, and back up before:

```sh
helm upgrade gateway ./helm-sibuna-<version>.tgz --namespace sibuna \
  --set secret.existingSecret=sibuna-admission -f operator-values.yaml
```

A Helm rollback does not undo a database schema migration.

See `SECURITY.md` in the Sibuna repository for private vulnerability reporting.
