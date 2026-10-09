# Sibuna distribution releases

Keep recipes and validation in this monorepo. A separate `insanai/homebrew-sibuna`
repository is a thin publishing tap containing the qualified `Formula/sibuna.rb`.
Community archive submissions remain separate reviews; upstream release packages
are not admission into Debian, Fedora, Arch, Homebrew core or GNU Guix.

## Release outputs

The existing native Linux, macOS and Windows binary qualification remains intact.
A new stable tag also prepares:

- Debian and RPM packages for x86-64 and ARM64; Arch `sibuna-bin` for x86-64.
- FreeBSD 15.1/amd64 `.pkg` and OpenBSD 7.9/amd64 `.tgz`, built natively
  against each qualified system’s headers and libraries. These are CLI packages.
- A corresponding-source bundle with verified SQLite inputs, and a Homebrew source
  formula with its measured SHA-256. No cask is generated.
- A two-architecture minimal OCI image for `ghcr.io/insanai/sibuna:VERSION`.
- A versioned Helm chart, indexed at `https://insanai.github.io/sibuna/charts`.

Release archives carry licenses, notices, source provenance and executable hashes.
`SHA256SUMS` covers every downloadable release artifact, including the chart and
formula. Packages wrap the **qualified** static Linux release executables; the
container copies those same executables and adds a checksum-pinned distroless base
with CA certificates. It contains no shell, package manager, Python or compiler.
The runtime is UID/GID 65532. Build/test tools run outside the shipped image.

The release job refuses to replace published releases or existing versioned image
tags. Do not re-tag an existing version. Increase the app version, Chart.yaml
version/appVersion, and existing source-offer/release-note references together
before the next tag. Version 0.3.5 uses the complete distribution workflow;
the original v0.3.3 application assets remain unchanged.
For initial Helm publication, `helm-bootstrap.yml` verifies both existing
v0.3.3 Linux downloads against GitHub digests, their published checksums,
executable manifests and the original source commit. It qualifies the image and
chart, then publishes a separate `helm-v0.3.3` release without altering the app
release or latest marker. Image labels identify the original binary source and
the separate packaging revision. The supplemental security policy comes from
that packaging revision. Future app tags use the complete release workflow.

## Linux operations

Package metadata uses the owner-authorized public contact configured in the
`SIBUNA_PACKAGE_CONTACT` repository variable. Its value is not duplicated in
public documentation or recipes. Security reports use GitHub private vulnerability reporting, not this
public packaging address.

Install downloaded packages using `apt install ./sibuna_*.deb`,
`dnf install ./sibuna-*.rpm`, or `pacman -U ./sibuna-bin-*.pkg.tar.zst`.
These unsigned artifacts are distributed through authenticated GitHub HTTPS with
checksums. A signed APT/DNF repository, Fedora/COPR submission, Debian source
package and AUR PKGBUILD are **later** publishing channels with independent gates.
Do not disable signature verification in a configured system repository.

Installation creates a locked `sibuna` identity and installs an optional systemd
unit. It neither enables nor starts the daemon. Set the IP-literal origin in
`/etc/sibuna/service.env`, then explicitly run `systemctl enable --now sibuna`.
The default proxy listener is `127.0.0.1:8080`; the console is off.
First service start creates a private 32-byte admission seed under
`/var/lib/sibuna`, as the service user. Restarts, reinstall and removal preserve
that seed and data. Invalid seed permissions, contents or symlinks fail startup.
Configuration is preserved using each package format's configuration mechanism.
An upgrade reloads unit definitions but deliberately requires the operator to
restart the service; back up data and review compatibility first. Removal stops
and disables the unit. Remove/purge keeps data and the service identity, so retire
those explicitly only after backup. Console setup is a separate, stopped-daemon
operation described in the upstream deployment guide; no admin is created.

## BSD operations

Verify the matching release's `SHA256SUMS` over authenticated GitHub HTTPS before
installing the exact package for your OS release and CPU. As root, use:

```sh
pkg add ./sibuna-0.3.5-freebsd-15.1-amd64.pkg
pkg_add -D unsigned ./sibuna-0.3.5.tgz
```

The OpenBSD option accepts only this explicitly requested unsigned upstream file;
it does not change system repository signature policy. These artifacts are not
accepted FreeBSD/OpenBSD ports and do not promise other ABI versions or CPUs.
Native package metadata records library/ABI requirements and qualified provenance.

Both install `/usr/local/bin/sibuna` and license/security/source notices under
`/usr/local/share/doc/sibuna`. They create no service, account, credentials or state.
Run as an operator-chosen unprivileged user with a private 32-byte admission seed,
a private data directory, and an IP-literal origin. Console bootstrap remains an
explicit stopped-daemon operation. Stop Sibuna before replacing or removing its
package; back up retained state and keys first. Restart explicitly after review.
Package replacement/removal leaves separately managed configuration, seed and data
alone. FreeBSD `rc.subr`, OpenBSD `rc.d`/`rcctl`, and Linux systemd are distinct;
these initial BSD packages supply no service integration or pledge/unveil policy.

See the book's [operator guide](https://insanai.github.io/sibuna/book/operations.html) for
CLI, console and deployment details. Future official ports have separate source,
staging, library, maintainer and service-review requirements in SID 0011.

## Homebrew operations

Install the published source formula from the Sibuna-maintained tap:

```sh
brew tap insanai/sibuna
brew install insanai/sibuna/sibuna
sibuna --version
```

The formula builds with Zig 0.17.0 and Python 3.14, installed as build
dependencies by Homebrew. It supplies no bottles and starts no service.
Configure a private admission seed, persistent state and an IP-literal origin
before starting the CLI; the console is opt-in. This tap is separate from
Homebrew core, whose admission requires independent community review.

Back up state and stop your running Sibuna process before upgrading:

```sh
brew update
brew upgrade insanai/sibuna/sibuna
```

To remove the CLI after stopping it:

```sh
brew uninstall insanai/sibuna/sibuna
```

Keep operator-owned configuration, seed and state outside Homebrew's installation;
retain them through upgrades and removal. The [tap README](https://github.com/insanai/homebrew-sibuna)
also describes compiler requirements, release checksums and automatic formula updates.

## Publishing setup

1. **GitHub release/GHCR:** the organization must allow Actions to publish packages.
   The workflow uses `GITHUB_TOKEN` with `contents:write`, `packages:write`, and
   `actions:write` (to refresh Pages). No separate registry account or long-lived
   image-publishing key is needed. Initial GHCR packages default to private:
   the organization must also permit public packages under organization
   Settings → Packages → Package creation. That permission affects every
   organization member, so an owner should explicitly authorize it. For a
   one-package bootstrap, enable it only for the visibility change and restore
   the prior creation restriction afterward; existing public packages remain
   public and their authorized release workflow can publish new versions.
   after the first image push, an organization owner must make the `sibuna`
   container package public and verify an anonymous pull. The publish job checks
   anonymous access and stops before publishing the GitHub release/chart if it
   is private. After changing visibility, rerun the failed publish job to reuse
   the qualified artifacts; an existing byte-identical image is accepted for
   this retry, while a different image at that version is refused. Source labels associate
   it with this repository. Do not announce a usable public chart until this is
   verified. The versioned image digest is attached as `IMAGE-DIGEST.txt`.
2. **Homebrew tap:** the public `insanai/homebrew-sibuna` repository is the thin
   publishing destination. Its daily/manual updater uses its own `GITHUB_TOKEN`
   to import the qualified formula after publication, verifying source/formula
   release checksums against GitHub asset digests. No cross-repository secret is
   required. Recipes, the updater and its workflow remain in this monorepo under
   `distribution/homebrew/`; the tap also carries a README and Sibuna license texts.
   The optional monorepo PR workflow can still use HOMEBREW_TAP_REPOSITORY and a
   narrowly scoped HOMEBREW_TAP_TOKEN for reviewed update PRs instead.
   Install with `brew install insanai/sibuna/sibuna`
   only after the qualified formula is present. The source formula
   requires exactly the release's Zig compiler. Homebrew core submission needs
   its own audit, human review and AI-assistance disclosure; the tap is not core.
3. **Helm hosting:** existing Pages deploys docs and the complete chart index in
   one deployment, retaining checksum-verified chart versions from published
   releases. Release automation dispatches the Pages workflow after publication;
   ordinary documentation deployments also rebuild the index. The chart source
   is packaged with chart/app versions matching the release, so subsequent tags
   automatically update the index.
4. **Artifact Hub:** create your account (and optionally a project organization),
   add a Helm repository named `sibuna` with URL
   `https://insanai.github.io/sibuna/charts` after `index.yaml` is publicly live.
   Put the assigned repository UUID in the public repository variable
   `ARTIFACTHUB_REPOSITORY_ID` (an existing repository secret with that name is
   also supported), then run the Documentation workflow to publish
   `artifacthub-repo.yml` for verified-publisher metadata. Ordinary indexing
   needs no API key in the release workflow. No personal owner emails are put
   in chart metadata. Artifact Hub indexes charts; GHCR hosts the runtime image.

The Artifact Hub account has been created. The first chart/image passed actual
Kubernetes qualification. The GHCR image is public and anonymous access was
verified; the organization's public-package creation permission was enabled
briefly with owner approval and then restored. The `helm-v0.3.3` chart release
is published and the Pages index contains Sibuna 0.3.3. The repository URL above is registered in Artifact Hub. The owner has configured its public repository UUID
as `ARTIFACTHUB_REPOSITORY_ID`; Pages accepts either a variable or the existing
secret and publishes only a validated UUID in verified-publisher metadata.
The public metadata was checked against Artifact Hub's registered repository ID.
Artifact Hub indexed the initial 0.3.3 chart and now lists 0.3.5; its public API
reports the publisher as verified. New charts use the same repository and ownership metadata.
The Homebrew tap publishes the qualified 0.3.5 source formula, README, Sibuna
license files and daily/manual release updater. Official community
packaging described by SID 0011 remains separate submission/review work.

## Published 0.3.5 qualification

[Sibuna 0.3.5](https://github.com/insanai/sibuna/releases/tag/v0.3.5) contains all
17 expected assets. [Release run 37918808388](https://github.com/insanai/sibuna/actions/runs/37918808388)
passed every required gate on attempt 3 at the unchanged source tag, including
both native BSD jobs and actual Linux package/systemd, Homebrew and Kubernetes
lifecycles. The preceding CRS cluster failures during leader changes are retained
in SID 0011; shipped packages have clustering disabled.
Independent public downloads matched all 16 checksum entries and GitHub asset
digests, including executable manifests and exact source provenance. Anonymous
GHCR access includes amd64/arm64 and matches the published `IMAGE-DIGEST.txt`.

The [tap import](https://github.com/insanai/homebrew-sibuna/actions/runs/37925792397)
passed and published [Formula/sibuna.rb](https://github.com/insanai/homebrew-sibuna/blob/main/Formula/sibuna.rb)
with the verified corresponding-source checksum. Install with
`brew install insanai/sibuna/sibuna`; this is a source formula without bottles or a cask.
The same updater checks future qualified stable releases daily or by manual dispatch.
Pages automatically rebuilds the Helm index; Artifact Hub tracks the registered
repository with the existing verified ownership metadata.
The live repository passed Helm add/update and an exact-checksum 0.3.5 pull,
retaining the earlier 0.3.3 chart. Artifact Hub now indexes chart/app version
0.3.5 with the qualified chart digest and verified publisher status.

## Validation

`Distribution recipes` checks workflow syntax, Helm schema/template constraints,
archive provenance/tamper rejection and concurrent private-seed creation on PRs.
The release workflow additionally builds/tests the Homebrew formula, installs
Linux and both BSD native packages, exercises a real systemd lifecycle on its disposable runner,
checks read-only/non-root container restart, and deploys/upgrades/uninstalls the
actual chart/image in kind. BSD jobs build against native system libc, run the
existing library/live tests and qualify installed CLI authentication, persistent
restart and shutdown as an ordinary user before replacement/removal. The kind test checks persistence and Secret access;
its default CNI is not evidence of NetworkPolicy enforcement. Qualify network
isolation with the production CNI before external exposure.

The initial remote qualification passed the full Linux suite (105 steps, 1188
tests), both static architecture builds, a network-disabled source-bundle build,
Debian/Fedora fixture lifecycles and the minimal image runtime checks. The remote
host's parent container policy blocks Arch hook pipes and nested Kubernetes Pod
sandboxes; full Arch/systemd/Helm lifecycle qualification remains a normal CI
release gate. Do not weaken the shipped image/chart to bypass those host limits.
