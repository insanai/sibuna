# Sibuna distribution releases

Keep recipes and validation in this monorepo. A separate `insanai/homebrew-sibuna`
repository is a thin publishing tap containing the generated `Formula/sibuna.rb`.
Community archive submissions remain separate reviews; upstream release packages
are not admission into Debian, Fedora, Arch, Homebrew core or GNU Guix.

## Release outputs

The existing native Linux, macOS and Windows binary qualification remains intact.
A new stable tag also prepares:

- Debian and RPM packages for x86-64 and ARM64; Arch `sibuna-bin` for x86-64.
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
before the next tag. The new files
are for the next application release; they do not retroactively change v0.3.3.
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
2. **Homebrew tap:** create the public `insanai/homebrew-sibuna` repository with an
   initial default-branch commit. Set `HOMEBREW_TAP_REPOSITORY` to that name and
   `HOMEBREW_TAP_TOKEN` to a narrowly scoped GitHub App token or fine-grained token
   granting that tap contents and pull-request writes. No secret goes in source.
   After a release, automation proposes a formula-update PR; a maintainer reviews
   and merges it. Without credentials the formula is still attached to the
   release for manual review. Install with `brew install insanai/sibuna/sibuna`
   only after the tap is created and the formula merged. The source formula
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
is published and the Pages index contains Sibuna 0.3.3. Register the repository
URL above in Artifact Hub. The owner has configured its public repository UUID
as `ARTIFACTHUB_REPOSITORY_ID`; Pages accepts either a variable or the existing
secret and publishes only a validated UUID in verified-publisher metadata.
Tap setup and
official community packaging described by SID 0011 remain separate launch work.

## Validation

`Distribution recipes` checks workflow syntax, Helm schema/template constraints,
archive provenance/tamper rejection and concurrent private-seed creation on PRs.
The release workflow additionally builds/tests the Homebrew formula, installs
native packages, exercises a real systemd lifecycle on its disposable runner,
checks read-only/non-root container restart, and deploys/upgrades/uninstalls the
actual chart/image in kind. The kind test checks persistence and Secret access;
its default CNI is not evidence of NetworkPolicy enforcement. Qualify network
isolation with the production CNI before external exposure.

The initial remote qualification passed the full Linux suite (105 steps, 1188
tests), both static architecture builds, a network-disabled source-bundle build,
Debian/Fedora fixture lifecycles and the minimal image runtime checks. The remote
host's parent container policy blocks Arch hook pipes and nested Kubernetes Pod
sandboxes; full Arch/systemd/Helm lifecycle qualification remains a normal CI
release gate. Do not weaken the shipped image/chart to bypass those host limits.
