#let sid-number = "0011"
#let sid-title = "Distribution Launch: Native Packages, GNU Guix, BSD Ports, and Helm"
#let sid-state = "discussion"
#let sid-created = "2026-10-09"
#let sid-discussion = "Code-reviewed launch plan for Debian, RPM, Arch, Homebrew, WinGet, GNU Guix, FreeBSD, OpenBSD, and Helm: repository ownership, community requirements, accounts, source builds, service lifecycle, security reporting, and per-target release gates."
#let sid-labels = ("distribution", "packaging", "guix", "operations", "launch",)
#let sid-authors = ("Sibuna Contributors",)
#let sid-category = "Distribution Specification"
#let sid-status = "Open for Discussion"
#let sid-last-updated = "2026-10-09"

#import "../../shared/sid.typ": sid-document

#show: doc => sid-document(
  sid-number, sid-title, doc,
  authors: sid-authors, state: sid-state, created: sid-created,
  discussion: sid-discussion, labels: sid-labels,
  category: sid-category, status: sid-status, last-updated: sid-last-updated,
)

= Abstract and Revision

This record specifies the work and evidence required to launch Sibuna through nine targets:
Debian/Ubuntu, Fedora/RPM, Arch Linux, Homebrew, WinGet, GNU Guix, FreeBSD Ports, OpenBSD Ports, and
Kubernetes Helm. It covers community policies, accounts, source provenance, licensing,
service lifecycle, private security reporting, and native verification.

*Revision, 2026-10-09:* Reviewed checkout `ea1a365`, version `0.3.3`, against release tooling,
CLI parsing, network routes, policy loading, console initialization, storage, and shutdown.
Replaced unsupported examples and guarantees, added account onboarding, and added the local
Guix candidate `guix.scm` plus `tools/prepare_distribution_source.py` for offline source builds.
SID 0001 and `SECURITY.md` define the security response process used by this launch.

*Status:* Keep the overall specification in `discussion` pending the remaining targets' review
and qualification. The initial Helm 0.3.3 chart and minimal two-architecture GHCR image are
published, with the public Pages index and actual qualification recorded below. The owner has
created an Artifact Hub account and configured its repository UUID in GitHub; public
ownership verification is recorded separately. No Debian,
Fedora, Arch, Homebrew core, Guix, BSD or WinGet community acceptance is claimed. External
setup requirements remain open until their own verified records are added.

= Scope and Launch Decision

Use the existing single-node release profile:
`-Doptimize=safe -Dstrip=true -Dstorage=true -Dconsole=true -Dcluster=false`.
The console is compiled in but starting it remains an operator decision. A separately named
engine-only variant may use `-Dconsole=false` with LGPL metadata and feature declarations.
Do not silently ship that variant as the full package. Clustering is a later, separately
qualified profile with OpenSSL, certificates, independent node storage, and compatibility gates.

Upstream-maintained channels may launch before a community archive accepts Sibuna, provided
their own gates pass. Label the origin: an upstream APT repository, COPR, Homebrew tap, or local
Guix recipe is not inclusion in Debian, Fedora, Homebrew core, or official GNU Guix.
Each target has an independent release decision; missing BSD support need not block WinGet.

TLS termination and application runtimes belong to the operator. Installation must not open
firewalls, create administrator credentials, or expose the console. Ports 8080 (proxy), 3000
(example origin), 19446 (explicit console choice), and 19447 (example cluster choice) are
package conventions, not IANA assignments or universal application defaults.

= Code Review: Implemented Contracts

#table(
  columns: (0.9fr, 2.5fr),
  table.header([*Area*], [*Verified behavior and implication*]),
  [Platforms], [`tools/release_targets.py` covers Linux x86-64/ARM64, macOS ARM64/x86-64, and Windows x86-64. Separate native BSD jobs target FreeBSD 15.1/amd64 and OpenBSD 7.9/amd64; each must pass before publication.],
  [Compiler], [`build.zig.zon` requires Zig 0.17.0, pinned in `tools/zig-release.json`. Older distribution compilers cannot be assumed compatible.],
  [Licenses], [`LICENSE` scopes engine LGPL-3.0 and console AGPL-3.0. The default executable is AGPL-covered. Apache-2.0 describes CRS rules, not Sibuna.],
  [Config], [`libs/core/src/config.zig` parses CLI arguments and rejects unknown options. No general INI reader or `--config` exists. Environment files need explicit argument mapping.],
  [Seed], [`main.zig:resolveSecret` reads `--secret-file`, then `SIBUNA_SECRET`, otherwise creates ephemeral randomness. Files accept 32 raw bytes or 64 hex characters; ownership/modes are not enforced by the daemon.],
  [Console], [`--console host:port` requires storage. The config port field is 9443, not 19446. Packages may explicitly choose 19446. Bootstrap is `sibuna console init-admin admin --data-dir PATH`, with the daemon stopped. Console keys are separate from admission seeds.],
  [Health], [`GET /__sibuna/health` reports process status/configuration. `/healthz` is an ordinary application route. The native endpoint does not check origin availability or storage quorum.],
  [Metrics], [`libs/core/src/metrics.zig` exports `/__sibuna/metrics`. `server.zig` handles internal routes before policy; policy rules cannot make metrics loopback-only.],
  [Policy], [`libs/policy/src/loader.zig` rejects unknown keys. Use `name`, `path`, `user_agent`, `cidrs`, and nested `challenge`; the original `id`, `priority`, `path_prefix`, `source_cidr`, and `version` example fails startup.],
  [Origin], [`libs/net/src/proxy.zig:connectUpstream` parses an IP literal. A Kubernetes Service DNS name does not currently work as `--upstream-host`. Gateway charts need a qualified resolution workflow or daemon DNS support.],
  [Windows], [`shutdown.zig` installs console control handlers, not `ServiceMain` or `StartServiceCtrlDispatcher`. Direct `sc.exe create sibuna.exe` cannot implement an SCM service. WinGet launches as portable CLI packaging first.],
)

== Existing Release Foundation

`.github/workflows/release.yml` checks version/source links, console assets, native build
variants, library and live daemon tests, and CRS contracts before publication.
`tools/package_release.py` requires a clean tree and packages notices, licenses, executable
digest, commit, target, features, compiler, and corresponding-source information.
A workflow definition is not proof that a particular run passed: record actual run IDs and digests.

Archives use `sibuna-linux-amd64.tar.gz`, `sibuna-linux-arm64.tar.gz`,
`sibuna-macos-arm64.tar.gz`, `sibuna-macos-amd64.tar.gz`, and `sibuna-windows-amd64.zip`,
under versioned release URLs. Preserve the unsigned macOS status and SID 0007 performance
exception. Do not promise signing, whole-process zero allocations, guaranteed throughput,
or a passed console-impact benchmark based on packaging alone.

= Initial Launch Implementation

The immediate scope is upstream GitHub release packages, a source-built Homebrew formula,
and a working single-node Helm chart/image. It is not a Debian archive upload, Fedora RPM
review, AUR registration, Homebrew core acceptance, or an official Guix package.

`.github/workflows/release.yml` retains all five native executable jobs across Linux, macOS
and Windows, and existing CRS/runtime gates. New jobs wrap qualified Linux musl archives as
Debian/RPM packages on x86-64 and ARM64 and an Arch `sibuna-bin` package on x86-64, verify
manifest features/target/version/commit and executable digest, and include all notices/source
provenance. ARM Arch is a separate community target and is deferred. Packages install stopped;
loopback systemd activation is explicit. Runtime seed creation runs as the locked service user.
Configuration, private seeds, data and account ownership persist through upgrade/removal.

`tools/package_source.py` exports tracked source in an isolated tree, validates/stages the
pinned SQLite inputs, and attaches a source bundle plus a formula with its measured SHA-256.
`distribution/homebrew/sibuna.rb.in` builds from source with the exact supported Zig version;
there is no cask. A native macOS source-build/test job gates publication. Tap updates become
reviewable PRs only when the owner configures an existing tap and scoped cross-repository
credentials. The release still carries the formula when those credentials are absent.

Container qualification checks non-root/read-only operation and persistent restart. The chart
requires an existing Secret, uses group-readable 0440 projections with fsGroup 65532, one
writer, Recreate, retained PVC, internal ClusterIP and default-deny NetworkPolicy. No console,
admin, public ingress, HPA or sidecar is installed. Initial schema accepts IPv4 literal origins;
DNS resolution and IPv6 chart values are deferred. The release gate includes an actual kind
install/upgrade/uninstall test. kind's default CNI does not establish NetworkPolicy enforcement;
production CNI and external internal-route denial remain operator qualification requirements.

`tools/build_chart_repository.py` verifies chart assets against release SHA256SUMS and builds
`https://insanai.github.io/sibuna/charts/index.yaml`, retaining published chart versions in
existing Pages deployments. The release explicitly dispatches Pages after publication;
GITHUB_TOKEN-generated release events cannot be assumed to trigger another workflow.
Artifact Hub indexes that HTTP repository and does not host the image or chart bytes.

== Exact Setup Prerequisites

- *Package metadata:* The project owner supplied the required public package contact on
  2026-10-09. Configure it as SIBUNA_PACKAGE_CONTACT; do not duplicate the address in public
  documentation. It is packaging metadata, not a new security mailbox.
  Public security reporting continues through GitHub private vulnerability reporting with
  private primary/backup role assignments. Personal responder names remain absent.
- *GitHub/GHCR:* Organization package publication rights and the workflow GITHUB_TOKEN suffice
  for this repository's image. No separate registry account/key is required. The first GHCR
  package defaults to private; an owner must make it public and verify anonymous pulls before
  announcing a usable chart. Version tags must never be replaced; IMAGE-DIGEST.txt records
  the image digest. These files prepare future releases and do not change published v0.3.3.
- *Homebrew:* Create a public `insanai/homebrew-sibuna` repository with an initialized default
  branch. Set public variable HOMEBREW_TAP_REPOSITORY and secret HOMEBREW_TAP_TOKEN with only
  that tap's contents/PR write permissions, or supported scoped GitHub App access. Review the
  generated update PR before merge. Core submission remains a separate human/community review.
- *Pages/Artifact Hub:* Enable/retain the existing Pages workflow and Actions dispatch rights.
  After the chart index is public, the owner registers an Artifact Hub account/organization
  and adds the Helm repository URL. Set the assigned public UUID as ARTIFACTHUB_REPOSITORY_ID
  and redeploy Pages to emit artifacthub-repo.yml. No recurring Artifact Hub API key is needed
  for ordinary repository indexing. Do not put personal owner email fields in that metadata.

See `distribution/README.md` and the chart README for actual operator/setup instructions.
Native packaging/image/chart validation runs on the designated remote GNU/Linux build host;
local checks are limited to lightweight edits, syntax and documents. Keep infrastructure
addresses and private responder assignments out of public metadata.

= Repository Ownership and Source of Truth

*Decision:* Keep upstream-owned distribution recipes, service samples, container definitions,
Helm chart source, tests, and release tooling in the Sibuna monorepo. Use separate repositories
only for an ecosystem's publishing mechanism, community-owned packaging, or a later explicitly
independent maintenance boundary. Do not create one upstream repository per operating system.

This lets one review update a CLI option, policy grammar, default path, service definition,
license notice, and packaging test together. The code review above found exactly those kinds
of drift in the original examples. A separate packaging monorepo today would add cross-repository
coordination and another release identity without resolving the outstanding native-build gates.
Small independent publishing repositories can still limit who has publishing access.

#table(
  columns: (1.1fr, 1.8fr, 1.7fr),
  table.header([*Content*], [*Upstream-owned source*], [*Distribution destination*]),
  [Debian/RPM/BSD], [Recipes and reusable integration under `distribution/` subdirectories, beside tests and the daemon.], [Community packaging trees/review systems; signed upstream APT/RPM metadata is a hosting destination, not necessarily another source Git repository.],
  [Homebrew], [Source formula/resources and tests in `distribution/homebrew/`.], [A small dedicated tap, proposed `insanai/homebrew-sibuna`, exporting qualified formulae; homebrew/core separately owns accepted definitions.],
  [WinGet], [Release-manifest generation/validation in the monorepo.], [Versioned manifests submitted to microsoft/winget-pkgs, which owns accepted community metadata.],
  [Guix], [Root `guix.scm` candidate now; reusable origins/package/service modules later under `distribution/guix/`.], [Official Guix packaging repository after review. An optional authenticated upstream channel can expose a designated monorepo directory; a new Git repository is not required initially.],
  [Images/Helm], [Container and chart source, schema and deployment tests under `distribution/`.], [GHCR runtime images; GitHub Pages HTTP chart repository indexed by Artifact Hub. Listing does not relocate source ownership.],
)

The proposed tap does not yet exist by virtue of this specification. Establish ownership and
permissions through the onboarding gates before using its installation commands. Homebrew
expects a Git tap and its conventional GitHub name for one-argument tap commands.
WinGet accepts reviewed manifests in its community repository. OCI registries distribute
packaged charts independently of their source repository.
#link("https://docs.brew.sh/Taps")[Homebrew taps];
#link("https://learn.microsoft.com/en-us/windows/package-manager/package/repository")[WinGet repository];
#link("https://helm.sh/docs/topics/registries/")[Helm OCI registries].

== Synchronization and Release Identity

After native qualification and immutable source/archive publication, export the upstream-owned
recipe to the tap or prepare a community submission. Record upstream source version/commit,
recipe commit, packaging revision, target, artifact hash, and qualification run. Do not resolve
source from a moving default branch or publish templates containing placeholder checksums.
Publishing/export checks should fail if a recipe claims a different version, feature profile,
license, source offer, or asset digest. Credentials are scoped to each destination and live in
protected release environments; monorepo membership alone does not grant publishing rights.

Downstream-accepted recipes are authoritative for their community and may contain reviewed
platform-specific changes. Track these changes, bring reusable fixes back upstream, and propose
new reviewed updates. Do not blindly overwrite downstream work or assert that upstream controls
community publication. Packaging-only revisions are distinct from daemon version changes:
Debian/RPM revisions, Homebrew formula revisions, Guix recipe/channel commits, and Helm chart
versions can advance while referring to the same immutable application source. Never replace
published immutable artifacts to synchronize repositories.

Split an upstream packaging repository later only when its team, access restrictions, or release
cadence is independently maintained, or when a community workflow requires it. Such a split must
document ownership, version/provenance contracts, CI, shared-helper dependencies, security update
routing, and synchronization before moving files. Keep one clear upstream owner for each recipe.

= Accounts, Permissions, and Repository Onboarding

Account creation is not package acceptance. Assign a primary maintainer and backup for each
channel; use reachable contacts rather than `team@sibuna.local`. Inventory existing accounts
before registering duplicates. Account identities, signing-key fingerprints, ownership,
recovery custody, and permission scope belong in a maintainer register; passwords, tokens,
private keys, and recovery codes never belong in git or SIDs. Human owners complete email
verification, MFA, agreements, and any identity checks; account registration is not automated here.

Public security contacts use project roles and GitHub private reporting, not personal names,
emails, phone numbers, or contact details. Use an approved monitored project-controlled identity
where package metadata requires a public contact. The two security owners are assigned privately;
GitHub permissions and notifications must be verified without publishing a personal roster.

#table(
  columns: (0.85fr, 1.8fr, 1.8fr),
  table.header([*Channel*], [*Identity/setup before submission*], [*Acceptance/publishing authority*]),
  [Debian/Ubuntu], [Monitored maintainer email; OpenPGP signing identity; Salsa and mentors.debian.net accounts where used. Launchpad account/signing key for a chosen Ubuntu PPA.], [ITP and sponsorship/review. Debian Developer membership is not required to prepare a package; authorized upload requires a sponsor or appropriate archive rights. A PPA is a separate channel.],
  [Fedora/EPEL], [Fedora Accounts identity, current contributor agreement, review tracker access, packager sponsorship and required authentication. COPR account/project if chosen.], [Package review, approved maintainer/SCM access, build/update workflow. COPR ownership is not Fedora/EPEL inclusion.],
  [Homebrew], [GitHub account/fork for core PRs; organization-owned tap and scoped CI access for the upstream tap.], [Core maintainers merge after review. No separate paid Homebrew publisher registration is needed.],
  [WinGet], [GitHub account/fork and permissions for microsoft/winget-pkgs PRs; stable HTTPS asset hosting.], [Repository schema/security/installation CI and maintainer review. This is not Microsoft Store publisher registration.],
  [Guix], [Monitored contributor email and current patch-tracker or forge account when required by the chosen workflow; pinned channels for local builds.], [Guix maintainer review/merge. No store-style publisher registration or committer rights are needed for an initial contribution. A private channel is separately owned/authenticated.],
  [FreeBSD], [Reachable maintainer email and Bugzilla account for ports problem reports; subscribe to relevant updates.], [Port review and a ports committer's merge. A FreeBSD committer account is not a prerequisite to contributing a port.],
  [OpenBSD], [Reachable email and ports mailing-list participation; matching ports/base system.], [Submission/review through ports contributors/committers; no commercial publisher account.],
  [Helm/images], [GitHub organization package namespace, GHCR visibility/write rights, scoped registry credentials or supported workload identity. Artifact Hub account only if listing there.], [Registry publication after image/chart gates. Artifact Hub listing/verified-publisher metadata is separate from OCI publication.],
)

Before first publication, verify namespace ownership and package-name collisions, MFA and
recovery, one minimum-scope publishing identity per destination, protected release environments,
rotation/revocation, and a backup maintainer's access. APT/RPM repositories additionally need
metadata signing keys, public-key distribution, TLS hosting, and an update/expiry plan.
Never place community upload credentials in ordinary pull-request CI.

Record each onboarding item as pending, requested, or verified, with owner/date/evidence.
The GitHub source remote exists; this does not verify the user's other accounts, package
namespace permissions, signing infrastructure, or sponsorship. All unverified entries are
launch gates, not assumed completed setup.

References: #link("https://www.debian.org/doc/manuals/developers-reference/pkgs.en.html#new-packages")[Debian new packages];
#link("https://docs.fedoraproject.org/en-US/package-maintainers/Joining_the_Package_Maintainers/")[Fedora maintainer onboarding];
#link("https://docs.brew.sh/How-To-Open-a-Homebrew-Pull-Request")[Homebrew PR workflow];
#link("https://learn.microsoft.com/en-us/windows/package-manager/package/repository")[WinGet submissions].

== Contribution Rules, Including AI Assistance

Read each destination's current contribution and AI-use policies before preparing a submission.
This revision and the local Guix candidate were AI-assisted; do not misrepresent their origin.
Homebrew requires disclosure in the initial PR, human review before submission, no AI author
trailers, and personally answering maintainer questions without AI assistance. The submitting
human must fulfill those rules; an automated agent must not handle those review replies.
#link("https://docs.brew.sh/How-To-Open-a-Homebrew-Pull-Request#artificial-intelligencelarge-language-model-aillm-usage")[Homebrew AI contribution requirements].

Do not infer another project's rules from Homebrew. Guix GCD 008 was checked and is marked
withdrawn, so its proposed restrictions are not asserted as adopted policy. Recheck current
Guix guidance and destination hosting rules before submission. Human review alone must not
be presented as overriding a prohibition; if a destination excludes the contribution, keep
it as an upstream/local artifact or obtain an eligible independently authored implementation.

= Shared Package and Security Contracts

== Source, Dependency, and License Provenance

Community packages build native executables and browser Wasm from immutable corresponding
source, with complete declared dependencies and an offline build sandbox. Upstream binary
archives remain a convenience channel. Do not wrap a Linux musl binary in an RPM and call
it a Fedora source build.

The remote dependencies in `vendor/zaxonlite/build.zig.zon` are SQLite 3.50.4 and sqlite-vec
0.1.9. Vendored Zaxonlite/Paxos compatibility corrections are documented in
`vendor/provenance.json` and `NOTICE`. Prefer community libraries where supported; otherwise
record the reviewed bundling rationale and security update owner. The custom SQLite flags
and compiled-in vector extension mean unbundling requires implementation, not just metadata.

Fetch immutable checksummed archives outside the sandbox. `tools/prepare_distribution_source.py`
verifies the six pinned amalgamation file digests before copying sources and replacing the two
remote dependency entries with local paths in an unpacked build tree. It performs no network
requests. File digests are not archive SHA-256 values. Dependency updates require reviewing
both the lock and these digests. Do not rewrite the release checkout during packaging.

Console CSS and geographic data are committed generated assets with source, locks, and digests
in the console asset tooling/notices. Zig rebuilds the interface and solver Wasm. Qualify
community requirements for regenerating CSS/data from declared source inputs; digest verification
is not regeneration. Account for `vendor/libinjection` data generation and notices as well.

Default first-party package metadata is AGPL-3.0-only; the separate engine scope is
LGPL-3.0-only. Preserve `LICENSE`, `LICENSES/`, `NOTICE`, component license declarations,
and exact corresponding source. Runtime CRS rules remain optional verified rule data; Apache-2.0
must not replace the Sibuna license. Debian copyright, RPM expressions, Homebrew metadata,
Guix license objects, and BSD license declarations follow their respective formats.

== Filesystem, Lifecycle, and Least Privilege

Install immutable binaries and samples read-only. Administrator configuration is root-owned
and service-group-readable (typically directory 0750/files 0640). Private writable state
belongs to the service account; never recursively chown `/etc/sibuna` to the network daemon.
A package must install without a live origin, initialized console, internet, or systemd PID 1.

Use platform account and supervisor helpers idempotently. Debian service handling honors
maintainer-script policy and `policy-rc.d`; RPM/BSD follow their native enablement conventions.
At the upstream recipe level, prefer explicit activation after operator configuration where
platform policy permits. Run a foreground process under one supervisor and log appropriately.
Graceful stop must flush state and release the exclusive data-directory lock.

Preserve configuration, keys, accounts, and databases through upgrades and ordinary removal.
Even Debian purge must not recursively erase operator databases by default; document explicit
separate data deletion. Do not assign arbitrary fixed host UID/GIDs. Image UID/GID 65532 is an
image contract. Package installation and profile rollback do not undo database migrations.

== Secrets and Administrator Bootstrap

Admission seed, console key, and cluster authentication keys are independent. Unix files
are 0600 or 0400 under a private service-owned state directory; Windows uses restrictive ACLs.
Never put live keys, administrator passwords, or state in packages, images, Guix store paths,
Helm values, release logs, or shared CI artifacts.

A required service bootstrap helper must validate existing regular files/ownership/length,
reject symlinks, avoid overwrites, and propagate errors. Create a same-directory random
stage, set permissions/owner, flush, install atomically without replacement, then flush the
directory. Serialize concurrent starts, validate the winner, and clean failed stages.
Direct `openssl rand > seed` with suppressed errors does not satisfy this contract.
`distribution/linux/seed.py` implements atomic no-replace creation, validates the winner, and
rejects unsafe existing files. Concurrent first-start and failure cases have tests. Qualify the
installed service lifecycle on Linux before launch. Never rotate on upgrade.

An initial host service uses recognized arguments and loopback exposure:

```sh
sibuna --host 127.0.0.1 --port 8080 \
  --upstream-host 127.0.0.1 --upstream-port 3000 \
  --secret-file /var/lib/sibuna/admission.seed \
  --data-dir /var/lib/sibuna --shield
```

Enable the console separately with `--console 127.0.0.1:19446` and an independent
`--console-key-file /var/lib/sibuna/console.key` after stopped-daemon local bootstrap
as the service user against the same data directory. Do not enable `--trust-forwarded`
on a listener reachable by arbitrary clients; forward-auth defaults to trusting forwarded
addresses and must be reachable only by the intended ingress.

== Security Response Readiness

`SECURITY.md` is the public policy; SID 0001 governs confidential triage, remediation, and
coordinated disclosure. Support the latest stable release, with older releases receiving fixes
only by explicit announcement. New packages must link to this policy, identify update owners,
and retain the response limitations. Do not promise a 24/7 team, bounty, or fixed resolution SLA.

Before launching a new package channel, enable and verify GitHub private vulnerability reporting,
assign a primary and backup responder, verify notifications and recovery, and exercise a private
reporting drill without creating a fake public advisory. On 2026-10-09 the API initially reported
private reporting disabled; this revision enables it and rechecks the setting. That check does
not prove notification delivery, responder coverage, or that the uncommitted policy is public.
Those remain explicit launch tasks. No security mailbox is invented.

Confirmed fixes require regression evidence, affected/fixed version ranges, mitigation and
upgrade guidance, advisory coordination, and downstream security contacts before disclosure.
Downstream backports have their own support policy. Revoke compromised release credentials,
quarantine affected artifacts, and publish an advisory/replacement version rather than silently
replacing an immutable released archive.

== Loader-Compatible Sample Policy

This optional sample preserves challenge behavior for unmatched traffic:

```json
{
  "default_action": "CHALLENGE",
  "waf": true,
  "rules": [
    {
      "name": "login-work",
      "action": "CHALLENGE",
      "path": "/auth/login",
      "challenge": {"difficulty": 18, "algorithm": "posw"}
    }
  ]
}
```

An explicit rule list replaces built-in rules; document that consequence. A site's ALLOW health
rule is an operator choice, not an unconditional package bypass. User-agent criteria use the
implemented bounded pattern grammar, not arbitrary regex alternation or verified bot identities.
Internal health/metrics bypass policy and cannot be secured by this sample.

= Community Package Requirements and Gates

== Debian / Ubuntu

Provide a non-native source package: control/rules/changelog, machine-readable copyright,
`source/format` as `3.0 (quilt)`, install files, tests, and service definition. Declare debhelper
compat 13, a qualified Zig 0.17 compiler, and actual build/test dependencies. Build offline in
`sbuild`. Use `Architecture: any` for the source package, publishing only tested architectures;
`${shlibs:Depends}` and `${misc:Depends}` reflect actual native linkage/helpers.

The current checked Policy is 4.7.4.1, released 2026-03-31, replacing the draft's 4.6.2 claim.
Declare the applicable checked Standards-Version and deviations. Use debhelper service helpers,
not direct `systemctl enable`. CLI installation must not require systemd. Respect conffiles and
retain state through removal. ITP/sponsorship and Ubuntu/PPA onboarding are separate gates.
#link("https://www.debian.org/doc/debian-policy/")[Debian Policy Manual].

Required evidence: `sbuild`, `lintian`, `autopkgtest`, `piuparts`, non-systemd installation,
policy-controlled activation, service start/stop, upgrade/config retention, and removal tests.

== Fedora / EPEL / Upstream RPM

Use source-based `%build`, `%check`, and staged `%install` with native toolchain/libc, applicable
compiler flags, actual license expressions, systemd/sysusers macros, SELinux review, and
`%config(noreplace)`. Declare/document permitted bundling and `Provides: bundled(component)`
versions where required. The previous binary-only spec is not a Fedora source package.
#link("https://docs.fedoraproject.org/en-US/packaging-guidelines/")[Fedora Packaging Guidelines].

The accessible Fedora catalog currently lists Zig 0.16.0 on Rawhide/Fedora 45, below Sibuna's
requirement. Resolve a source-built 0.17 toolchain before promising Fedora/EPEL inclusion.
A COPR/upstream RPM is separately labelled. Required evidence: `mock`, `rpmlint`, license and
package review, SELinux-enforcing service lifecycle, and per-release/architecture tests.
A Fedora build does not establish RHEL support.
#link("https://packages.fedoraproject.org/pkgs/zig/zig/")[Fedora Zig catalog].

== Homebrew

Use an upstream tap while core prerequisites remain unresolved. Core builds from immutable
checksummed source and requires stable releases, supported-platform tests, declared dependencies,
and visible justified bundling exceptions. Platform-specific upstream binaries are not core
formula inputs. Bottles come from the qualified source formula. Add a useful integration test,
not only `--version`.
#link("https://docs.brew.sh/Acceptable-Formulae")[Homebrew Acceptable Formulae].

The initial source formula installs the CLI only, without a brew services definition. Later
service support must use prefix/etc/var, not hard-coded architecture paths. `brew services` uses launchd on macOS
and systemd on Linux where supported, under the invoking user. State and keys persist outside
the Cellar; secrets use declared tools. Required evidence: strict online audit/style checks,
current PR checks including `brew lgtm --online` where applicable, source builds, `brew test`,
and service start/stop/restart on qualified macOS CPUs and Linux. Follow the AI-use rules above.

== WinGet

Initial scope is portable CLI installation. Generate the version/default-locale/installer
manifests using the current accepted community schema and actual Windows x86-64 ZIP digest.
Use `InstallerType: zip`, `NestedInstallerType: portable`, and `NestedInstallerFiles` containing
`RelativeFilePath: sibuna.exe` plus a portable command alias. Hash the ZIP, not the executable.
Advertise only the qualified Windows minimum/architecture. No Microsoft Store registration
or SCM registration is implied.
#link("https://learn.microsoft.com/en-us/windows/package-manager/package/manifest")[WinGet manifests];
#link("https://github.com/microsoft/winget-pkgs/tree/master/doc/manifest/schema")[repository schemas].

Required evidence: schema checks, `winget validate`, Windows Sandbox/local-manifest installation,
repository CI/review, alias/version/live proxy tests, upgrade and portable uninstall, preserving
external state. Future SCM support requires native callbacks or a separately licensed/qualified
wrapper, installer ACLs, proper argument quoting, graceful stop and recovery tests.
#link("https://learn.microsoft.com/en-us/windows/win32/services/service-entry-point")[SCM dispatcher contract].

== GNU Guix

`guix.scm` is a local source-build candidate for the full single-node profile. It captures a
filtered source checkout and the two extracted pinned amalgamations as declared `local-file`
inputs, verifies their digests, stages dependencies offline, rebuilds Wasm, checks committed
assets, runs `zig build test`, verifies the version, and installs binary/docs/licenses.
Python/Node are build/test inputs. No service runs or mutable state is created during installation.

Populate pinned source inputs outside the sandbox with ordinary `zig build`. The recipe requires
`zig@0.17.0` from Guix, or `GUIX_SIBUNA_ZIG` naming an equivalent source-built package in a pinned
channel. It rejects other versions. It does not define Zig or prove official Guix availability.
The inspected official Guix compiler module exports versions through 0.16.0, with 0.13 as
its default; the 0.17.0 toolchain is an explicit pending dependency, not an assumed package.
Its explicit `gnu-build-system` phases accommodate Zig 0.17 flags and native Guix libc paths;
review current `zig-build-system` APIs before substituting them.

```sh
# In GNU/Linux Guix with a qualified source-built Zig 0.17.0 package:
zig build
guix build -f guix.scm
guix package -f guix.scm
# Profile rollback changes binaries, not database migrations.
```

For community submission, replace local checkout/cache inputs with immutable measured `origin`
hashes and appropriate source packages, provide a source-built compiler/bootstrap chain, resolve
asset regeneration/bundling requirements, and follow current contribution rules. Never import a
prebuilt upstream compiler to bypass Guix bootstrap. The local candidate is not upstream-ready.
#link("https://guix.gnu.org/manual/devel/en/html_node/Build-Systems.html")[Guix build systems];
#link("https://guix.gnu.org/manual/devel/en/html_node/Packaging-Guidelines.html")[packaging guidelines].

Guix System service support is separate future work: typed configuration mapped to CLI arguments,
service account, activation of private mutable state, and a Shepherd foreground service using the
store binary. No systemd unit on Guix System. Keep keys/database out of `/gnu/store`; port 8080
needs no capability. Profile users can run the CLI or configure user Shepherd without root.

Required evidence: Guix evaluation and sandbox build on x86-64/ARM64 GNU/Linux, `guix lint` on
an upstream module, no-network build, `guix build --check` reproducibility, source/license review,
pinned channel/derivation identities, and service tests when Shepherd exists. Guile read checks
on this macOS workspace are not Guix package evaluation or build qualification.

== FreeBSD Ports

Use source distfiles/checksums, qualified current `USES=zig`, staging, pkg-descr/pkg-plist,
license metadata, and a reachable maintainer. Let ports infrastructure manage accounts and
`@sample` configuration. A category such as security requires community review. Upstream Linux
archives are not BSD binaries. `rc.subr` defaults disabled, uses the chosen unprivileged account,
configuration under `/usr/local/etc/sibuna` and state under `/var/db/sibuna`, and supervises the
correct foreground child. `daemon(8)`/rc.subr alone are not a sandbox.
#link("https://docs.freebsd.org/en/books/porters-handbook/")[FreeBSD Porter's Handbook].

Required evidence: port formatting/lint, `poudriere testport`, stage/check-plist, native socket,
shutdown/storage behavior, and install/start/upgrade/remove on every advertised release/CPU.
Resolve toolchain/std.Io portability before submission; follow current contribution policy.

== OpenBSD Ports

Use the current Makefile template, source distfile checksums, pkg/DESCR/pkg/PLIST, proper
account/state/config directives, license permissions, and matching native base/ports tree.
Use rc.d/rcctl with a foreground daemon and chosen unprivileged account. Do not conflate it
with FreeBSD rc.subr or claim pledge/unveil support that Sibuna has not implemented.
#link("https://www.openbsd.org/faq/ports/guide.html")[OpenBSD Porting Guide].

Required evidence: native compiler/I/O qualification, checksum/package checks,
`make port-lib-depends-check` where applicable, `make update-plist`, `make package`, and
installation/upgrade/stop/removal tests. Submit through the current ports process.

== Arch Linux

The initial upstream release emits an x86-64 `sibuna-bin` package, with `provides` and
`conflicts` for Sibuna and package metadata/licenses/notices, using nFPM's Arch backend.
Install with `pacman -U` after HTTPS/checksum verification. This does not create a signed
pacman repository or submit an AUR package. Do not label it an official Arch package.

A later AUR launch requires a reviewed PKGBUILD and generated .SRCINFO, architecture and
license declarations, immutable URLs/checksums, no network fetches in build/package phases,
and conformity with the current AUR binary-package naming/submission rules. A source-built
`sibuna` recipe is distinct from `sibuna-bin`. Account setup and trusted-user review for any
official repository admission are separate. ARM is not implicitly official Arch support.
#link("https://wiki.archlinux.org/title/Arch_package_guidelines")[Arch packaging guidelines];
#link("https://wiki.archlinux.org/title/AUR_submission_guidelines")[AUR submission guidelines].

== Helm / OCI Images

The revised release workflow prepares a two-architecture OCI image from the qualified static
Linux release executables and a checksum-pinned distroless base. Publish it as
`ghcr.io/insanai/sibuna:VERSION`, carry notices/source links, run UID/GID 65532, and allow
chart digest pinning. The image contains CA certificates and a runtime identity but no shell,
package manager, Python, compiler, or build utilities. Publishing a chart alone does not require
a container build; deploying Sibuna in Kubernetes requires an available runtime image.
Maintain Chart.yaml, values/schema, helpers, NOTES, deployment/service, persistence, and optional
monitor/network/ingress resources. Chart version and application version are distinct metadata; initial releases advance both
together. Optional monitoring/ingress resources are deferred in this first chart.
#link("https://helm.sh/docs/chart_best_practices/")[Helm best practices].

For the first chart, `helm-bootstrap.yml` may wrap an already published stable application
release instead of rebuilding or replacing its binaries. It checks GitHub asset digests,
SHA256SUMS, both executable manifests/hashes, and the original tag's source commit. The
application tag must match the chart/app version. Existing source offers remain intact; OCI
labels separately identify the packaging revision and supplemental security policy. The image
and actual Restricted Kubernetes install/upgrade/uninstall must pass before publication.
Publish chart assets on a separate `helm-vVERSION` release, never change the application release
assets or latest marker, and rebuild the unified Pages index afterward. Future application
releases use the full distribution workflow. An Artifact Hub account has been created; the
HTTP repository must be live before registration. Registration does not require publishing
an account key in this repository. Add its public repository UUID after registration for
verified-publisher metadata, without owner names or emails.

Launch one replica with its own volume and Recreate strategy for the current single-node owner.
Never share a writable SQLite directory between pods or overlap old/new owners during rolling
upgrade. HPA is off; clustered charts require independent node volumes and a qualified profile.
Sidecars can use loopback origin IP. DNS-based gateway examples wait for resolution support or
a separately tested IP-literal reconfiguration mechanism.

Require an existing stable Secret. UID 65532 cannot read a root-owned projected 0400 file;
qualify group-readable projection (for example 0440 with fsGroup), or a private non-root copy.
No secret generation on Helm upgrade. Require non-root, no privilege escalation, drop ALL
capabilities, RuntimeDefault seccomp, read-only root plus explicit writable state/tmp, and no
service-account token automount unless needed. Read-only root is an additional choice, not
by itself proof of Restricted PSS.
The chart passes `/var/lib/sibuna/data` inside its mounted state volume: the non-root daemon
creates/owns the private 0700 child directory. A storage-driver-owned mount root cannot be
chmodded by UID 65532 even when fsGroup grants write access. No privileged chown/init utility
is needed; existing claims must permit child creation or provide that correctly owned child.
#link("https://kubernetes.io/docs/concepts/security/pod-security-standards/")[Pod Security Standards].

Startup/liveness uses `/__sibuna/health` with initialization grace. Readiness means listener
readiness until dependency checks exist. ServiceMonitor uses matching selectors, a named Service
port and `/__sibuna/metrics`; render monitoring CRDs only when enabled/installed. No default
public console Service. Required evidence: `helm lint --strict`, schema/template checks with
options on/off, Kubernetes validation, Restricted admission, Kind install/upgrade/uninstall,
actual traffic, Secret readability, state retention, and ingress metrics refusal.
Signing/provenance is claimed only when implemented and verified; label unsigned artifacts.

= Monitoring and Exposure

Health/metrics bypass policy on the data-plane port. Loopback host defaults limit direct exposure.
A public ingress must restrict metrics and optional health paths while allowing necessary browser
challenge/worker/verification routes. NetworkPolicy filters connections, not URLs: allowing an
ingress connection to port 8080 does not stop it forwarding public metrics requests. Verify
external denial and authorized scraper access through the installed deployment.

Existing metrics include `sibuna_requests_total`, `sibuna_allowed_total`, `sibuna_denied_total`,
`sibuna_challenged_total`, `sibuna_challenges_issued_total`, `sibuna_solutions_accepted_total`,
`sibuna_solutions_rejected_total`, `sibuna_rate_limited_total`, `sibuna_banned_total`,
`sibuna_bans_issued_total`, `sibuna_proxied_total`, `sibuna_upstream_errors_total`,
`sibuna_parse_errors_total`, `sibuna_overloaded_total`, `sibuna_incidents_persisted_total`,
`sibuna_incidents_dropped_total`, `sibuna_incident_write_failures_total`, and
`sibuna_incident_batches_total`. They reset on restart; use rate/increase appropriately.
CRS counters are conditional and must match `libs/crs/src/metrics.zig`.

No request-duration histogram or CPU/memory series is currently exported by Sibuna; use process
exporters instead of inventing names. Candidate alerts cover `up == 0`, sustained upstream
errors/overload, and incident loss/write failures, scoped to the correct job and validated against
real workload thresholds. Guard ratio denominators. Counters do not prove complete failure coverage.

= Service Hardening and Upgrade Limits

Linux candidate units use Type=simple, User/Group, StateDirectory, private umask, bounded restart,
SIGTERM, and explicit CLI mapping. Port 8080 grants no ambient capabilities and an empty bounding
set; privileged binding is an administrator override. Qualify ProtectSystem/ProtectHome,
PrivateTmp, NoNewPrivileges, kernel/control-group protections, address-family/system-call limits,
SQLite WAL/temp writes and CRS staging through real service tests. A systemd security score is
not a substitute for behavior checks or a portable supervisor contract.
#link("https://www.freedesktop.org/software/systemd/man/latest/systemd.service.html")[systemd service documentation].

Back up consistent stopped-daemon state (including SQLite WAL/related files as applicable) and
keys before schema-changing upgrades. Qualify migrations on a copy. Current v0.3.3 notes retain
schema 46 and prohibit incompatible older binaries. Package/Guix/Helm rollback does not revert
a database schema: prove compatibility or restore its matching backup with the daemon stopped.
Never edit a schema marker to force downgrade. Single-node restart/Recreate entails interruption;
do not promise zero downtime, guaranteed zero data loss, or effortless schema rollback.

= Readiness, Owners, and Ordered Rollout

#table(
  columns: (0.8fr, 1.15fr, 2.25fr),
  table.header([*Target*], [*Present here*], [*Open launch evidence*]),
  [Archives], [Workflow and tools], [Actual native release runs, immutable tag/assets, source/license closure.],
  [Debian/RPM/Arch], [Upstream binary-package tooling and service], [Actual native release/lifecycle runs; signed archive/community source recipes and acceptance remain separate.],
  [Homebrew], [Generated source formula and build gate], [Create thin tap, scoped update-PR credentials, native formula run; core audit/acceptance separately. No cask.],
  [WinGet], [Windows ZIP contract], [GitHub contribution identity, actual manifests/hash, native portable qualification.],
  [Guix], [Local candidate/helper], [Source-built compiler, Guix evaluation/build, origins/policy review; Shepherd later.],
  [BSD], [Native CLI package recipes and workflow gates], [Actual source/package/runtime runs; complete independent official ports and service review remain separate.],
  [Helm], [Chart/schema, qualified public image/chart, Pages index and verified repository UUID metadata], [Artifact Hub indexing/verified-publisher status, production network isolation and origin/ingress validation.],
  [Security], [Policy/process and reporting setting], [Merge/publish policy, responder assignments, notification/recovery drill and downstream contacts.],
)

1. Release owner verifies immutable source/dependency/license closure and retains existing release
   gates. Account owners inventory/register only the needed identities and qualify publishing access.
2. Packaging owners implement shared samples/bootstrap and Debian/RPM service recipes, then source
   Homebrew formula and portable WinGet manifests. Qualify each independently.
3. Guix owner runs the candidate in pinned GNU/Linux Guix; resolves toolchain, origins, asset and
   policy blockers before community submission. BSD owners establish native support before ports.
4. Container owner implements a single-node image/chart first; delays unresolved gateways/clustering.
5. Security owner and backup verify private intake/notifications, publish SECURITY.md, and prepare
   response/downstream procedures. Community maintainers prepare review artifacts and own feedback.
6. Release owner publishes each qualified target with exact channel/version/architecture/minimum OS,
   installation instructions, residual limits, and a reachable maintenance/update contact.

All roles require named assignees before launch. Track each account/setup item, issue/PR,
expected artifact, test log, digest, reviewer, and residual risk; do not invent a deadline or
mark a pending gate complete. The distribution tree now contains executable recipes and validation tools;
workflow definitions still require actual successful runs before publication. `guix.scm` is already at the root and
included in the Zig source package paths.

SID 0011 becomes committed only when its implemented target scope is explicit, required recipes
are merged, native source/lifecycle/security gates pass, provenance is correct, and operational
limits are documented. Record external acceptance separately. A narrower initial launch revises
scope and leaves deferred targets visibly pending.

= Local Verification Record (2026-10-09)

- `zig build fmt test sid -j2` passed: 105/105 steps and 1188/1188 tests. This is native
  macOS single-node verification, not qualification of every distribution or clustering.
- An isolated source tree with the two remote dependencies replaced by verified local
  amalgamations built the full safe/stripped profile with baseline CPU and an empty dependency
  cache: 14/14 steps passed. Both browser Wasm artifacts were rebuilt. The existing console
  size warning remains: 719413 bytes versus a 655360-byte review threshold.
- That executable passed version, sample-policy loading, persistent startup/restart, health,
  metrics, protected-login challenge, and graceful-shutdown smoke checks on loopback.
- Source preparation rejected corrupt inputs, symlinks, lock drift, and repeat staging;
  valid staged files matched the pinned inputs exactly. Invalid validation cases left the
  manifest and staging paths unchanged.
- Release packaging includes SECURITY.md in both tar.gz and ZIP. The ZIP format check used
  a synthetic executable fixture and is not Windows runtime qualification.
- Guile read checks and official Guix API inspection passed; no Guix package evaluation,
  GNU/Linux derivation build, reproducibility, or Shepherd service qualification is claimed.
- Both revised SIDs compile to PDF and HTML; code-review, account, and security pages were
  visually inspected. Metadata, YAML syntax, public-contact privacy, and diff checks passed.
- GitHub private reporting is enabled and API-verified. Responder notification/coverage drills,
  policy publication, account onboarding, community acceptance, and package publishing remain
  independent launch gates.

= Remote Distribution Verification Record (2026-10-09)

These results use an isolated validation snapshot on the designated GNU/Linux build host;
the fixtures are not public release assets and do not replace v0.3.3.

- The native Linux `zig build fmt test sid -j2` completed 105/105 steps with 1188/1188 tests.
- Safe/stripped Linux musl builds completed 14/14 steps on x86-64 and 14/14 steps for ARM64
  cross-compilation. ARM64 execution is still the existing native release-runner gate.
- The corresponding-source bundle built 14/14 steps with networking disabled and an empty
  global dependency cache. SQLite inputs were verified/staged and both Wasm artifacts rebuilt.
- Actual Debian/RPM packages were generated on both architectures and Arch on x86-64. Debian
  and Fedora container fixtures passed installation, private seed creation/repeat, configuration
  preservation on reinstall, removal with retained seed/state and service identity. Final
  metadata changes retain these contracts; the real systemd lifecycle gate runs on the
  disposable GitHub runner, not on a claimed remote production service installation.
- The two-platform OCI archive was exported with the pinned BuildKit image and inspected with
  skopeo. The x86-64 runtime image is about 17 MB uncompressed and passed non-root/read-only
  startup and restart with private Secret and persistent state mounts. Filesystem inspection
  verified CA certificates and absence of shell, Python, Zig, package managers and downloaders.
- Helm strict lint, positive/negative schema/template checks and workflow actionlint passed.
  Repository generation from existing published releases correctly yields an empty chart index
  before the first chart release; new chart assets will populate it after publication.
- Full remote Arch-hook and Kubernetes workload qualification remain blocked by the parent
  container policy: Arch cannot create hook pipes, and nested Kubernetes Pod sandboxes cannot
  reopen a required network sysctl. A test-only kubelet user-namespace setting allowed the
  control plane to start and Restricted admission accepted the chart resources; this is not
  evidence of a healthy chart installation. Do not weaken the shipped image or chart to work
  around the host. Preserve the normal GitHub-runner lifecycle/deployment gates before launch.
- The supplied package contact was configured as SIBUNA_PACKAGE_CONTACT without duplicating
  its value in public recipes/security documents. At this validation stage GHCR publication,
  public visibility, tap setup/PR credentials, Artifact Hub registration and notification
  drills were pending; the subsequent Helm publication record follows below.

= First Helm Publication Qualification (2026-10-09)

- The original v0.3.3 Linux assets were verified against GitHub asset digests,
  published SHA256SUMS, executable hashes/manifests and source commit
  `4f91644f2d5f20e6173ed0f4f54d598fac7f0cc2`. No application release asset changed.
- #link("https://github.com/insanai/sibuna/actions/runs/37889965763")[Bootstrap run 37889965763]
  passed actual non-root/read-only container checks and Restricted Kubernetes installation,
  listener health, Recreate upgrade, and uninstall with retained PVC/Secret. A preceding
  failure exposed storage-driver mount-root ownership; the chart now uses an owned child
  data directory. The failure and fix were also reproduced on the designated build host.
- The qualified chart and multi-platform OCI archive are retained as run artifacts.
  The publishing retry verifies unchanged recipe bytes and the successful actual runtime gate,
  then copies that same archive. Ubuntu 24.04 provides the required skopeo digest-preserving
  copy option. A different already-existing image at the version is never overwritten.
- The image uploaded to GHCR. With explicit owner authorization, public package creation was
  enabled briefly, the Sibuna package made public, and the original creation restriction
  restored and UI-verified. An anonymous registry inspection on the designated build host
  succeeded. The multi-platform image digest is
  `sha256:75c63a05885c97325175773594e4e30a47163f2a84df807b111e43ea3c954759`.
- #link("https://github.com/insanai/sibuna/releases/tag/helm-v0.3.3")[Helm 0.3.3]
  is published separately; the original v0.3.3 application assets/latest marker are unchanged.
  The chart SHA-256 is `5bcfcef57a946b16a2b5ba8bc23c2d43e50ea0f11406c47febb0506a0e26eaca`.
- #link("https://github.com/insanai/sibuna/actions/runs/37890615215")[Publishing run 37890615215]
  succeeded using the original qualified artifacts. Both image architectures and their layers
  were downloaded anonymously on the designated build host.
- #link("https://github.com/insanai/sibuna/actions/runs/37891247895")[Pages run 37891247895]
  deployed the populated #link("https://insanai.github.io/sibuna/charts/index.yaml")[HTTP index],
  which lists Sibuna 0.3.3 and its matching public chart download/digest. The owner has created
  an Artifact Hub account and configured ARTIFACTHUB_REPOSITORY_ID as a repository secret.
  Pages now accepts either a variable (preferred for this public identifier) or that existing
  secret, validates/canonicalizes the UUID, and publishes only repositoryID in adjacent
  artifacthub-repo.yml. No owner contact data or API key is published. Verify the served file
  and Artifact Hub's indexing/ownership status separately. Production CNI enforcement, origin
  traffic and ingress route restrictions remain operator deployment gates.
- A Helm client on the designated build host added/updated the live repository, found
  `sibuna/sibuna` at chart/app version 0.3.3, downloaded the package with the matching digest,
  and successfully rendered it using an operator-owned Secret reference.
- #link("https://github.com/insanai/sibuna/actions/runs/37892240603")[Ownership metadata Pages run]
  succeeded. The public #link("https://insanai.github.io/sibuna/charts/artifacthub-repo.yml")[metadata]
  returned HTTP 200 and its sole repositoryID matched the registered `sibuna` repository's
  public Artifact Hub API response exactly. No owner names or email addresses are included.
  Artifact Hub still reported verified_publisher false and no indexed package at this check;
  the next processing cycle, rather than metadata publication alone, sets that badge.

= Version 0.3.5 Release Scope

The requested next release is 0.3.5. It retains all five binary archives and adds
upstream Debian/RPM (x86-64 and ARM64), Arch (x86-64), FreeBSD 15.1/amd64 and
OpenBSD 7.9/amd64 packages to the same GitHub release. A source formula, offline
corresponding-source bundle, chart and qualified public image accompany them.
All English and seven translated README, book, operator-guide and website editions
share versioned links and package commands. Historical benchmark results retain
their original versions/commits and SID 0007's exception is not reclassified.

BSD packages install only the CLI and notices under /usr/local. They create no
account, rc service, administrator, credentials or state. Operators choose an
unprivileged identity, private keys/state and explicit startup; stop before
replacement/removal. Native jobs use the qualified base system's SDK and ordinary
user limits, test the installed console/proxy/ingress, then replace/remove while
checking retained operator files. FreeBSD .pkg carries ABI metadata; OpenBSD .tgz
records native wanted libraries. SHA256SUMS includes both. Accepting an explicitly
downloaded unsigned OpenBSD file does not disable system repository verification.
These packages are not official ports; poudriere/ports-tree and service integration
remain their community submission gates.

The immutable v0.3.4 candidate was not published. Its native binaries, CRS,
source and container/chart jobs passed, but Homebrew initially used stale runner
metadata and Arch's minimal container suppressed documentation extraction.
#link("https://github.com/insanai/sibuna/actions/runs/37894651349")[Original qualification]
and #link("https://github.com/insanai/sibuna/actions/runs/37895138415")[recovery]
retained publication gating. Homebrew passed after brew update; recovery correctly
refused the failed Arch gate. The Arch fixture now removes only its documentation
NoExtract pattern, preserving signature policy. No v0.3.4 app/image/chart was released.

Native BSD investigation on the designated build host passed both actual proxy
and ingress suites. A pure-Python large-frame masking fixture exceeded WebSocket
idle limits under software emulation; equivalent byte-translation masking now
passes with the original idle deadlines and independent RFC frame tests. FreeBSD
also passed persistent console qualification. OpenBSD startup exposed a capacity-sized incident-ring temporary exceeding the
ordinary 4 MiB stack and a C indirect-function sanitizer reading execute-only
libc instruction bytes. Incident and console telemetry rings now initialize directly in their allocated
storage. Only OpenBSD's C indirect-function sanitizer is omitted; other safe-mode
checks and execute-only system mappings remain intact. The installed console
and native package lifecycle still require successful ordinary-user logs. Do not
publish either an unqualified package or a version whose required release jobs failed.
Recovery requires successful original BSD jobs/artifacts as well as existing gates.

= References and Verification Limits

Policies checked on 2026-10-09. Debian, Homebrew, Microsoft, BSD, Helm, Kubernetes, GitHub, and
Fedora's compiler catalog were accessible. Fedora guideline pages and full Guix manual retrieval
were restricted; official indexed material offered partial corroboration. Recheck complete current
policies before asserting compliance. Guix GCD 008 was fetched from the official consensus repository
and is withdrawn; do not mistake a proposal for adopted rules.

- #link("https://docs.fedoraproject.org/en-US/packaging-guidelines/ReviewGuidelines/")[Fedora package review].
- #link("https://guix.gnu.org/manual/devel/en/html_node/Submitting-Patches.html")[Guix submitting patches].
- #link("https://codeberg.org/guix/guix-consensus-documents/src/branch/main/008-genai.md")[Guix GCD 008 (withdrawn)].
- #link("https://docs.github.com/en/code-security/how-tos/report-and-fix-vulnerabilities/configure-vulnerability-reporting/configure-for-a-repository")[GitHub private reporting setup].
- Repository evidence: LICENSE, NOTICE, CONTRIBUTING.md, SECURITY.md, build.zig.zon,
  vendor/provenance.json, release workflow/notes, CLI/server/proxy/policy/console source,
  guix.scm, and the offline source helper.
- Related: SID 0001 (standards/security), SID 0005 (storage), SID 0007 (console), SID 0010 (CRS).
