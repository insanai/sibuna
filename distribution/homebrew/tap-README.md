# Sibuna Homebrew tap

The upstream tap for [Sibuna](https://github.com/insanai/sibuna), an admission
proxy with proof-of-work challenges and WAF inspection. This repository publishes
a CLI **formula**, built from source. Packaging source and qualification live in
the [Sibuna monorepo](https://github.com/insanai/sibuna/tree/main/distribution/homebrew).

The formula is imported only after an upstream release passes its native
Homebrew source-build and restart tests. The latest published release currently
predates qualified source formula assets; installation becomes available when
the 0.3.5 release qualification finishes and `Formula/sibuna.rb` appears here.

## Installation

Once the formula is published:

```sh
brew tap insanai/sibuna
brew install insanai/sibuna/sibuna
sibuna --version
```

The source build requires the release's exact Zig version and Python 3.14. If
Homebrew's Zig has moved to a different version, follow the upstream installation
guide rather than changing the compiler check. No service starts automatically.
The upstream Homebrew gate builds and tests this formula on macOS 15. This tap
currently provides source builds; it does not publish prebuilt Homebrew bottles.

Before running Sibuna, create a private 32-byte admission seed and configure a
persistent private data directory, an IP-literal origin and an appropriate
process manager. The console is opt-in. See the
[operator guide](https://insanai.github.io/sibuna/book/operations.html) for
configuration, origin protection, upgrades and backup requirements.

```sh
brew update
brew upgrade insanai/sibuna/sibuna
# Stop your running process before replacement/removal.
brew uninstall insanai/sibuna/sibuna
```

Operator-owned seeds, configuration and state live outside Homebrew's installation
and must be retained during upgrade/removal. Back up state before an upgrade;
binary rollback does not undo a database migration.

## Release updates

The daily **Update Sibuna formula** workflow imports the formula attached to the
latest stable application release. It verifies the formula and corresponding
source bundle against release checksums and GitHub asset digests before committing
the recipe. Maintainers can also run the workflow with a published release tag.
It uses this tap's scoped `GITHUB_TOKEN`; no cross-repository publishing secret
is required. The source-build and runtime gates run upstream before publication.

This tap is maintained by Sibuna. Homebrew core inclusion requires a separate
community audit and human review. AI-assisted packaging work must be disclosed
in any community submission.

## License and security

This tap's first-party recipes, tooling and documentation follow Sibuna's
**LGPL-3.0-only** licensing. The default installed binary includes the console
and is a combined work under **AGPL-3.0-only**; the engine remains LGPL-3.0-only.
See [LICENSE](LICENSE), [LICENSES](LICENSES) and [NOTICE](NOTICE) for the upstream
scope and third-party terms. Immutable corresponding source is attached to each
qualified release and recorded in the formula.

Please report security issues privately through
[Sibuna's security reporting page](https://github.com/insanai/sibuna/security/advisories/new).
See [SECURITY.md](SECURITY.md) for the policy. Public issues are for non-sensitive
packaging defects; do not include credentials, private seeds or vulnerability
details.
