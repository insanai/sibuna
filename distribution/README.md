# Distribution

This directory holds the packaging recipes of the Sibuna releases. The release workflow (`.github/workflows/release.yml`) uses them on every tag `v*`; a manual run of the workflow builds and checks everything without publishing.

| Path | What it is |
| --- | --- |
| `linux/` | The systemd unit, the sysusers entry, `service.env`, the seed helper and the package scripts of the Debian, RPM and Arch packages. |
| `container/` | The Dockerfile of the image: the static musl executable on a distroless base, user 65532. |
| `helm/sibuna/` | The Helm chart: one Pod, an operator-owned Secret for the seed, a PVC for the SQLite state. |
| `homebrew/` | The template of the Homebrew formula, which installs the release archives. |
| `scripts/` | The Python scripts the release workflow runs (standard library only, except PyYAML for the chart check). |

## Release flow

```text
prepare: version check, WebAssembly modules (once)
   |
   +--> build (5 runners) --> linux-packages (deb, rpm, Arch) --+
   |      |                   homebrew (formula, brew test)     |
   |      +-----------------> container (image, kind + chart) --+--> publish (tags only)
   +--> source-and-chart (source bundle, Helm chart) -----------+
   +--> freebsd, openbsd (native build and package in a VM) ----+
```

Every platform job builds with the same WebAssembly modules (`SIBUNA_POW_WASM`, `SIBUNA_CONSOLE_WASM`), runs `--version` and `scripts/smoke_test.py` against the executable it built, and packages it with `scripts/package_release.py`. The publish job runs only after every job passed. It copies the verified image to GHCR, writes `SHA256SUMS`, and creates the GitHub release and marks it the latest one; a beta is a public release too.

## Maintainer setup

- The repository variable `SIBUNA_PACKAGE_CONTACT` names the maintainer address written into the deb, rpm, Arch and BSD packages. A tag build stops without it.
- The GHCR package `ghcr.io/insanai/sibuna` must give this repository's workflows write access and be public; the publish job refuses to name an image that cannot be pulled anonymously.
- `cargo xtask licenses` regenerates `LICENSES/THIRD-PARTY-RUST.txt` after a dependency change; CI fails while it is stale.
