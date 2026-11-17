# RPM packaging for Cheat Engine for Linux

The spec builds two packages:

| Package | Contents |
| --- | --- |
| `cheat-engine-linux` | `cheatengine`, `cescan`, `cetutorial`, `cegtutorial`, `libcecore.so.1`, `libspeedhack.so`, `libcecore_mono_agent.so`, the bundled Keystone runtime, the desktop file, icon, AppStream metainfo, MIME association, docs and licences |
| `cheat-engine-linux-devel` | `libcecore` headers, the linker symlink and `cecore.pc` |

`%post` runs `setcap cap_sys_ptrace+ep` on `cheatengine` and `cescan`, the same
permission the `.deb` grants: without it the default
`kernel.yama.ptrace_scope=1` stops the scanner from reading another process.
The binaries then run as secure-exec processes, so they use only the built-in
translation catalogue (see `docs/I18N.md`).

Keystone is **bundled** (`Source1`): no Fedora package provides the assembler
under a usable name, and upstream's CMakeLists sets `CMP0051` to `OLD`, which
current CMake rejects. `%prep` applies the repository's idempotent
`cmake/patch_keystone.cmake` to the pinned source before configuring.

## Build

From the repository root, on Fedora, with the dependencies installed:

```bash
sudo bash packaging/build-rpm.sh --install-deps   # dnf builddep from the spec
bash packaging/build-rpm.sh                       # binary + source RPM
```

Or build in a container, which needs only podman or docker:

```bash
bash packaging/build-rpm.sh --container           # fedora:latest
```

Results land in `rpm-out/`:

```
cheat-engine-linux-1.1.0-1.fc45.x86_64.rpm
cheat-engine-linux-1.1.0-1.fc45.x86_64.rpm.sha256
cheat-engine-linux-devel-1.1.0-1.fc45.x86_64.rpm
cheat-engine-linux-devel-1.1.0-1.fc45.x86_64.rpm.sha256
cheat-engine-linux-1.1.0-1.fc45.src.rpm
cheat-engine-linux-1.1.0-1.fc45.src.rpm.sha256
rpmlint.log            # advisory
```

rpmbuild also writes debuginfo/debugsource packages into `rpm-out/`; the CI
action stages only the runtime, devel and source packages (with their
`.sha256` files) into `rpm-release/` for the artifact and the release.

Each package gets its own `.sha256` file, the same convention as the `.deb` and
the AppImage on the release page.

The script uses the spec's `BuildRequires` as the only dependency list (via
`dnf builddep`, with a `BuildRequires`-parsing fallback when the plugin is
unavailable), makes the source tarball with `git archive` from `HEAD`, downloads
the Keystone tarball and verifies its sha256 against the spec. It refuses to
build from a dirty working tree unless `--allow-dirty` is passed.

To build the source RPM only, for COPR or openSUSE OBS:

```bash
bash packaging/build-rpm.sh --srpm
```

## What CI runs

`.github/workflows/rpm.yml` builds both packages in a `fedora:latest`
container, installs them, then checks that `setcap` was applied, that the
frontends, headers and pkg-config file are installed, and that the dependency
generator produced sensible `Requires`. (The frontends themselves run in the
spec's `%check` section: a binary with file capabilities cannot be executed
inside an unprivileged container.) Every run also keeps the release packages
(runtime, devel and source, with per-file `.sha256` files) as the
`rpm-packages` workflow artifact, so a build can be downloaded without a
release.

On release tags `release.yml` runs the same composite action in parallel with
the AppImage/.deb job, after the same compatibility gates, and keeps the
packages as an artifact. Only the final `publish` job creates the GitHub
release, with one `action-gh-release` call that uploads the `.rpm`, the
`.src.rpm`, their `.sha256` files, the `.deb` and the AppImage together. The
release therefore never exists half-finished while a gate is still running, and
a failed RPM build leaves the `.deb` and AppImage release intact.

## Distributing

- **COPR**: create a project, then submit the source RPM:
  `copr-cli build <project> rpm-out/*.src.rpm`. A SCM project pointing at this
  repository also works if it can run a `make srpm` target; the upload method
  needs no extra files in the tree.
- **openSUSE OBS**: the spec is close to usable, but openSUSE names some
  dependencies differently (`qt6-base-devel`, `qt6-tools-devel`, ...). Those
  `BuildRequires` need a per-distribution adapter; the build itself (CMake,
  install rules, `%post` setcap) is the same. Only Fedora is validated in CI.
- **Fedora proper**: the package needs a review, and bundling Keystone requires
  an FPC exception. COPR is the practical path until Keystone (or a compatible
  replacement) is packaged in Fedora.

## Keeping the pins current

`Version` must match `project(cecore VERSION ...)` in `CMakeLists.txt`; the
build script and the CI workflow both compare them. To bump Keystone, update
`%global keystone_version`, `%global keystone_commit` and
`%global keystone_sha256` together (the script refuses a mismatching tarball),
and keep `cmake/patch_keystone.cmake` in sync with the new source.

## Troubleshooting

```bash
sudo dnf install ./rpm-out/cheat-engine-linux-*.x86_64.rpm
getcap /usr/bin/cheatengine            # cap_sys_ptrace=ep
sudo dnf remove cheat-engine-linux
```

If `%post` cannot set the capability (for example in a locked-down container),
the package still installs and prints a warning; the app's permission dialog
still offers the pkexec grant, the same as a source build.
