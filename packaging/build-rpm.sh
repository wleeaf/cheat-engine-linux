#!/usr/bin/env bash
# Build the cheat-engine-linux RPM (and source RPM).
#
# The source tarball is generated from the current git commit, and the pinned
# Keystone tarball is downloaded and checked against the sha256 in the spec, so
# a clean checkout is all this script needs. Build dependencies come from the
# spec: with dnf's builddep plugin when available, otherwise from its
# BuildRequires lines directly.
#
# Usage:
#   packaging/build-rpm.sh                 # build binary + source RPM here
#   packaging/build-rpm.sh --srpm          # source RPM only (for COPR/OBS)
#   packaging/build-rpm.sh --container     # build inside fedora:latest
#   packaging/build-rpm.sh --install-deps  # only install BuildRequires (root)
#   packaging/build-rpm.sh --check         # only validate spec/source pins
#
# Options:
#   --outdir DIR     copy the results here (default: <repo>/rpm-out)
#   --topdir DIR     rpmbuild _topdir (default: <repo>/build/rpmbuild)
#   --container IMG  run the build in a container (default image fedora:latest)
#   --no-rpmlint     skip the rpmlint report
#   --allow-dirty    build even if the working tree has uncommitted changes
#                    (the tarball still comes from the last commit)
#
# rpmlint findings are written to rpm-out/rpmlint.log. They are a report, not a
# gate: the release CI keeps the log with the run.

set -euo pipefail

self=$(readlink -f "$0")
repo=$(cd "$(dirname "$self")/.." && pwd)
spec="$repo/packaging/rpm/cheat-engine-linux.spec"

outdir="$repo/rpm-out"
topdir="$repo/build/rpmbuild"
container=""
install_deps_only=0
srpm_only=0
check_only=0
run_rpmlint=1
allow_dirty=0

die() { echo "build-rpm.sh: $*" >&2; exit 1; }
note() { echo "==> $*"; }

usage() {
    sed -n '2,30p' "$self" | sed 's/^# \{0,1\}//'
    exit 0
}

while [ $# -gt 0 ]; do
    case "$1" in
        --outdir) outdir=$(readlink -m "$2"); shift 2 ;;
        --topdir) topdir=$(readlink -m "$2"); shift 2 ;;
        --container) container="${2:-fedora:latest}"; [ $# -ge 2 ] && shift 2 || shift ;;
        --srpm) srpm_only=1; shift ;;
        --install-deps) install_deps_only=1; shift ;;
        --check) check_only=1; shift ;;
        --no-rpmlint) run_rpmlint=0; shift ;;
        --allow-dirty) allow_dirty=1; shift ;;
        -h|--help) usage ;;
        *) die "unknown argument: $1 (try --help)" ;;
    esac
done

[ -f "$spec" ] || die "spec not found: $spec"

# ── Values that must agree before anything is built ──────────────────────────
version=$(sed -n 's/^project(cecore VERSION \([0-9.]*\).*/\1/p' "$repo/CMakeLists.txt")
[ -n "$version" ] || die "cannot read the project version from CMakeLists.txt"
spec_version=$(sed -n 's/^Version:[[:space:]]*//p' "$spec" | head -1)
spec_version=${spec_version%%%*}
[ "$version" = "$spec_version" ] \
    || die "spec Version ($spec_version) does not match CMakeLists.txt ($version)"
keystone_sha256=$(sed -n 's/^%global keystone_sha256[[:space:]]*//p' "$spec" | head -1)
keystone_commit=$(sed -n 's/^%global keystone_commit[[:space:]]*//p' "$spec" | head -1)
[ -n "$keystone_sha256" ] && [ -n "$keystone_commit" ] \
    || die "cannot read the Keystone pin from the spec"
# Source1's name; the spec builds it from the same commit with a macro.
keystone_archive="keystone-$keystone_commit"
note "version $version, Keystone $keystone_archive"

if [ "$check_only" -eq 1 ]; then
    note "spec and source pins are consistent"
    exit 0
fi

# ── Build dependency installation (run as root, inside a Fedora build root) ──
install_build_requires() {
    command -v dnf >/dev/null 2>&1 || die "--install-deps needs dnf"
    dnf -y install rpm-build
    if dnf -y builddep "$spec"; then
        return
    fi
    note "dnf builddep unavailable; installing the spec's BuildRequires directly"
    # One source of truth: the spec. These names take no arguments and no
    # version constraints in this spec, so plain word splitting is fine.
    local reqs
    reqs=$(sed -n 's/^BuildRequires:[[:space:]]*//p' "$spec" \
           | sed 's/[[:space:]]*#.*$//' | sort -u)
    # shellcheck disable=SC2086
    dnf -y install $reqs
}

if [ "$install_deps_only" -eq 1 ]; then
    install_build_requires
    exit 0
fi

if [ -n "$container" ]; then
    engine=$(command -v podman || command -v docker || true)
    [ -n "$engine" ] || die "no podman or docker for --container"
    [ -d "$repo" ] || die "repository path is not a directory: $repo"
    note "building in $container with $engine"
    # git and curl are needed for git archive and the Keystone download; they are
    # not BuildRequires, so install them before the inner build.
    "$engine" run --rm -v "$repo:$repo" -w "$repo" -e HOME=/tmp "$container" \
        bash -c "dnf -y install git curl rpm-build >/dev/null && bash '$self' --install-deps && bash '$self' --outdir '$outdir' --topdir '$topdir'$([ "$run_rpmlint" -eq 0 ] && echo ' --no-rpmlint')$([ "$allow_dirty" -eq 1 ] && echo ' --allow-dirty')"
    exit 0
fi

if [ -z "$(git -C "$repo" rev-parse --short HEAD 2>/dev/null)" ]; then
    die "$repo is not a git checkout; the source tarball is made with git archive"
fi
if [ -n "$(git -C "$repo" status --porcelain --untracked-files=no)" ] && [ "$allow_dirty" -eq 0 ]; then
    die "working tree has uncommitted changes; commit them or pass --allow-dirty"
fi

# ── Sources ─────────────────────────────────────────────────────────────────
sources="$topdir/SOURCES"
mkdir -p "$sources" "$topdir/SPECS"
cp "$spec" "$topdir/SPECS/"

tarball="$sources/cheat-engine-linux-$version.tar.gz"
note "creating $tarball from $(git -C "$repo" rev-parse --short HEAD)"
git -C "$repo" archive --format=tar.gz \
    --prefix="cheat-engine-linux-$version/" \
    -o "$tarball" HEAD

keystone_tgz="$sources/$keystone_archive.tar.gz"
if [ ! -f "$keystone_tgz" ]; then
    note "downloading Keystone $keystone_commit"
    curl -L --fail --retry 3 --retry-delay 2 \
        -o "$keystone_tgz.part" \
        "https://github.com/keystone-engine/keystone/archive/$keystone_commit/$keystone_archive.tar.gz"
    mv "$keystone_tgz.part" "$keystone_tgz"
fi
actual=$(sha256sum "$keystone_tgz" | cut -d' ' -f1)
[ "$actual" = "$keystone_sha256" ] \
    || die "Keystone tarball sha256 mismatch: got $actual, spec has $keystone_sha256"

# ── rpmbuild ────────────────────────────────────────────────────────────────
jobs=$(nproc 2>/dev/null || echo 2)
[ "$jobs" -ge 2 ] && [ "$jobs" -gt 8 ] && jobs=8
build_arg=-ba
[ "$srpm_only" -eq 1 ] && build_arg=-bs

note "rpmbuild $build_arg ($jobs jobs)"
if ! rpmbuild "$build_arg" \
        --define "_topdir $topdir" \
        --define "_smp_mflags -j$jobs" \
        --define "_smp_build_ncpus $jobs" \
        "$topdir/SPECS/cheat-engine-linux.spec" 2>&1 | tee "$topdir/build.log"; then
    die "rpmbuild failed; see $topdir/build.log"
fi

# ── Collect results ─────────────────────────────────────────────────────────
mkdir -p "$outdir"
find "$topdir/RPMS" "$topdir/SRPMS" -type f -name '*.rpm' -exec cp -f {} "$outdir/" \;
[ -n "$(ls -A "$outdir" 2>/dev/null)" ] || die "rpmbuild produced no packages"
note "packages in $outdir:"
ls -1 "$outdir"/*.rpm
( cd "$outdir" && for rpm in ./*.rpm; do sha256sum "$rpm" > "$rpm.sha256"; done )

if [ "$run_rpmlint" -eq 1 ] && command -v rpmlint >/dev/null 2>&1; then
    note "rpmlint report (advisory)"
    # shellcheck disable=SC2086
    rpmlint "$outdir"/*.rpm > "$outdir/rpmlint.log" 2>&1 || true
    grep -v ': W: ' "$outdir/rpmlint.log" | head -40 || true
fi

note "done"
