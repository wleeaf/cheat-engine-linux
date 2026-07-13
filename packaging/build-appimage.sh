#!/bin/bash
# Build Cheat Engine as an AppImage using linuxdeploy + the Qt plugin.
#
# linuxdeploy-plugin-qt bundles the Qt libraries AND the Qt plugins — most
# importantly the platform plugin (platforms/libqxcb.so) — and rewrites rpaths
# correctly. The earlier hand-rolled `ldd | allowlist` copy missed the plugins,
# so the resulting AppImage failed at runtime with
#   "could not find or load the Qt platform plugin \"xcb\"".
# It also produces a versioned, self-contained artifact.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT="$SCRIPT_DIR/.."
BUILD_DIR="$ROOT/build"
APPDIR="$BUILD_DIR/AppDir"
TOOLS="$BUILD_DIR/appimage-tools"

# Output file name carries the project version (parsed from CMakeLists project()).
VERSION="$(sed -nE 's/^project\(cecore VERSION ([0-9.]+).*/\1/p' "$ROOT/CMakeLists.txt")"
VERSION="${VERSION:-0.0.0}"

echo "Building cecore (Release)..."
cmake -S "$ROOT" -B "$BUILD_DIR" -DCMAKE_BUILD_TYPE=Release -DCMAKE_INSTALL_PREFIX=/usr
cmake --build "$BUILD_DIR" -j"$(nproc)"

echo "Fetching linuxdeploy + Qt plugin + appimagetool (cached in $TOOLS)..."
mkdir -p "$TOOLS"
fetch() {  # fetch <url> <dest>
    [ -x "$2" ] && return 0
    if command -v wget >/dev/null 2>&1; then wget -q -O "$2" "$1"; else curl -sSL -o "$2" "$1"; fi
    chmod +x "$2"
}
LD="https://github.com/linuxdeploy"
fetch "$LD/linuxdeploy/releases/download/continuous/linuxdeploy-x86_64.AppImage"                 "$TOOLS/linuxdeploy"
fetch "$LD/linuxdeploy-plugin-qt/releases/download/continuous/linuxdeploy-plugin-qt-x86_64.AppImage" "$TOOLS/linuxdeploy-plugin-qt"
fetch "https://github.com/AppImage/appimagetool/releases/download/continuous/appimagetool-x86_64.AppImage" "$TOOLS/appimagetool"

# cecore is versioned (SOVERSION); bundle the soname symlink so it resolves.
CECORE_LIB="$(ls "$BUILD_DIR"/libcecore.so.* 2>/dev/null | grep -E 'libcecore\.so\.[0-9]+$' | head -1)"

echo "Bundling into AppDir with linuxdeploy..."
rm -rf "$APPDIR"
export PATH="$TOOLS:$PATH"
export APPIMAGE_EXTRACT_AND_RUN=1   # run the tool AppImages without needing FUSE (CI/containers)
export QMAKE="$(command -v qmake6 || command -v qmake)"
export VERSION
export OUTPUT="$BUILD_DIR/CheatEngine-${VERSION}-x86_64.AppImage"

"$TOOLS/linuxdeploy" --appdir "$APPDIR" \
    --executable "$BUILD_DIR/cheatengine" \
    --executable "$BUILD_DIR/cescan" \
    ${CECORE_LIB:+--library "$CECORE_LIB"} \
    --desktop-file "$SCRIPT_DIR/cheatengine.desktop" \
    --icon-file "$SCRIPT_DIR/cheatengine.png" \
    --plugin qt \
    --output appimage

echo "AppImage created: $OUTPUT"
