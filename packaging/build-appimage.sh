#!/bin/bash
# Build Cheat Engine as an AppImage
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
BUILD_DIR="$SCRIPT_DIR/../build"
APPDIR="$BUILD_DIR/AppDir"

echo "Building cecore..."
cd "$SCRIPT_DIR/.."
cmake -B build -DCMAKE_BUILD_TYPE=Release -DCMAKE_INSTALL_PREFIX=/usr
cmake --build build -j$(nproc)

echo "Creating AppDir..."
rm -rf "$APPDIR"
mkdir -p "$APPDIR/usr/bin" "$APPDIR/usr/lib" "$APPDIR/usr/share/applications" "$APPDIR/usr/share/icons/hicolor/256x256/apps"

# Copy binaries
cp "$BUILD_DIR/cheatengine" "$APPDIR/usr/bin/"
cp "$BUILD_DIR/cescan" "$APPDIR/usr/bin/"

# Copy libraries
cp "$BUILD_DIR/libcecore.so" "$APPDIR/usr/lib/"
ldd "$BUILD_DIR/cheatengine" | grep "=> /" | awk '{print $3}' | while read lib; do
    case "$lib" in
        /usr/lib/x86_64-linux-gnu/libQt6*|*/libcapstone*|*/libkeystone*)
            cp "$lib" "$APPDIR/usr/lib/" 2>/dev/null || true
            ;;
    esac
done

# Copy desktop file
cp "$SCRIPT_DIR/cheatengine.desktop" "$APPDIR/usr/share/applications/"

# Create a simple icon (placeholder)
convert -size 256x256 xc:'#1e1e2e' -fill '#89b4fa' -gravity center \
    -pointsize 72 -annotate +0+0 'CE' \
    "$APPDIR/usr/share/icons/hicolor/256x256/apps/cheatengine.png" 2>/dev/null || \
    touch "$APPDIR/usr/share/icons/hicolor/256x256/apps/cheatengine.png"

# Symlinks for AppImage
ln -sf usr/share/applications/cheatengine.desktop "$APPDIR/"
ln -sf usr/share/icons/hicolor/256x256/apps/cheatengine.png "$APPDIR/"

# Create AppRun
cat > "$APPDIR/AppRun" << 'APPRUN'
#!/bin/bash
HERE="$(dirname "$(readlink -f "$0")")"
export LD_LIBRARY_PATH="$HERE/usr/lib:$LD_LIBRARY_PATH"
exec "$HERE/usr/bin/cheatengine" "$@"
APPRUN
chmod +x "$APPDIR/AppRun"

# Build AppImage (if appimagetool available)
if command -v appimagetool &>/dev/null; then
    appimagetool "$APPDIR" "$BUILD_DIR/CheatEngine-x86_64.AppImage"
    echo "AppImage created: $BUILD_DIR/CheatEngine-x86_64.AppImage"
else
    echo "appimagetool not found. AppDir ready at: $APPDIR"
    echo "Install appimagetool from: https://github.com/AppImage/AppImageKit"
fi
