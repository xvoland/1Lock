#!/bin/bash
# Build the macOS bundle from the release binary. The name comes from APP_TITLE.
#
# Xcode is not needed: iconutil, sips and codesign are enough, they ship with
# macOS. A bundle is just an ordinary folder with a fixed structure.
#
# Usage: scripts/make-bundle.sh [path-to-the-source-binary]

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# The name and the version are taken from the sources so that Info.plist and
# the "About" window cannot drift apart.
APP_NAME=$(sed -n 's/^const APP_TITLE: &str = "\(.*\)";/\1/p' "$ROOT/crates/ui/src/main.rs")
# The version comes from the latest tag: on macOS the "About" panel reads it
# from exactly here, from Info.plist, and it has to match what the app itself
# shows (see crates/ui/build.rs).
#
# The logic is the one in build.rs, and that duplication is the point: `git
# describe --abbrev=0` answers "which is the newest tag reachable from here",
# which for every commit after a release is that same release. Six weeks of
# work would have shipped labelled 1.27.0, claiming to be a release that never
# happened. On the tagged commit the version is bare; one commit later it gains
# -dev, and an unreleased build says so by itself.
# --match отбрасывает теги, не похожие на версию: тег `nightly` иначе стал бы
# версией дословно и попал бы в Info.plist, где ни macOS, ни Explorer ничего
# в нём не поймут.
DESCRIBE=$(git -C "$ROOT" describe --tags --abbrev=0 --match 'v[0-9]*' 2>/dev/null || true)
if [[ -n "$DESCRIBE" ]]; then
    HEAD_SHA=$(git -C "$ROOT" rev-parse HEAD 2>/dev/null || true)
    TAG_SHA=$(git -C "$ROOT" rev-list -n 1 "$DESCRIBE" 2>/dev/null || true)
    VERSION="${DESCRIBE#v}"
    if [[ -n "$HEAD_SHA" && "$HEAD_SHA" != "$TAG_SHA" ]]; then
        VERSION="$VERSION-dev"
    fi
else
    # Without git, take the package version — just like build.rs does.
    VERSION=$(sed -n 's/^version = "\(.*\)"/\1/p' "$ROOT/Cargo.toml" | head -1)
fi
AUTHOR=$(sed -n 's/^const APP_AUTHOR: &str = "\(.*\)";/\1/p' "$ROOT/crates/ui/src/main.rs")
URL=$(sed -n 's/^const APP_URL: &str = "\(.*\)";/\1/p' "$ROOT/crates/ui/src/main.rs")
COPYRIGHT=$(sed -n 's/^const APP_COPYRIGHT: &str = "\(.*\)";/\1/p' "$ROOT/crates/ui/src/main.rs")
COMMENTS=$(sed -n 's/^const APP_COMMENTS: &str = "\(.*\)";/\1/p' "$ROOT/crates/ui/src/main.rs")
BUILD=1

if [[ -z "$APP_NAME" || -z "$VERSION" ]]; then
    echo "failed to read APP_TITLE/APP_VERSION from crates/ui/src/main.rs" >&2
    exit 1
fi
BUNDLE_ID="com.xvoland.1lock"

BIN_SRC="${1:-$ROOT/target/release/opclient-ui}"
if [[ ! -f "$BIN_SRC" ]]; then
    echo "binary not found: $BIN_SRC" >&2
    echo "build it first: cargo build --release -p opclient-ui" >&2
    exit 1
fi

# This script only packages, it does not build. Without this check it would
# silently wrap an hour-old binary and print "done" — which looked like a
# successful build of fresh code while a stale one was inside.
if [[ -n "$(find "$ROOT/crates" "$ROOT/Cargo.toml" -newer "$BIN_SRC" \
            \( -name '*.rs' -o -name '*.toml' \) 2>/dev/null | head -1)" ]]; then
    echo "binary is older than the sources: $BIN_SRC" >&2
    echo "rebuild: cargo build --release -p opclient-ui" >&2
    echo "or pass a ready path as the first argument" >&2
    exit 1
fi

BUILD_DIR="$ROOT/dist"
APP="$BUILD_DIR/$APP_NAME.app"
STAGE="$BUILD_DIR/.stage"

echo "==> cleanup"
rm -rf "$STAGE"
mkdir -p "$STAGE/Contents/MacOS" "$STAGE/Contents/Resources"

echo "==> binary"
cp "$BIN_SRC" "$STAGE/Contents/MacOS/$APP_NAME"
chmod +x "$STAGE/Contents/MacOS/$APP_NAME"

echo "==> Info.plist"
cat > "$STAGE/Contents/Info.plist" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>CFBundleName</key>
    <string>$APP_NAME</string>
    <key>CFBundleDisplayName</key>
    <string>$APP_NAME</string>
    <key>CFBundleIdentifier</key>
    <string>$BUNDLE_ID</string>
    <key>CFBundleExecutable</key>
    <string>$APP_NAME</string>
    <key>CFBundleIconFile</key>
    <string>AppIcon</string>
    <key>CFBundlePackageType</key>
    <string>APPL</string>
    <key>CFBundleInfoDictionaryVersion</key>
    <string>6.0</string>
    <key>CFBundleShortVersionString</key>
    <string>$VERSION</string>
    <key>CFBundleVersion</key>
    <string>$BUILD</string>
    <key>CFBundleGetInfoString</key>
    <string>$COMMENTS</string>
    <!-- The system "About" panel takes these fields from Info.plist rather
         than from the muda metadata: without them the author and website are
         not shown. -->
    <key>NSHumanReadableCopyright</key>
    <string>$COPYRIGHT · $URL</string>
    <key>NSApplicationName</key>
    <string>$APP_NAME</string>
    <key>NSPrincipalClass</key>
    <string>NSApplication</string>
    <key>LSMinimumSystemVersion</key>
    <string>11.0</string>
    <key>LSApplicationCategoryType</key>
    <string>public.app-category.utilities</string>
    <key>NSHighResolutionCapable</key>
    <true/>
    <!-- The application opens 1PIF files on double-click. -->
    <key>CFBundleDocumentTypes</key>
    <array>
        <dict>
            <key>CFBundleTypeName</key>
            <string>1Password Export</string>
            <key>CFBundleTypeRole</key>
            <string>Editor</string>
            <key>LSHandlerRank</key>
            <string>Alternate</string>
            <key>CFBundleTypeExtensions</key>
            <array>
                <string>1pif</string>
            </array>
        </dict>
    </array>
</dict>
</plist>
PLIST
plutil -lint "$STAGE/Contents/Info.plist" >/dev/null

echo "==> icon"
ICONSET="$BUILD_DIR/AppIcon.iconset"
rm -rf "$ICONSET"
mkdir -p "$ICONSET"

# Icon sources: first the external one (a source next to the project), then
# the one in the repository, and only then we draw a fallback. The order
# matters for CI: the external folder is not there, and without the second
# step the macOS artifact would get the drawn icon while the .exe would get
# the one in assets, and the two would diverge.
ICON_SRC="${ICON_SRC:-$ROOT/../assets/icon.png}"
if [[ ! -f "$ICON_SRC" ]]; then
    ICON_SRC="$ROOT/assets/app-icon.png"
fi
MASTER="$BUILD_DIR/AppIcon-1024.png"
if [[ -f "$ICON_SRC" ]]; then
    echo "   using $ICON_SRC"
    # Normalise to 1024×1024: sips preserves the alpha channel, iconutil
    # requires it.
    sips -z 1024 1024 "$ICON_SRC" --out "$MASTER" >/dev/null
else
    echo "   no icon of our own, drawing a fallback"
    python3 "$ROOT/scripts/make_icon.py" "$MASTER" 1024
fi

# iconutil wants every size; the missing ones come from downscaling
add_size() { sips -z "$1" "$1" "$MASTER" --out "$ICONSET/$2" >/dev/null; }
add_size 16   icon_16x16.png
add_size 32   icon_16x16@2x.png
add_size 32   icon_32x32.png
add_size 64   icon_32x32@2x.png
add_size 128  icon_128x128.png
add_size 256  icon_128x128@2x.png
add_size 256  icon_256x256.png
add_size 512  icon_256x256@2x.png
add_size 512  icon_512x512.png
cp "$MASTER" "$ICONSET/icon_512x512@2x.png"

iconutil -c icns "$ICONSET" -o "$STAGE/Contents/Resources/AppIcon.icns"
rm -rf "$ICONSET" "$BUILD_DIR/AppIcon-1024.png"

echo "==> signing"
# An ad-hoc signature is enough for local launch. Without it Gatekeeper may
# complain about a binary that did not come from the store.
codesign --force --sign - --timestamp=none "$STAGE" >/dev/null 2>&1 \
    || echo "   warning: codesign did not work, launching may be restricted"

echo "==> install"
rm -rf "$APP"
mv "$STAGE" "$APP"
rmdir "$BUILD_DIR" 2>/dev/null || true

echo
echo "done: $APP"
echo "size: $(du -sh "$APP" | cut -f1)"
echo "launch: open \"$APP\""
