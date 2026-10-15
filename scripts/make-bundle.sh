#!/bin/bash
# Сборка macOS-бандла из release-бинарника. Имя берётся из APP_TITLE.
#
# Xcode не нужен: достаточно iconutil, sips и codesign, они входят в
# состав macOS. Бандл — это обычная папка с фиксированной структурой.
#
# Запуск: scripts/make-bundle.sh [путь-к-исходника-бинарника]

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# Название и версию берём из исходников, чтобы Info.plist и окно
# «О приложении» не расходились.
APP_NAME=$(sed -n 's/^const APP_TITLE: &str = "\(.*\)";/\1/p' "$ROOT/crates/ui/src/main.rs")
# Версию берём из последнего тега: панель «О приложении» на macOS читает её
# именно отсюда, из Info.plist, и она обязана совпадать с той, что показывает
# само приложение (см. crates/ui/build.rs).
VERSION=$(git -C "$ROOT" describe --tags --abbrev=0 2>/dev/null | sed 's/^v//')
if [[ -z "$VERSION" ]]; then
    # Без git берём версию пакета — как это делает build.rs.
    VERSION=$(sed -n 's/^version = "\(.*\)"/\1/p' "$ROOT/Cargo.toml" | head -1)
fi
AUTHOR=$(sed -n 's/^const APP_AUTHOR: &str = "\(.*\)";/\1/p' "$ROOT/crates/ui/src/main.rs")
URL=$(sed -n 's/^const APP_URL: &str = "\(.*\)";/\1/p' "$ROOT/crates/ui/src/main.rs")
COPYRIGHT=$(sed -n 's/^const APP_COPYRIGHT: &str = "\(.*\)";/\1/p' "$ROOT/crates/ui/src/main.rs")
COMMENTS=$(sed -n 's/^const APP_COMMENTS: &str = "\(.*\)";/\1/p' "$ROOT/crates/ui/src/main.rs")
BUILD=1

if [[ -z "$APP_NAME" || -z "$VERSION" ]]; then
    echo "не удалось прочитать APP_TITLE/APP_VERSION из crates/ui/src/main.rs" >&2
    exit 1
fi
BUNDLE_ID="com.xvoland.1lock"

BIN_SRC="${1:-$ROOT/target/release/opclient-ui}"
if [[ ! -f "$BIN_SRC" ]]; then
    echo "не найден бинарник: $BIN_SRC" >&2
    echo "сначала соберите его: cargo build --release -p opclient-ui" >&2
    exit 1
fi

# Скрипт только пакует, а не собирает. Без этой проверки он молча заворачивал
# бинарник часовой давности и печатал «готово» — выглядело как успешная сборка
# свежего кода, а внутри оказывался старый.
if [[ -n "$(find "$ROOT/crates" "$ROOT/Cargo.toml" -newer "$BIN_SRC" \
            \( -name '*.rs' -o -name '*.toml' \) 2>/dev/null | head -1)" ]]; then
    echo "бинарник старше исходников: $BIN_SRC" >&2
    echo "пересоберите: cargo build --release -p opclient-ui" >&2
    echo "или передайте готовый путь первым аргументом" >&2
    exit 1
fi

BUILD_DIR="$ROOT/dist"
APP="$BUILD_DIR/$APP_NAME.app"
STAGE="$BUILD_DIR/.stage"

echo "==> чистка"
rm -rf "$STAGE"
mkdir -p "$STAGE/Contents/MacOS" "$STAGE/Contents/Resources"

echo "==> бинарник"
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
    <!-- Системная панель «О приложении» берёт эти поля из Info.plist,
         а не из метаданных muda: без них автор и сайт не показываются. -->
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
    <!-- Приложение открывает файлы 1PIF двойным кликом. -->
    <key>CFBundleDocumentTypes</key>
    <array>
        <dict>
            <key>CFBundleTypeName</key>
            <string>Экспорт 1Password</string>
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

echo "==> иконка"
ICONSET="$BUILD_DIR/AppIcon.iconset"
rm -rf "$ICONSET"
mkdir -p "$ICONSET"

# Источник иконки: своя картинка рядом с проектом, иначе рисуем запасную.
ICON_SRC="${ICON_SRC:-$ROOT/../assets/icon.png}"
MASTER="$BUILD_DIR/AppIcon-1024.png"
if [[ -f "$ICON_SRC" ]]; then
    echo "   используем $ICON_SRC"
    # Приводим к 1024×1024: sips сохраняет альфа-канал, iconutil его требует.
    sips -z 1024 1024 "$ICON_SRC" --out "$MASTER" >/dev/null
else
    echo "   своей иконки нет, рисуем запасную"
    python3 "$ROOT/scripts/make_icon.py" "$MASTER" 1024
fi

# iconutil ждёт все размеры; недостающие получаем уменьшением
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

echo "==> подпись"
# Ad-hoc подпись достаточно для локального запуска. Без неё Gatekeeper
# может ругаться на бинарник, запущенный не из магазина.
codesign --force --sign - --timestamp=none "$STAGE" >/dev/null 2>&1 \
    || echo "   предупреждение: codesign не сработал, запуск может быть ограничен"

echo "==> установка"
rm -rf "$APP"
mv "$STAGE" "$APP"
rmdir "$BUILD_DIR" 2>/dev/null || true

echo
echo "готово: $APP"
echo "размер: $(du -sh "$APP" | cut -f1)"
echo "запуск: open \"$APP\""
