//! Версия приложения берётся из последнего тега git.
//!
//! Раньше версия была константой в `main.rs`, и её забывали поднимать: теги
//! дошли до v1.5.0, а панель «О приложении» и Info.plist показывали 1.0.0.
//! Теперь единственный источник правды — тег, а забыть его нельзя: на
//! `cargo build` без тега сборка просто не запустится.
//!
//! Без git (например, из распакованного архива) берётся версия пакета из
//! Cargo.toml: она тоже может устареть, но хотя бы что-то осмысленное.

use std::process::Command;

/// Последний тег без префикса `v`, например `1.5.0`.
fn version_from_git() -> Option<String> {
    // Репозиторий лежит уровнем выше пакета.
    let repo = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|p| p.parent())?;

    let out = Command::new("git")
        .args(["describe", "--tags", "--abbrev=0"])
        .current_dir(repo)
        .output()
        .ok()?;

    if !out.status.success() {
        return None;
    }

    let tag = String::from_utf8(out.stdout).ok()?.trim().to_string();
    let tag = tag.strip_prefix('v').unwrap_or(&tag);
    if tag.is_empty() {
        None
    } else {
        Some(tag.to_string())
    }
}

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=../../.git/HEAD");
    println!("cargo:rerun-if-changed=../../.git/packed-refs");

    let version = version_from_git()
        .or_else(|| std::env::var("CARGO_PKG_VERSION").ok())
        .unwrap_or_else(|| "0.0.0".to_string());

    println!("cargo:rustc-env=OPCLIENT_VERSION={version}");

    resources(&version);
}

/// Вшивает иконку и версию в `.exe` под Windows.
///
/// На macOS тем же занимается `scripts/make-bundle.sh`: там ресурсы лежат в
/// Info.plist, здесь — в самом бинарнике. Версия берётся из того же тега,
/// иначе в свойствах файла было бы 1.0.0 из Cargo.toml, а в macOS-бандле
/// 1.27.0, и панель «О приложении» показывала бы разное на двух системах.
fn resources(version: &str) {
    // Скрипт сборки компилируется для хоста, а не для цели, поэтому
    // проверять надо переменную cargo, а не собственный `cfg`.
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() != Ok("windows") {
        return;
    }

    let manifest_dir = std::path::PathBuf::from(
        std::env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR"),
    );
    // Путь абсолютный: `rc.exe` ищет файл относительно каталога пакета, а
    // иконка лежит уровнем выше, в assets/ всего репозитория.
    let icon = manifest_dir
        .join("../assets/app-icon.png")
        .canonicalize()
        .expect("assets/app-icon.png не найден");

    let mut res = winresource::WindowsResource::new();
    res.set_icon(icon.to_str().expect("путь не в utf-8"));
    res.set("FileDescription", &crate_title());
    res.set("ProductName", &crate_title());
    res.set("CompanyName", &crate_author());
    res.set("LegalCopyright", &crate_copyright());
    res.set("InternalName", &crate_title());
    res.set("OriginalFilename", "1Lock.exe");

    // Строковые свойства Windows показывает в свойствах файла, числовые нужны
    // для сравнения версий программно. 1.27.0 -> 1<<16 | 27.
    if let Some((major, minor)) = numeric_version(version) {
        res.set_version_info(winresource::VersionInfo::FILEVERSION, (major << 16) | minor);
        res.set_version_info(winresource::VersionInfo::PRODUCTVERSION, (major << 16) | minor);
    }
    res.set("FileVersion", version);
    res.set("ProductVersion", version);

    res.compile().expect("не собрались ресурсы Windows");
}

/// Название и автор читаются из исходников: иначе версия и название в
/// ресурсах.exe и в Info.plist разъедутся, как уже разъезжали.
fn crate_title() -> String {
    field("APP_TITLE").unwrap_or_else(|| "1Lock".to_string())
}

fn crate_author() -> String {
    field("APP_AUTHOR").unwrap_or_default()
}

fn crate_copyright() -> String {
    field("APP_COPYRIGHT").unwrap_or_default()
}

/// Значение константы вида `const APP_TITLE: &str = "1Lock";`.
fn field(name: &str) -> Option<String> {
    let src = std::fs::read_to_string(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/main.rs"),
    )
    .ok()?;
    let key = format!("const {name}: &str = \"");
    let start = src.find(&key)? + key.len();
    let rest = &src[start..];
    let end = rest.find('"')?;
    Some(rest[..end].to_string())
}

/// `1.27.0` -> `(1, 27)`. Неразобранная версия просто не даст числовых
/// свойств: строковые останутся, и это лучше, чем падение сборки.
fn numeric_version(version: &str) -> Option<(u64, u64)> {
    let mut parts = version.trim_start_matches('v').split('.');
    let major = parts.next()?.trim().parse().ok()?;
    let minor = parts.next().unwrap_or("0").trim().parse().ok()?;
    Some((major, minor))
}
