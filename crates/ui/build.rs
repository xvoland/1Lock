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
    println!("cargo:rerun-if-changed=../../.git/refs/tags");

    let version = version_from_git()
        .or_else(|| std::env::var("CARGO_PKG_VERSION").ok())
        .unwrap_or_else(|| "0.0.0".to_string());

    println!("cargo:rustc-env=OPCLIENT_VERSION={version}");
}
