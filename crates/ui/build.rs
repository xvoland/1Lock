//! The app version is taken from the most recent git tag.
//!
//! The version used to be a constant in `main.rs`, and people kept forgetting
//! to bump it: tags had reached v1.5.0 while the "About" panel and Info.plist
//! still showed 1.0.0. Now the tag is the single source of truth, and it
//! cannot be forgotten: without a tag, `cargo build` simply refuses to run.
//!
//! A tag on its own is not enough, though. `git describe --tags --abbrev=0`
//! answers "the newest tag reachable from here", which for every commit after
//! a release is that same release. Six weeks of work would have gone out
//! labelled 1.27.0, claiming to be a release that never happened. So the tag
//! is compared with HEAD: on the tagged commit the version is the bare number,
//! and one commit later it becomes `1.27.0-dev`. A build that was never
//! released says so on its own.
//!
//! Without git (for example, from an unpacked archive) the package version
//! from Cargo.toml is used: it can be stale too, but at least it means
//! something.

use std::process::Command;

/// The most recent tag without the `v` prefix, for example `1.5.0`, with
/// `-dev` appended when HEAD is not the tagged commit.
fn version_from_git() -> Option<String> {
    // The repository sits one level above the package.
    let repo = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|p| p.parent())?;

    // Only tags that look like a version count. A tag called `nightly` would
    // otherwise become the version verbatim and land in Info.plist and in the
    // Windows version resource, where neither macOS nor Explorer can make
    // sense of it.
    let describe = git(
        repo,
        &["describe", "--tags", "--abbrev=0", "--match", "v[0-9]*"],
    )?;
    let describe = describe.trim();
    if describe.is_empty() {
        return None;
    }

    // Both sides are asked for explicitly rather than trusting describe to
    // mean "this commit": a build in CI runs on a detached HEAD at the tag,
    // and the two answers have to be comparable.
    let head = git(repo, &["rev-parse", "HEAD"])?;
    let tagged = git(repo, &["rev-list", "-n", "1", describe])?;

    let tag = describe.strip_prefix('v').unwrap_or(describe);
    if head.trim() == tagged.trim() {
        Some(tag.to_string())
    } else {
        Some(format!("{tag}-dev"))
    }
}

/// Runs git in `dir` and returns its trimmed stdout.
fn git(dir: &std::path::Path, args: &[&str]) -> Option<String> {
    let out = Command::new("git").args(args).current_dir(dir).output().ok()?;
    if !out.status.success() {
        return None;
    }
    String::from_utf8(out.stdout).ok()
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

/// Embeds the icon and the version into the `.exe` on Windows.
///
/// On macOS `scripts/make-bundle.sh` does the same job: there the resources
/// live in Info.plist, here they live in the binary itself. The version comes
/// from the same tag, otherwise the file properties would say 1.0.0 from
/// Cargo.toml while the macOS bundle says 1.27.0, and the "About" panel would
/// show different things on the two systems.
fn resources(version: &str) {
    // The build script is compiled for the host, not for the target, so the
    // cargo variable has to be checked rather than our own `cfg`.
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() != Ok("windows") {
        return;
    }

    let manifest_dir = std::path::PathBuf::from(
        std::env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR"),
    );
    // The path is absolute: `rc.exe` looks for the file relative to the
    // package directory, while the icon lives in the repository-wide
    // assets/. From the `crates/ui` package directory that is two levels up,
    // not one: `../assets` would point at `crates/assets`, which does not
    // exist, and the build would fail exactly on Windows — there build.rs is
    // the only thing looking for the icon.
    //
    // It must be the .ico, not the .png: `rc.exe` rejects a PNG with RC2175
    // "is not in 3.00 format" — it wants a real ICO container. The .ico is
    // built from the very same PNG by scripts/make_ico.py, so the two can
    // never drift apart visually.
    let icon = manifest_dir
        .join("../../assets/app-icon.ico")
        .canonicalize()
        .expect("assets/app-icon.ico not found");

    let mut res = winresource::WindowsResource::new();
    res.set_icon(icon.to_str().expect("path is not utf-8"));
    res.set("FileDescription", &crate_title());
    res.set("ProductName", &crate_title());
    res.set("CompanyName", &crate_author());
    res.set("LegalCopyright", &crate_copyright());
    res.set("InternalName", &crate_title());
    res.set("OriginalFilename", "1Lock.exe");

    // Windows shows the string properties in the file properties, while the
    // numeric ones are needed to compare versions programmatically.
    // 1.27.0 -> 1<<16 | 27.
    if let Some((major, minor)) = numeric_version(version) {
        res.set_version_info(winresource::VersionInfo::FILEVERSION, (major << 16) | minor);
        res.set_version_info(winresource::VersionInfo::PRODUCTVERSION, (major << 16) | minor);
    }
    res.set("FileVersion", version);
    res.set("ProductVersion", version);

    res.compile().expect("failed to compile Windows resources");
}

/// The name and author are read from the sources: otherwise the version and
/// the name in the .exe resources and in Info.plist drift apart, as they
/// already have.
fn crate_title() -> String {
    field("APP_TITLE").unwrap_or_else(|| "1Lock".to_string())
}

fn crate_author() -> String {
    field("APP_AUTHOR").unwrap_or_default()
}

fn crate_copyright() -> String {
    field("APP_COPYRIGHT").unwrap_or_default()
}

/// The value of a constant shaped like `const APP_TITLE: &str = "1Lock";`.
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

/// `1.27.0` -> `(1, 27)`. An unparsable version simply yields no numeric
/// properties: the string ones stay, and that is better than failing the build.
fn numeric_version(version: &str) -> Option<(u64, u64)> {
    let mut parts = version.trim_start_matches('v').split('.');
    let major = parts.next()?.trim().parse().ok()?;
    let minor = parts.next().unwrap_or("0").trim().parse().ok()?;
    Some((major, minor))
}
