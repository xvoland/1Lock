//! Remembering the last opened export file.
//!
//! A single path is stored in a text file under `~/.config`. There are no
//! secrets there — just a path — so no encryption is needed. A write that
//! fails is better than a panic: the save error is ignored, the opened file
//! works anyway.

use std::path::{Path, PathBuf};

/// Path to the file holding the remembered path.
///
/// On Windows there is usually no `HOME` variable, and the old code returned
/// `None`: the remembered path was silently disabled, with no error and no
/// message. There we use `%APPDATA%` — the standard place for settings on
/// Windows.
///
/// Both branches are tail expressions rather than an early `return`: exactly
/// one of them survives `cfg`, and a `return` in front of nothing reads as
/// dead code to clippy — but only on the platform that keeps it.
fn state_file() -> Option<PathBuf> {
    #[cfg(target_os = "windows")]
    {
        let dir = std::env::var_os("APPDATA")?;
        Some(PathBuf::from(dir).join(crate::APP_TITLE).join("last-path"))
    }
    #[cfg(not(target_os = "windows"))]
    {
        let home = std::env::var_os("HOME")?;
        Some(PathBuf::from(home).join(".config/1lock/last-path"))
    }
}

/// The last opened file, if it still exists.
pub fn last_path() -> Option<PathBuf> {
    let raw = std::fs::read_to_string(state_file()?).ok()?;
    let raw = raw.trim();
    if raw.is_empty() {
        return None;
    }
    let p = PathBuf::from(raw);
    p.exists().then_some(p)
}

/// Remembers the path to an export file.
pub fn remember(path: &Path) {
    let Some(file) = state_file() else {
        return;
    };
    if let Some(dir) = file.parent() {
        let _ = std::fs::create_dir_all(dir);
    }
    let _ = std::fs::write(&file, path.to_string_lossy().as_bytes());
}

/// Forgets the last file.
///
/// Called when the vault is locked: if the path stayed, the next launch would
/// open again whatever the user had locked away from.
pub fn forget() {
    if let Some(file) = state_file() {
        let _ = std::fs::remove_file(file);
    }
}

/// Reduces the chosen path to the export file itself.
///
/// 1Password hands over a `Name….1pif` directory containing `data.1pif`. If a
/// directory was chosen, look for the file inside it.
pub fn resolve_export(chosen: &Path) -> PathBuf {
    if chosen.is_dir() {
        let inner = chosen.join("data.1pif");
        if inner.exists() {
            return inner;
        }
    }
    chosen.to_path_buf()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn directory_becomes_data_1pif() {
        let dir = std::env::temp_dir().join("opclient-resolve-test");
        let _ = std::fs::create_dir_all(&dir);
        let file = dir.join("data.1pif");
        std::fs::write(&file, b"{}").unwrap();

        assert_eq!(resolve_export(&dir), file);
        assert_eq!(resolve_export(&file), file);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn empty_directory_stays_a_directory() {
        let dir = std::env::temp_dir().join("opclient-resolve-empty");
        let _ = std::fs::create_dir_all(&dir);
        assert_eq!(resolve_export(&dir), dir);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
