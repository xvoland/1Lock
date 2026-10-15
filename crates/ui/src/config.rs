//! Запоминание последнего открытого файла экспорта.
//!
//! Хранится один путь в текстовом файле под `~/.config`. Секретов там нет —
//! только путь, поэтому никакого шифрования не требуется. Запись лучше не
//! удаётся, чем падает: ошибку сохранения игнорируем, открытый файл всё
//! равно работает.

use std::path::{Path, PathBuf};

/// Путь к файлу с запомненным путём.
fn state_file() -> Option<PathBuf> {
    let home = std::env::var_os("HOME")?;
    Some(PathBuf::from(home).join(".config/1lock/last-path"))
}

/// Последний открытый файл, если он ещё существует.
pub fn last_path() -> Option<PathBuf> {
    let raw = std::fs::read_to_string(state_file()?).ok()?;
    let raw = raw.trim();
    if raw.is_empty() {
        return None;
    }
    let p = PathBuf::from(raw);
    p.exists().then_some(p)
}

/// Запоминает путь к файлу экспорта.
pub fn remember(path: &Path) {
    let Some(file) = state_file() else {
        return;
    };
    if let Some(dir) = file.parent() {
        let _ = std::fs::create_dir_all(dir);
    }
    let _ = std::fs::write(&file, path.to_string_lossy().as_bytes());
}

/// Забывает последний файл.
///
/// Вызывается при извлечении хранилища: если бы путь остался, следующий
/// запуск снова открыл бы то, с чем пользователь разошёлся.
pub fn forget() {
    if let Some(file) = state_file() {
        let _ = std::fs::remove_file(file);
    }
}

/// Приводит выбранный путь к самому файлу экспорта.
///
/// 1Password отдаёт каталог `Имя….1pif`, внутри которого лежит `data.1pif`.
/// Если выбрали каталог, ищем файл внутри него.
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
    fn каталог_превращается_в_data_1pif() {
        let dir = std::env::temp_dir().join("opclient-resolve-test");
        let _ = std::fs::create_dir_all(&dir);
        let file = dir.join("data.1pif");
        std::fs::write(&file, b"{}").unwrap();

        assert_eq!(resolve_export(&dir), file);
        assert_eq!(resolve_export(&file), file);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn пустой_каталог_остаётся_каталогом() {
        let dir = std::env::temp_dir().join("opclient-resolve-empty");
        let _ = std::fs::create_dir_all(&dir);
        assert_eq!(resolve_export(&dir), dir);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
