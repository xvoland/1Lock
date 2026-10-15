//! `opclient-core` — чтение формата 1Password Agile Keychain (`.1p4`).
//!
//! # Что работает сейчас
//!
//! - открытие базы строго на чтение;
//! - обзор профиля, папок, категорий, элементов;
//! - разбор контейнера `opdata01` и геометрии блоба `IV ‖ CT ‖ HMAC`;
//! - проверка HMAC заданным ключом (однозначный критерий);
//! - полная SHA-256 базы для контроля неизменности исходника.
//!
//! # Что не работает
//!
//! Расшифровка. KDF не восстановлен: соль для PBKDF2 лежит внутри
//! зашифрованного блока `encryptedSymmetricKey`. Подробности и журнал
//! неудачных гипотез — в `docs/FORMAT.md`.
//!
//! # Пример
//!
//! ```no_run
//! use opclient_core::{Vault, KeyProvider, keys::Unavailable};
//!
//! let v = Vault::open("/path/to/OnePassword.sqlite")?;
//! let s = v.summary()?;
//! println!("элементов: {}", s.item_count);
//! assert!(Unavailable.master_key().is_err()); // соль неизвестна
//! # Ok::<(), opclient_core::Error>(())
//! ```

#![forbid(unsafe_code)]
#![warn(missing_debug_implementations)]

pub mod audit;
pub mod envelope;
pub mod error;
pub mod kdf;
pub mod keys;
pub mod pif;
pub mod totp;
pub mod vault;

pub use envelope::{Envelope, HmacStatus};
pub use error::{Error, Result};
pub use keys::KeyProvider;
pub use vault::{Item, Vault};

/// Длина ключа AES-256, используемого для блоков профиля и элементов.
pub const KEY_LEN: usize = envelope::KEY_LEN;

/// Версия крейта.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Статус восстановления KDF на момент сборки.
pub fn kdf_status() -> kdf::KdfStatus {
    kdf::STATUS
}
#[cfg(test)]
mod integration {
    use super::*;

    /// Тест на реальном экспорте, если файл доступен.
    /// Путь задаётся переменной окружения `OPCLIENT_GOLDEN_1PIF`.
    /// Без неё тест пропускается, чтобы сборка не зависела от личных данных.
    #[test]
    fn parses_real_export_when_present() {
        let Ok(path) = std::env::var("OPCLIENT_GOLDEN_1PIF") else {
            eprintln!("OPCLIENT_GOLDEN_1PIF не задан — тест пропущен");
            return;
        };
        let pif = pif::Pif::from_file(&path).expect("экспорт должен читаться");
        let entries = pif.entries();
        assert!(!entries.is_empty(), "в экспорте нет записей");
        eprintln!("прочитано записей: {}", entries.len());

        // У каждой записи должен быть заголовок, иначе список UI будет пустым.
        let titled = entries.iter().filter(|i| i.title.is_some()).count();
        assert!(titled > 0, "нет ни одной записи с заголовком");

        // Поиск обязан что-то находить.
        let first = entries[0].title.clone().unwrap_or_default();
        let q: String = first.chars().take(4).collect();
        if q.len() >= 2 {
            assert!(!pif.search(&q).is_empty(), "поиск по {q:?} ничего не нашёл");
        }
    }

    /// Согласованность: TOTP-код из экспорта считается и не падает.
    #[test]
    fn totp_from_export_is_computable() {
        let Ok(path) = std::env::var("OPCLIENT_GOLDEN_1PIF") else {
            return;
        };
        let pif = pif::Pif::from_file(&path).expect("экспорт должен читаться");
        let mut checked = 0;
        for item in pif.entries() {
            if let Some(uri) = item.totp() {
                if let Ok(t) = totp::Totp::parse(uri) {
                    let code = t.code_at(totp::now_unix());
                    assert_eq!(code.len() as u32, t.digits());
                    checked += 1;
                    if checked >= 3 {
                        break;
                    }
                }
            }
        }
        eprintln!("TOTP проверен для {checked} записей");
    }
}
