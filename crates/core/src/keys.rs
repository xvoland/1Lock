//! Источник ключей для расшифровки.
//!
//! Статус: **KDF не восстановлен.** См. [`crate::kdf`] и `docs/FORMAT.md`.
//!
//! Что подтверждено дизасмблером (`OnePasswordCore`, `OPSymmetricKey.m`):
//!
//! ```text
//! combined = email.ag_trim.lowercaseString + ":" + B5PasswordPrehash(password)
//! B5PasswordPrehash(pw) = base64url_no_pad(SHA256(utf8(trim(pw))))
//! rawKey   = PBKDF2-HMAC-SHA256(utf8(combined), salt, iterations, 32)
//! если personalKey: rawKey = combineWithBytes(personalKey, rawKey)
//! ```
//!
//! Что **не** подтверждено: какая именно соль используется. По коду
//! `-[B5UserAccount masterUnlockKeyForPassword:]` соль берётся из
//! `encryptedSymmetricKey` (`opdata <uuid>-scramble` в plist), а не из
//! `profiles.salt`. Но сам scramble-блоб зашифрован, поэтому соль
//! неизвестна вне цикла. Это и есть причина, по которой подбор не сошёлся.

use crate::envelope::KEY_LEN;
use crate::error::{Error, Result};

/// Ключ для расшифровки блоков профиля и элементов.
pub trait KeyProvider {
    /// Имя источника — для диагностики.
    fn name(&self) -> &str;

    /// Возвращает 32-байтовый ключ либо ошибку, если ключ недоступен.
    fn master_key(&self) -> Result<[u8; KEY_LEN]>;
}

/// Заглушка: всегда сообщает, что ключ недоступен.
///
/// Существует, чтобы вся остальная система (парсинг, обзор, CLI)
/// была рабочей и собиралась до восстановления KDF.
#[derive(Debug, Default, Clone)]
pub struct Unavailable;

impl KeyProvider for Unavailable {
    fn name(&self) -> &str {
        "unavailable"
    }

    fn master_key(&self) -> Result<[u8; KEY_LEN]> {
        Err(Error::KeyUnavailable(
            "KDF не восстановлен: соль для PBKDF2 лежит внутри зашифрованного \
             блока encryptedSymmetricKey (<uuid>-scramble в plist 1Password), \
             поэтому ключ нельзя вывести из бэкапа .1p4"
                .into(),
        ))
    }
}

/// Ключ, известный извне (например, восстановленный офлайн или из
/// ground-truth экспорта). Для тестов и сверки.
#[derive(Debug, Clone)]
pub struct StaticKey(pub [u8; KEY_LEN]);

impl KeyProvider for StaticKey {
    fn name(&self) -> &str {
        "static"
    }

    fn master_key(&self) -> Result<[u8; KEY_LEN]> {
        Ok(self.0)
    }
}

/// Промежуточные значения KDF — то, что известно, и то, что нет.
#[derive(Debug, Clone)]
pub struct KdfInputs {
    /// Число итераций PBKDF2.
    pub iterations: u32,
    /// Соль профиля — предполагаемый, но не подтверждённый источник.
    pub profile_salt: Vec<u8>,
    /// Зашифрованный блок `encryptedSymmetricKey`, если найден.
    pub scramble: Option<Vec<u8>>,
    /// Email аккаунта: пусто для локальной версии.
    pub email: String,
    /// Наличие `personalKey`.
    pub has_personal_key: bool,
}

impl KdfInputs {
    /// `true`, если для PBKDF2 есть всё необходимое, кроме самого ключа.
    pub fn salt_known(&self) -> bool {
        !self.profile_salt.is_empty()
    }
}

/// `B5PasswordPrehash`, восстановленный из `_B5PasswordPrehash` (0x2ae0f).
///
/// ```text
/// s = password; s = CFStringTrimWhitespace(s)
/// h = SHA256(utf8(s)); b = base64url(h); b = b.replace("=", "")
/// ```
///
/// Реализация здесь — эталон для сверки с Rust-версией.
///
/// # Ошибка
///
/// Возвращает ошибку, если пароль не является валидным UTF-8.
pub fn b5_password_prehash(password: &str) -> Result<String> {
    let trimmed = password.trim_matches(|c: char| c.is_whitespace());
    let digest = crate::kdf::sha256(trimmed.as_bytes());
    Ok(crate::kdf::base64url_nopad(&digest))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unavailable_reports_why() {
        let e = Unavailable.master_key().unwrap_err();
        assert!(matches!(e, Error::KeyUnavailable(_)));
    }

    #[test]
    fn static_key_roundtrip() {
        let k = StaticKey([4u8; KEY_LEN]);
        assert_eq!(k.master_key().unwrap(), [4u8; KEY_LEN]);
    }

    #[test]
    fn prehash_is_43_chars() {
        let p = b5_password_prehash("whatever").unwrap();
        assert_eq!(p.len(), 43);
        assert!(!p.contains('='));
        assert!(!p.contains('+'));
        assert!(!p.contains('/'));
    }
}
