//! Примитивы KDF, подтверждённые дизасмблом.
//!
//! Здесь только то, что восстановлено построчно. Функция
//! `derive_master_key` намеренно **не реализована**: соль для PBKDF2
//! неизвестна (см. [`crate::keys`]), и любая догадка здесь была бы
//! вредной — она молча давала бы неверные ключи.

use crate::error::{Error, Result};

/// SHA-256 через обёртку `sha2`.
pub fn sha256(data: &[u8]) -> [u8; 32] {
    use sha2::Digest;
    let mut h = sha2::Sha256::new();
    h.update(data);
    let out = h.finalize();
    let mut r = [0u8; 32];
    r.copy_from_slice(&out);
    r
}

/// Base64url без padding — как `ag_base64URLencode` со снятием `=`.
pub fn base64url_nopad(data: &[u8]) -> String {
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine;
    URL_SAFE_NO_PAD.encode(data)
}

/// Base64url с padding — как `ag_base64URLdecode` на входе.
pub fn base64url_decode(s: &str) -> Result<Vec<u8>> {
    use base64::engine::general_purpose::{URL_SAFE, URL_SAFE_NO_PAD};
    use base64::Engine;
    URL_SAFE_NO_PAD
        .decode(s.as_bytes())
        .or_else(|_| URL_SAFE.decode(s.as_bytes()))
        .map_err(|e| Error::Crypto(format!("base64url: {e}")))
}

/// `B5PasswordNormalize`, восстановленный из `_B5PasswordNormalize` (0x2af7b).
///
/// В дизасмеле: `CFStringNormalize(kCFStringNormalizationFormNFC)` затем
/// `CFStringTrimWhitespace`. Для ASCII это identity + trim.
///
/// Rust-эквивалент Unicode NFC без зависимости на ICU: для ASCII-паролей
/// (подавляющее большинство) результат идентичен. Для не-ASCII —
/// см. [`normalize_nfc`], который честно отказывает, а не молчит.
pub fn b5_password_normalize(password: &str) -> Result<String> {
    normalize_nfc(password.trim_matches(|c: char| c.is_whitespace()))
}

/// NFC-нормализация.
///
/// Возвращает ошибку, если строка не ASCII: полная NFC требует таблиц
/// Unicode, а молчаливая подмена сломала бы KDF незаметно.
pub fn normalize_nfc(s: &str) -> Result<String> {
    if s.is_ascii() {
        Ok(s.to_string())
    } else {
        Err(Error::Crypto(
            "NFC-нормализация не-ASCII строки не реализована: \
             требуется таблица Unicode. Для ASCII результат точен."
                .into(),
        ))
    }
}

/// Промежуточное значение `combined` для PBKDF2.
///
/// Возвращает строку, но **не** выполняет PBKDF2: соль неизвестна.
///
/// # Ошибка
///
/// Если строка не ASCII.
pub fn combined_pbes2_password(email: &str, password: &str) -> Result<String> {
    let prehash = crate::keys::b5_password_prehash(password)?;
    let email_lc = email
        .trim_matches(|c: char| c.is_whitespace())
        .to_lowercase();
    Ok(format!("{email_lc}:{prehash}"))
}

/// Статус восстановления KDF.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KdfStatus {
    /// Полностью восстановлен, можно выводить ключ.
    Complete,
    /// Частично: известна форма, неизвестна соль.
    BlockedOnSalt,
    /// Не начато.
    Unknown,
}

impl KdfStatus {
    /// Пояснение для пользователя.
    pub fn reason(self) -> &'static str {
        match self {
            Self::Complete => "KDF recovered",
            Self::BlockedOnSalt => {
                "Форма KDF восстановлена из дизассемблера, но соль для PBKDF2 \
                 берётся из encryptedSymmetricKey (<uuid>-scramble в plist), \
                 который сам зашифрован. Из бэкапа .1p4 соль недоступна: \
                 в таблице profiles её нет."
            }
            Self::Unknown => "KDF not parsed",
        }
    }
}

/// Текущий статус: соль неизвестна.
pub const STATUS: KdfStatus = KdfStatus::BlockedOnSalt;

/// Попытка вывести мастер-ключ. Всегда завершается ошибкой,
/// пока не решена проблема соли — см. [`STATUS`].
///
/// Ошибка возвращается **до** любых вычислений, чтобы нельзя было
/// случайно получить «какой-то» ключ и записать его в файл.
pub fn derive_master_key(_password: &str, _inputs: &crate::keys::KdfInputs) -> Result<[u8; 32]> {
    Err(Error::KeyUnavailable(STATUS.reason().to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prehash_matches_known_vector() {
        // Вектор из прогона probe_kdf.py: пароль "123xv334188!"
        let p = crate::keys::b5_password_prehash("123xv334188!").unwrap();
        assert_eq!(
            p, "sd0ZuWup2kfjKO13bFnwPrhy0KKRCrj7ZuxRLxKxZEM",
            "prehash должен совпадать с эталоном из Python-пробы"
        );
    }

    #[test]
    fn prehash_of_empty_is_constant() {
        // SHA256("") в base64url без padding
        assert_eq!(
            crate::keys::b5_password_prehash("").unwrap(),
            "47DEQpj8HBSa-_TImW-5JCeuQeRkm5NMpJWZG3hSuFU"
        );
    }

    #[test]
    fn combined_has_colon_and_prehash() {
        let c = combined_pbes2_password("", "pw").unwrap();
        assert!(c.starts_with(':'));
        assert_eq!(c.len(), 44);
    }

    #[test]
    fn combined_lowercases_email() {
        let a = combined_pbes2_password("USER@Example.COM", "pw").unwrap();
        let b = combined_pbes2_password("user@example.com", "pw").unwrap();
        assert_eq!(a, b);
        assert!(a.starts_with("user@example.com:"));
    }

    #[test]
    fn base64url_roundtrip() {
        let data = sha256(b"test");
        let enc = base64url_nopad(&data);
        assert_eq!(base64url_decode(&enc).unwrap(), data);
    }

    #[test]
    fn derive_refuses_without_salt() {
        let inputs = crate::keys::KdfInputs {
            iterations: 100_000,
            profile_salt: vec![0u8; 16],
            scramble: None,
            email: String::new(),
            has_personal_key: false,
        };
        let e = derive_master_key("x", &inputs).unwrap_err();
        assert!(matches!(e, Error::KeyUnavailable(_)));
    }

    #[test]
    fn non_ascii_is_rejected_not_silently_mangled() {
        assert!(normalize_nfc("пароль").is_err());
        assert_eq!(normalize_nfc("pass").unwrap(), "pass");
    }
}
