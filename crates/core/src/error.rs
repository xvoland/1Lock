//! Ошибки чтения формата 1Password.

use thiserror::Error;

/// Результат операции.
pub type Result<T> = std::result::Result<T, Error>;

/// Ошибка чтения формата.
#[derive(Debug, Error)]
pub enum Error {
    /// База или файл не найден.
    #[error("no such path: {0}")]
    NotFound(String),

    /// Данных меньше, чем нужно для разбора.
    #[error("data truncated: got {have}, need {need}")]
    Truncated {
        /// Сколько байт есть.
        have: usize,
        /// Сколько требуется.
        need: usize,
    },

    /// Ошибка SQLite.
    #[error("SQLite: {0}")]
    Sqlite(#[from] rusqlite::Error),

    /// Ошибка криптографии или формата блоба.
    #[error("crypto/format: {0}")]
    Crypto(String),

    /// HMAC не сошёлся — расшифровка не имеет смысла.
    #[error("HMAC mismatch ({0}), decryption is impossible")]
    HmacNotVerified(String),

    /// Заголовок `opdata01` не распознан.
    #[error("expected opdata01 magic, got {0:?}")]
    BadMagic([u8; 8]),

    /// Ключ недоступен: KDF ещё не восстановлен.
    #[error("key unavailable: {0}")]
    KeyUnavailable(String),

    /// Ошибка ввода-вывода.
    #[error("I/O: {0}")]
    Io(#[from] std::io::Error),

    /// Ошибка разбора JSON.
    #[error("JSON: {0}")]
    Json(#[from] serde_json::Error),
}
