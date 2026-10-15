//! TOTP/HOTP по RFC 4226 и RFC 6238.
//!
//! Разбирает URI вида `otpauth://totp/Issuer:account?secret=…&period=30&digits=6&algorithm=SHA1`.
//!
//! Секрет — это база32 (RFC 4648, без padding, обычно запись 1Password).
//!
//! ## Замечание о совместимости
//!
//! 1Password использует стандартный HOTP/TOTP. Поддерживаются SHA-1 (по
//! умолчанию), SHA-256 и SHA-512 — выбор через параметр `algorithm`.
//! Значение по умолчанию `SHA1`, как требует RFC 6238 и как делает
//! большинство приложений, включая 1Password.

use hmac::{Hmac, Mac};
use sha1::Sha1;
use sha2::{Sha256, Sha512};

/// Ошибка разбора или вычисления.
#[derive(Debug, PartialEq, Eq)]
pub enum TotpError {
    /// Неизвестная схема (ожидается `otpauth`).
    BadScheme,
    /// Отсутствует обязательный параметр `secret`.
    MissingSecret,
    /// Секрет не является корректным base32.
    BadSecret,
    /// Неподдерживаемый алгоритм.
    BadAlgorithm,
    /// Некорректный URI в целом.
    BadUri,
}

impl std::fmt::Display for TotpError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            Self::BadScheme => "expected an otpauth:// URI",
            Self::MissingSecret => "the URI has no secret parameter",
            Self::BadSecret => "secret is not valid base32",
            Self::BadAlgorithm => "unsupported algorithm (SHA1/SHA256/SHA512)",
            Self::BadUri => "malformed URI",
        };
        f.write_str(s)
    }
}

impl std::error::Error for TotpError {}

/// Хеш-функция OTP.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Algorithm {
    /// SHA-1, по умолчанию.
    Sha1,
    /// SHA-256.
    Sha256,
    /// SHA-512.
    Sha512,
}

impl Algorithm {
    fn from_uri(s: &str) -> Result<Self, TotpError> {
        match s.to_ascii_uppercase().as_str() {
            "SHA1" | "" => Ok(Self::Sha1),
            "SHA256" => Ok(Self::Sha256),
            "SHA512" => Ok(Self::Sha512),
            _ => Err(TotpError::BadAlgorithm),
        }
    }
}

/// Разобранный дескриптор TOTP.
#[derive(Debug, Clone)]
pub struct Totp {
    secret: Vec<u8>,
    digits: u32,
    period: u64,
    algorithm: Algorithm,
}

impl Totp {
    /// Разбирает `otpauth://` URI.
    pub fn parse(uri: &str) -> Result<Self, TotpError> {
        let rest = uri.strip_prefix("otpauth://").ok_or(TotpError::BadScheme)?;
        let rest = rest
            .strip_prefix("totp/")
            .or_else(|| rest.strip_prefix("hotp/"))
            .ok_or(TotpError::BadScheme)?;

        let (_label, query) = match rest.split_once('?') {
            Some((l, q)) => (l, q),
            None => (rest, ""),
        };

        let mut secret = None;
        let mut digits = 6u32;
        let mut period = 30u64;
        let mut algorithm = Algorithm::Sha1;

        for pair in query.split('&').filter(|p| !p.is_empty()) {
            let (key, value) = pair.split_once('=').unwrap_or((pair, ""));
            let value = percent_decode(value);
            match key.to_ascii_lowercase().as_str() {
                "secret" => secret = Some(value),
                "digits" => digits = value.parse().unwrap_or(6),
                "period" => period = value.parse().unwrap_or(30),
                "algorithm" => algorithm = Algorithm::from_uri(&value)?,
                _ => {}
            }
        }

        let secret = secret.ok_or(TotpError::MissingSecret)?;
        let bytes = decode_base32(&secret).ok_or(TotpError::BadSecret)?;

        if period == 0 {
            period = 30;
        }
        if !(6..=8).contains(&digits) {
            digits = 6;
        }

        Ok(Self {
            secret: bytes,
            digits,
            period,
            algorithm,
        })
    }

    /// Число цифр в коде.
    pub fn digits(&self) -> u32 {
        self.digits
    }

    /// Период в секундах.
    pub fn period(&self) -> u64 {
        self.period
    }

    /// Код для момента `unix_seconds`.
    pub fn code_at(&self, unix_seconds: u64) -> String {
        let counter = unix_seconds / self.period;
        let mac = match self.algorithm {
            Algorithm::Sha1 => hmac_sha1(&self.secret, &counter.to_be_bytes()),
            Algorithm::Sha256 => {
                let mut m = Hmac::<Sha256>::new_from_slice(&self.secret).unwrap();
                m.update(&counter.to_be_bytes());
                m.finalize().into_bytes().to_vec()
            }
            Algorithm::Sha512 => {
                let mut m = Hmac::<Sha512>::new_from_slice(&self.secret).unwrap();
                m.update(&counter.to_be_bytes());
                m.finalize().into_bytes().to_vec()
            }
        };

        let offset = (mac[mac.len() - 1] & 0x0F) as usize;
        let binary = ((mac[offset] as u32 & 0x7F) << 24)
            | ((mac[offset + 1] as u32) << 16)
            | ((mac[offset + 2] as u32) << 8)
            | (mac[offset + 3] as u32);

        let modulus = 10u32.pow(self.digits);
        format!("{:0width$}", binary % modulus, width = self.digits as usize)
    }

    /// Код для текущего момента.
    pub fn code_now(&self) -> String {
        self.code_at(now_unix())
    }

    /// Остаток секунд до смены кода.
    pub fn seconds_remaining(&self, unix_seconds: u64) -> u64 {
        self.period - (unix_seconds % self.period)
    }
}

/// HMAC-SHA1 поверх крейта `sha1` — используется по умолчанию в OTP.
fn hmac_sha1(key: &[u8], data: &[u8]) -> Vec<u8> {
    let mut m = Hmac::<Sha1>::new_from_slice(key)
        .map_err(|_| "wrong key length")
        .expect("any key is accepted");
    m.update(data);
    m.finalize().into_bytes().to_vec()
}

/// Декодер base32 (RFC 4648, алфавит A–Z и 2–7).
///
/// Пробелы и дефисы внутри секрета игнорируются, padding `=` не требуется.
/// 5 бит на символ: 8 символов дают 5 байт.
fn decode_base32(s: &str) -> Option<Vec<u8>> {
    let mut bits = 0u32;
    let mut acc = 0u32;
    let mut out = Vec::with_capacity(s.len() * 5 / 8 + 1);

    for ch in s.chars() {
        if ch.is_whitespace() || ch == '-' || ch == '=' {
            continue;
        }
        let v = match ch.to_ascii_uppercase() {
            'A'..='Z' => ch.to_ascii_uppercase() as u32 - 'A' as u32,
            '2'..='7' => ch.to_ascii_uppercase() as u32 - '2' as u32 + 26,
            _ => return None,
        };
        acc = (acc << 5) | v;
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            out.push(((acc >> bits) & 0xFF) as u8);
        }
    }
    if out.is_empty() {
        return None;
    }
    Some(out)
}

fn percent_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            let hex = std::str::from_utf8(&bytes[i + 1..i + 3]).ok();
            if let Some(v) = hex.and_then(|h| u8::from_str_radix(h, 16).ok()) {
                out.push(v);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Текущее время Unix.
pub fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Вектор RFC 6238: secret = "12345678901234567890" (ASCII),
    /// SHA-1, 8 цифр, T=59 → 94287082.
    const SECRET: &str = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";

    #[test]
    fn rfc6238_sha1_vector() {
        let t = Totp::parse(&format!(
            "otpauth://totp/x?secret={SECRET}&digits=8&algorithm=SHA1"
        ))
        .unwrap();
        assert_eq!(t.code_at(59), "94287082");
    }

    #[test]
    fn rfc6238_multiple_times() {
        let t = Totp::parse(&format!(
            "otpauth://totp/x?secret={SECRET}&digits=8&algorithm=SHA1"
        ))
        .unwrap();
        assert_eq!(t.code_at(1_111_111_109), "07081804");
        assert_eq!(t.code_at(1_234_567_890), "89005924");
    }

    #[test]
    fn defaults_are_six_digits_thirty_seconds() {
        let t = Totp::parse(&format!("otpauth://totp/x?secret={SECRET}")).unwrap();
        assert_eq!(t.digits(), 6);
        assert_eq!(t.period(), 30);
        assert_eq!(t.code_at(59).len(), 6);
    }

    #[test]
    fn rejects_bad_input() {
        assert_eq!(Totp::parse("https://x").err(), Some(TotpError::BadScheme));
        assert_eq!(
            Totp::parse("otpauth://totp/x").err(),
            Some(TotpError::MissingSecret)
        );
        assert!(matches!(
            Totp::parse("otpauth://totp/x?secret=!!!&algorithm=SHA1"),
            Err(TotpError::BadSecret)
        ));
        assert!(matches!(
            Totp::parse("otpauth://totp/x?secret=AAAA&algorithm=MD5"),
            Err(TotpError::BadAlgorithm)
        ));
    }

    #[test]
    fn handles_space_and_padding_in_secret() {
        let t =
            Totp::parse("otpauth://totp/x?secret=GEZD GNBV GY3T QOJQ GEZD GNBV GY3T QOJQ").unwrap();
        let t2 = Totp::parse(&format!("otpauth://totp/x?secret={SECRET}")).unwrap();
        assert_eq!(t.code_at(59), t2.code_at(59));
    }

    #[test]
    fn seconds_remaining_within_period() {
        let t = Totp::parse(&format!("otpauth://totp/x?secret={SECRET}")).unwrap();
        let r = t.seconds_remaining(61);
        assert!((1..=30).contains(&r));
        assert_eq!(t.seconds_remaining(60), 30);
    }

    #[test]
    fn sha1_matches_known_sha1_digest() {
        // SHA-1("abc") = a9993e364706816aba3e25717850c26c9cd0d89d
        let d = <sha1::Sha1 as sha1::Digest>::digest(b"abc");
        assert_eq!(
            d.iter().map(|b| format!("{b:02x}")).collect::<String>(),
            "a9993e364706816aba3e25717850c26c9cd0d89d"
        );
    }

    #[test]
    fn percent_decoding() {
        assert_eq!(percent_decode("a%20b"), "a b");
        assert_eq!(percent_decode("plain"), "plain");
    }
}
