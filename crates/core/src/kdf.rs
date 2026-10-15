//! KDF primitives confirmed by the disassembly.
//!
//! Only what was recovered line by line. `derive_master_key` is
//! deliberately **not implemented**: the PBKDF2 salt is unknown (see
//! [`crate::keys`]), and any guess here would be harmful — it would
//! silently yield wrong keys.

use crate::error::{Error, Result};

/// SHA-256 via the `sha2` wrapper.
pub fn sha256(data: &[u8]) -> [u8; 32] {
    use sha2::Digest;
    let mut h = sha2::Sha256::new();
    h.update(data);
    let out = h.finalize();
    let mut r = [0u8; 32];
    r.copy_from_slice(&out);
    r
}

/// Base64url without padding — like `ag_base64URLencode` with `=` stripped.
pub fn base64url_nopad(data: &[u8]) -> String {
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine;
    URL_SAFE_NO_PAD.encode(data)
}

/// Base64url with padding — matching what `ag_base64URLdecode` takes.
pub fn base64url_decode(s: &str) -> Result<Vec<u8>> {
    use base64::engine::general_purpose::{URL_SAFE, URL_SAFE_NO_PAD};
    use base64::Engine;
    URL_SAFE_NO_PAD
        .decode(s.as_bytes())
        .or_else(|_| URL_SAFE.decode(s.as_bytes()))
        .map_err(|e| Error::Crypto(format!("base64url: {e}")))
}

/// `B5PasswordNormalize`, recovered from `_B5PasswordNormalize` (0x2af7b).
///
/// In the disassembly: `CFStringNormalize(kCFStringNormalizationFormNFC)`
/// followed by `CFStringTrimWhitespace`. For ASCII that is identity + trim.
///
/// The Rust stand-in for Unicode NFC without an ICU dependency: for ASCII
/// passwords (the overwhelming majority) the result is identical. For
/// non-ASCII, see [`normalize_nfc`], which honestly refuses rather than
/// staying silent.
pub fn b5_password_normalize(password: &str) -> Result<String> {
    normalize_nfc(password.trim_matches(|c: char| c.is_whitespace()))
}

/// NFC normalization.
///
/// Returns an error if the string is not ASCII: full NFC needs Unicode
/// tables, and silently substituting something would break the KDF unnoticed.
pub fn normalize_nfc(s: &str) -> Result<String> {
    if s.is_ascii() {
        Ok(s.to_string())
    } else {
        Err(Error::Crypto(
            "NFC normalization of a non-ASCII string is not implemented: \
             a Unicode table is required. For ASCII the result is exact."
                .into(),
        ))
    }
}

/// Intermediate `combined` value for PBKDF2.
///
/// Returns the string but does **not** run PBKDF2: the salt is unknown.
///
/// # Errors
///
/// If the string is not ASCII.
pub fn combined_pbes2_password(email: &str, password: &str) -> Result<String> {
    let prehash = crate::keys::b5_password_prehash(password)?;
    let email_lc = email
        .trim_matches(|c: char| c.is_whitespace())
        .to_lowercase();
    Ok(format!("{email_lc}:{prehash}"))
}

/// KDF recovery status.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KdfStatus {
    /// Fully recovered, the key can be derived.
    Complete,
    /// Partial: the shape is known, the salt is not.
    BlockedOnSalt,
    /// Not started.
    Unknown,
}

impl KdfStatus {
    /// Explanation for the user.
    pub fn reason(self) -> &'static str {
        match self {
            Self::Complete => "KDF recovered",
            Self::BlockedOnSalt => {
                "The KDF shape was recovered from the disassembler, but the PBKDF2 \
                 salt is taken from encryptedSymmetricKey (<uuid>-scramble in the plist), \
                 which is itself encrypted. The salt is unavailable from a .1p4 backup: \
                 the profiles table does not contain it."
            }
            Self::Unknown => "KDF not parsed",
        }
    }
}

/// Current status: the salt is unknown.
pub const STATUS: KdfStatus = KdfStatus::BlockedOnSalt;

/// Attempt to derive the master key. Always fails,
/// until the salt problem is solved — see [`STATUS`].
///
/// The error is returned **before** any computation, so that nobody can
/// accidentally end up with "some" key and write it to the file.
pub fn derive_master_key(_password: &str, _inputs: &crate::keys::KdfInputs) -> Result<[u8; 32]> {
    Err(Error::KeyUnavailable(STATUS.reason().to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prehash_matches_known_vector() {
        // Vector from the probe_kdf.py run: password "123xv334188!"
        let p = crate::keys::b5_password_prehash("123xv334188!").unwrap();
        assert_eq!(
            p, "sd0ZuWup2kfjKO13bFnwPrhy0KKRCrj7ZuxRLxKxZEM",
            "prehash must match the reference from the Python probe"
        );
    }

    #[test]
    fn prehash_of_empty_is_constant() {
        // SHA256("") in base64url without padding
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
