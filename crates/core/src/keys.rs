//! Key source for decryption.
//!
//! Status: **the KDF is not recovered.** See [`crate::kdf`] and
//! `docs/FORMAT.md`.
//!
//! What the disassembler confirms (`OnePasswordCore`, `OPSymmetricKey.m`):
//!
//! ```text
//! combined = email.ag_trim.lowercaseString + ":" + B5PasswordPrehash(password)
//! B5PasswordPrehash(pw) = base64url_no_pad(SHA256(utf8(trim(pw))))
//! rawKey   = PBKDF2-HMAC-SHA256(utf8(combined), salt, iterations, 32)
//! if personalKey: rawKey = combineWithBytes(personalKey, rawKey)
//! ```
//!
//! What is **not** confirmed: which salt is actually used. From the code
//! of `-[B5UserAccount masterUnlockKeyForPassword:]` the salt comes from
//! `encryptedSymmetricKey` (`opdata <uuid>-scramble` in the plist), not
//! from `profiles.salt`. But the scramble blob itself is encrypted, so the
//! salt is unknown outside the loop. That is why the brute force never
//! converged.

use crate::envelope::KEY_LEN;
use crate::error::{Error, Result};

/// Key for decrypting profile and item blobs.
pub trait KeyProvider {
    /// Name of the source — for diagnostics.
    fn name(&self) -> &str;

    /// Returns the 32-byte key, or an error if the key is unavailable.
    fn master_key(&self) -> Result<[u8; KEY_LEN]>;
}

/// Stub: always reports that the key is unavailable.
///
/// Exists so that the rest of the system (parsing, browsing, CLI)
/// works and builds until the KDF is recovered.
#[derive(Debug, Default, Clone)]
pub struct Unavailable;

impl KeyProvider for Unavailable {
    fn name(&self) -> &str {
        "unavailable"
    }

    fn master_key(&self) -> Result<[u8; KEY_LEN]> {
        Err(Error::KeyUnavailable(
            "KDF not recovered: the PBKDF2 salt lives inside the encrypted \
             encryptedSymmetricKey block (<uuid>-scramble in the 1Password plist), \
             so the key cannot be derived from a .1p4 backup"
                .into(),
        ))
    }
}

/// A key known from outside (e.g. recovered offline or from a
/// ground-truth export). For tests and cross-checking.
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

/// Intermediate KDF values — what is known and what is not.
#[derive(Debug, Clone)]
pub struct KdfInputs {
    /// PBKDF2 iteration count.
    pub iterations: u32,
    /// Profile salt — an assumed but unconfirmed source.
    pub profile_salt: Vec<u8>,
    /// The encrypted `encryptedSymmetricKey` blob, if found.
    pub scramble: Option<Vec<u8>>,
    /// Account email: empty for the local variant.
    pub email: String,
    /// Whether a `personalKey` is present.
    pub has_personal_key: bool,
}

impl KdfInputs {
    /// `true` if everything PBKDF2 needs is available except the key itself.
    pub fn salt_known(&self) -> bool {
        !self.profile_salt.is_empty()
    }
}

/// `B5PasswordPrehash`, recovered from `_B5PasswordPrehash` (0x2ae0f).
///
/// ```text
/// s = password; s = CFStringTrimWhitespace(s)
/// h = SHA256(utf8(s)); b = base64url(h); b = b.replace("=", "")
/// ```
///
/// The implementation here is the reference to cross-check the Rust
/// version against.
///
/// # Errors
///
/// Returns an error if the password is not valid UTF-8.
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
