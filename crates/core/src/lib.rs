//! `opclient-core` — reading the 1Password Agile Keychain (`.1p4`) format.
//!
//! # What works today
//!
//! - opening the database strictly read-only;
//! - browsing the profile, folders, categories, items;
//! - parsing the `opdata01` container and the `IV ‖ CT ‖ HMAC` blob geometry;
//! - checking the HMAC with a given key (an unambiguous criterion);
//! - a full SHA-256 of the database to keep an eye on the source staying unchanged.
//!
//! # What does not work
//!
//! Decryption. The KDF has not been recovered: the salt for PBKDF2 lives inside
//! the encrypted `encryptedSymmetricKey` block. Details and a log of failed
//! hypotheses — in `docs/FORMAT.md`.
//!
//! # Example
//!
//! ```no_run
//! use opclient_core::{Vault, KeyProvider, keys::Unavailable};
//!
//! let v = Vault::open("/path/to/OnePassword.sqlite")?;
//! let s = v.summary()?;
//! println!("items: {}", s.item_count);
//! assert!(Unavailable.master_key().is_err()); // salt is unknown
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

/// Length of the AES-256 key used for profile and item blocks.
pub const KEY_LEN: usize = envelope::KEY_LEN;

/// Crate version.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// KDF recovery status as of this build.
pub fn kdf_status() -> kdf::KdfStatus {
    kdf::STATUS
}
#[cfg(test)]
mod integration {
    use super::*;

    /// Test against a real export, if the file is available.
    /// The path is given by the `OPCLIENT_GOLDEN_1PIF` environment variable.
    /// Without it the test is skipped, so the build does not depend on personal data.
    #[test]
    fn parses_real_export_when_present() {
        let Ok(path) = std::env::var("OPCLIENT_GOLDEN_1PIF") else {
            eprintln!("OPCLIENT_GOLDEN_1PIF is not set — test skipped");
            return;
        };
        let pif = pif::Pif::from_file(&path).expect("export must be readable");
        let entries = pif.entries();
        assert!(!entries.is_empty(), "the export has no entries");
        eprintln!("read {} entries", entries.len());

        // Every entry must have a title, otherwise the UI list comes out empty.
        let titled = entries.iter().filter(|i| i.title.is_some()).count();
        assert!(titled > 0, "not a single entry has a title");

        // Search has to find something.
        let first = entries[0].title.clone().unwrap_or_default();
        let q: String = first.chars().take(4).collect();
        if q.len() >= 2 {
            assert!(!pif.search(&q).is_empty(), "search for {q:?} found nothing");
        }
    }

    /// Consistency: a TOTP code from the export can be computed without failing.
    #[test]
    fn totp_from_export_is_computable() {
        let Ok(path) = std::env::var("OPCLIENT_GOLDEN_1PIF") else {
            return;
        };
        let pif = pif::Pif::from_file(&path).expect("export must be readable");
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
        eprintln!("TOTP verified for {checked} entries");
    }
}
