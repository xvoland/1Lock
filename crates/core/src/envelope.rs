//! The `opdata01` container and the `IV ‖ CT ‖ HMAC` blob layout.
//!
//! ## What the disassembler confirmed
//!
//! Source: `OnePasswordCore.framework`, file `OPAESKey.m`,
//! method `-[OPAESKey encryptDataOfLength:reader:writer:error:]`.
//!
//! ```text
//! IV   = _randomData(16)                          // 16 random bytes
//! key  = OPAESKey._rawKey                          // 32 bytes (AES-256)
//! CBC  = CCCryptorCreate(ENCRYPT, AES, PKCS7, key, 32, IV, &cryptor)
//! HMAC = CCHmacInit(SHA256, key); CCHmacUpdate(buf, buf.length)
//! blob = IV(16) ‖ ciphertext ‖ HMAC(32)           // encrypt-then-MAC
//! ```
//!
//! The HMAC is computed **over `IV ‖ ciphertext`** with that same 32-byte key.
//!
//! ## What is NOT confirmed
//!
//! Applying this scheme to `profiles.master_key_data` is an extrapolation
//! from `OPAESKey` up to the database serialization layer. The `opdata01`
//! header structure (the first 8 bytes after the magic) is not understood: the values
//! differ per record type and are neither a version nor a length.
//!
//! [`Envelope::hmac_status`] says so honestly.

use aes::cipher::{block_padding::Pkcs7, BlockDecryptMut, KeyIvInit};
use hmac::{Hmac, Mac};
use sha2::Sha256;

use crate::error::{Error, Result};

type Aes256CbcDec = cbc::Decryptor<aes::Aes256>;
type HmacSha256 = Hmac<Sha256>;

/// Magic prefix of a serialized 1Password blob.
pub const MAGIC: [u8; 8] = *b"opdata01";

/// Length of the magic.
pub const MAGIC_LEN: usize = 8;

/// Header length: magic + 8 bytes of record type/flag.
pub const HEADER_LEN: usize = 16;

/// IV length.
pub const IV_LEN: usize = 16;

/// HMAC-SHA256 length.
pub const MAC_LEN: usize = 32;

/// AES-256 key length.
pub const KEY_LEN: usize = 32;

/// Blob header: 8 magic bytes + 8 bytes that depend on the record type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Header {
    /// Always `opdata01`.
    pub magic: [u8; 8],
    /// The raw 8 bytes after the magic. Their meaning is not established.
    pub tag: [u8; 8],
}

impl Header {
    /// Parses the first 16 bytes of a blob.
    pub fn parse(bytes: &[u8]) -> Result<Self> {
        if bytes.len() < HEADER_LEN {
            return Err(Error::Truncated {
                have: bytes.len(),
                need: HEADER_LEN,
            });
        }
        let mut magic = [0u8; 8];
        magic.copy_from_slice(&bytes[..8]);
        let mut tag = [0u8; 8];
        tag.copy_from_slice(&bytes[8..16]);
        Ok(Self { magic, tag })
    }

    /// `true` when the magic equals `opdata01`.
    pub fn has_magic(&self) -> bool {
        self.magic == MAGIC
    }

    /// Header bytes in their original order.
    pub fn to_bytes(self) -> [u8; HEADER_LEN] {
        let mut out = [0u8; HEADER_LEN];
        out[..8].copy_from_slice(&self.magic);
        out[8..].copy_from_slice(&self.tag);
        out
    }
}

/// Result of an HMAC check.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HmacStatus {
    /// HMAC matched: the key is right, the data is intact.
    Valid,
    /// HMAC did not match: either the key is wrong or the data is damaged.
    Invalid,
    /// The check is impossible (blob too short, or zero key).
    NotChecked,
}

/// An `IV ‖ ciphertext ‖ HMAC` block — what lives in the `key_data` field
/// (always 112 bytes) and, after the header, in the profile fields.
#[derive(Debug, Clone)]
pub struct Envelope {
    iv: [u8; IV_LEN],
    ciphertext: Vec<u8>,
    mac: [u8; MAC_LEN],
}

impl Envelope {
    /// Parses a blob by the `IV ‖ CT ‖ HMAC` layout.
    pub fn parse(bytes: &[u8]) -> Result<Self> {
        if bytes.len() < IV_LEN + MAC_LEN {
            return Err(Error::Truncated {
                have: bytes.len(),
                need: IV_LEN + MAC_LEN,
            });
        }
        let mut iv = [0u8; IV_LEN];
        iv.copy_from_slice(&bytes[..IV_LEN]);
        let mut mac = [0u8; MAC_LEN];
        mac.copy_from_slice(&bytes[bytes.len() - MAC_LEN..]);
        let ciphertext = bytes[IV_LEN..bytes.len() - MAC_LEN].to_vec();
        Ok(Self {
            iv,
            ciphertext,
            mac,
        })
    }

    /// The blob's IV.
    pub fn iv(&self) -> &[u8; IV_LEN] {
        &self.iv
    }

    /// The ciphertext without IV and HMAC.
    pub fn ciphertext(&self) -> &[u8] {
        &self.ciphertext
    }

    /// The HMAC exactly as recorded in the blob.
    pub fn mac(&self) -> &[u8; MAC_LEN] {
        &self.mac
    }

    /// Total size of the blob in bytes.
    pub fn len(&self) -> usize {
        IV_LEN + self.ciphertext.len() + MAC_LEN
    }

    /// Always `false`: the smallest blob still holds an IV and an HMAC.
    pub fn is_empty(&self) -> bool {
        false
    }

    /// Checks HMAC-SHA256 over `IV ‖ ciphertext` with the same key.
    ///
    /// The criterion is unambiguous: false positives are 2⁻²⁵⁶.
    pub fn verify(&self, key: &[u8; KEY_LEN]) -> HmacStatus {
        if key.iter().all(|b| *b == 0) {
            return HmacStatus::NotChecked;
        }
        self.check_mac(key).unwrap_or(HmacStatus::NotChecked)
    }

    fn check_mac(&self, key: &[u8; KEY_LEN]) -> Result<HmacStatus> {
        let mut mac = HmacSha256::new_from_slice(key)
            .map_err(|_| Error::Crypto("HMAC: wrong key length".into()))?;
        mac.update(&self.iv);
        mac.update(&self.ciphertext);
        let calc = mac.finalize().into_bytes();
        Ok(if calc.as_slice() == self.mac.as_slice() {
            HmacStatus::Valid
        } else {
            HmacStatus::Invalid
        })
    }

    /// Decrypts AES-256-CBC and strips PKCS#7.
    ///
    /// Only worth calling after [`Envelope::verify`] == [`HmacStatus::Valid`]:
    /// otherwise the result is just random noise.
    pub fn decrypt(&self, key: &[u8; KEY_LEN]) -> Result<Vec<u8>> {
        match self.verify(key) {
            HmacStatus::Valid => {}
            other => {
                return Err(Error::HmacNotVerified(format!("{other:?}")));
            }
        }
        if self.ciphertext.is_empty() || self.ciphertext.len() % 16 != 0 {
            return Err(Error::Crypto(format!(
                "ciphertext length {} is not a multiple of 16",
                self.ciphertext.len()
            )));
        }
        let mut buf = self.ciphertext.clone();
        let pt = Aes256CbcDec::new(key.into(), (&self.iv).into())
            .decrypt_padded_mut::<Pkcs7>(&mut buf)
            .map_err(|e| Error::Crypto(format!("AES-CBC/PKCS7: {e}")))?;
        Ok(pt.to_vec())
    }

    /// Tries to decrypt without requiring a valid HMAC.
    ///
    /// Diagnostics only: useful to tell "the key is wrong" apart from "the key
    /// is right but the format isn't what we assumed". Do not use in production.
    pub fn decrypt_unverified(&self, key: &[u8; KEY_LEN]) -> Option<Vec<u8>> {
        if self.ciphertext.is_empty() || self.ciphertext.len() % 16 != 0 {
            return None;
        }
        Aes256CbcDec::new(key.into(), (&self.iv).into())
            .decrypt_padded_mut::<Pkcs7>(&mut self.ciphertext.clone())
            .ok()
            .map(|p| p.to_vec())
    }

    /// Diagnostics: length, HMAC, and a decryption attempt.
    pub fn inspect(&self, key: Option<&[u8; KEY_LEN]>) -> EnvelopeReport {
        let status = match key {
            Some(k) => self.verify(k),
            None => HmacStatus::NotChecked,
        };
        let unverified_plaintext = key
            .and_then(|k| self.decrypt_unverified(k))
            .map(|p| p.len());
        EnvelopeReport {
            total_len: self.len(),
            iv: *self.iv(),
            ciphertext_len: self.ciphertext.len(),
            mac: *self.mac(),
            hmac: status,
            unverified_plaintext_len: unverified_plaintext,
        }
    }
}

/// Diagnostics report for a blob.
#[derive(Debug, Clone)]
pub struct EnvelopeReport {
    /// Total size of the blob.
    pub total_len: usize,
    /// IV.
    pub iv: [u8; IV_LEN],
    /// Ciphertext length.
    pub ciphertext_len: usize,
    /// HMAC taken from the blob.
    pub mac: [u8; MAC_LEN],
    /// Result of the HMAC check.
    pub hmac: HmacStatus,
    /// Plaintext length when the HMAC check is skipped — diagnostics only.
    pub unverified_plaintext_len: Option<usize>,
}

/// Parses a complete database field: `opdata01` header + blob.
pub fn parse_field(bytes: &[u8]) -> Result<(Header, Option<Envelope>)> {
    let header = Header::parse(bytes)?;
    let rest = &bytes[HEADER_LEN..];
    let envelope = if rest.len() >= IV_LEN + MAC_LEN {
        Some(Envelope::parse(rest)?)
    } else {
        None
    };
    Ok((header, envelope))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hmac_of(key: &[u8; KEY_LEN], iv: &[u8], ct: &[u8]) -> [u8; MAC_LEN] {
        let mut m = HmacSha256::new_from_slice(key).unwrap();
        m.update(iv);
        m.update(ct);
        m.finalize().into_bytes().into()
    }

    fn make_blob(key: &[u8; KEY_LEN], iv: &[u8; IV_LEN], ct: &[u8]) -> Vec<u8> {
        let mac = hmac_of(key, iv, ct);
        let mut v = Vec::new();
        v.extend_from_slice(iv);
        v.extend_from_slice(ct);
        v.extend_from_slice(&mac);
        v
    }

    #[test]
    fn header_roundtrip() {
        let mut b = MAGIC.to_vec();
        b.extend_from_slice(&[0x00, 0x01, 0, 0, 0, 0, 0, 0]);
        let h = Header::parse(&b).unwrap();
        assert!(h.has_magic());
        assert_eq!(&h.tag[..2], &[0x00, 0x01]);
        assert_eq!(h.to_bytes().to_vec(), b);
    }

    #[test]
    fn header_rejects_short() {
        assert!(matches!(
            Header::parse(&[0u8; 8]),
            Err(Error::Truncated { .. })
        ));
    }

    #[test]
    fn envelope_verifies_good_key() {
        let key = [7u8; KEY_LEN];
        let iv = [3u8; IV_LEN];
        let ct = vec![9u8; 64];
        let blob = make_blob(&key, &iv, &ct);
        let e = Envelope::parse(&blob).unwrap();
        assert_eq!(e.len(), blob.len());
        assert_eq!(e.verify(&key), HmacStatus::Valid);
    }

    #[test]
    fn envelope_rejects_wrong_key() {
        let key = [7u8; KEY_LEN];
        let iv = [3u8; IV_LEN];
        let ct = vec![9u8; 64];
        let blob = make_blob(&key, &iv, &ct);
        let e = Envelope::parse(&blob).unwrap();
        assert_eq!(e.verify(&[8u8; KEY_LEN]), HmacStatus::Invalid);
    }

    #[test]
    fn decrypt_refuses_without_valid_hmac() {
        let e = Envelope::parse(&make_blob(&[7u8; KEY_LEN], &[3u8; IV_LEN], &[9u8; 16])).unwrap();
        let err = e.decrypt(&[8u8; KEY_LEN]).unwrap_err();
        assert!(matches!(err, Error::HmacNotVerified(_)));
    }

    #[test]
    fn aes_roundtrip_with_hmac() {
        use aes::cipher::{block_padding::Pkcs7, BlockEncryptMut, KeyIvInit};
        type Enc = cbc::Encryptor<aes::Aes256>;

        let key = [0x11u8; KEY_LEN];
        let iv = [0x22u8; IV_LEN];
        // 32 bytes of data; buffer padded to a full PKCS7 block (16) — otherwise PadError
        let plain = b"0123456789abcdef0123456789abcde1".as_ref();
        let mut buf = vec![0u8; plain.len() + 16];
        buf[..plain.len()].copy_from_slice(plain);
        let n = plain.len();
        let ct = Enc::new((&key).into(), (&iv).into())
            .encrypt_padded_mut::<Pkcs7>(&mut buf, n)
            .unwrap()
            .to_vec();

        let e = Envelope::parse(&make_blob(&key, &iv, &ct)).unwrap();
        assert_eq!(e.verify(&key), HmacStatus::Valid);
        assert_eq!(e.decrypt(&key).unwrap(), plain);
    }

    #[test]
    fn zero_key_is_not_checked() {
        let e = Envelope::parse(&make_blob(&[7u8; KEY_LEN], &[3u8; IV_LEN], &[1u8; 16])).unwrap();
        assert_eq!(e.verify(&[0u8; KEY_LEN]), HmacStatus::NotChecked);
    }
}
