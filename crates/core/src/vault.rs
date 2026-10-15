//! Reading the `.1p4` database — strictly read-only.
//!
//! ## Guarantee that the source stays untouched
//!
//! The database is opened with `SQLITE_OPEN_READ_ONLY` and without `SQLITE_OPEN_CREATE`.
//! On top of that a SHA-256 of the bytes is taken, so it can be compared
//! before and after a read — see [`Vault::fingerprint`] and the test check.
//!
//! ## Confirmed structure
//!
//! Obtained by inspecting `OnePassword.sqlite` from a `.1p4` backup:
//!
//! | Table            | Contents                                             |
//! |------------------|------------------------------------------------------|
//! | `profiles`       | 15 columns, `iterations`, `salt`, `master_key_data`, `overview_key_data` |
//! | `items`          | 17 columns, `uuid`, `key_data`(112 B), `overview_data` |
//! | `item_details`   | `data` — the encrypted body of the item              |
//! | `folders`        | encrypted overview data                              |
//! | `categories`     | UUID and encrypted overview data                     |
//!
//! Every substantive field is encrypted: `items.title` is empty for all 541 records,
//! and the table has no `username`/`location_key` columns.

use rusqlite::{Connection, OpenFlags};
use serde::Serialize;
use sha2::{Digest, Sha256};

use crate::envelope::{parse_field, Envelope, Header, KEY_LEN};
use crate::error::{Error, Result};

/// Profile metadata.
#[derive(Debug, Clone)]
pub struct Profile {
    /// Row identifier.
    pub id: i64,
    /// Profile UUID.
    pub uuid: String,
    /// Profile name.
    pub profile_name: String,
    /// PBKDF2 iteration count.
    pub iterations: i64,
    /// Salt from the profile (16 bytes).
    ///
    /// WARNING: not confirmed that this is the salt for `master_key_data`.
    /// In the code the salt is taken from `encryptedSymmetricKey`, which is not in the backup.
    pub salt: Vec<u8>,
    /// Master key block with the `opdata01` header.
    pub master_key_data: Vec<u8>,
    /// Overview key block.
    pub overview_key_data: Vec<u8>,
    /// Password hint (if set).
    pub password_hint: Option<String>,
}

/// A folder.
#[derive(Debug, Clone)]
pub struct Folder {
    /// Folder UUID.
    pub uuid: String,
    /// Encrypted overview data.
    pub overview_data: Vec<u8>,
}

/// A vault item.
#[derive(Debug, Clone)]
pub struct Item {
    /// Item UUID.
    pub uuid: String,
    /// Category UUID.
    pub category_uuid: Option<String>,
    /// Folder UUID.
    pub folder_uuid: Option<String>,
    /// Encrypted body — 112 bytes, `IV‖CT‖HMAC` layout.
    pub key_data: Vec<u8>,
    /// Encrypted overview data.
    pub overview_data: Vec<u8>,
    /// Deletion flag.
    pub trashed: i64,
    /// Unix creation time.
    pub created_at: i64,
    /// Unix update time.
    pub updated_at: i64,
}

/// A category.
///
/// Unlike folders, `categories` keeps part of the data in cleartext
/// in the `json` column — confirmed by `PRAGMA table_info(categories)`.
/// The field descriptions inside `json` themselves are encrypted.
#[derive(Debug, Clone)]
pub struct Category {
    /// Category UUID.
    pub uuid: String,
    /// Singular name, cleartext.
    pub singular_name: String,
    /// Plural name, cleartext.
    pub plural_name: String,
    /// JSON field description (partly cleartext, partly encrypted).
    pub json: String,
}

/// Database summary — what can be shown without decrypting anything.
#[derive(Debug, Serialize)]
pub struct VaultSummary {
    /// Profile UUID.
    pub profile_uuid: String,
    /// Profile name.
    pub profile_name: String,
    /// PBKDF2 iteration count.
    pub iterations: i64,
    /// Profile salt in hex.
    pub salt_hex: String,
    /// SHA-256 of the database.
    pub db_sha256: String,
    /// Number of items.
    pub item_count: usize,
    /// Number of folders.
    pub folder_count: usize,
    /// Number of categories.
    pub category_count: usize,
    /// Size of `master_key_data`.
    pub master_key_data_len: usize,
    /// Whether every `key_data` has the expected 112 bytes.
    pub key_data_uniform: bool,
}

/// An opened `.1p4` database.
pub struct Vault {
    conn: Connection,
    path: std::path::PathBuf,
}

impl std::fmt::Debug for Vault {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Vault")
            .field("path", &self.path)
            .finish_non_exhaustive()
    }
}

impl Vault {
    /// Opens the database **read-only**.
    pub fn open(path: impl AsRef<std::path::Path>) -> Result<Self> {
        let path = path.as_ref();
        if !path.exists() {
            return Err(Error::NotFound(path.display().to_string()));
        }
        let conn = Connection::open_with_flags(
            path,
            OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_URI,
        )?;
        Ok(Self {
            conn,
            path: path.to_path_buf(),
        })
    }

    /// Path to the database.
    pub fn path(&self) -> &std::path::Path {
        &self.path
    }

    /// SHA-256 of the database file — to check that reading it changed nothing.
    pub fn fingerprint(&self) -> Result<String> {
        let bytes = std::fs::read(&self.path)?;
        Ok(hex(&Sha256::digest(&bytes)))
    }

    /// The profile.
    pub fn profile(&self) -> Result<Profile> {
        let p = self
            .conn
            .query_row(
                "SELECT id, uuid, profile_name, iterations, salt,
                        master_key_data, overview_key_data, password_hint
                 FROM profiles LIMIT 1",
                [],
                |r| {
                    Ok(Profile {
                        id: r.get(0)?,
                        uuid: r.get(1)?,
                        profile_name: r.get(2)?,
                        iterations: r.get(3)?,
                        salt: r.get(4)?,
                        master_key_data: r.get(5)?,
                        overview_key_data: r.get(6)?,
                        password_hint: r.get(7)?,
                    })
                },
            )
            .map_err(|e| match e {
                rusqlite::Error::QueryReturnedNoRows => {
                    Error::Crypto("profiles contains no lines".into())
                }
                other => Error::Sqlite(other),
            })?;
        Ok(p)
    }

    /// All folders.
    pub fn folders(&self) -> Result<Vec<Folder>> {
        let mut st = self
            .conn
            .prepare("SELECT uuid, overview_data FROM folders ORDER BY uuid")?;
        let rows = st.query_map([], |r| {
            Ok(Folder {
                uuid: r.get(0)?,
                overview_data: r.get(1)?,
            })
        })?;
        Ok(rows.collect::<std::result::Result<Vec<_>, _>>()?)
    }

    /// All categories.
    pub fn categories(&self) -> Result<Vec<Category>> {
        let mut st = self.conn.prepare(
            "SELECT uuid, singular_name, plural_name, json
             FROM categories ORDER BY display_order, uuid",
        )?;
        let rows = st.query_map([], |r| {
            Ok(Category {
                uuid: r.get(0)?,
                singular_name: r.get::<_, Option<String>>(1)?.unwrap_or_default(),
                plural_name: r.get::<_, Option<String>>(2)?.unwrap_or_default(),
                json: r.get::<_, Option<String>>(3)?.unwrap_or_default(),
            })
        })?;
        Ok(rows.collect::<std::result::Result<Vec<_>, _>>()?)
    }

    /// All items.
    pub fn items(&self) -> Result<Vec<Item>> {
        let mut st = self.conn.prepare(
            "SELECT uuid, category_uuid, folder_uuid, key_data, overview_data,
                    trashed, created_at, updated_at
             FROM items ORDER BY uuid",
        )?;
        let rows = st.query_map([], |r| {
            Ok(Item {
                uuid: r.get(0)?,
                category_uuid: r.get(1)?,
                folder_uuid: r.get(2)?,
                key_data: r.get(3)?,
                overview_data: r.get(4)?,
                trashed: r.get(5)?,
                created_at: r.get(6)?,
                updated_at: r.get(7)?,
            })
        })?;
        Ok(rows.collect::<std::result::Result<Vec<_>, _>>()?)
    }

    /// Summary that requires no decryption.
    pub fn summary(&self) -> Result<VaultSummary> {
        let p = self.profile()?;
        let items = self.items()?;
        let uniform = items
            .iter()
            .map(|i| i.key_data.len())
            .all(|l| l == IV_CT_HMAC_LEN);
        Ok(VaultSummary {
            profile_uuid: p.uuid,
            profile_name: p.profile_name,
            iterations: p.iterations,
            salt_hex: hex(&p.salt),
            db_sha256: self.fingerprint()?,
            item_count: items.len(),
            folder_count: self.folders()?.len(),
            category_count: self.categories()?.len(),
            master_key_data_len: p.master_key_data.len(),
            key_data_uniform: uniform,
        })
    }

    /// Diagnostics for the `master_key_data` block: header and blob geometry.
    pub fn inspect_master_key_data(&self) -> Result<MasterKeyReport> {
        let p = self.profile()?;
        let (header, env) = parse_field(&p.master_key_data)?;
        if !header.has_magic() {
            return Err(Error::BadMagic(header.magic));
        }
        Ok(MasterKeyReport {
            header_tag: header.tag,
            total_len: p.master_key_data.len(),
            envelope: env.as_ref().map(|e| e.inspect(None)),
        })
    }

    /// Diagnostics for one item's `key_data`.
    ///
    /// These blobs come **without** the `opdata01` header — they are bare
    /// `IV ‖ CT ‖ HMAC`.
    pub fn inspect_item_key(&self, uuid: &str) -> Result<KeyDataReport> {
        let kd: Vec<u8> = self
            .conn
            .query_row("SELECT key_data FROM items WHERE uuid = ?1", [uuid], |r| {
                r.get(0)
            })
            .map_err(|e| match e {
                rusqlite::Error::QueryReturnedNoRows => Error::NotFound(format!("item {uuid}")),
                other => Error::Sqlite(other),
            })?;
        let env = Envelope::parse(&kd)?;
        Ok(KeyDataReport {
            uuid: uuid.to_string(),
            report: env.inspect(None),
        })
    }

    /// Checks every `key_data` against a single key — returns how many HMACs matched.
    ///
    /// This is the basis for validating a recovered KDF: the right key must
    /// yield `total`, otherwise something is wrong.
    pub fn count_valid_mac(&self, key: &[u8; KEY_LEN]) -> Result<MacScan> {
        let items = self.items()?;
        let mut valid = 0usize;
        let mut parsed = 0usize;
        for it in &items {
            let Ok(env) = Envelope::parse(&it.key_data) else {
                continue;
            };
            parsed += 1;
            if env.verify(key) == crate::envelope::HmacStatus::Valid {
                valid += 1;
            }
        }
        Ok(MacScan {
            total: items.len(),
            parsed,
            valid,
        })
    }
}

/// Expected `key_data` length: IV(16) + CT(64) + HMAC(32).
pub const IV_CT_HMAC_LEN: usize = 112;

/// Diagnostics for `master_key_data`.
#[derive(Debug)]
pub struct MasterKeyReport {
    /// 8 bytes after the magic — record type, meaning not established.
    pub header_tag: [u8; 8],
    /// Total size of the field.
    pub total_len: usize,
    /// Geometry of the nested blob, if it is large enough.
    pub envelope: Option<crate::envelope::EnvelopeReport>,
}

/// Diagnostics for `key_data`.
#[derive(Debug)]
pub struct KeyDataReport {
    /// Item UUID.
    pub uuid: String,
    /// Blob geometry.
    pub report: crate::envelope::EnvelopeReport,
}

/// Result of a bulk HMAC check.
#[derive(Debug, Clone, Copy)]
pub struct MacScan {
    /// Total items.
    pub total: usize,
    /// Successfully parsed as `IV‖CT‖HMAC`.
    pub parsed: usize,
    /// Matched HMACs.
    pub valid: usize,
}

fn hex(b: &[u8]) -> String {
    let mut s = String::with_capacity(b.len() * 2);
    for byte in b {
        use std::fmt::Write;
        let _ = write!(s, "{byte:02x}");
    }
    s
}

/// Test: the field starts with the `opdata01` magic.
pub fn is_opdata(bytes: &[u8]) -> bool {
    Header::parse(bytes).map(|h| h.has_magic()).unwrap_or(false)
}
