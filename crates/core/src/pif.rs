//! Reading the 1PIF format — a 1Password export whose contents are already decrypted.
//!
//! The format is JSON Lines, not one JSON object. Service strings of the form
//! `***<uuid>***` appear between records and point at attachments.
//! The legacy format (1Password 3/4) is a single JSON object with an
//! `items` field; the parser accepts both.
//!
//! ## Where this data comes from
//!
//! 1PIF only ever comes out of a 1Password export, so it is a snapshot,
//! not a live vault. An app built on this format is an export client,
//! not a manager wired to a vault.
//!
//! ## Privacy
//!
//! Secret values (`P` fields — passwords, `C` fields — a secret checkbox,
//! plus `otpauth`) sit in memory in plaintext, exactly as in the source
//! file. This module neither logs nor writes them to disk.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

/// Field type, by 1Password's code.
pub const FIELD_PASSWORD: &str = "P";
/// A checkbox holding a secret (a concealed value).
pub const FIELD_SECRET_CHECKBOX: &str = "C";

/// One exported record.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct PifItem {
    /// Record identifier.
    pub uuid: String,
    /// Type: `webforms.WebForm`, `passwords.Password`, `securenotes.SecureNote`, …
    #[serde(rename = "typeName")]
    pub type_name: Option<String>,
    /// Title (plain text in 1PIF).
    pub title: Option<String>,
    /// Domain without the scheme.
    #[serde(rename = "locationKey")]
    pub location_key: Option<String>,
    /// Full URL.
    pub location: Option<String>,
    /// Contents with decrypted fields.
    #[serde(rename = "secureContents")]
    pub secure_contents: Option<SecureContents>,
    /// Content hash (hex, 6–8 chars).
    #[serde(rename = "contentsHash")]
    pub contents_hash: Option<String>,
    /// Security level: `SL5`.
    #[serde(rename = "securityLevel")]
    pub security_level: Option<String>,
    /// Creation time, Unix.
    #[serde(rename = "createdAt")]
    pub created_at: Option<i64>,
    /// Modification time, Unix.
    #[serde(rename = "updatedAt")]
    pub updated_at: Option<i64>,
    /// Folder identifier.
    #[serde(rename = "folderUuid")]
    pub folder_uuid: Option<String>,
    /// Trashed flag. A deleted record still stays in the export.
    pub trashed: Option<bool>,
    /// Open contents: tags, for example.
    #[serde(rename = "openContents", default)]
    pub open_contents: Option<serde_json::Map<String, serde_json::Value>>,
    /// Timestamp of the last transaction.
    #[serde(rename = "txTimestamp", default)]
    pub tx_timestamp: Option<i64>,

    /// The original JSON line from the file.
    ///
    /// Kept so that a save writes untouched records back byte for
    /// byte. Not every 1PIF field survives `PifItem` — `txTimestamp`,
    /// `trashed` and `openContents`, for instance — and re-serializing would
    /// silently drop them. The raw line guards against that.
    #[serde(skip)]
    pub raw: String,

    /// The record was edited, so it has to be serialized afresh.
    #[serde(skip)]
    pub dirty: bool,
}

/// Decrypted record contents.
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct SecureContents {
    /// Record fields. Only web forms use them.
    #[serde(default)]
    pub fields: Vec<PifField>,
    /// The record's password as one string — how `passwords.Password`
    /// records write it. Their `fields` may be empty.
    #[serde(default)]
    pub password: Option<String>,
    /// Notes in plaintext (when the record type allows them).
    #[serde(rename = "notesPlain")]
    pub notes_plain: Option<String>,
    /// Notes in base64 (old format).
    pub notes: Option<String>,
    /// URL list.
    #[serde(rename = "URLs", default)]
    pub urls: Vec<PifUrl>,
    /// Password history.
    #[serde(rename = "passwordHistory", default)]
    pub password_history: Vec<PifHistoryEntry>,
    /// Form sections: tabs and their labelled fields.
    #[serde(default)]
    pub sections: Vec<PifSection>,
    /// Keys specific to the record type.
    ///
    /// For cards, mail, licences and documents the data sits directly in
    /// `secureContents` — `ccnum`, `pop_password`, `reg_code` and so on.
    /// There is no universal list of such keys, so they land in
    /// this map instead of being spelled out one per type in the struct.
    #[serde(flatten)]
    pub extra: std::collections::BTreeMap<String, serde_json::Value>,
}

/// A record section — the description of one tab.
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct PifSection {
    /// Tab label.
    pub title: Option<String>,
    /// The tab's internal name.
    pub name: Option<String>,
    /// Section fields.
    #[serde(default)]
    pub fields: Vec<PifSectionField>,
}

/// A field inside a section.
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct PifSectionField {
    /// Value type: `string`, `concealed`, `monthYear`, …
    pub k: Option<String>,
    /// The field's internal name.
    pub n: Option<String>,
    /// Value.
    #[serde(default)]
    pub v: Option<serde_json::Value>,
    /// Field label for the UI.
    pub t: Option<String>,
    /// Attributes: `guarded`, `clipboardFilter` and the like.
    #[serde(default)]
    pub a: Option<serde_json::Value>,
}

/// A record field.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct PifField {
    /// Field type: `T` (text), `P` (password), `C` (secret), `I` (button), …
    ///
    /// Real exports sometimes omit the key, hence the default.
    #[serde(rename = "type", default)]
    pub field_type: String,
    /// Field name.
    #[serde(default)]
    pub name: Option<String>,
    /// Value. For `P`/`C` this is a secret.
    #[serde(default)]
    pub value: String,
    /// UI element identifier.
    #[serde(rename = "designation")]
    pub designation: Option<String>,
    /// Link to a section.
    pub section: Option<PifSectionRef>,
}

/// Link to a section.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct PifSectionRef {
    /// Section identifier.
    pub id: Option<String>,
}

/// A record URL.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct PifUrl {
    /// Address.
    pub url: Option<String>,
}

/// A password history entry.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct PifHistoryEntry {
    /// Value (a secret).
    #[serde(default)]
    pub value: String,
    /// Modification time, Unix.
    pub time: Option<i64>,
}

/// Top-level object of the old format.
#[derive(Debug, Deserialize)]
struct PifDocument {
    #[serde(default)]
    items: Vec<PifItem>,
}

/// A parsed export.
#[derive(Debug, Clone)]
pub struct Pif {
    /// All records, folders included.
    pub items: Vec<PifItem>,
    /// Number of `***<uuid>***` separator lines in the file.
    ///
    /// These are NOT attachments: the separator is the same string throughout
    /// the dump, a leftover from the old format that keeps records apart.
    /// The attachments themselves live in the `attachments` directory next to
    /// [`Pif::attachments`].
    pub record_separators: usize,
    /// Attachments per record: record uuid → its files.
    pub attachments: HashMap<String, Vec<Attachment>>,
    /// The separator line written between records.
    pub separator: String,
    /// Attachments that go to the trash on the next save.
    ///
    /// Stored alongside the record uuid: the trash mirrors the
    /// `attachments` layout, so the directory shows where a file came from.
    pub attachments_to_trash: Vec<(String, PathBuf)>,
    /// Path to the export file: needed to place an attachment beside it.
    pub source_path: Option<PathBuf>,
}

/// The separator 1Password writes into a dump.
pub const DEFAULT_SEPARATOR: &str = "***5642bee8-a5ff-11dc-8314-0800200c9a66***";

/// A file attached to a record.
#[derive(Debug, Clone)]
pub struct Attachment {
    /// File name.
    pub name: String,
    /// Size in bytes.
    pub size: u64,
    /// Full path on disk.
    pub path: PathBuf,
    /// Where the file will be copied from on save.
    ///
    /// `Some` — the user picked the file and it is not in the export yet.
    /// `None` — the file is already in place.
    pub pending_source: Option<PathBuf>,
}

impl Attachment {
    /// Whether there is an image worth displaying.
    pub fn is_image(&self) -> bool {
        matches!(
            self.name
                .rsplit_once('.')
                .map(|(_, e)| e.to_ascii_lowercase())
                .as_deref(),
            Some("jpg" | "jpeg" | "png" | "gif" | "bmp" | "webp" | "tif" | "tiff")
        )
    }
}

impl Pif {
    /// Parses the contents of an export file.
    ///
    /// Accepts both JSON Lines and a single JSON object with an `items`
    /// field. Service strings `***<uuid>***` are skipped.
    pub fn parse(text: &str) -> Result<Self, PifError> {
        let trimmed = text.trim_start();

        if trimmed.starts_with('{') && !trimmed.starts_with("{\"uuid\"") {
            // single wrapper object
            let doc: PifDocument = serde_json::from_str(text).map_err(PifError::Json)?;
            return Ok(Self {
                items: doc.items,
                record_separators: 0,
                attachments: HashMap::new(),
                separator: DEFAULT_SEPARATOR.to_string(),
                attachments_to_trash: Vec::new(),
                source_path: None,
            });
        }

        let mut items = Vec::new();
        let mut separators = 0usize;

        for (lineno, line) in text.lines().enumerate() {
            let s = line.trim();
            if s.is_empty() {
                continue;
            }
            if is_attachment_marker(s) {
                separators += 1;
                continue;
            }
            match serde_json::from_str::<PifItem>(s) {
                Ok(mut item) => {
                    item.raw = s.to_string();
                    items.push(item)
                }
                Err(e) => {
                    return Err(PifError::Line {
                        lineno: lineno + 1,
                        source: e,
                    })
                }
            }
        }

        if items.is_empty() {
            return Err(PifError::Empty);
        }

        Ok(Self {
            items,
            record_separators: separators,
            attachments: HashMap::new(),
            separator: DEFAULT_SEPARATOR.to_string(),
            attachments_to_trash: Vec::new(),
            source_path: None,
        })
    }

    /// Reads an export file and picks up attachments from the neighbouring directory.
    pub fn from_file(path: impl AsRef<Path>) -> Result<Self, PifError> {
        let path = path.as_ref();
        let text = std::fs::read_to_string(path).map_err(|e| PifError::Io {
            path: path.display().to_string(),
            source: e,
        })?;
        let mut parsed = Self::parse(&text)?;
        parsed.attachments = scan_attachments(path, &parsed.items);
        parsed.source_path = Some(path.to_path_buf());
        // Drop anything past its trash deadline right when the file is opened.
        parsed.purge_trash();
        Ok(parsed)
    }

    /// Creates a new empty 1PIF store in `dir`.
    ///
    /// The file is not quite empty: [`Pif::parse`] treats an empty file as an
    /// error — a guard against opening the wrong file — so a single folder
    /// record goes inside. Folders show up neither in the list nor in
    /// categories, yet they make the file valid; otherwise the store we just
    /// created would not open on the next launch.
    ///
    /// `contentsHash` is not written: how it is computed is unknown, and a
    /// made-up value is worse than none. Whether 1Password accepts such a
    /// file on import is unverified.
    ///
    /// An existing `data.1pif` is left alone: [`PifError::Exists`] is returned.
    pub fn create(dir: impl AsRef<Path>) -> Result<Self, PifError> {
        let dir = dir.as_ref();
        let data = dir.join("data.1pif");

        if data.exists() {
            return Err(PifError::Exists {
                path: data.display().to_string(),
            });
        }

        std::fs::create_dir_all(dir.join("attachments")).map_err(|e| PifError::Io {
            path: dir.join("attachments").display().to_string(),
            source: e,
        })?;

        let mut starter = Self::parse(STARTER_DOCUMENT)?;
        starter.source_path = Some(data.clone());
        starter.save(&data)?;
        starter.source_path = Some(data);

        Ok(starter)
    }

    /// Writes the changes to the file.
    ///
    /// A backup is taken before writing: `data.1pif` → `.bak1`, and
    /// older copies shift down, so the last [`BACKUP_KEEP`] versions are kept.
    /// The write goes to a temp file followed by a rename, so that an
    /// interrupted save never leaves a truncated `data.1pif`.
    ///
    /// Unmodified records are emitted from [`PifItem::raw`] verbatim, so fields
    /// the parser knows nothing about survive a save.
    pub fn save(&mut self, path: impl AsRef<Path>) -> Result<(), PifError> {
        let path = path.as_ref();

        if path.exists() {
            rotate_backups(path)?;
        }

        let mut out = String::new();
        for it in &self.items {
            let line = if it.dirty || it.raw.is_empty() {
                serde_json::to_string(it).map_err(PifError::Json)?
            } else {
                it.raw.clone()
            };
            out.push_str(&line);
            out.push('\n');
            out.push_str(&self.separator);
            out.push('\n');
        }

        // Write next to the target: the temp file has to be on the same volume.
        let tmp = path.with_extension("1pif.tmp");
        std::fs::write(&tmp, out.as_bytes()).map_err(|e| PifError::Io {
            path: tmp.display().to_string(),
            source: e,
        })?;
        std::fs::rename(&tmp, path).map_err(|e| PifError::Io {
            path: path.display().to_string(),
            source: e,
        })?;

        self.flush_attachments()
    }

    /// Marks a record as edited so that a save rewrites it.
    pub fn touch(&mut self, uuid: &str) {
        if let Some(it) = self.items.iter_mut().find(|i| i.uuid == uuid) {
            it.dirty = true;
        }
    }

    /// Whether there are unsaved changes.
    pub fn has_changes(&self) -> bool {
        self.items.iter().any(|i| i.dirty)
    }

    /// Clears the dirty flags: the file has been written.
    pub fn mark_saved(&mut self) {
        for it in &mut self.items {
            it.dirty = false;
        }
    }

    /// Attaches a file to a record. Nothing touches disk until [`Pif::save`].
    ///
    /// In 1PIF the link is carried by the directory name alone:
    /// `attachments/<record uuid>/<file>`. There is no reference in the JSON,
    /// so copying the file is enough and `data.1pif` itself stays untouched.
    pub fn attach(&mut self, uuid: &str, source: &Path) -> Result<Attachment, PifError> {
        let meta = std::fs::metadata(source).map_err(|e| PifError::Io {
            path: source.display().to_string(),
            source: e,
        })?;
        let name = source
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .ok_or_else(|| PifError::Io {
                path: source.display().to_string(),
                source: std::io::Error::other("file has no name"),
            })?;

        let dir = self.attachments_dir_for(uuid)?;

        // The name inside the directory must not clash with an existing one.
        let mut final_name = name.clone();
        let mut n = 1;
        while dir.join(&final_name).exists()
            || self
                .attachments
                .get(uuid)
                .is_some_and(|list| list.iter().any(|a| a.name == final_name))
        {
            final_name = unique_name(&name, n);
            n += 1;
        }

        let att = Attachment {
            name: final_name.clone(),
            size: meta.len(),
            path: dir.join(&final_name),
            pending_source: Some(source.to_path_buf()),
        };
        self.attachments
            .entry(uuid.to_string())
            .or_default()
            .push(att.clone());
        Ok(att)
    }

    /// Detaches a file. It is deleted from disk only on [`Pif::save`].
    pub fn detach(&mut self, uuid: &str, name: &str) -> bool {
        let Some(list) = self.attachments.get_mut(uuid) else {
            return false;
        };
        let Some(pos) = list.iter().position(|a| a.name == name) else {
            return false;
        };
        let removed = list.remove(pos);
        if list.is_empty() {
            self.attachments.remove(uuid);
        }
        // No point deleting a file that is not there, let alone one not copied yet.
        if removed.pending_source.is_none() && removed.path.exists() {
            self.attachments_to_trash
                .push((uuid.to_string(), removed.path));
        }
        true
    }

    /// A record's attachments.
    pub fn attachments_of(&self, uuid: &str) -> &[Attachment] {
        self.attachments.get(uuid).map(Vec::as_slice).unwrap_or(&[])
    }

    /// Whether attachment changes are pending.
    pub fn attachments_changed(&self) -> bool {
        !self.attachments_to_trash.is_empty()
            || self
                .attachments
                .values()
                .flatten()
                .any(|a| a.pending_source.is_some())
    }

    /// The record's attachment directory.
    fn attachments_dir_for(&self, uuid: &str) -> Result<PathBuf, PifError> {
        if let Some(dir) = self
            .attachments
            .get(uuid)
            .and_then(|l| l.first())
            .and_then(|a| a.path.parent())
        {
            return Ok(dir.to_path_buf());
        }
        let Some(pif_path) = self.source_path.as_deref() else {
            return Err(PifError::Io {
                path: uuid.to_string(),
                source: std::io::Error::other("export file is not open"),
            });
        };
        // The attachment directory sits beside the export file, not inside it:
        // `Name….1pif/attachments/`, while `Name….1pif/data.1pif/attachments/`
        // is a different path that does not exist.
        let dir = pif_path
            .parent()
            .map(|p| p.join("attachments"))
            .unwrap_or_else(|| PathBuf::from("attachments"));
        Ok(dir.join(uuid))
    }

    /// Flushes the pending attachment changes to disk.
    fn flush_attachments(&mut self) -> Result<(), PifError> {
        let err = |e: std::io::Error, p: &Path| PifError::Io {
            path: p.display().to_string(),
            source: e,
        };

        // New files go first: if anything fails, nothing is lost yet.
        let mut done: Vec<(String, String)> = Vec::new();
        for (uuid, list) in &self.attachments {
            for att in list {
                let Some(src) = att.pending_source.as_ref() else {
                    continue;
                };
                if let Some(dir) = att.path.parent() {
                    std::fs::create_dir_all(dir).map_err(|e| err(e, dir))?;
                }
                std::fs::copy(src, &att.path).map_err(|e| err(e, &att.path))?;
                done.push((uuid.clone(), att.name.clone()));
            }
        }
        for (uuid, name) in done {
            if let Some(att) = self
                .attachments
                .get_mut(&uuid)
                .and_then(|l| l.iter_mut().find(|a| a.name == name))
            {
                att.pending_source = None;
                att.size = std::fs::metadata(&att.path)
                    .map(|m| m.len())
                    .unwrap_or(att.size);
            }
        }

        // Only then do the deletions move to the trash.
        let trash = self.trash_dir();
        for (uuid, path) in std::mem::take(&mut self.attachments_to_trash) {
            if let Some(dir) = &trash {
                let _ = move_to_trash(dir, &uuid, &path);
            } else {
                // No trash available: delete outright, last resort.
                let _ = std::fs::remove_file(&path);
            }
        }
        Ok(())
    }

    /// Creates a new record of the chosen type. Returns its uuid.
    ///
    /// Field names are copied from a real dump. The `sections` block is not
    /// written: in a dump it runs alongside the top-level keys, our
    /// parser reads both, and the extra structure would only add places to
    /// get wrong in a file we create. Whether 1Password accepts such a
    /// record is unverified, same as everything else we write ourselves.
    pub fn create_item(&mut self, draft: &EntryDraft, kind: ItemKind) -> String {
        let uuid = new_uuid();
        let now = unix_now();

        let mut item = PifItem {
            uuid: uuid.clone(),
            type_name: Some(kind.type_name().to_string()),
            title: Some(draft.title.trim().to_string()),
            location_key: None,
            location: None,
            secure_contents: Some(SecureContents::default()),
            contents_hash: None,
            security_level: Some("SL5".to_string()),
            created_at: Some(now),
            updated_at: Some(now),
            folder_uuid: None,
            trashed: None,
            open_contents: None,
            tx_timestamp: Some(now),
            raw: String::new(),
            dirty: true,
        };

        let sc = item
            .secure_contents
            .get_or_insert_with(SecureContents::default);
        let notes = draft.notes.trim();
        let user = draft.username.trim();
        let pass = draft.password.trim();
        let url = draft.url.trim();
        let a = draft.extra_a.trim();
        let b = draft.extra_b.trim();

        // Stores a "key → value" pair, skipping empty values: an unfilled
        // field never appears in a dump.
        let mut put = |key: &str, value: &str| {
            if !value.is_empty() {
                sc.extra.insert(key.to_string(), value.into());
            }
        };

        match kind {
            // The only type with `designation` fields: only here are login and
            // password unambiguous.
            ItemKind::Login => {
                set_designated(&mut sc.fields, "username", "username", "T", user);
                set_designated(&mut sc.fields, "password", "password", "P", pass);
                if !notes.is_empty() {
                    sc.notes_plain = Some(notes.to_string());
                }
                if !url.is_empty() {
                    sc.urls.push(PifUrl {
                        url: Some(url.to_string()),
                    });
                }
            }
            ItemKind::SecureNote => {
                if !notes.is_empty() {
                    sc.notes_plain = Some(notes.to_string());
                }
            }
            ItemKind::Password => {
                if !pass.is_empty() {
                    sc.password = Some(pass.to_string());
                }
                if !url.is_empty() {
                    sc.urls.push(PifUrl {
                        url: Some(url.to_string()),
                    });
                }
                if !notes.is_empty() {
                    sc.notes_plain = Some(notes.to_string());
                }
            }
            // Expiry is kept in two keys: month and year.
            ItemKind::CreditCard => {
                put("cardholder", user);
                put("ccnum", pass);
                put("type", url);
                let (mm, yy) = split_expiry(a);
                put("expiry_mm", &mm);
                put("expiry_yy", &yy);
                put("cvv", b);
            }
            ItemKind::EmailAccount => {
                put("smtp_server", user);
                put("smtp_username", pass);
                put("smtp_password", url);
                put("pop_server", b);
                if !notes.is_empty() {
                    sc.notes_plain = Some(notes.to_string());
                }
            }
            ItemKind::Passport => {
                put("issuing_authority", user);
                put("number", pass);
                put("issue_date", url);
                if !notes.is_empty() {
                    sc.notes_plain = Some(notes.to_string());
                }
            }
            ItemKind::Server => {
                put("username", user);
                // The server's `password` key collides with the typed
                // `SecureContents` field. It cannot go into `extra`: serde would emit
                // both on serialization and the file would become invalid.
                if !pass.is_empty() {
                    sc.password = Some(pass.to_string());
                }
                put("port", b);
                if !notes.is_empty() {
                    sc.notes_plain = Some(notes.to_string());
                }
            }
            ItemKind::SoftwareLicence => {
                put("reg_name", user);
                put("reg_code", pass);
                put("download_link", url);
                put("publisher_website", notes);
                put("product_version", b);
            }
            // An identity document keeps its number and issuer in a dump;
            // the type stores nothing else.
            ItemKind::Identity => {
                put("type", user);
                put("number", pass);
                put("issuing_authority", url);
                if !notes.is_empty() {
                    sc.notes_plain = Some(notes.to_string());
                }
            }
        }

        self.items.push(item);
        uuid
    }

    /// Creates a new login record. Returns its uuid.
    ///
    /// It is created as a web form: only those carry `designation` fields
    /// in a dump, which is what makes login and password unambiguous.
    ///
    /// `contentsHash` is left unset — the algorithm behind that sum is
    /// unconfirmed, and a fabricated value would be a lie. The app does not
    /// need it to work, but importing such a file back into 1Password may
    /// fail.
    pub fn create_login(&mut self, draft: &EntryDraft) -> String {
        let uuid = new_uuid();
        let now = unix_now();

        let mut item = PifItem {
            uuid: uuid.clone(),
            type_name: Some("webforms.WebForm".to_string()),
            title: Some(draft.title.trim().to_string()),
            location_key: None,
            location: None,
            secure_contents: Some(SecureContents::default()),
            contents_hash: None,
            security_level: Some("SL5".to_string()),
            created_at: Some(now),
            updated_at: Some(now),
            folder_uuid: None,
            trashed: None,
            open_contents: None,
            tx_timestamp: Some(now),
            raw: String::new(),
            dirty: true,
        };
        draft.apply(&mut item);

        self.items.push(item);
        uuid
    }

    /// Deletes a record. Returns `true` if it existed.
    pub fn remove(&mut self, uuid: &str) -> bool {
        let before = self.items.len();
        self.items.retain(|i| i.uuid != uuid);
        if let Some(list) = self.attachments.remove(uuid) {
            for a in list {
                if a.pending_source.is_none() && a.path.exists() {
                    self.attachments_to_trash.push((uuid.to_string(), a.path));
                }
            }
        }
        self.items.len() != before
    }

    /// Record by uuid.
    pub fn find(&self, uuid: &str) -> Option<&PifItem> {
        self.items.iter().find(|i| i.uuid == uuid)
    }

    /// Record by uuid, for editing.
    pub fn find_mut(&mut self, uuid: &str) -> Option<&mut PifItem> {
        self.items.iter_mut().find(|i| i.uuid == uuid)
    }

    /// Folder by uuid.
    pub fn folder(&self, uuid: &str) -> Option<&PifItem> {
        self.items
            .iter()
            .find(|i| i.uuid == uuid && i.type_name.as_deref() == Some(FOLDER_TYPE))
    }

    /// How many live records the folder holds.
    pub fn folder_count(&self, uuid: &str) -> usize {
        self.items
            .iter()
            .filter(|i| {
                !i.trashed.unwrap_or(false)
                    && i.type_name.as_deref() != Some(FOLDER_TYPE)
                    && i.folder_uuid.as_deref() == Some(uuid)
            })
            .count()
    }

    /// Creates a folder and returns its uuid.
    ///
    /// As with records, `contentsHash` stays unset: the sum's algorithm is
    /// unconfirmed, and a made-up value is worse than none.
    pub fn create_folder(&mut self, title: &str) -> String {
        let uuid = new_uuid();
        let now = unix_now();
        let title = title.trim();

        self.items.push(PifItem {
            uuid: uuid.clone(),
            type_name: Some(FOLDER_TYPE.to_string()),
            title: Some(if title.is_empty() {
                "Untitled Folder".to_string()
            } else {
                title.to_string()
            }),
            location_key: None,
            location: None,
            secure_contents: Some(SecureContents::default()),
            contents_hash: None,
            security_level: Some("SL5".to_string()),
            created_at: Some(now),
            updated_at: Some(now),
            folder_uuid: None,
            trashed: None,
            open_contents: None,
            tx_timestamp: Some(now),
            raw: String::new(),
            dirty: true,
        });
        uuid
    }

    /// Renames a folder. Returns `false` if there is no such folder.
    pub fn rename_folder(&mut self, uuid: &str, title: &str) -> bool {
        let title = title.trim();
        let Some(folder) = self
            .items
            .iter_mut()
            .find(|i| i.uuid == uuid && i.type_name.as_deref() == Some(FOLDER_TYPE))
        else {
            return false;
        };

        if folder.title.as_deref() == Some(title) {
            return true;
        }
        folder.title = Some(title.to_string());
        folder.dirty = true;
        true
    }

    /// Deletes a folder. Its records are not deleted: they just lose the link.
    ///
    /// 1Password behaves the same way — removing a folder and losing all of
    /// its contents would be a careless way to lose data.
    pub fn remove_folder(&mut self, uuid: &str) -> bool {
        if self.folder(uuid).is_none() {
            return false;
        }

        let mut touched = false;
        for item in &mut self.items {
            if item.folder_uuid.as_deref() == Some(uuid) {
                item.folder_uuid = None;
                item.dirty = true;
                touched = true;
            }
        }

        self.items.retain(|i| i.uuid != uuid);
        touched
    }

    /// Puts a record in a folder. An empty `folder` puts it at the top level.
    ///
    /// The record has to exist; otherwise nothing happens quietly, because
    /// a UI handler has no reason to return an error.
    pub fn set_folder(&mut self, uuid: &str, folder: Option<&str>) -> bool {
        let Some(item) = self
            .items
            .iter_mut()
            .find(|i| i.uuid == uuid && i.type_name.as_deref() != Some(FOLDER_TYPE))
        else {
            return false;
        };

        // An empty string means "no folder", not a folder with such a uuid.
        let target = folder.filter(|f| !f.is_empty());
        if item.folder_uuid.as_deref() == target {
            return true;
        }

        item.folder_uuid = target.map(str::to_string);
        item.dirty = true;
        true
    }

    /// Records, folders excluded.
    pub fn entries(&self) -> Vec<&PifItem> {
        self.items
            .iter()
            .filter(|i| i.type_name.as_deref() != Some(FOLDER_TYPE))
            .collect()
    }

    /// Trashed records: marked `trashed: true`.
    pub fn trashed(&self) -> Vec<&PifItem> {
        self.items
            .iter()
            .filter(|i| i.trashed.unwrap_or(false) && i.type_name.as_deref() != Some(FOLDER_TYPE))
            .collect()
    }

    /// Live records: neither trashed nor folders.
    pub fn alive(&self) -> Vec<&PifItem> {
        self.items
            .iter()
            .filter(|i| !i.trashed.unwrap_or(false) && i.type_name.as_deref() != Some(FOLDER_TYPE))
            .collect()
    }

    /// Folders: records with `typeName: system.folder.Regular`.
    ///
    /// A folder in 1PIF is an ordinary record of a special type, and it
    /// differs in exactly one way: other records carry `folderUuid` pointing at it.
    pub fn folders(&self) -> Vec<&PifItem> {
        self.items
            .iter()
            .filter(|i| i.type_name.as_deref() == Some(FOLDER_TYPE))
            .collect()
    }

    /// Searches title, domain and URL, case-insensitively.
    pub fn search(&self, query: &str) -> Vec<&PifItem> {
        let q = query.to_lowercase();
        self.entries()
            .into_iter()
            .filter(|i| i.matches(&q))
            .collect()
    }
}

/// Folder type code.
pub const FOLDER_TYPE: &str = "system.folder.Regular";

/// The record a new store starts with.
///
/// Exactly one folder: it does not get in the user's way (folders are
/// hidden from the lists) and it makes the file parseable. The fields
/// mirror a real 1Password export; `contentsHash` is absent on purpose, see [`Pif::create`].
const STARTER_DOCUMENT: &str = concat!(
    r#"{"uuid":"00000000000000000000000000000001","securityLevel":"SL5","#,
    r#""title":"My Items","secureContents":{},"typeName":"system.folder.Regular"}"#
);

fn is_attachment_marker(s: &str) -> bool {
    s.starts_with("***")
        && s.ends_with("***")
        && s.len() > 6
        && s[3..s.len() - 3]
            .chars()
            .all(|c| c.is_ascii_hexdigit() || c == '-')
}

impl PifItem {
    /// A field that is safe to display and search.
    fn matches(&self, lower_q: &str) -> bool {
        let hit = |s: Option<&String>| {
            s.map(|v| v.to_lowercase().contains(lower_q))
                .unwrap_or(false)
        };
        hit(self.title.as_ref())
            || hit(self.location_key.as_ref())
            || hit(self.location.as_ref())
            || (self
                .secure_contents
                .as_ref()
                .map(|sc| {
                    sc.urls.iter().any(|u| {
                        u.url
                            .as_ref()
                            .is_some_and(|v| v.to_lowercase().contains(lower_q))
                    }) || sc.fields.iter().any(|f| {
                        f.name
                            .as_ref()
                            .is_some_and(|n| n.to_lowercase().contains(lower_q))
                    })
                })
                .unwrap_or(false))
    }

    /// Record type for display: a human-readable name.
    pub fn kind(&self) -> &str {
        match self.type_name.as_deref().unwrap_or("") {
            "webforms.WebForm" => "Logins",
            "passwords.Password" => "Passwords",
            "securenotes.SecureNote" => "Secure Notes",
            "wallet.onlineservices.Email.v2" => "Email Accounts",
            "wallet.financial.CreditCard" => "Credit Cards",
            "wallet.government.SsnUS" => "Identities",
            "wallet.government.Passport" => "Passports",
            "wallet.computer.License" => "Software Licences",
            "wallet.computer.UnixServer" => "Servers",
            FOLDER_TYPE => "Folder",
            other => other,
        }
    }

    /// The record's main password.
    ///
    /// Real exports often give a web form several non-empty `P` fields
    /// (a registration password next to the login one, say), so the first one
    /// cannot be taken by position. The canonical field is tagged
    /// `designation: "password"`; `secureContents.password` is the fallback
    /// for records without `fields`.
    pub fn primary_password(&self) -> Option<&str> {
        let sc = self.secure_contents.as_ref()?;

        let by_designation = sc
            .fields
            .iter()
            .find(|f| f.designation.as_deref() == Some("password") && !f.value.is_empty());
        if let Some(v) = by_designation {
            return Some(&v.value);
        }

        let by_name = sc.fields.iter().find(|f| {
            matches!(
                f.name.as_deref().unwrap_or("").to_lowercase().as_str(),
                "password" | "pass" | "pwd"
            ) && !f.value.is_empty()
        });
        if let Some(v) = by_name {
            return Some(&v.value);
        }

        if let Some(p) = sc.password.as_deref() {
            if !p.is_empty() {
                return Some(p);
            }
        }

        sc.fields
            .iter()
            .find(|f| f.field_type == FIELD_PASSWORD && !f.value.is_empty())
            .map(|f| f.value.as_str())
    }

    /// The record's logins: `username`, `login`, `email` and their variants.
    ///
    /// The field tagged `designation: "username"` comes first — that is the
    /// canonical login. The other names serve as a fallback because a dump
    /// contains both `pass` and `Имя пользователя`.
    pub fn usernames(&self) -> Vec<&str> {
        let Some(sc) = self.secure_contents.as_ref() else {
            return Vec::new();
        };

        let mut out: Vec<&str> = Vec::new();

        let by_designation: Vec<&str> = sc
            .fields
            .iter()
            .filter(|f| f.designation.as_deref() == Some("username"))
            .map(|f| f.value.as_str())
            .filter(|v| !v.trim().is_empty())
            .collect();
        let by_name: Vec<&str> = sc
            .fields
            .iter()
            .filter(|f| is_username_field(&f.name))
            .map(|f| f.value.as_str())
            .filter(|v| !v.trim().is_empty())
            .collect();

        // Servers keep the login in a flat key, with no form fields.
        if by_designation.is_empty() && by_name.is_empty() {
            if let Some(v) = sc.extra.get("username").and_then(|v| value_as_str(v)) {
                let v = v.trim();
                if !v.is_empty() {
                    return vec![v];
                }
            }
        }

        let source = if by_designation.is_empty() {
            by_name
        } else {
            by_designation
        };
        for v in source {
            let v = v.trim();
            if !out.contains(&v) {
                out.push(v);
            }
        }
        out
    }

    /// Addresses from the `location` field and the `URLs` section, no duplicates.
    pub fn urls(&self) -> Vec<&str> {
        let mut out: Vec<&str> = Vec::new();

        if let Some(l) = self.location.as_deref().map(str::trim) {
            if !l.is_empty() && !out.contains(&l) {
                out.push(l);
            }
        }
        if let Some(sc) = self.secure_contents.as_ref() {
            for u in &sc.urls {
                if let Some(v) = u.url.as_deref().map(str::trim) {
                    if !v.is_empty() && !out.contains(&v) {
                        out.push(v);
                    }
                }
            }
            // Licences, documents and mail keep addresses in flat keys.
            for key in [
                "website",
                "download_link",
                "publisher_website",
                "provider_website",
            ] {
                if let Some(v) = sc.extra.get(key).and_then(|v| value_as_str(v)) {
                    let v = v.trim();
                    if !v.is_empty() && !out.contains(&v) {
                        out.push(v);
                    }
                }
            }
        }
        out
    }

    /// The TOTP field: a value prefixed with `otpauth://`.
    pub fn totp(&self) -> Option<&str> {
        self.secure_contents.as_ref()?.fields.iter().find_map(|f| {
            if f.value.starts_with("otpauth://") {
                Some(f.value.as_str())
            } else {
                None
            }
        })
    }

    /// Notes in plaintext.
    pub fn notes(&self) -> Option<&str> {
        self.secure_contents.as_ref()?.notes_plain.as_deref()
    }

    /// Fields specific to the record type: card number, expiry, POP/SMTP,
    /// licence key, document number.
    ///
    /// Only web forms keep their data in `fields[]`; cards, mail,
    /// licences and documents use flat keys in `secureContents` plus duplicates
    /// in `sections`. Flat keys are read first, whatever is missing is then
    /// dug out of the sections by field label.
    ///
    /// Returns `(label, value, mask)` triples.
    pub fn extra_fields(&self) -> Vec<(String, String, bool)> {
        let Some(sc) = self.secure_contents.as_ref() else {
            return Vec::new();
        };

        let mut out: Vec<(String, String, bool)> = Vec::new();

        // 1. Flat keys are the source of truth.
        for (key, raw) in &sc.extra {
            if let Some((label, secret)) = describe_key(key) {
                if let Some(v) = value_to_string(raw) {
                    push_extra(&mut out, label, v, secret);
                }
            }
        }

        // 2. Sections fill in what the flat keys do not have.
        for s in &sc.sections {
            for f in &s.fields {
                let Some(name) = f.n.as_deref() else {
                    continue;
                };
                if is_noise_key(name) {
                    continue;
                }
                let Some(v) = f.v.as_ref().and_then(value_to_string) else {
                    continue;
                };
                match describe_key(name) {
                    Some((label, secret)) => push_extra(&mut out, label, v, secret),
                    None => {
                        if let Some(t) = f.t.as_deref().map(str::trim).filter(|t| !t.is_empty()) {
                            push_extra(&mut out, t, v, guarded(f));
                        }
                    }
                }
            }
        }

        out
    }
}

/// Adds a pair to the list unless it is already there.
fn push_extra(out: &mut Vec<(String, String, bool)>, label: &str, value: String, secret: bool) {
    let value = value.trim().to_string();
    if value.is_empty() {
        return;
    }
    // The same label or the same value twice is redundant.
    if out
        .iter()
        .any(|(l, existing, _)| l == label || existing == &value)
    {
        return;
    }
    out.push((label.trim().to_string(), value, secret));
}

/// A JSON string value, borrowed without copying.
fn value_as_str(v: &serde_json::Value) -> Option<&str> {
    match v {
        serde_json::Value::String(s) => Some(s.as_str()),
        _ => None,
    }
}

/// A JSON value as a string, if it is one.
fn value_to_string(v: &serde_json::Value) -> Option<String> {
    match v {
        serde_json::Value::String(s) => Some(s.clone()),
        serde_json::Value::Number(n) => Some(n.to_string()),
        serde_json::Value::Bool(b) => Some(b.to_string()),
        _ => None,
    }
}

/// The field is marked secret.
fn guarded(f: &PifSectionField) -> bool {
    f.a.as_ref()
        .and_then(|a| a.get("guarded"))
        .and_then(|g| g.as_str())
        == Some("yes")
}

/// Internal field names: hashed duplicates and conflict variants.
///
/// A dump contains fields like `A90930AA80B1461EA634F666DACB517C` — the same
/// security code saved under an internal key — and
/// `cvv_conflict_1` — the variant discarded while resolving a conflict.
/// There is no reason to show these to the user.
fn is_noise_key(name: &str) -> bool {
    if name.ends_with("_conflict_1") {
        return true;
    }
    let hex = name.chars().all(|c| c.is_ascii_hexdigit());
    hex && name.len() == 32
}

/// Label and secrecy flag for a known key.
fn describe_key(key: &str) -> Option<(&'static str, bool)> {
    let (label, secret): (&'static str, bool) = match key {
        // Card
        "cardholder" => ("Cardholder", true),
        "ccnum" => ("Card Number", true),
        "expiry" => ("Valid Thru", false),
        "expiry_mm" => ("Expiry Month", false),
        "expiry_yy" => ("Expiry Year", false),
        "validFrom" => ("Valid From", false),
        "validFrom_mm" => ("Start Month", false),
        "validFrom_yy" => ("Start Year", false),
        "cvv" => ("Security Code", true),
        "pin" => ("PIN", true),
        "cashLimit" => ("Cash Limit", false),
        "creditLimit" => ("Credit Limit", false),
        "type" => ("Type", false),
        // Mail
        "provider" => ("Provider", false),
        "provider_website" => ("Provider Website", false),
        "pop_server" => ("POP Server", false),
        "pop_port" => ("POP Port", false),
        "pop_type" => ("POP Type", false),
        "pop_username" => ("POP Account", false),
        "pop_password" => ("POP Password", true),
        "pop_security" => ("POP Encryption", false),
        "pop_authentication" => ("POP Authentication", false),
        "smtp_server" => ("SMTP Server", false),
        "smtp_port" => ("SMTP Port", false),
        "smtp_username" => ("SMTP Account", false),
        "smtp_password" => ("SMTP Password", true),
        "smtp_security" => ("SMTP Encryption", false),
        "smtp_authentication" => ("SMTP Authentication", false),
        // Licence
        "reg_name" => ("Owner Name", false),
        "reg_code" => ("License Key", true),
        "product_version" => ("Version", false),
        "download_link" => ("Download Link", false),
        "publisher_website" => ("Publisher Website", false),
        "order_date" => ("Order Date", false),
        "order_date_dd" => ("Order Day", false),
        "order_date_mm" => ("Order Month", false),
        "order_date_yy" => ("Order Year", false),
        "company" => ("Company", false),
        // Documents
        "issuing_authority" => ("Issued By", false),
        "number" => ("Number", false),
        "issue_date" => ("Issue Date", false),
        "issue_date_dd" => ("Issue Day", false),
        "issue_date_mm" => ("Issue Month", false),
        "issue_date_yy" => ("Issue Year", false),
        "name" => ("Name", false),
        // Common
        "website" => ("Website", false),
        _ => return None,
    };
    Some((label, secret))
}

/// A record draft for the editor.
///
/// The fields mirror what the app can display: title, login,
/// password, URL and notes. The rest of the record contents are left
/// alone on edit — [`EntryDraft::apply`] changes only what is listed here.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct EntryDraft {
    /// Title.
    pub title: String,
    /// Login.
    pub username: String,
    /// Password.
    pub password: String,
    /// URL.
    pub url: String,
    /// Notes.
    pub notes: String,
    /// Extra slot: its meaning depends on the record type.
    ///
    /// On a card it is the expiry, on a server the port, on a licence the
    /// version. Separate slots exist because a card needs two of them,
    /// and they cannot be named any other way: "notes" is taken already.
    pub extra_a: String,
    /// Second extra slot: on a card it is the security code.
    pub extra_b: String,
}

/// Record types the app can create.
///
/// The set and the field names come from a real 1Password dump: for every
/// type except login the data sits in named keys right inside
/// `secureContents`, not in a list of `designation` fields.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ItemKind {
    /// Login with a password.
    Login,
    /// A note with no credentials.
    SecureNote,
    /// A password with no login.
    Password,
    /// Bank card.
    CreditCard,
    /// Mail account.
    EmailAccount,
    /// Passport.
    Passport,
    /// Server.
    Server,
    /// Software licence.
    SoftwareLicence,
    /// Identity document.
    Identity,
}

impl ItemKind {
    /// The `typeName` value in a dump.
    pub fn type_name(self) -> &'static str {
        match self {
            ItemKind::Login => "webforms.WebForm",
            ItemKind::SecureNote => "securenotes.SecureNote",
            ItemKind::Password => "passwords.Password",
            ItemKind::CreditCard => "wallet.financial.CreditCard",
            ItemKind::EmailAccount => "wallet.onlineservices.Email.v2",
            ItemKind::Passport => "wallet.government.Passport",
            ItemKind::Server => "wallet.computer.UnixServer",
            ItemKind::SoftwareLicence => "wallet.computer.License",
            ItemKind::Identity => "wallet.government.SsnUS",
        }
    }

    /// The type's label in the UI.
    pub fn label(self) -> String {
        match self {
            ItemKind::Login => "Login".to_string(),
            ItemKind::SecureNote => "Secure Note".to_string(),
            ItemKind::Password => "Password".to_string(),
            ItemKind::CreditCard => "Credit Card".to_string(),
            ItemKind::EmailAccount => "Email Account".to_string(),
            ItemKind::Passport => "Passport".to_string(),
            ItemKind::Server => "Server".to_string(),
            ItemKind::SoftwareLicence => "Software Licence".to_string(),
            ItemKind::Identity => "Identity".to_string(),
        }
    }

    /// All types — this is what the pick buttons in the editor iterate over.
    pub fn all() -> [ItemKind; 9] {
        [
            ItemKind::Login,
            ItemKind::SecureNote,
            ItemKind::Password,
            ItemKind::CreditCard,
            ItemKind::EmailAccount,
            ItemKind::Passport,
            ItemKind::Server,
            ItemKind::SoftwareLicence,
            ItemKind::Identity,
        ]
    }

    /// Field labels for this type.
    ///
    /// The five draft slots are labelled differently per type: on a card
    /// "username" is the cardholder and on a licence the licence key. An
    /// empty label means the slot is not needed for this type and the field
    ///
    /// Order: login slot, password slot, URL slot, notes, second extra
    /// slot.
    pub fn field_labels(self) -> [&'static str; 5] {
        match self {
            ItemKind::Login => ["Username", "Password", "URL", "", ""],
            ItemKind::Password => ["", "Password", "URL", "Notes", ""],
            ItemKind::SecureNote => ["", "", "", "Notes", ""],
            ItemKind::CreditCard => ["Cardholder", "Card Number", "Card Type", "", "MM/YYYY, CVV"],
            ItemKind::EmailAccount => [
                "SMTP Server",
                "SMTP Username",
                "SMTP Password",
                "Notes",
                "POP Server",
            ],
            ItemKind::Passport => [
                "Issuing Authority",
                "Passport Number",
                "Issue Date",
                "Notes",
                "",
            ],
            ItemKind::Server => ["Hostname", "Username", "Password", "Notes", "Port"],
            ItemKind::SoftwareLicence => [
                "Owner",
                "License Key",
                "Download Link",
                "Publisher Website",
                "Version",
            ],
            ItemKind::Identity => ["Type", "Number", "Issuing Authority", "Notes", ""],
        }
    }
}

/// Splits "09/2027" or "09/27" into month and year, the way 1Password writes them.
///
/// The year is kept as four digits: in a dump it is four digits, and on
/// a two-digit year on re-import could be read as 2027 or
/// as 1927.
fn split_expiry(raw: &str) -> (String, String) {
    let raw = raw.trim();
    let Some((mm, rest)) = raw.split_once('/') else {
        return (String::new(), String::new());
    };
    let yy = rest
        .trim()
        .chars()
        .filter(char::is_ascii_digit)
        .collect::<String>();
    let yy = match yy.len() {
        0 => String::new(),
        1 | 2 => format!("20{yy:0>2}"),
        _ => yy,
    };
    (mm.trim().to_string(), yy)
}

impl EntryDraft {
    /// Builds a draft from a record.
    pub fn from_item(it: &PifItem) -> Self {
        Self {
            title: it.title.clone().unwrap_or_default(),
            username: it.usernames().first().copied().unwrap_or("").to_string(),
            password: it.primary_password().unwrap_or("").to_string(),
            url: it.urls().first().copied().unwrap_or("").to_string(),
            notes: it.notes().unwrap_or("").to_string(),
            // The extra slots are filled in when creating a record of a
            // specific type: they are useless for editing, because that type's
            // fields live in extra_fields and are displayed separately.
            extra_a: String::new(),
            extra_b: String::new(),
        }
    }

    /// Writes the values into a record.
    ///
    /// Form fields are appended when missing: without `designation` there is
    /// no way to tell a real password from a decoy registration field.
    pub fn apply(&self, it: &mut PifItem) {
        it.title = Some(self.title.trim().to_string());

        let now = unix_now();
        it.updated_at = Some(now);
        it.tx_timestamp = Some(now);

        // Fields
        let sc = it
            .secure_contents
            .get_or_insert_with(SecureContents::default);
        set_designated(&mut sc.fields, "username", "username", "T", &self.username);
        set_designated(&mut sc.fields, "password", "password", "P", &self.password);

        // URL and domain
        let url = self.url.trim().to_string();
        if url.is_empty() {
            sc.urls.clear();
            it.location = None;
            it.location_key = None;
        } else {
            let matches_existing = |u: &PifUrl| match u.url.as_deref().map(str::trim) {
                Some(v) => v == url || Some(v) == it.location.as_deref(),
                None => false,
            };
            match sc.urls.iter_mut().find(|u| matches_existing(u)) {
                Some(u) => u.url = Some(url.clone()),
                None => sc.urls.push(PifUrl {
                    url: Some(url.clone()),
                }),
            }
            it.location = Some(url);
            it.location_key = Some(host_of(self.url.trim()));
        }

        // Notes
        let notes = self.notes.trim();
        if notes.is_empty() {
            sc.notes_plain = None;
        } else {
            sc.notes_plain = Some(notes.to_string());
        }
    }
}

/// Sets the value of a `designation`-tagged field.
fn set_designated(
    fields: &mut Vec<PifField>,
    designation: &str,
    name: &str,
    field_type: &str,
    value: &str,
) {
    if value.is_empty() {
        fields.retain(|f| f.designation.as_deref() != Some(designation));
        return;
    }
    if let Some(f) = fields
        .iter_mut()
        .find(|f| f.designation.as_deref() == Some(designation))
    {
        f.value = value.to_string();
        return;
    }
    fields.push(PifField {
        field_type: field_type.to_string(),
        name: Some(name.to_string()),
        value: value.to_string(),
        designation: Some(designation.to_string()),
        section: None,
    });
}

/// Host name from the URL: `https://shop.example.com/a` → `shop.example.com`.
fn host_of(url: &str) -> String {
    let rest = url.split_once("://").map(|(_, r)| r).unwrap_or(url);
    rest.split(['/', ':', '?', '#'])
        .next()
        .unwrap_or(rest)
        .trim_start_matches("www.")
        .to_string()
}

/// Current time in Unix seconds.
pub fn unix_now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// A new uuid in 1PIF format: 32 uppercase hex characters, no dashes.
///
/// Entropy comes from `getrandom`, which is already in the tree as a
/// transitive dependency and wraps `/dev/urandom` on Unix and `BCryptGenRandom`
/// on Windows. Reading `/dev/urandom` directly was shorter, but it only
/// exists on Unix: on Windows the open failed, the failure was swallowed and
/// every new item got `00000000000000000000000000000000`. Items, folders and
/// attachments are keyed by this uuid, so that collision was not cosmetic.
///
/// A failure of the syscall itself must not produce zeros either. Time and a
/// counter are weaker, but they cannot collide within one run, and a uuid is
/// only ever compared for equality inside a single export.
pub fn new_uuid() -> String {
    use std::sync::atomic::Ordering;

    let mut bytes = [0u8; 16];
    if getrandom::fill(&mut bytes).is_err() {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(0);
        bytes[..8].copy_from_slice(&nanos.to_le_bytes());
        bytes[8..].copy_from_slice(&UUID_COUNTER.fetch_add(1, Ordering::Relaxed).to_le_bytes());
        // The low byte is set unconditionally: a clock that has not ticked
        // since boot would otherwise leave a zero byte in every uuid.
        bytes[15] |= 1;
    }
    bytes.iter().map(|b| format!("{b:02X}")).collect()
}

/// Makes the fallback unique within one run.
static UUID_COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// The trash directory next to the export.
pub const TRASH_DIR_NAME: &str = "trash";

/// How many days a file may sit in the trash.
///
/// After that the app deletes it itself. Before that, no: as long as it
/// can still be restored, let it lie there.
pub const TRASH_MAX_AGE_DAYS: u64 = 30;

/// Seconds in a day.
const DAY: u64 = 86_400;

/// Trash state: how many files and how much space.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct TrashStats {
    /// Number of files.
    pub files: usize,
    /// Total size in bytes.
    pub bytes: u64,
}

impl Pif {
    /// The trash directory for this export.
    pub fn trash_dir(&self) -> Option<PathBuf> {
        let pif_path = self.source_path.as_deref()?;
        let base = pif_path.parent()?;
        Some(base.join(TRASH_DIR_NAME))
    }

    /// What is in the trash right now.
    pub fn trash_stats(&self) -> TrashStats {
        let Some(dir) = self.trash_dir() else {
            return TrashStats::default();
        };
        collect_trash(&dir)
    }

    /// Removes from the trash everything that has been there past the deadline.
    ///
    /// Returns the number of removed files. Directory read errors are
    /// ignored: no trash, nothing to clean.
    pub fn purge_trash(&self) -> usize {
        let Some(dir) = self.trash_dir() else {
            return 0;
        };
        let cutoff = std::time::SystemTime::now()
            .checked_sub(std::time::Duration::from_secs(TRASH_MAX_AGE_DAYS * DAY));

        let mut removed = 0usize;
        let Ok(entries) = std::fs::read_dir(&dir) else {
            return 0;
        };
        for sub in entries.flatten() {
            let Ok(files) = std::fs::read_dir(sub.path()) else {
                continue;
            };
            for f in files.flatten() {
                let Ok(meta) = f.metadata() else { continue };
                let Ok(modified) = meta.modified() else {
                    continue;
                };
                let Some(cutoff) = cutoff else { return removed };
                if modified < cutoff && std::fs::remove_file(f.path()).is_ok() {
                    removed += 1;
                }
            }
            // Drop an emptied record directory so we do not accumulate litter.
            let _ = std::fs::remove_dir(sub.path());
        }
        removed
    }

    /// Empties the trash completely. Returns the number of removed files.
    pub fn empty_trash(&self) -> usize {
        let Some(dir) = self.trash_dir() else {
            return 0;
        };
        let stats = collect_trash(&dir);
        if std::fs::remove_dir_all(&dir).is_ok() {
            stats.files
        } else {
            0
        }
    }
}

/// Counts the trash contents.
fn collect_trash(dir: &Path) -> TrashStats {
    let mut stats = TrashStats::default();
    let Ok(entries) = std::fs::read_dir(dir) else {
        return stats;
    };
    for sub in entries.flatten() {
        let Ok(files) = std::fs::read_dir(sub.path()) else {
            continue;
        };
        for f in files.flatten() {
            if f.metadata().map(|m| m.is_file()).unwrap_or(false) {
                stats.files += 1;
                stats.bytes += f.metadata().map(|m| m.len()).unwrap_or(0);
            }
        }
    }
    stats
}

/// Moves a file to the trash, keeping the `trash/<uuid>/<name>` layout.
///
/// The modification time is reset: a photo from a dump may carry an mtime
/// from five years ago and would fly out on the very first cleanup
/// without ever having spent time in the trash.
fn move_to_trash(trash: &Path, uuid: &str, from: &Path) -> std::io::Result<PathBuf> {
    let dir = trash.join(uuid);
    std::fs::create_dir_all(&dir)?;

    let name = from
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| "file".to_string());

    let mut target = dir.join(&name);
    let mut n = 1;
    while target.exists() {
        target = dir.join(unique_name(&name, n));
        n += 1;
    }

    match std::fs::rename(from, &target) {
        Ok(()) => {}
        Err(_) => {
            // The file system may be a different one: copy and remove instead.
            std::fs::copy(from, &target)?;
            std::fs::remove_file(from)?;
        }
    }

    if let Ok(f) = std::fs::OpenOptions::new().write(true).open(&target) {
        let now = std::time::SystemTime::now();
        let _ = f.set_times(std::fs::FileTimes::new().set_modified(now));
    }

    Ok(target)
}

/// File name with a number, so an existing one is not overwritten: `photo.jpg` → `photo-1.jpg`.
fn unique_name(name: &str, n: usize) -> String {
    let path = Path::new(name);
    let stem = path
        .file_stem()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_else(|| name.to_string());
    match path.extension().and_then(|e| e.to_str()) {
        Some(ext) => format!("{stem}-{n}.{ext}"),
        None => format!("{stem}-{n}"),
    }
}

/// How many recent versions to keep next to the file.
pub const BACKUP_KEEP: usize = 5;

/// Shifts the backups and makes a new one.
///
/// `data.1pif.bak1` is the newest copy, `.bak5` the oldest of the kept
/// ones. Copies beyond `BACKUP_KEEP` slots are deleted.
fn rotate_backups(path: &Path) -> Result<(), PifError> {
    let err = |e: std::io::Error, p: &Path| PifError::Io {
        path: p.display().to_string(),
        source: e,
    };

    // Shift from oldest to newest so nothing gets overwritten.
    for n in (1..BACKUP_KEEP).rev() {
        let from = backup_path(path, n);
        if from.exists() {
            let to = backup_path(path, n + 1);
            std::fs::rename(&from, &to).map_err(|e| err(e, &to))?;
        }
    }

    let first = backup_path(path, 1);
    std::fs::copy(path, &first).map_err(|e| err(e, &first))?;
    Ok(())
}

/// Path to a backup copy: `data.1pif.bak1`.
fn backup_path(path: &Path, n: usize) -> PathBuf {
    let mut s = path.as_os_str().to_os_string();
    s.push(format!(".bak{n}"));
    PathBuf::from(s)
}
///
/// 1Password lays the files out in directories, and a directory name is the
/// record uuid without dashes. The JSON holds no reference to an attachment,
/// the link is the directory name alone, hence this way of looking them up.
///
/// Directories that match no record are ignored.
fn scan_attachments(pif_path: &Path, items: &[PifItem]) -> HashMap<String, Vec<Attachment>> {
    let mut known: HashMap<String, &str> = HashMap::new();
    for it in items {
        known.insert(it.uuid.to_uppercase(), it.uuid.as_str());
    }

    let Some(root) = pif_path.parent().map(|p| p.join("attachments")) else {
        return HashMap::new();
    };
    let Ok(dirs) = std::fs::read_dir(&root) else {
        return HashMap::new();
    };

    let mut out: HashMap<String, Vec<Attachment>> = HashMap::new();

    for dir in dirs.flatten() {
        if !dir.path().is_dir() {
            continue;
        }
        let raw = dir.file_name();
        let Some(name) = raw.to_str() else {
            continue;
        };
        let Some(uuid) = known.get(&name.to_uppercase()) else {
            continue;
        };
        let Ok(files) = std::fs::read_dir(dir.path()) else {
            continue;
        };

        let mut list: Vec<Attachment> = files
            .flatten()
            .filter_map(|f| {
                let meta = f.metadata().ok()?;
                if !meta.is_file() {
                    return None;
                }
                Some(Attachment {
                    name: f.file_name().to_string_lossy().into_owned(),
                    size: meta.len(),
                    path: f.path(),
                    pending_source: None,
                })
            })
            .collect();
        list.sort_by(|a, b| a.name.cmp(&b.name));

        if !list.is_empty() {
            out.insert((*uuid).to_string(), list);
        }
    }
    out
}

/// A file size for display: `12 KB`, `3 MB`.
pub fn human_size(bytes: u64) -> String {
    const KB: f64 = 1024.0;
    if bytes < 1024 {
        return format!("{bytes} B");
    }
    let mut v = bytes as f64 / KB;
    if v < 1024.0 {
        return format!("{v:.0} KB");
    }
    v /= 1024.0;
    format!("{v:.1} MB")
}

/// A field name counts as a login.
///
/// The Russian variants are deliberately not translated along with the UI:
/// they are field names from the export file, not app labels.
fn is_username_field(name: &Option<String>) -> bool {
    matches!(
        name.as_deref().unwrap_or("").to_lowercase().as_str(),
        "username" | "login" | "login name" | "email" | "user" | "имя пользователя" | "логин"
    )
}

/// An export parsing error.
#[derive(Debug)]
pub enum PifError {
    /// I/O error.
    Io {
        /// Path to the file.
        path: String,
        /// Underlying error.
        source: std::io::Error,
    },
    /// JSON error.
    Json(serde_json::Error),
    /// JSON error on a specific line.
    Line {
        /// Line number, 1-based.
        lineno: usize,
        /// Underlying error.
        source: serde_json::Error,
    },
    /// The file contained no records.
    Empty,
    /// An export already exists at the path: we will not overwrite someone else's file.
    Exists {
        /// Path to the file.
        path: String,
    },
}

impl std::fmt::Display for PifError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io { path, source } => write!(f, "cannot read {path}: {source}"),
            Self::Json(e) => write!(f, "JSON: {e}"),
            Self::Line { lineno, source } => write!(f, "line {lineno}: {source}"),
            Self::Empty => write!(f, "the file contains no items"),
            Self::Exists { path } => {
                write!(f, "an export already exists at {path}")
            }
        }
    }
}

impl std::error::Error for PifError {}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = r#"{"uuid":"A1","typeName":"webforms.WebForm","title":"GitHub","locationKey":"github.com","location":"https://github.com","secureContents":{"fields":[{"type":"T","name":"username","value":"me@example.com"},{"type":"P","name":"password","value":"secret123"}],"URLs":[{"url":"https://github.com"}],"notesPlain":"note"},"contentsHash":"1234abcd","securityLevel":"SL5"}
***5642bee8-a5ff-11dc-8314-0800200c9a66***
{"uuid":"B2","typeName":"system.folder.Regular","title":"EMails"}
{"uuid":"C3","typeName":"passwords.Password","title":"Mail account","secureContents":{"fields":[{"type":"P","value":"p@ss"}]}}"#;

    #[test]
    fn parses_jsonl_with_attachment_marker() {
        let p = Pif::parse(SAMPLE).unwrap();
        assert_eq!(p.items.len(), 3);
        assert_eq!(p.entries().len(), 2);
        assert_eq!(p.folders().len(), 1);
        assert_eq!(p.folders()[0].title.as_deref(), Some("EMails"));
    }

    #[test]
    fn extracts_password_and_usernames() {
        let p = Pif::parse(SAMPLE).unwrap();
        let gh = p.items.iter().find(|i| i.uuid == "A1").unwrap();
        assert_eq!(gh.primary_password(), Some("secret123"));
        assert_eq!(gh.usernames(), vec!["me@example.com"]);
        assert_eq!(gh.notes(), Some("note"));
        assert!(gh.urls().contains(&"https://github.com"));
    }

    #[test]
    fn search_is_case_insensitive() {
        let p = Pif::parse(SAMPLE).unwrap();
        assert_eq!(p.search("github").len(), 1);
        assert_eq!(p.search("GITHUB").len(), 1);
        assert_eq!(p.search("mail").len(), 1);
        // The record kind is not searched: search only looks at the title,
        // the URL and the record's fields.
        assert_eq!(p.search("Passwords").len(), 0);
        assert_eq!(p.search("nosuchthing").len(), 0);
    }

    #[test]
    fn folder_type_is_detected() {
        assert!(is_attachment_marker(
            "***5642bee8-a5ff-11dc-8314-0800200c9a66***"
        ));
        assert!(!is_attachment_marker("{\"uuid\":\"x\"}"));
        assert!(!is_attachment_marker("***not-hex***"));
    }

    #[test]
    fn kind_is_human_readable() {
        let p = Pif::parse(SAMPLE).unwrap();
        assert_eq!(p.items[0].kind(), "Logins");
        assert_eq!(p.items[2].kind(), "Passwords");
    }

    #[test]
    fn rejects_empty_input() {
        assert!(matches!(Pif::parse("   \n\n"), Err(PifError::Empty)));
    }

    /// A new store opens right away: it holds one folder, which is invisible
    /// in the lists.
    #[test]
    fn new_store_opens_immediately() {
        let root = std::env::temp_dir().join(format!("pif-create-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);

        let created = Pif::create(&root).unwrap();
        assert!(root.join("data.1pif").exists(), "the file should appear");
        assert!(root.join("attachments").is_dir(), "the attachments directory is needed");

        // The folder must not show up for the user.
        assert!(created.alive().is_empty(), "no live records yet");
        assert_eq!(created.items.len(), 1, "one starter folder inside");
        assert_eq!(created.items[0].type_name.as_deref(), Some(FOLDER_TYPE));

        // The point: the file must survive an app restart.
        let reopened = Pif::from_file(root.join("data.1pif")).unwrap();
        assert!(reopened.alive().is_empty());
        assert_eq!(reopened.items.len(), 1);

        let _ = std::fs::remove_dir_all(&root);
    }

    /// A foreign export is not overwritten.
    #[test]
    fn create_does_not_overwrite_an_existing_file() {
        let root = std::env::temp_dir().join(format!("pif-create-exists-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        std::fs::write(root.join("data.1pif"), " precious\n").unwrap();

        let err = Pif::create(&root).unwrap_err();
        assert!(
            matches!(err, PifError::Exists { .. }),
            "we expect a refusal, not an overwrite"
        );
        assert_eq!(
            std::fs::read_to_string(root.join("data.1pif")).unwrap(),
            " precious\n",
            "another file's contents must not change"
        );

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn parses_legacy_single_object() {
        let legacy = r#"{"items":[{"uuid":"Z","typeName":"passwords.Password","title":"old"}]}"#;
        let p = Pif::parse(legacy).unwrap();
        assert_eq!(p.entries().len(), 1);
    }
}
#[cfg(test)]
mod real_export_tests {
    use super::*;

    /// A real `webforms.WebForm` record: it carries several `P` fields,
    /// and the canonical password is tagged `designation`.
    #[test]
    fn webform_prefers_designated_password() {
        let raw = r#"{"uuid":"u1","typeName":"webforms.WebForm","title":"Banggood","locationKey":"banggood.com","secureContents":{"URLs":[{"url":"https://www.banggood.com"}],"fields":[{"name":"password","type":"P","value":"DECOY-FIRST"},{"name":"username","type":"T","value":""},{"name":"email","type":"T","value":"Enter email"},{"name":"email","type":"T","designation":"username","value":"me@example.com"},{"name":"password","type":"P","designation":"password","value":"REAL-SECRET"}]}}"#;
        let p = Pif::parse(raw).unwrap();
        let it = &p.items[0];

        assert_eq!(it.primary_password(), Some("REAL-SECRET"));
        assert_eq!(it.usernames(), vec!["me@example.com"]);
        assert_eq!(it.urls(), vec!["https://www.banggood.com"]);
    }

    /// A real `passwords.Password` record: no fields, the password as a string.
    #[test]
    fn password_item_reads_plain_password_field() {
        let raw = r#"{"uuid":"u2","typeName":"passwords.Password","title":"nocopyrightsounds.co.uk","locationKey":"nocopyrightsounds.co.uk","location":"http://nocopyrightsounds.co.uk/wp-login/","secureContents":{"password":"rg7qqLPhFTjQ"}}"#;
        let p = Pif::parse(raw).unwrap();
        let it = &p.items[0];

        assert_eq!(it.primary_password(), Some("rg7qqLPhFTjQ"));
        assert!(it.usernames().is_empty());
        assert_eq!(it.urls(), vec!["http://nocopyrightsounds.co.uk/wp-login/"]);
    }

    /// An empty record title occurs in dumps — that is normal, not an error.
    #[test]
    fn title_may_be_empty_string() {
        let raw = r#"{"uuid":"u3","typeName":"webforms.WebForm","title":"","secureContents":{}}"#;
        let p = Pif::parse(raw).unwrap();
        assert_eq!(p.items[0].title.as_deref(), Some(""));
    }

    /// A note: the text lives in `notesPlain`.
    #[test]
    fn secure_note_reads_notes_plain() {
        let raw = r#"{"uuid":"u4","typeName":"securenotes.SecureNote","title":"WM","secureContents":{"notesPlain":"transfers to card"}}"#;
        let p = Pif::parse(raw).unwrap();
        assert_eq!(p.items[0].notes(), Some("transfers to card"));
    }

    /// Both the `password` field and `secureContents.password` can be empty,
    /// and then the record simply has no password.
    #[test]
    fn no_password_returns_none() {
        let raw = r#"{"uuid":"u5","typeName":"wallet.computer.License","title":"X","secureContents":{"fields":[{"name":"owner","type":"T","value":"me"}],"password":""}}"#;
        let p = Pif::parse(raw).unwrap();
        assert_eq!(p.items[0].primary_password(), None);
    }
}

#[cfg(test)]
mod wallet_tests {
    use super::*;

    /// A real `wallet.financial.CreditCard` record: none of the data is in `fields`,
    /// it lives in flat keys and is duplicated in the sections.
    const CARD: &str = r#"{"uuid":"C1","typeName":"wallet.financial.CreditCard","title":"Credit card","secureContents":{"cardholder":"Vitalii","ccnum":"5314451117033352","expiry_yy":"2016","expiry_mm":"9","type":"mc","cvv":"712","sections":[{"fields":[{"k":"string","n":"cardholder","v":"Vitalii","t":"Cardholder name"},{"k":"string","n":"A90930AA80B1461EA634F666DACB517C","v":"5314 4511 1703 3352 712","t":"CVV"}],"title":"","name":""}]}}"#;

    #[test]
    fn card_is_read_from_flat_keys() {
        let p = Pif::parse(CARD).unwrap();
        let extras = p.items[0].extra_fields();
        let get = |name: &str| {
            extras
                .iter()
                .find(|(l, _, _)| l == name)
                .map(|(_, v, _)| v.clone())
        };
        assert_eq!(get("Cardholder").as_deref(), Some("Vitalii"));
        assert_eq!(get("Card Number").as_deref(), Some("5314451117033352"));
        assert_eq!(get("Security Code").as_deref(), Some("712"));
        assert_eq!(get("Expiry Year").as_deref(), Some("2016"));
    }

    #[test]
    fn secret_fields_are_flagged() {
        let p = Pif::parse(CARD).unwrap();
        let extras = p.items[0].extra_fields();
        let secret = |name: &str| {
            extras
                .iter()
                .find(|(l, _, _)| l == name)
                .map(|(_, _, s)| *s)
                .unwrap_or(false)
        };
        assert!(secret("Card Number"), "the card number must be masked");
        assert!(secret("Security Code"));
        assert!(secret("Cardholder"));
        assert!(!secret("Expiry Year"));
    }

    #[test]
    fn internal_keys_and_conflicts_are_hidden() {
        let p = Pif::parse(CARD).unwrap();
        let extras = p.items[0].extra_fields();
        // the hash key and _conflict_1 are filtered out, the value did not double
        assert!(!extras.iter().any(|(l, _, _)| l.len() == 32));
        assert!(!extras
            .iter()
            .any(|(_, v, _)| v == "5314 4511 1703 3352 712"));
    }

    /// A real `wallet.onlineservices.Email.v2` record.
    const MAIL: &str = r#"{"uuid":"M1","typeName":"wallet.onlineservices.Email.v2","title":"Mail","secureContents":{"pop_password":"pop-secret","pop_server":"pop.example.com","pop_port":"995","pop_type":"tls","smtp_server":"smtp.example.com","smtp_port":"587","sections":[{"fields":[{"k":"concealed","n":"pop_password","v":"pop-secret","t":"Password","a":{"guarded":"yes"}}],"title":"POP"}]}}"#;

    #[test]
    fn mail_is_read() {
        let p = Pif::parse(MAIL).unwrap();
        let extras = p.items[0].extra_fields();
        let get = |name: &str| {
            extras
                .iter()
                .find(|(l, _, _)| l == name)
                .map(|(_, v, _)| v.clone())
        };
        assert_eq!(get("POP Server").as_deref(), Some("pop.example.com"));
        assert_eq!(get("POP Port").as_deref(), Some("995"));
        assert_eq!(get("POP Password").as_deref(), Some("pop-secret"));
        assert_eq!(get("SMTP Server").as_deref(), Some("smtp.example.com"));
    }

    /// The server login lives in a flat key, with no form fields.
    #[test]
    fn server_yields_its_login_from_a_flat_key() {
        let raw = r#"{"uuid":"S1","typeName":"wallet.computer.UnixServer","title":"Server","secureContents":{"username":"root","password":"toor"}}"#;
        let p = Pif::parse(raw).unwrap();
        assert_eq!(p.items[0].usernames(), vec!["root"]);
        assert_eq!(p.items[0].primary_password(), Some("toor"));
    }

    /// A web form must not grow wallet fields.
    #[test]
    fn web_form_yields_no_extra_fields() {
        let raw = r#"{"uuid":"W1","typeName":"webforms.WebForm","title":"Site","secureContents":{"fields":[{"name":"username","type":"T","designation":"username","value":"me"},{"name":"password","type":"P","designation":"password","value":"pw"}]}}"#;
        let p = Pif::parse(raw).unwrap();
        assert!(p.items[0].extra_fields().is_empty());
    }

    /// `guarded` fields are taken from the sections and count as secret.
    #[test]
    fn field_from_a_section_with_a_label() {
        let raw = r#"{"uuid":"X1","typeName":"wallet.computer.License","title":"License","secureContents":{"sections":[{"fields":[{"k":"concealed","n":"unknown_thing","v":"secret","t":"Product key","a":{"guarded":"yes"}}]}]}}"#;
        let p = Pif::parse(raw).unwrap();
        let extras = p.items[0].extra_fields();
        assert_eq!(extras.len(), 1);
        assert_eq!(extras[0].0, "Product key");
        assert_eq!(extras[0].1, "secret");
        assert!(extras[0].2, "guarded must mean secret");
    }
}

#[cfg(test)]
mod attachment_tests {
    use super::*;

    /// Builds an export in a temp directory: data.1pif + attachments/.
    fn build(
        tag: &str,
        item_uuid: &str,
        att_dir: Option<&str>,
        files: &[(&str, &[u8])],
    ) -> PathBuf {
        // Each test needs its own directory: cargo runs them in parallel
        // inside one process, so the pid is shared.
        let root = std::env::temp_dir().join(format!("opclient-att-{tag}-{item_uuid}"));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        let line = format!(
            "{{\"uuid\":\"{item_uuid}\",\"typeName\":\"securenotes.SecureNote\",\"title\":\"T\",\"secureContents\":{{\"notesPlain\":\"n\"}}}}"
        );
        std::fs::write(root.join("data.1pif"), line).unwrap();
        if let Some(d) = att_dir {
            let dir = root.join("attachments").join(d);
            std::fs::create_dir_all(&dir).unwrap();
            for (name, body) in files {
                std::fs::write(dir.join(name), body).unwrap();
            }
        }
        root.join("data.1pif")
    }

    #[test]
    fn attachments_bind_by_directory_name() {
        let path = build(
            "link",
            "AAAA1111BBBB2222CCCC3333DDDD4444",
            Some("aaaa1111bbbb2222cccc3333dddd4444"),
            &[("IMG_1.JPG", b"jpeg-bytes"), ("doc.pdf", b"pdf-bytes")],
        );
        let pif = Pif::from_file(&path).unwrap();
        let files = pif
            .attachments
            .get("AAAA1111BBBB2222CCCC3333DDDD4444")
            .unwrap();

        assert_eq!(files.len(), 2, "both files should be found");
        assert_eq!(files[0].name, "IMG_1.JPG");
        assert_eq!(files[1].name, "doc.pdf");
        assert_eq!(files[0].size, 10);

        let _ = std::fs::remove_dir_all(path.parent().unwrap());
    }

    #[test]
    fn a_foreign_attachment_directory_is_ignored() {
        let path = build(
            "foreign",
            "AAAA1111BBBB2222CCCC3333DDDD4444",
            Some("NOT-OURS"),
            &[],
        );
        let pif = Pif::from_file(&path).unwrap();
        assert!(pif.attachments.is_empty());
        let _ = std::fs::remove_dir_all(path.parent().unwrap());
    }

    #[test]
    fn without_an_attachment_directory_it_still_reads() {
        let path = build("none", "AAAA1111BBBB2222CCCC3333DDDD4444", None, &[]);
        let pif = Pif::from_file(&path).unwrap();
        assert_eq!(pif.items.len(), 1);
        assert!(pif.attachments.is_empty());
        let _ = std::fs::remove_dir_all(path.parent().unwrap());
    }

    #[test]
    fn a_record_separator_is_not_an_attachment() {
        let text = "{\"uuid\":\"U1\",\"typeName\":\"securenotes.SecureNote\",\"title\":\"A\",\"secureContents\":{}}\n***5642bee8-a5ff-11dc-8314-0800200c9a66***\n";
        let pif = Pif::parse(text).unwrap();
        assert_eq!(pif.record_separators, 1);
        assert!(pif.attachments.is_empty());
    }

    #[test]
    fn size_is_human_readable() {
        assert_eq!(human_size(500), "500 B");
        assert_eq!(human_size(2048), "2 KB");
        assert_eq!(human_size(5 * 1024 * 1024), "5.0 MB");
    }
}

#[cfg(test)]
mod roundtrip_tests {
    use super::*;

    /// A real export, if it sits next to the workspace.
    fn real_export() -> Option<PathBuf> {
        let p = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../../golden")
            .join("1Password 2026-10-13, 03_54 PM (533 items and 2 folders).1pif/data.1pif");
        p.exists().then_some(p)
    }

    fn tmp_copy(src: &Path, tag: &str) -> PathBuf {
        let dst = std::env::temp_dir().join(format!("opclient-rt-{tag}-data.1pif"));
        std::fs::copy(src, &dst).unwrap();
        dst
    }

    /// The main guarantee: reading and immediately writing yields the same file.
    #[test]
    fn read_and_write_match_byte_for_byte() {
        let Some(src) = real_export() else {
            eprintln!("real export not found — check skipped");
            return;
        };
        let before = std::fs::read(&src).unwrap();
        let work = tmp_copy(&src, "identical");

        let mut pif = Pif::from_file(&work).unwrap();
        assert!(!pif.has_changes());
        pif.save(&work).unwrap();

        let after = std::fs::read(&work).unwrap();
        assert_eq!(
            before.len(),
            after.len(),
            "size changed: was {}, became {}",
            before.len(),
            after.len()
        );
        assert_eq!(before, after, "the file changed on read and write");

        let _ = std::fs::remove_file(&work);
    }

    /// Editing one record must not damage the others.
    #[test]
    fn editing_one_record_leaves_the_others_alone() {
        let Some(src) = real_export() else {
            return;
        };
        let work = tmp_copy(&src, "one-edit");

        let mut pif = Pif::from_file(&work).unwrap();
        let untouched: Vec<String> = pif.items.iter().map(|i| i.raw.clone()).collect();

        let target = pif.items[3].uuid.clone();
        pif.items[3].title = Some("CHECK".into());
        pif.touch(&target);
        assert!(pif.has_changes());
        pif.save(&work).unwrap();

        let again = Pif::from_file(&work).unwrap();
        assert_eq!(again.items[3].title.as_deref(), Some("CHECK"));
        let changed: Vec<usize> = (0..again.items.len())
            .filter(|&i| again.items[i].raw != untouched[i])
            .collect();
        assert_eq!(changed, vec![3], "exactly one record should change");
        assert!(!again.has_changes());

        let _ = std::fs::remove_file(&work);
    }

    /// Backups shift along instead of piling up forever.
    #[test]
    fn rotation_keeps_five_copies() {
        let Some(src) = real_export() else {
            return;
        };
        let work = tmp_copy(&src, "rotate");
        let mut pif = Pif::from_file(&work).unwrap();

        for i in 0..(BACKUP_KEEP + 3) {
            pif.items[3].title = Some(format!("edit {i}"));
            pif.touch(&pif.items[3].uuid.clone());
            pif.save(&work).unwrap();
        }

        for n in 1..=BACKUP_KEEP {
            assert!(
                backup_path(&work, n).exists(),
                "the .bak{n} copy should exist"
            );
        }
        assert!(
            !backup_path(&work, BACKUP_KEEP + 1).exists(),
            "there should be no sixth copy"
        );

        let _ = std::fs::remove_file(&work);
        for n in 1..=BACKUP_KEEP + 1 {
            let _ = std::fs::remove_file(backup_path(&work, n));
        }
    }

    /// A backup is the previous state of the file.
    #[test]
    fn backup_holds_the_previous_version() {
        let Some(src) = real_export() else {
            return;
        };
        let work = tmp_copy(&src, "bakvalue");
        let original = std::fs::read(&work).unwrap();

        let mut pif = Pif::from_file(&work).unwrap();
        pif.items[3].title = Some("CHECK".into());
        pif.touch(&pif.items[3].uuid.clone());
        pif.save(&work).unwrap();

        let bak = std::fs::read(backup_path(&work, 1)).unwrap();
        assert_eq!(bak, original, "the backup should hold the original file");

        let _ = std::fs::remove_file(&work);
        let _ = std::fs::remove_file(backup_path(&work, 1));
    }
}

#[cfg(test)]
mod crud_tests {
    use super::*;

    fn draft() -> EntryDraft {
        EntryDraft {
            title: "GitHub".into(),
            username: "me@example.com".into(),
            password: "s3cret-pass".into(),
            url: "https://github.com/login".into(),
            notes: "work account".into(),
            extra_a: String::new(),
            extra_b: String::new(),
        }
    }

    #[test]
    fn a_new_item_reads_back_as_a_login() {
        assert!(Pif::parse("").is_err(), "an empty file must not parse");
        let mut pif = Pif::parse(
            "{\"uuid\":\"U1\",\"typeName\":\"securenotes.SecureNote\",\"title\":\"A\",\"secureContents\":{}}\n",
        )
        .unwrap();

        let uuid = pif.create_login(&draft());
        let it = pif.find(&uuid).unwrap();

        assert_eq!(it.title.as_deref(), Some("GitHub"));
        assert_eq!(it.usernames(), vec!["me@example.com"]);
        assert_eq!(it.primary_password(), Some("s3cret-pass"));
        assert_eq!(it.location.as_deref(), Some("https://github.com/login"));
        assert_eq!(it.location_key.as_deref(), Some("github.com"));
        assert_eq!(it.notes(), Some("work account"));
        assert!(it.dirty);
    }

    #[test]
    fn uuid_is_unique_and_looks_like_the_export() {
        let mut pif = Pif::parse(
            "{\"uuid\":\"U1\",\"typeName\":\"securenotes.SecureNote\",\"title\":\"A\",\"secureContents\":{}}\n",
        )
        .unwrap();
        let a = pif.create_login(&draft());
        let b = pif.create_login(&draft());
        assert_ne!(a, b);
        assert_eq!(a.len(), 32);
        assert!(a
            .chars()
            .all(|c| c.is_ascii_hexdigit() && !c.is_lowercase()));
    }

    #[test]
    fn an_edit_only_changes_its_own() {
        let mut pif = Pif::parse(
            "{\"uuid\":\"U1\",\"typeName\":\"securenotes.SecureNote\",\"title\":\"A\",\"secureContents\":{\"notesPlain\":\"old\"}}\n",
        )
        .unwrap();
        let uuid = pif.create_login(&draft());
        pif.mark_saved();

        let mut d = EntryDraft::from_item(pif.find(&uuid).unwrap());
        d.password = "new-password".into();
        d.apply(pif.find_mut(&uuid).unwrap());
        pif.touch(&uuid);

        let it = pif.find(&uuid).unwrap();
        assert_eq!(it.primary_password(), Some("new-password"));
        assert_eq!(
            it.usernames(),
            vec!["me@example.com"],
            "the login must not get lost"
        );
        // the other record is untouched
        assert_eq!(pif.find("U1").unwrap().notes(), Some("old"));
        // fields do not double up on a repeat edit
        let passes = it
            .secure_contents
            .as_ref()
            .unwrap()
            .fields
            .iter()
            .filter(|f| f.designation.as_deref() == Some("password"))
            .count();
        assert_eq!(passes, 1, "the password field must stay single");
    }

    #[test]
    fn clearing_a_field_removes_it() {
        let mut pif = Pif::parse(
            "{\"uuid\":\"U1\",\"typeName\":\"securenotes.SecureNote\",\"title\":\"A\",\"secureContents\":{}}\n",
        )
        .unwrap();
        let uuid = pif.create_login(&draft());
        let mut d = EntryDraft::from_item(pif.find(&uuid).unwrap());
        d.password = String::new();
        d.notes = String::new();
        d.apply(pif.find_mut(&uuid).unwrap());

        let it = pif.find(&uuid).unwrap();
        assert_eq!(it.primary_password(), None);
        assert_eq!(it.notes(), None);
    }

    #[test]
    fn removal_drops_the_record() {
        let mut pif = Pif::parse(
            "{\"uuid\":\"U1\",\"typeName\":\"securenotes.SecureNote\",\"title\":\"A\",\"secureContents\":{}}\n{\"uuid\":\"U2\",\"typeName\":\"securenotes.SecureNote\",\"title\":\"B\",\"secureContents\":{}}\n",
        )
        .unwrap();
        assert!(pif.remove("U2"));
        assert!(!pif.remove("NO-SUCH"));
        assert_eq!(pif.items.len(), 1);
        assert!(pif.find("U2").is_none());
    }

    /// The full path: create, save to a file, read back, delete.
    #[test]
    fn full_path_through_a_file() {
        let dir = std::env::temp_dir().join(format!("opclient-crud-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let file = dir.join("data.1pif");
        std::fs::write(
            &file,
            "{\"uuid\":\"U1\",\"typeName\":\"securenotes.SecureNote\",\"title\":\"A\",\"secureContents\":{}}\n",
        )
        .unwrap();

        let mut pif = Pif::from_file(&file).unwrap();
        let uuid = pif.create_login(&draft());
        pif.save(&file).unwrap();

        let mut again = Pif::from_file(&file).unwrap();
        assert!(!again.has_changes());
        let it = again
            .find(&uuid)
            .expect("the record must survive a save");
        assert_eq!(it.primary_password(), Some("s3cret-pass"));
        assert_eq!(it.usernames(), vec!["me@example.com"]);

        again.remove(&uuid);
        again.save(&file).unwrap();
        let third = Pif::from_file(&file).unwrap();
        assert!(third.find(&uuid).is_none());
        assert_eq!(third.items.len(), 1);

        // after all the saves the file has not fallen apart
        let text = std::fs::read_to_string(&file).unwrap();
        let lines: Vec<&str> = text.lines().filter(|l| !l.is_empty()).collect();
        assert_eq!(lines.len(), 2, "the record and the separator should remain");
        assert!(lines[1].starts_with("***"));

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn the_host_is_taken_from_the_url() {
        assert_eq!(
            host_of("https://shop.example.com/a?b=1"),
            "shop.example.com"
        );
        assert_eq!(host_of("http://www.example.com:8080/x"), "example.com");
        assert_eq!(host_of("example.org"), "example.org");
    }
}

#[cfg(test)]
mod attachment_delete_tests {
    use super::*;

    /// An export with one image, ready for the delete checks.
    fn export(tag: &str) -> (PathBuf, PathBuf) {
        let root = std::env::temp_dir().join(format!("opclient-del-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        let file = root.join("data.1pif");
        std::fs::write(
            &file,
            "{\"uuid\":\"U1\",\"typeName\":\"securenotes.SecureNote\",\"title\":\"A\",\"secureContents\":{}}\n",
        )
        .unwrap();
        (file, root)
    }

    /// The external image file the user will attach.
    fn source_image(tag: &str) -> PathBuf {
        let p = std::env::temp_dir().join(format!("opclient-src-{tag}.png"));
        std::fs::write(&p, b"\x89PNG\r\n\x1a\n fake image bytes").unwrap();
        p
    }

    #[test]
    fn removing_a_record_carries_its_attachment_away() {
        let (file, root) = export("carry");
        let src = source_image("carry");

        let mut pif = Pif::from_file(&file).unwrap();
        let uuid = pif.create_login(&EntryDraft::default());
        pif.attach(&uuid, &src).unwrap();
        pif.save(&file).unwrap();

        let att_path = pif.attachments_of(&uuid)[0].path.clone();
        assert!(
            att_path.exists(),
            "after the save the file should be in the export"
        );
        let record_gone_after = pif.attachments_of(&uuid).len();
        assert_eq!(record_gone_after, 1);

        // Remove the record and save.
        assert!(pif.remove(&uuid));
        pif.save(&file).unwrap();

        assert!(
            !att_path.exists(),
            "the attachment went with the record — this cannot be undone"
        );

        let _ = std::fs::remove_file(&src);
        let _ = std::fs::remove_dir_all(&root);
    }

    /// Undoing a delete must not touch the disk: the file is removed only
    /// on save, not at the moment of the click.
    #[test]
    fn before_a_save_the_file_is_still_there() {
        let (file, root) = export("pending");
        let src = source_image("pending");

        let mut pif = Pif::from_file(&file).unwrap();
        let uuid = pif.create_login(&EntryDraft::default());
        pif.attach(&uuid, &src).unwrap();
        pif.save(&file).unwrap();
        let att = pif.attachments_of(&uuid)[0].path.clone();

        pif.remove(&uuid);
        assert!(att.exists(), "before the save the file must stay on disk");
        assert!(
            pif.attachments_changed(),
            "the change should be deferred"
        );

        let _ = std::fs::remove_file(&src);
        let _ = std::fs::remove_dir_all(&root);
    }

    /// Detaching one file leaves the others alone.
    #[test]
    fn detach_removes_only_the_chosen_file() {
        let (file, root) = export("one");
        let a = source_image("one-a");
        let b = std::env::temp_dir().join("opclient-src-one-b.txt");
        std::fs::write(&b, b"not an image").unwrap();

        let mut pif = Pif::from_file(&file).unwrap();
        let uuid = pif.create_login(&EntryDraft::default());
        pif.attach(&uuid, &a).unwrap();
        pif.attach(&uuid, &b).unwrap();
        pif.save(&file).unwrap();
        assert_eq!(pif.attachments_of(&uuid).len(), 2);

        let png = pif
            .attachments_of(&uuid)
            .iter()
            .find(|x| x.name.ends_with(".png"))
            .unwrap()
            .path
            .clone();
        let txt = pif
            .attachments_of(&uuid)
            .iter()
            .find(|x| x.name.ends_with(".txt"))
            .unwrap()
            .path
            .clone();

        assert!(pif.detach(&uuid, &png.file_name().unwrap().to_string_lossy()));
        pif.save(&file).unwrap();

        assert!(!png.exists(), "the detached file is deleted");
        assert!(txt.exists(), "the other attachments are untouched");

        let _ = std::fs::remove_file(&a);
        let _ = std::fs::remove_file(&b);
        let _ = std::fs::remove_dir_all(&root);
    }

    /// Identical names do not overwrite each other.
    #[test]
    fn identical_names_do_not_overwrite() {
        let (file, root) = export("dup");
        let a = std::env::temp_dir().join("opclient-dup-1.png");
        let b = std::env::temp_dir().join("opclient-dup-2.png");
        std::fs::write(&a, b"first").unwrap();
        std::fs::write(&b, b"second").unwrap();

        let mut pif = Pif::from_file(&file).unwrap();
        let uuid = pif.create_login(&EntryDraft::default());
        let first = pif.attach(&uuid, &a).unwrap();
        let second = pif.attach(&uuid, &b).unwrap();
        assert_ne!(first.name, second.name, "the names should differ");
        assert_eq!(second.name, "opclient-dup-2.png");
        assert_eq!(first.name, "opclient-dup-1.png");

        let _ = std::fs::remove_file(&a);
        let _ = std::fs::remove_file(&b);
        let _ = std::fs::remove_dir_all(&root);
    }

    fn folder_doc(uuid: &str, title: &str) -> String {
        format!(
            r#"{{"uuid":"{uuid}","typeName":"system.folder.Regular","title":"{title}","secureContents":{{}}}}"#
        )
    }

    fn login_doc(uuid: &str, title: &str, folder: Option<&str>) -> String {
        let folder = match folder {
            Some(f) => format!(r#""folderUuid":"{f}","#),
            None => String::new(),
        };
        format!(
            r#"{{"uuid":"{uuid}","typeName":"webforms.WebForm","title":"{title}",{folder}"secureContents":{{}}}}"#
        )
    }

    fn pif_of(text: &str) -> Pif {
        Pif::parse(text).unwrap()
    }

    /// Folders are visible and their records counted, but they are not in the entry list.
    #[test]
    fn folders_are_separate_from_entries() {
        let pif = pif_of(
            &[
                folder_doc("F1", "Work"),
                login_doc("U1", "GitHub", Some("F1")),
                login_doc("U2", "Forum", None),
            ]
            .join("\n"),
        );

        assert_eq!(pif.folders().len(), 1);
        assert_eq!(pif.folders()[0].title.as_deref(), Some("Work"));

        // No folder should show up in the entry list.
        assert_eq!(pif.alive().len(), 2);
        assert!(pif.alive().iter().all(|i| i.uuid != "F1"));

        assert_eq!(pif.folder_count("F1"), 1, "one record in the folder");
        assert_eq!(pif.folder_count("F2"), 0, "zero for a folder that does not exist");
        assert!(pif.folder("F1").is_some());
        assert!(pif.folder("U1").is_none(), "a record is not a folder");
    }

    /// Creating, renaming and deleting a folder.
    #[test]
    fn a_folder_can_be_created_renamed_and_deleted() {
        let mut pif = pif_of(&login_doc("U1", "GitHub", None));

        let uuid = pif.create_folder("  Work  ");
        assert_eq!(pif.folder(&uuid).unwrap().title.as_deref(), Some("Work"));
        assert!(
            pif.folder(&uuid).unwrap().dirty,
            "a new folder should be rewritten"
        );

        assert!(pif.rename_folder(&uuid, " Office "));
        assert_eq!(pif.folder(&uuid).unwrap().title.as_deref(), Some("Office"));
        assert!(
            !pif.rename_folder("no-such", "x"),
            "no folder, no edit"
        );

        // Deleting a folder must not take its contents with it.
        assert!(pif.set_folder("U1", Some(&uuid)));
        assert!(pif.remove_folder(&uuid));
        assert!(pif.folder(&uuid).is_none());
        assert_eq!(pif.alive().len(), 1, "the record stayed put");
        assert_eq!(pif.find("U1").unwrap().folder_uuid, None, "the link is dropped");
        assert!(!pif.remove_folder(&uuid), "cannot delete twice");
    }

    /// A trashed record does not count towards the folder.
    #[test]
    fn a_trashed_record_is_not_counted_in_the_folder() {
        let pif = pif_of(&[
            folder_doc("F1", "Work"),
            login_doc("U1", "GitHub", Some("F1")),
            r#"{"uuid":"U2","typeName":"webforms.WebForm","title":"Old","trashed":true,"folderUuid":"F1","secureContents":{}}"#.to_string(),
        ]
        .join("\n"));

        assert_eq!(pif.folder_count("F1"), 1, "the trashed one is not counted");
        assert_eq!(pif.trashed().len(), 1);
    }

    /// An empty folder name is replaced by a placeholder, and whitespace is trimmed.
    #[test]
    fn an_empty_folder_name_is_replaced_by_a_placeholder() {
        let mut pif = pif_of(&login_doc("U1", "GitHub", None));
        let uuid = pif.create_folder("   ");
        assert_eq!(
            pif.folder(&uuid).unwrap().title.as_deref(),
            Some("Untitled Folder")
        );
    }

    /// Binding to a nonexistent folder, and to the folder itself, is a no-op.
    #[test]
    fn an_entry_cannot_be_bound_to_a_nonexistent_folder() {
        let mut pif =
            pif_of(&[folder_doc("F1", "Work"), login_doc("U1", "GitHub", None)].join("\n"));

        // The field may be set to any string, and that is not checked:
        // 1Password sorts the records into folders when it opens the file.
        assert!(pif.set_folder("U1", Some("F1")));
        assert_eq!(pif.find("U1").unwrap().folder_uuid.as_deref(), Some("F1"));

        // A folder cannot go into a folder.
        assert!(!pif.set_folder("F1", Some("F1")));
        assert!(!pif.set_folder("no-such", Some("F1")));
    }

    /// Folders survive a save and a reopen of the file.
    #[test]
    fn folders_survive_a_save() {
        let dir = std::env::temp_dir().join(format!("pif-folder-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("data.1pif"), login_doc("U1", "GitHub", None)).unwrap();

        let mut pif = Pif::from_file(dir.join("data.1pif")).unwrap();
        let uuid = pif.create_folder("Work");
        pif.set_folder("U1", Some(&uuid));
        pif.save(dir.join("data.1pif")).unwrap();

        let again = Pif::from_file(dir.join("data.1pif")).unwrap();
        assert_eq!(again.folders().len(), 1);
        assert_eq!(again.folders()[0].title.as_deref(), Some("Work"));
        assert_eq!(again.folder_count(&uuid), 1);
        assert_eq!(
            again.find("U1").unwrap().folder_uuid.as_deref(),
            Some(uuid.as_str())
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    fn draft_of() -> EntryDraft {
        EntryDraft {
            title: "Test".into(),
            username: "user@example.com".into(),
            password: "secret42".into(),
            url: "example.com".into(),
            notes: "note".into(),
            extra_a: "09/2027".into(),
            extra_b: "123".into(),
        }
    }

    fn created(kind: ItemKind) -> PifItem {
        let mut pif = Pif::parse("").unwrap_or_else(|_| {
            // Parsing an empty string fails, so take the stub.
            Pif::parse("{}\n").unwrap()
        });
        let uuid = pif.create_item(&draft_of(), kind);
        pif.find(&uuid).unwrap().clone()
    }

    #[test]
    fn the_item_kind_is_written_to_type_name() {
        for kind in ItemKind::all() {
            let item = created(kind);
            assert_eq!(item.type_name.as_deref(), Some(kind.type_name()));
        }
    }

    #[test]
    fn the_login_is_written_via_designation() {
        let item = created(ItemKind::Login);
        let sc = item.secure_contents.as_ref().unwrap();
        assert!(sc
            .fields
            .iter()
            .any(|f| f.designation.as_deref() == Some("username")));
        assert!(sc
            .fields
            .iter()
            .any(|f| f.designation.as_deref() == Some("password")));
    }

    #[test]
    fn a_note_is_stored_in_the_notes() {
        let item = created(ItemKind::SecureNote);
        assert_eq!(
            item.secure_contents
                .as_ref()
                .unwrap()
                .notes_plain
                .as_deref(),
            Some("note")
        );
        assert!(item.secure_contents.as_ref().unwrap().extra.is_empty());
    }

    #[test]
    fn a_card_writes_number_expiry_and_code() {
        let item = created(ItemKind::CreditCard);
        let extra = &item.secure_contents.as_ref().unwrap().extra;
        assert_eq!(
            extra.get("cardholder"),
            Some(&serde_json::json!("user@example.com"))
        );
        assert_eq!(extra.get("ccnum"), Some(&serde_json::json!("secret42")));
        assert_eq!(extra.get("expiry_mm"), Some(&serde_json::json!("09")));
        // The year expands to four digits: otherwise 27 could be read on
        // import as the year 1927.
        assert_eq!(extra.get("expiry_yy"), Some(&serde_json::json!("2027")));
        assert_eq!(extra.get("cvv"), Some(&serde_json::json!("123")));
    }

    #[test]
    fn mail_writes_smtp_and_pop() {
        let item = created(ItemKind::EmailAccount);
        let extra = &item.secure_contents.as_ref().unwrap().extra;
        assert_eq!(
            extra.get("smtp_server"),
            Some(&serde_json::json!("user@example.com"))
        );
        assert_eq!(
            extra.get("smtp_password"),
            Some(&serde_json::json!("example.com"))
        );
        assert_eq!(extra.get("pop_server"), Some(&serde_json::json!("123")));
    }

    #[test]
    fn the_server_and_the_licence_write_their_own_keys() {
        let server = created(ItemKind::Server);
        let se = &server.secure_contents.as_ref().unwrap().extra;
        assert_eq!(
            se.get("username"),
            Some(&serde_json::json!("user@example.com"))
        );
        assert_eq!(se.get("port"), Some(&serde_json::json!("123")));

        let licence = created(ItemKind::SoftwareLicence);
        let le = &licence.secure_contents.as_ref().unwrap().extra;
        assert_eq!(le.get("reg_code"), Some(&serde_json::json!("secret42")));
        assert_eq!(le.get("product_version"), Some(&serde_json::json!("123")));
    }

    #[test]
    fn the_passport_and_the_identity_write_the_number() {
        let passport = created(ItemKind::Passport);
        assert_eq!(
            passport
                .secure_contents
                .as_ref()
                .unwrap()
                .extra
                .get("number"),
            Some(&serde_json::json!("secret42"))
        );
        let identity = created(ItemKind::Identity);
        assert_eq!(
            identity
                .secure_contents
                .as_ref()
                .unwrap()
                .extra
                .get("issuing_authority"),
            Some(&serde_json::json!("example.com"))
        );
    }

    /// Empty fields never reach the file: a dump has no unfilled field.
    #[test]
    fn empty_fields_are_not_written() {
        let draft = EntryDraft {
            title: "Empty".into(),
            ..draft_of()
        };
        let mut pif = Pif::parse("{}\n").unwrap();
        let uuid = pif.create_item(
            &EntryDraft {
                username: String::new(),
                password: String::new(),
                url: String::new(),
                notes: String::new(),
                extra_a: String::new(),
                extra_b: String::new(),
                ..draft
            },
            ItemKind::CreditCard,
        );
        let item = pif.find(&uuid).unwrap();
        assert!(item.secure_contents.as_ref().unwrap().extra.is_empty());
    }

    #[test]
    fn expiry_parses_from_two_and_four_digit_years() {
        assert_eq!(
            split_expiry("09/2027"),
            ("09".to_string(), "2027".to_string())
        );
        assert_eq!(split_expiry("9/27"), ("9".to_string(), "2027".to_string()));
        assert_eq!(split_expiry(""), (String::new(), String::new()));
        assert_eq!(split_expiry("no slash"), (String::new(), String::new()));
    }

    /// A new record of any type survives a save and a re-read.
    #[test]
    fn records_of_all_kinds_survive_a_save() {
        let dir = std::env::temp_dir().join(format!("pif-kinds-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("data.1pif"), "{}\n").unwrap();

        let mut pif = Pif::from_file(dir.join("data.1pif")).unwrap();
        for kind in ItemKind::all() {
            pif.create_item(&draft_of(), kind);
        }
        pif.save(dir.join("data.1pif")).unwrap();

        let again = Pif::from_file(dir.join("data.1pif")).unwrap();
        for kind in ItemKind::all() {
            let found = again
                .items
                .iter()
                .filter(|i| i.type_name.as_deref() == Some(kind.type_name()));
            assert_eq!(
                found.count(),
                1,
                "a record of kind {kind:?} did not survive the save"
            );
        }

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Every kind has field labels, and none of the empties are pointless.
    #[test]
    fn every_kind_has_field_labels() {
        for kind in ItemKind::all() {
            assert!(!kind.label().is_empty());
            let labels = kind.field_labels();
            assert!(
                labels.iter().any(|l| !l.is_empty()),
                "{kind:?} has no labelled field at all"
            );
            for (slot, label) in labels.iter().enumerate() {
                let trimmed = label.trim();
                assert!(
                    trimmed.is_empty() || trimmed.len() <= 24,
                    "the field label for slot {slot} of {kind:?} is unacceptably long: {trimmed}"
                );
            }
        }
    }
}

#[cfg(test)]
mod tests_common_unique {
    /// A directory unique to each call: tests run in parallel and
    /// share the pid.
    pub fn uniq(tag: &str) -> std::path::PathBuf {
        use std::sync::atomic::{AtomicUsize, Ordering};
        static N: AtomicUsize = AtomicUsize::new(0);
        let n = N.fetch_add(1, Ordering::Relaxed);
        std::env::temp_dir().join(format!("opclient-{tag}-{}-{n}", std::process::id()))
    }
}

#[cfg(test)]
mod trash_tests {
    use super::*;

    /// An export with one record and an external image file.
    fn fixture(tag: &str) -> (PathBuf, PathBuf, PathBuf) {
        let root = tests_common_unique::uniq(tag);
        std::fs::create_dir_all(&root).unwrap();
        let file = root.join("data.1pif");
        std::fs::write(
            &file,
            "{\"uuid\":\"U1\",\"typeName\":\"securenotes.SecureNote\",\"title\":\"A\",\"secureContents\":{}}\n",
        )
        .unwrap();
        let src = std::env::temp_dir().join(format!("{tag}-photo.jpg"));
        std::fs::write(&src, b"\xff\xd8\xff fake jpeg").unwrap();
        (file, root, src)
    }

    /// An old file: a photo taken long ago, down in its mtime.
    fn backdate(path: &Path, days: u64) {
        let f = std::fs::OpenOptions::new().write(true).open(path).unwrap();
        let when = std::time::SystemTime::now() - std::time::Duration::from_secs(days * DAY);
        f.set_times(std::fs::FileTimes::new().set_modified(when))
            .unwrap();
    }

    #[test]
    fn removal_puts_the_file_in_the_trash() {
        let (file, root, src) = fixture("trash-basic");

        let mut pif = Pif::from_file(&file).unwrap();
        let uuid = pif.create_login(&EntryDraft::default());
        pif.attach(&uuid, &src).unwrap();
        pif.save(&file).unwrap();
        let att = pif.attachments_of(&uuid)[0].path.clone();
        assert!(att.exists());

        pif.remove(&uuid);
        pif.save(&file).unwrap();

        assert!(!att.exists(), "the file vanished from the attachments");
        let stats = pif.trash_stats();
        assert_eq!(stats.files, 1, "the file should be in the trash");
        assert!(stats.bytes > 0, "the size should be counted");

        let trashed = pif
            .trash_dir()
            .unwrap()
            .join(&uuid)
            .join("trash-basic-photo.jpg");
        assert!(trashed.exists(), "the trash layout mirrors attachments");

        let _ = std::fs::remove_file(&src);
        let _ = std::fs::remove_dir_all(&root);
    }

    /// An old photo must not fly out of the trash immediately: its
    /// timestamp is reset when it is moved.
    #[test]
    fn an_old_photo_waits_out_its_term() {
        let (file, root, src) = fixture("trash-old");
        backdate(&src, 5 * 365);

        let mut pif = Pif::from_file(&file).unwrap();
        let uuid = pif.create_login(&EntryDraft::default());
        pif.attach(&uuid, &src).unwrap();
        pif.save(&file).unwrap();

        pif.remove(&uuid);
        pif.save(&file).unwrap();

        let stats = pif.trash_stats();
        assert_eq!(stats.files, 1, "a fresh deletion should not vanish at once");
        assert_eq!(pif.purge_trash(), 0, "the cleanup should remove nothing");

        let _ = std::fs::remove_file(&src);
        let _ = std::fs::remove_dir_all(&root);
    }

    /// A file that sat longer than 30 days is removed.
    #[test]
    fn an_expired_file_is_removed_by_the_term() {
        let (file, root, src) = fixture("trash-expiry");

        let mut pif = Pif::from_file(&file).unwrap();
        let uuid = pif.create_login(&EntryDraft::default());
        pif.attach(&uuid, &src).unwrap();
        pif.save(&file).unwrap();
        pif.remove(&uuid);
        pif.save(&file).unwrap();
        assert_eq!(pif.trash_stats().files, 1);

        // Wait out the term.
        let dir = pif.trash_dir().unwrap();
        backdate(
            &dir.join(&uuid).join("trash-expiry-photo.jpg"),
            TRASH_MAX_AGE_DAYS + 1,
        );

        assert_eq!(pif.purge_trash(), 1, "the expired file should vanish");
        assert_eq!(pif.trash_stats().files, 0);

        let _ = std::fs::remove_file(&src);
        let _ = std::fs::remove_dir_all(&root);
    }

    /// A manual purge removes everything at once.
    #[test]
    fn a_manual_purge_removes_everything() {
        let (file, root, src) = fixture("trash-empty");

        let mut pif = Pif::from_file(&file).unwrap();
        let uuid = pif.create_login(&EntryDraft::default());
        pif.attach(&uuid, &src).unwrap();
        pif.save(&file).unwrap();
        pif.remove(&uuid);
        pif.save(&file).unwrap();

        assert_eq!(pif.trash_stats().files, 1);
        assert_eq!(pif.empty_trash(), 1);
        assert_eq!(pif.trash_stats().files, 0);
        assert!(!pif.trash_dir().unwrap().exists());

        let _ = std::fs::remove_file(&src);
        let _ = std::fs::remove_dir_all(&root);
    }

    /// Before a save the trash does not change: "Delete" without "Save"
    /// must not move anything anywhere.
    #[test]
    fn before_a_save_the_trash_is_empty() {
        let (file, root, src) = fixture("trash-lazy");

        let mut pif = Pif::from_file(&file).unwrap();
        let uuid = pif.create_login(&EntryDraft::default());
        pif.attach(&uuid, &src).unwrap();
        pif.save(&file).unwrap();

        pif.remove(&uuid);
        assert_eq!(pif.trash_stats().files, 0, "the move only happens on save");
        assert!(
            pif.attachments_changed(),
            "the change should be deferred"
        );

        let _ = std::fs::remove_file(&src);
        let _ = std::fs::remove_dir_all(&root);
    }

    /// Without a trash nothing breaks: empty stats, purge returns zero.
    #[test]
    fn without_a_trash_all_is_quiet() {
        let stats = TrashStats::default();
        assert_eq!(stats.files, 0);
        assert_eq!(stats.bytes, 0);
        let _ = collect_trash(Path::new("/no/such/path"));
    }
}
