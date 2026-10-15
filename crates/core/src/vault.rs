//! Чтение базы `.1p4` — строго read-only.
//!
//! ## Гарантия неизменности исходных данных
//!
//! База открывается флагми `SQLITE_OPEN_READ_ONLY` без `SQLITE_OPEN_CREATE`.
//! Дополнительно делается побайтовая копия SHA-256, которую можно сверить
//! до и после чтения — см�� [`Vault::fingerprint`] и проверку в тестах.
//!
//! ## Подтверждённая структура
//!
//! Получено осмотром `OnePassword.sqlite` из бэкапа `.1p4`:
//!
//! | Таблица            | Содержимое                                       |
//! |--------------------|--------------------------------------------------|
//! | `profiles`         | 15 колонок, `iterations`, `salt`, `master_key_data`, `overview_key_data` |
//! | `items`            | 17 колонок, `uuid`, `key_data`(112 B), `overview_data` |
//! | `item_details`     | `data` — зашифрованное тело элемента              |
//! | `folders`          | зашифрованные обзорные данные                     |
//! | `categories`       | UUID и шифрованные обзорные данные                |
//!
//! Все содержательные поля зашифрованы: `items.title` пуст у всех 541 записей,
//! колонок `username`/`location_key` в таблице нет.

use rusqlite::{Connection, OpenFlags};
use serde::Serialize;
use sha2::{Digest, Sha256};

use crate::envelope::{parse_field, Envelope, Header, KEY_LEN};
use crate::error::{Error, Result};

/// Хранилище с метаданными профиля.
#[derive(Debug, Clone)]
pub struct Profile {
    /// Идентификатор строки.
    pub id: i64,
    /// UUID профиля.
    pub uuid: String,
    /// Имя профиля.
    pub profile_name: String,
    /// Число итераций PBKDF2.
    pub iterations: i64,
    /// Соль из профиля (16 байт).
    ///
    /// ВНИМАНИЕ: не подтверждено, что это соль для `master_key_data`.
    /// По коду соль берётся из `encryptedSymmetricKey`, которого нет в бэкапе.
    pub salt: Vec<u8>,
    /// Блок мастер-ключа с заголовком `opdata01`.
    pub master_key_data: Vec<u8>,
    /// Блок обзорного ключа.
    pub overview_key_data: Vec<u8>,
    /// Подсказка к паролю (если задана).
    pub password_hint: Option<String>,
}

/// Папка.
#[derive(Debug, Clone)]
pub struct Folder {
    /// UUID папки.
    pub uuid: String,
    /// Зашифрованные обзорные данные.
    pub overview_data: Vec<u8>,
}

/// Элемент хранилища.
#[derive(Debug, Clone)]
pub struct Item {
    /// UUID элемента.
    pub uuid: String,
    /// UUID категории.
    pub category_uuid: Option<String>,
    /// UUID папки.
    pub folder_uuid: Option<String>,
    /// Зашифрованное тело — 112 байт, схема `IV‖CT‖HMAC`.
    pub key_data: Vec<u8>,
    /// Зашифрованные обзорные данные.
    pub overview_data: Vec<u8>,
    /// Признак удаления.
    pub trashed: i64,
    /// Unix-время создания.
    pub created_at: i64,
    /// Unix-время обновления.
    pub updated_at: i64,
}

/// Категория.
///
/// В отличие от папок, `categories` хранит часть данных открытым текстом
/// в колонке `json` — это подтверждено `PRAGMA table_info(categories)`.
/// Само описание полей внутри `json` зашифровано.
#[derive(Debug, Clone)]
pub struct Category {
    /// UUID категории.
    pub uuid: String,
    /// Имя в единственном числе, открытый текст.
    pub singular_name: String,
    /// Имя во множественном числе, открытый текст.
    pub plural_name: String,
    /// JSON-описание полей (частично открытая, частично зашифрованная).
    pub json: String,
}

/// Сводка по базе — то, что можно показать без расшифровки.
#[derive(Debug, Serialize)]
pub struct VaultSummary {
    /// UUID профиля.
    pub profile_uuid: String,
    /// Имя профиля.
    pub profile_name: String,
    /// Число итераций PBKDF2.
    pub iterations: i64,
    /// Соль профиля в hex.
    pub salt_hex: String,
    /// SHA-256 базы.
    pub db_sha256: String,
    /// Количество элементов.
    pub item_count: usize,
    /// Количество папок.
    pub folder_count: usize,
    /// Количество категорий.
    pub category_count: usize,
    /// Размер `master_key_data`.
    pub master_key_data_len: usize,
    /// Все ли `key_data` имеют ожидаемые 112 байт.
    pub key_data_uniform: bool,
}

/// Открытая база `.1p4`.
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
    /// Открывает базу **только на чтение**.
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

    /// Путь к базе.
    pub fn path(&self) -> &std::path::Path {
        &self.path
    }

    /// SHA-256 файла базы — для проверки, что чтение её не изменило.
    pub fn fingerprint(&self) -> Result<String> {
        let bytes = std::fs::read(&self.path)?;
        Ok(hex(&Sha256::digest(&bytes)))
    }

    /// Профиль.
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

    /// Все папки.
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

    /// Все категории.
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

    /// Все элементы.
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

    /// Сводка без расшифровки.
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

    /// Диагностика блока `master_key_data`: заголовок и геометрия блоба.
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

    /// Диагностика `key_data` одного элемента.
    ///
    /// Эти блобы идут **без** заголовка `opdata01` — это чистые
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

    /// Проверка всех `key_data` одним ключом — возвращает число сошедшихся HMAC.
    ///
    /// Основа для проверки восстановленного KDF: правильный ключ обязан
    /// дать `total`, иначе где-то ошибка.
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

/// Ожидаемая длина `key_data`: IV(16) + CT(64) + HMAC(32).
pub const IV_CT_HMAC_LEN: usize = 112;

/// Диагностика `master_key_data`.
#[derive(Debug)]
pub struct MasterKeyReport {
    /// 8 байт после магии — тип записи, смысл не установлен.
    pub header_tag: [u8; 8],
    /// Полный размер поля.
    pub total_len: usize,
    /// Геометрия вложенного блоба, если он достаточно велик.
    pub envelope: Option<crate::envelope::EnvelopeReport>,
}

/// Диагностика `key_data`.
#[derive(Debug)]
pub struct KeyDataReport {
    /// UUID элемента.
    pub uuid: String,
    /// Геометрия блоба.
    pub report: crate::envelope::EnvelopeReport,
}

/// Результат массовой проверки HMAC.
#[derive(Debug, Clone, Copy)]
pub struct MacScan {
    /// Всего элементов.
    pub total: usize,
    /// Успешно разобрано как `IV‖CT‖HMAC`.
    pub parsed: usize,
    /// Сошедшихся HMAC.
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

/// Признак: поле начинается с магии `opdata01`.
pub fn is_opdata(bytes: &[u8]) -> bool {
    Header::parse(bytes).map(|h| h.has_magic()).unwrap_or(false)
}
