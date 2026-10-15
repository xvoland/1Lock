//! Чтение формата 1PIF — экспорта 1Password с уже расшифрованным содержимым.
//!
//! Формат: JSON Lines, а не единый JSON-объект. Между записями встречаются
//! служебные строки вида `***<uuid>***`, ссылающиеся на вложения.
//! Устаревший формат (1Password 3/4) — это единый JSON-объект с полем
//! `items`; парсер принимает оба варианта.
//!
//! ## Важно о происхождении данных
//!
//! 1PIF получается только через экспорт из 1Password, то есть это снимок,
//! а не живой vault. Приложение на этом формате — это клиент экспорта,
//! а не менеджер, подключённый к хранилищу.
//!
//! ## Приватность
//!
//! Секретные значения (поля типа `P` — пароль, `C` — флажок с секретом,
//! а также `otpauth`) хранятся в памяти в открытом виде, как и в исходном
//! файле. Модуль не логирует их и не пишет на диск.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

/// Тип поля по коду 1Password.
pub const FIELD_PASSWORD: &str = "P";
/// Флажок с секретом (скрытое значение).
pub const FIELD_SECRET_CHECKBOX: &str = "C";

/// Одна запись экспорта.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct PifItem {
    /// Идентификатор записи.
    pub uuid: String,
    /// Тип: `webforms.WebForm`, `passwords.Password`, `securenotes.SecureNote`, …
    #[serde(rename = "typeName")]
    pub type_name: Option<String>,
    /// Заголовок (открытый текст в 1PIF).
    pub title: Option<String>,
    /// Домен без схемы.
    #[serde(rename = "locationKey")]
    pub location_key: Option<String>,
    /// Полный URL.
    pub location: Option<String>,
    /// Содержимое с расшифрованными полями.
    #[serde(rename = "secureContents")]
    pub secure_contents: Option<SecureContents>,
    /// Хеш содержимого (hex, 6–8 символов).
    #[serde(rename = "contentsHash")]
    pub contents_hash: Option<String>,
    /// Уровень защиты: `SL5`.
    #[serde(rename = "securityLevel")]
    pub security_level: Option<String>,
    /// Время создания, Unix.
    #[serde(rename = "createdAt")]
    pub created_at: Option<i64>,
    /// Время изменения, Unix.
    #[serde(rename = "updatedAt")]
    pub updated_at: Option<i64>,
    /// Идентификатор папки.
    #[serde(rename = "folderUuid")]
    pub folder_uuid: Option<String>,
    /// Отметка «в корзине». Удалённая запись сохраняется в экспорте.
    pub trashed: Option<bool>,
    /// Открытое содержимое: например, теги.
    #[serde(rename = "openContents", default)]
    pub open_contents: Option<serde_json::Map<String, serde_json::Value>>,
    /// Метка времени последней операции.
    #[serde(rename = "txTimestamp", default)]
    pub tx_timestamp: Option<i64>,

    /// Исходная строка JSON из файла.
    ///
    /// Сохраняется, чтобы при записи выдать неизменённые записи байт в
    /// байт. Через `PifItem` пройдут не все поля 1PIF — например,
    /// `txTimestamp`, `trashed` и `openContents` — и пересериализация
    /// стерла бы их молча. Сырая строка от этого страхует.
    #[serde(skip)]
    pub raw: String,

    /// Запись меняли: её нужно сериализовать заново.
    #[serde(skip)]
    pub dirty: bool,
}

/// Расшифрованное содержимое записи.
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct SecureContents {
    /// Поля записи. Их используют только веб-формы.
    #[serde(default)]
    pub fields: Vec<PifField>,
    /// Пароль записи одной строкой — так его пишут записи типа
    /// `passwords.Password`. Поле `fields` у них может быть пустым.
    #[serde(default)]
    pub password: Option<String>,
    /// Заметки в открытом виде (если запись их допускает).
    #[serde(rename = "notesPlain")]
    pub notes_plain: Option<String>,
    /// Заметки в base64 (старый формат).
    pub notes: Option<String>,
    /// Список URL.
    #[serde(rename = "URLs", default)]
    pub urls: Vec<PifUrl>,
    /// История паролей.
    #[serde(rename = "passwordHistory", default)]
    pub password_history: Vec<PifHistoryEntry>,
    /// Секции формы: описание вкладок и полей с подписями.
    #[serde(default)]
    pub sections: Vec<PifSection>,
    /// Ключи, специфичные для типа записи.
    ///
    /// Для карт, почты, лицензий и документов данные лежат прямо в
    /// `secureContents` — `ccnum`, `pop_password`, `reg_code` и так далее.
    /// Универсального списка таких ключей нет, поэтому они собираются в
    /// эту карту, а не выписываются в структуру по одному на каждый тип.
    #[serde(flatten)]
    pub extra: std::collections::BTreeMap<String, serde_json::Value>,
}

/// Секция записи — описание одной вкладки.
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct PifSection {
    /// Подпись вкладки.
    pub title: Option<String>,
    /// Внутреннее имя вкладки.
    pub name: Option<String>,
    /// Поля секции.
    #[serde(default)]
    pub fields: Vec<PifSectionField>,
}

/// Поле внутри секции.
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct PifSectionField {
    /// Тип значения: `string`, `concealed`, `monthYear`, …
    pub k: Option<String>,
    /// Внутреннее имя поля.
    pub n: Option<String>,
    /// Значение.
    #[serde(default)]
    pub v: Option<serde_json::Value>,
    /// Подпись поля для интерфейса.
    pub t: Option<String>,
    /// Атрибуты: `guarded`, `clipboardFilter` и прочие.
    #[serde(default)]
    pub a: Option<serde_json::Value>,
}

/// Поле записи.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct PifField {
    /// Тип поля: `T` (текст), `P` (пароль), `C` (секрет), `I` (кнопка), …
    ///
    /// В реальных экспортах ключ иногда отсутствует — потому необязателен.
    #[serde(rename = "type", default)]
    pub field_type: String,
    /// Имя поля.
    #[serde(default)]
    pub name: Option<String>,
    /// Значение. Для `P`/`C` это секрет.
    #[serde(default)]
    pub value: String,
    /// Идентификатор элемента интерфейса.
    #[serde(rename = "designation")]
    pub designation: Option<String>,
    /// Ссылка на секцию.
    pub section: Option<PifSectionRef>,
}

/// Ссылка на секцию.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct PifSectionRef {
    /// Идентификатор секции.
    pub id: Option<String>,
}

/// URL записи.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct PifUrl {
    /// Адрес.
    pub url: Option<String>,
}

/// Запись истории паролей.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct PifHistoryEntry {
    /// Значение (секрет).
    #[serde(default)]
    pub value: String,
    /// Время изменения, Unix.
    pub time: Option<i64>,
}

/// Верхнеуровневый объект старого формата.
#[derive(Debug, Deserialize)]
struct PifDocument {
    #[serde(default)]
    items: Vec<PifItem>,
}

/// Разобранный экспорт.
#[derive(Debug, Clone)]
pub struct Pif {
    /// Все записи, включая папки.
    pub items: Vec<PifItem>,
    /// Число строк-разделителей `***<uuid>***` в файле.
    ///
    /// Это НЕ вложения: во всей выгрузке разделитель один и тот же, он
    /// остался от старого формата и отделяет записи друг от друга.
    /// Сами вложения лежат в каталоге `attachments` рядом с файлом, см.
    /// [`Pif::attachments`].
    pub record_separators: usize,
    /// Вложения по записи: uuid записи → её файлы.
    pub attachments: HashMap<String, Vec<Attachment>>,
    /// Строка-разделитель между записями.
    pub separator: String,
    /// Вложения, уходящие в корзину при следующем сохранении.
    ///
    /// Хранятся вместе с uuid записи: корзина повторяет структуру
    /// `attachments`, чтобы по каталогу было видно, откуда файл.
    pub attachments_to_trash: Vec<(String, PathBuf)>,
    /// Путь к файлу экспорта: нужен, чтобы положить вложение рядом с ним.
    pub source_path: Option<PathBuf>,
}

/// Разделитель, который 1Password пишет в выгрузке.
pub const DEFAULT_SEPARATOR: &str = "***5642bee8-a5ff-11dc-8314-0800200c9a66***";

/// Файл, приложенный к записи.
#[derive(Debug, Clone)]
pub struct Attachment {
    /// Имя файла.
    pub name: String,
    /// Размер в байтах.
    pub size: u64,
    /// Полный путь на диске.
    pub path: PathBuf,
    /// Откуда файл будет скопирован при сохранении.
    ///
    /// `Some` — файл выбран пользователем и ещё не лежит в экспорте.
    /// `None` — файл уже на месте.
    pub pending_source: Option<PathBuf>,
}

impl Attachment {
    /// Есть ли картинка, которую можно показать.
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
    /// Разбирает содержимое файла экспорта.
    ///
    /// Принимает и JSON Lines, и единый JSON-объект с полем `items`.
    /// Служебные строки `***<uuid>***` пропускаются.
    pub fn parse(text: &str) -> Result<Self, PifError> {
        let trimmed = text.trim_start();

        if trimmed.starts_with('{') && !trimmed.starts_with("{\"uuid\"") {
            // единый объект-обёртка
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

    /// Читает файл экспорта и подхватывает вложения из каталога рядом.
    pub fn from_file(path: impl AsRef<Path>) -> Result<Self, PifError> {
        let path = path.as_ref();
        let text = std::fs::read_to_string(path).map_err(|e| PifError::Io {
            path: path.display().to_string(),
            source: e,
        })?;
        let mut parsed = Self::parse(&text)?;
        parsed.attachments = scan_attachments(path, &parsed.items);
        parsed.source_path = Some(path.to_path_buf());
        // Просроченное из корзины убираем сразу при открытии файла.
        parsed.purge_trash();
        Ok(parsed)
    }

    /// Создаёт новое пустое хранилище 1PIF в каталоге `dir`.
    ///
    /// Файл получается не совсем пустым: [`Pif::parse`] считает пустой файл
    /// ошибкой — это защита от открытия не того файла, — поэтому внутрь
    /// кладётся одна запись-папка. Папки не показываются ни в списке, ни в
    /// категориях, но делают файл валидным, иначе созданное хранилище не
    /// открылось бы при следующем запуске.
    ///
    /// `contentsHash` не пишется: как он считается, неизвестно, а выдуманное
    /// значение хуже его отсутствия. Принимает ли 1Password такой файл на
    /// импорте — не проверено.
    ///
    /// Уже существующий `data.1pif` не трогается: возвращается [`PifError::Exists`].
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

    /// Сохраняет изменения в файл.
    ///
    /// Перед записью делается резервная копия: `data.1pif` → `.bak1`, а
    /// прежние копии сдвигаются, так что хранится [`BACKUP_KEEP`] последних
    /// версий. Запись идёт во временный файл с последующим переименованием,
    /// чтобы прерванное сохранение не оставило обрезанный `data.1pif`.
    ///
    /// Неизменённые записи выписываются из [`PifItem::raw`] как есть, поэтому
    /// поля, о которых парсер не знает, переживают сохранение.
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

        // Пишем рядом с целью: временный файл обязан быть на том же томе.
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

    /// Помечает запись изменённой, чтобы при сохранении она переписалась.
    pub fn touch(&mut self, uuid: &str) {
        if let Some(it) = self.items.iter_mut().find(|i| i.uuid == uuid) {
            it.dirty = true;
        }
    }

    /// Есть ли несохранённые изменения.
    pub fn has_changes(&self) -> bool {
        self.items.iter().any(|i| i.dirty)
    }

    /// Снимает отметки об изменениях: файл записан.
    pub fn mark_saved(&mut self) {
        for it in &mut self.items {
            it.dirty = false;
        }
    }

    /// Прикрепляет файл к записи. Ничего не пишет на диск до [`Pif::save`].
    ///
    /// Связь в 1PIF держится только на имени каталога: `attachments/<uuid
    /// записи>/<файл>`. Ссылки в JSON нет, поэтому копирования файла
    /// достаточно — сам `data.1pif` менять не нужно.
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

        // Имя внутри каталога не должно совпадать с уже существующим.
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

    /// Открепляет файл. Файл удаляется с диска только при [`Pif::save`].
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
        // Несуществующий файл удалять незачем, ещё не скопированный — тем более.
        if removed.pending_source.is_none() && removed.path.exists() {
            self.attachments_to_trash
                .push((uuid.to_string(), removed.path));
        }
        true
    }

    /// Вложения записи.
    pub fn attachments_of(&self, uuid: &str) -> &[Attachment] {
        self.attachments.get(uuid).map(Vec::as_slice).unwrap_or(&[])
    }

    /// Есть ли отложенные изменения вложений.
    pub fn attachments_changed(&self) -> bool {
        !self.attachments_to_trash.is_empty()
            || self
                .attachments
                .values()
                .flatten()
                .any(|a| a.pending_source.is_some())
    }

    /// Каталог вложений записи.
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
        // Каталог вложений лежит рядом с файлом экспорта, а не внутри него:
        // `Имя….1pif/attachments/`, а `Имя….1pif/data.1pif/attachments/`
        // — это уже другой путь и он не существует.
        let dir = pif_path
            .parent()
            .map(|p| p.join("attachments"))
            .unwrap_or_else(|| PathBuf::from("attachments"));
        Ok(dir.join(uuid))
    }

    /// Переносит отложенные изменения вложений на диск.
    fn flush_attachments(&mut self) -> Result<(), PifError> {
        let err = |e: std::io::Error, p: &Path| PifError::Io {
            path: p.display().to_string(),
            source: e,
        };

        // Сначала копируем новые файлы: сорвавшись, ничего не теряем.
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

        // И только потом отправляем удаляемое в корзину.
        let trash = self.trash_dir();
        for (uuid, path) in std::mem::take(&mut self.attachments_to_trash) {
            if let Some(dir) = &trash {
                let _ = move_to_trash(dir, &uuid, &path);
            } else {
                // Корзина недоступна: удаляем, но это крайний случай.
                let _ = std::fs::remove_file(&path);
            }
        }
        Ok(())
    }

    /// Создаёт новую запись выбранного типа. Возвращает её uuid.
    ///
    /// Имена полей скопированы из настоящей выгрузки. Блок `sections` не
    /// пишется: в выгрузке он идёт параллельно верхнеуровневым ключам, наш
    /// разбор читает оба, а лишняя структура в созданном файле только
    /// добавила бы мест, где можно ошибиться. Примет ли 1Password такую
    /// запись — не проверено, как и всё остальное, что мы пишем сами.
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

        // Кладёт пару «ключ → значение», пропуская пустые значения: незаполненное
        // поле в выгрузке не встречается.
        let mut put = |key: &str, value: &str| {
            if !value.is_empty() {
                sc.extra.insert(key.to_string(), value.into());
            }
        };

        match kind {
            // Единственный тип с полями `designation`: только у него логин и
            // пароль читаются однозначно.
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
            // Срок действия хранится двумя ключами: месяц и год.
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
                // Ключ `password` у сервера совпадает с типизированным полем
                // SecureContents. Класть его в `extra` нельзя: при сериализации
                // serde выведет оба, и файл станет невалидным.
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
            // У документа личности в выгрузке есть номер и кем выдано;
            // остальное тип не хранит.
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

    /// Создаёт новую запись-логин. Возвращает её uuid.
    ///
    /// Создаётся веб-форма: только у неё в выгрузке есть поля с
    /// `designation`, а значит логин и пароль читаются однозначно.
    ///
    /// Поле `contentsHash` не заполняется — алгоритм этой суммы не
    /// подтверждён, и выдуманное значение было бы ложью. Для работы
    /// приложения оно не нужно, но импорт такого файла обратно в 1Password
    /// может не пройти.
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

    /// Удаляет запись. Возвращает `true`, если запись была.
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

    /// Запись по uuid.
    pub fn find(&self, uuid: &str) -> Option<&PifItem> {
        self.items.iter().find(|i| i.uuid == uuid)
    }

    /// Запись по uuid для правки.
    pub fn find_mut(&mut self, uuid: &str) -> Option<&mut PifItem> {
        self.items.iter_mut().find(|i| i.uuid == uuid)
    }

    /// Папка по uuid.
    pub fn folder(&self, uuid: &str) -> Option<&PifItem> {
        self.items
            .iter()
            .find(|i| i.uuid == uuid && i.type_name.as_deref() == Some(FOLDER_TYPE))
    }

    /// Сколько живых записей лежит в папке.
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

    /// Создаёт папку и возвращает её uuid.
    ///
    /// Как и у записей, `contentsHash` не заполняется: алгоритм суммы не
    /// подтверждён, а выдуманное значение хуже отсутствия.
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

    /// Переименовывает папку. Возвращает `false`, если папки нет.
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

    /// Удаляет папку. Её записи не удаляются: у них просто пропадает ссылка.
    ///
    /// Так же ведёт себя сам 1Password — убрать папку и потерять всё её
    /// содержимое было бы слишком легко потерять данные по неосторожности.
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

    /// Кладёт запись в папку. Пустой `folder` кладёт её на верхний уровень.
    ///
    /// Запись должна существовать; иначе тихо ничего не делается, потому
    /// что возвращать ошибку из обработчика интерфейса незачем.
    pub fn set_folder(&mut self, uuid: &str, folder: Option<&str>) -> bool {
        let Some(item) = self
            .items
            .iter_mut()
            .find(|i| i.uuid == uuid && i.type_name.as_deref() != Some(FOLDER_TYPE))
        else {
            return false;
        };

        // Пустая строка означает «без папки», а не папку с таким uuid.
        let target = folder.filter(|f| !f.is_empty());
        if item.folder_uuid.as_deref() == target {
            return true;
        }

        item.folder_uuid = target.map(str::to_string);
        item.dirty = true;
        true
    }

    /// Записи, исключая папки.
    pub fn entries(&self) -> Vec<&PifItem> {
        self.items
            .iter()
            .filter(|i| i.type_name.as_deref() != Some(FOLDER_TYPE))
            .collect()
    }

    /// Записи в корзине: помечены `trashed: true`.
    pub fn trashed(&self) -> Vec<&PifItem> {
        self.items
            .iter()
            .filter(|i| i.trashed.unwrap_or(false) && i.type_name.as_deref() != Some(FOLDER_TYPE))
            .collect()
    }

    /// Живые записи, без корзины и папок.
    pub fn alive(&self) -> Vec<&PifItem> {
        self.items
            .iter()
            .filter(|i| !i.trashed.unwrap_or(false) && i.type_name.as_deref() != Some(FOLDER_TYPE))
            .collect()
    }

    /// Папки: записи с `typeName: system.folder.Regular`.
    ///
    /// Папка в 1PIF — обычная запись особого типа, и отличие у неё одно:
    /// у прочих записей вместо `folderUuid` стоит ссылка на неё.
    pub fn folders(&self) -> Vec<&PifItem> {
        self.items
            .iter()
            .filter(|i| i.type_name.as_deref() == Some(FOLDER_TYPE))
            .collect()
    }

    /// Ищет по заголовку, домену и URL — без учёта регистра.
    pub fn search(&self, query: &str) -> Vec<&PifItem> {
        let q = query.to_lowercase();
        self.entries()
            .into_iter()
            .filter(|i| i.matches(&q))
            .collect()
    }
}

/// Код типа папки.
pub const FOLDER_TYPE: &str = "system.folder.Regular";

/// Запись, с которой начинается новое хранилище.
///
/// Ровно одна папка: она не мешает пользователю (папки скрыты из списков) и
/// делает файл разбираемым. Поля повторяют настоящий экспорт 1Password;
/// `contentsHash` отсутствует намеренно, см. [`Pif::create`].
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
    /// Поле, безопасное для показа и поиска.
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

    /// Тип записи для показа: человекочитаемое имя.
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

    /// Основной пароль записи.
    ///
    /// В реальных экспортах у веб-форм бывает несколько непустых полей типа
    /// `P` (например, пароль регистрации рядом с паролем входа), поэтому
    /// первое по счёту брать нельзя. Каноническое поле помечено
    /// `designation: "password"`; `secureContents.password` — запасной
    /// источник для записей без `fields`.
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

    /// Логины записи: `username`, `login`, `email` и их варианты.
    ///
    /// Сначала берётся поле с `designation: "username"` — это канонический
    /// логин. Остальные имена используются как запасной вариант, потому что
    /// в выгрузке встречаются и `pass`, и `Имя пользователя`.
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

        // Серверы хранят логин плоским ключом, без полей формы.
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

    /// Адреса из поля `location` и из раздела `URLs`, без повторов.
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
            // Лицензии, документы и почта хранят адреса плоскими ключами.
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

    /// Поле TOTP: значение с префиксом `otpauth://`.
    pub fn totp(&self) -> Option<&str> {
        self.secure_contents.as_ref()?.fields.iter().find_map(|f| {
            if f.value.starts_with("otpauth://") {
                Some(f.value.as_str())
            } else {
                None
            }
        })
    }

    /// Заметки в открытом виде.
    pub fn notes(&self) -> Option<&str> {
        self.secure_contents.as_ref()?.notes_plain.as_deref()
    }

    /// Поля, специфичные для типа записи: номер карты, срок, POP/SMTP,
    /// ключ лицензии, номер документа.
    ///
    /// Только у веб-форм данные лежат в `fields[]`; у карт, почты,
    /// лицензий и документов — плоскими ключами в `secureContents`
    /// плюс дублями в `sections`. Сначала берутся плоские ключи, затем
    /// недостающее добирается из секций по подписи поля.
    ///
    /// Возвращает пары «подпись, значение» и флаг, нужно ли маскировать.
    pub fn extra_fields(&self) -> Vec<(String, String, bool)> {
        let Some(sc) = self.secure_contents.as_ref() else {
            return Vec::new();
        };

        let mut out: Vec<(String, String, bool)> = Vec::new();

        // 1. Плоские ключи — источник правды.
        for (key, raw) in &sc.extra {
            if let Some((label, secret)) = describe_key(key) {
                if let Some(v) = value_to_string(raw) {
                    push_extra(&mut out, label, v, secret);
                }
            }
        }

        // 2. Секции — добираем то, чего нет в плоских ключах.
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

/// Добавляет пару в список, если её там ещё нет.
fn push_extra(out: &mut Vec<(String, String, bool)>, label: &str, value: String, secret: bool) {
    let value = value.trim().to_string();
    if value.is_empty() {
        return;
    }
    // Одна и та же подпись или одно и то же значение дважды не нужны.
    if out
        .iter()
        .any(|(l, existing, _)| l == label || existing == &value)
    {
        return;
    }
    out.push((label.trim().to_string(), value, secret));
}

/// Строковое значение JSON, без копирования.
fn value_as_str(v: &serde_json::Value) -> Option<&str> {
    match v {
        serde_json::Value::String(s) => Some(s.as_str()),
        _ => None,
    }
}

/// Значение JSON в строку, если это вообще значение.
fn value_to_string(v: &serde_json::Value) -> Option<String> {
    match v {
        serde_json::Value::String(s) => Some(s.clone()),
        serde_json::Value::Number(n) => Some(n.to_string()),
        serde_json::Value::Bool(b) => Some(b.to_string()),
        _ => None,
    }
}

/// Поле помечено как секретное.
fn guarded(f: &PifSectionField) -> bool {
    f.a.as_ref()
        .and_then(|a| a.get("guarded"))
        .and_then(|g| g.as_str())
        == Some("yes")
}

/// Служебные имена полей: дубликаты под хешами и варианты конфликта.
///
/// В выгрузке есть поля вида `A90930AA80B1461EA634F666DACB517C` — это тот же
/// проверочный код, сохранённый под внутренним ключом, и
/// `cvv_conflict_1` — вариант, отброшенный при разрешении конфликта.
/// Показывать их пользователю незачем.
fn is_noise_key(name: &str) -> bool {
    if name.ends_with("_conflict_1") {
        return true;
    }
    let hex = name.chars().all(|c| c.is_ascii_hexdigit());
    hex && name.len() == 32
}

/// Подпись и признак секретности для известного ключа.
fn describe_key(key: &str) -> Option<(&'static str, bool)> {
    let (label, secret): (&'static str, bool) = match key {
        // Карта
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
        // Почта
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
        // Лицензия
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
        // Документы
        "issuing_authority" => ("Issued By", false),
        "number" => ("Number", false),
        "issue_date" => ("Issue Date", false),
        "issue_date_dd" => ("Issue Day", false),
        "issue_date_mm" => ("Issue Month", false),
        "issue_date_yy" => ("Issue Year", false),
        "name" => ("Name", false),
        // Общее
        "website" => ("Website", false),
        _ => return None,
    };
    Some((label, secret))
}

/// Черновик записи для редактора.
///
/// Поля повторяют то, что приложение умеет показывать: название, логин,
/// пароль, адрес и заметки. Остальное содержимое записи при правке не
/// трогается — [`EntryDraft::apply`] меняет только перечисленное.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct EntryDraft {
    /// Название.
    pub title: String,
    /// Логин.
    pub username: String,
    /// Пароль.
    pub password: String,
    /// Адрес.
    pub url: String,
    /// Заметки.
    pub notes: String,
    /// Дополнительный слот: смысл зависит от типа записи.
    ///
    /// У карты это срок действия, у сервера — порт, у лицензии — версия.
    /// Отдельные слоты заведены потому, что у карты их два, а назвать их
    /// как-то иначе нельзя: «заметки» уже заняты.
    pub extra_a: String,
    /// Второй дополнительный слот: у карты это проверочный код.
    pub extra_b: String,
}

/// Типы записей, которые приложение умеет создавать.
///
/// Набор и имена полей взяты из настоящей выгрузки 1Password: у всех типов,
/// кроме логина, данные лежат именованными ключами прямо в `secureContents`,
/// а не в списке полей с `designation`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ItemKind {
    /// Логин с паролем.
    Login,
    /// Заметка без учётных данных.
    SecureNote,
    /// Пароль без логина.
    Password,
    /// Банковская карта.
    CreditCard,
    /// Почтовая учётная запись.
    EmailAccount,
    /// Паспорт.
    Passport,
    /// Сервер.
    Server,
    /// Лицензия на программу.
    SoftwareLicence,
    /// Документ, удостоверяющий личность.
    Identity,
}

impl ItemKind {
    /// Значение `typeName` в выгрузке.
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

    /// Подпись типа в интерфейсе.
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

    /// Все типы — так перебираются кнопки выбора в редакторе.
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

    /// Подписи полей формы для этого типа.
    ///
    /// Пять слотов черновика подписаны по-разному в зависимости от типа: в
    /// карте «логин» — это владелец, а в лицензии — ключ. Пустая подпись
    /// означает, что слот этому типу не нужен и поле не рисуется.
    ///
    /// Порядок: слот логина, слот пароля, слот адреса, заметки, второй
    /// дополнительный слот.
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

/// Разбирает «09/2027» или «09/27» на месяц и год, как их пишет 1Password.
///
/// Год сохраняется четырьмя цифрами: в выгрузке он четырёхзначный, и
/// двухзначный год при обратном импорте может быть прочитан как 2027-й или
/// как 1927-й.
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
    /// Собирает черновик из записи.
    pub fn from_item(it: &PifItem) -> Self {
        Self {
            title: it.title.clone().unwrap_or_default(),
            username: it.usernames().first().copied().unwrap_or("").to_string(),
            password: it.primary_password().unwrap_or("").to_string(),
            url: it.urls().first().copied().unwrap_or("").to_string(),
            notes: it.notes().unwrap_or("").to_string(),
            // Дополнительные слоты заполняются при создании записи
            // конкретного типа: для правки они не нужны, потому что поля
            // типа лежат в extra_fields и показываются отдельно.
            extra_a: String::new(),
            extra_b: String::new(),
        }
    }

    /// Вносит значения в запись.
    ///
    /// Поля формы дописываются, если их нет: без `designation` нельзя
    /// отличить настоящий пароль от подставного поля регистрации.
    pub fn apply(&self, it: &mut PifItem) {
        it.title = Some(self.title.trim().to_string());

        let now = unix_now();
        it.updated_at = Some(now);
        it.tx_timestamp = Some(now);

        // Поля
        let sc = it
            .secure_contents
            .get_or_insert_with(SecureContents::default);
        set_designated(&mut sc.fields, "username", "username", "T", &self.username);
        set_designated(&mut sc.fields, "password", "password", "P", &self.password);

        // Адрес и домен
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

        // Заметки
        let notes = self.notes.trim();
        if notes.is_empty() {
            sc.notes_plain = None;
        } else {
            sc.notes_plain = Some(notes.to_string());
        }
    }
}

/// Ставит значение поля с пометкой `designation`.
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

/// Имя узла из адреса: `https://shop.example.com/a` → `shop.example.com`.
fn host_of(url: &str) -> String {
    let rest = url.split_once("://").map(|(_, r)| r).unwrap_or(url);
    rest.split(['/', ':', '?', '#'])
        .next()
        .unwrap_or(rest)
        .trim_start_matches("www.")
        .to_string()
}

/// Текущее время в секундах Unix.
pub fn unix_now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// Новый uuid в формате 1PIF: 32 заглавные hex-символа без дефисов.
pub fn new_uuid() -> String {
    let mut bytes = [0u8; 16];
    // /dev/urandom есть на любой macOS-системе и не тянет зависимостей.
    if let Ok(mut f) = std::fs::File::open("/dev/urandom") {
        use std::io::Read;
        let _ = f.read_exact(&mut bytes);
    }
    bytes.iter().map(|b| format!("{b:02X}")).collect()
}

/// Каталог корзины рядом с экспортом.
pub const TRASH_DIR_NAME: &str = "trash";

/// Сколько дней пролежавшему в корзине файлу можно жить.
///
/// Дальше приложение удаляет его сам. Раньше — нет: пока можно
/// восстановить, пусть лежит.
pub const TRASH_MAX_AGE_DAYS: u64 = 30;

/// Сколько секунд в сутках.
const DAY: u64 = 86_400;

/// Состояние корзины: сколько файлов и сколько места.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct TrashStats {
    /// Число файлов.
    pub files: usize,
    /// Суммарный размер в байтах.
    pub bytes: u64,
}

impl Pif {
    /// Каталог корзины для этого экспорта.
    pub fn trash_dir(&self) -> Option<PathBuf> {
        let pif_path = self.source_path.as_deref()?;
        let base = pif_path.parent()?;
        Some(base.join(TRASH_DIR_NAME))
    }

    /// Что сейчас лежит в корзине.
    pub fn trash_stats(&self) -> TrashStats {
        let Some(dir) = self.trash_dir() else {
            return TrashStats::default();
        };
        collect_trash(&dir)
    }

    /// Удаляет из корзины всё, что пролежало дольше срока.
    ///
    /// Возвращает число удалённых файлов. Ошибки чтения каталога
    /// игнорируются: нет корзины — нечего чистить.
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
            // Пустой каталог записи убираем, чтобы не плодить мусор.
            let _ = std::fs::remove_dir(sub.path());
        }
        removed
    }

    /// Очищает корзину полностью. Возвращает число удалённых файлов.
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

/// Считает содержимое корзины.
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

/// Переносит файл в корзину, сохраняя структуру `корзина/<uuid>/<имя>`.
///
/// Время изменения файла выставляется заново: у фотографии из выгрузки
/// может быть mtime пятилетней давности, и такой файл улетел бы при
/// первой же очистке, не побыв в корзине.
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
            // Файловая система может быть другой: копируем и убираем.
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

/// Имя файла с номером, чтобы не затереть существующий: `photo.jpg` → `photo-1.jpg`.
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

/// Сколько последних версий хранить рядом с файлом.
pub const BACKUP_KEEP: usize = 5;

/// Сдвигает резервные копии и делает новую.
///
/// `data.1pif.bak1` — самая свежая копия, `.bak5` — самая старая из
/// хранимых. Копии, которым за пределами `BACKUP_KEEP` мест, удаляются.
fn rotate_backups(path: &Path) -> Result<(), PifError> {
    let err = |e: std::io::Error, p: &Path| PifError::Io {
        path: p.display().to_string(),
        source: e,
    };

    // Сдвигаем от самой старой к самой свежей, чтобы не затереть.
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

/// Путь к резервной копии: `data.1pif.bak1`.
fn backup_path(path: &Path, n: usize) -> PathBuf {
    let mut s = path.as_os_str().to_os_string();
    s.push(format!(".bak{n}"));
    PathBuf::from(s)
}
///
/// 1Password раскладывает файлы по каталогам, имя каталога — это uuid
/// записи без дефисов. Никакой ссылки на вложение в JSON нет, связь
/// держится только на имени каталога, поэтому искать приходится так.
///
/// Каталоги, не совпавшие ни с одной записью, игнорируются.
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

/// Размер файла для показа: `12 КБ`, `3 МБ`.
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

/// Имя поля считается логином.
///
/// Русские варианты здесь не переводятся вместе с интерфейсом: это имена
/// полей из файла выгрузки, а не надписи приложения.
fn is_username_field(name: &Option<String>) -> bool {
    matches!(
        name.as_deref().unwrap_or("").to_lowercase().as_str(),
        "username" | "login" | "login name" | "email" | "user" | "имя пользователя" | "логин"
    )
}

/// Ошибка разбора экспорта.
#[derive(Debug)]
pub enum PifError {
    /// Ошибка ввода-вывода.
    Io {
        /// Путь к файлу.
        path: String,
        /// Исходная ошибка.
        source: std::io::Error,
    },
    /// Ошибка JSON.
    Json(serde_json::Error),
    /// Ошибка JSON в конкретной строке.
    Line {
        /// Номер строки, начиная с 1.
        lineno: usize,
        /// Исходная ошибка.
        source: serde_json::Error,
    },
    /// В файле не нашлось ни одной записи.
    Empty,
    /// По пути уже лежит экспорт: затирать чужой файл мы не будем.
    Exists {
        /// Путь к файлу.
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

    const SAMPLE: &str = r#"{"uuid":"A1","typeName":"webforms.WebForm","title":"GitHub","locationKey":"github.com","location":"https://github.com","secureContents":{"fields":[{"type":"T","name":"username","value":"me@example.com"},{"type":"P","name":"password","value":"secret123"}],"URLs":[{"url":"https://github.com"}],"notesPlain":"заметка"},"contentsHash":"1234abcd","securityLevel":"SL5"}
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
        assert_eq!(gh.notes(), Some("заметка"));
        assert!(gh.urls().contains(&"https://github.com"));
    }

    #[test]
    fn search_is_case_insensitive() {
        let p = Pif::parse(SAMPLE).unwrap();
        assert_eq!(p.search("github").len(), 1);
        assert_eq!(p.search("GITHUB").len(), 1);
        assert_eq!(p.search("mail").len(), 1);
        // Название вида записи не ищется: search смотрит только на название,
        // адрес и поля записи.
        assert_eq!(p.search("Passwords").len(), 0);
        assert_eq!(p.search("нетакого").len(), 0);
    }

    #[test]
    fn folder_type_is_detected() {
        assert!(is_attachment_marker(
            "***5642bee8-a5ff-11dc-8314-0800200c9a66***"
        ));
        assert!(!is_attachment_marker("{\"uuid\":\"x\"}"));
        assert!(!is_attachment_marker("***не-hex***"));
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

    /// Новое хранилище сразу открывается: в нём лежит одна папка, которая в
    /// списках не видна.
    #[test]
    fn новое_хранилище_сразу_открывается() {
        let root = std::env::temp_dir().join(format!("pif-create-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);

        let created = Pif::create(&root).unwrap();
        assert!(root.join("data.1pif").exists(), "файл должен появиться");
        assert!(root.join("attachments").is_dir(), "каталог вложений нужен");

        // Папка не должна показываться пользователю.
        assert!(created.alive().is_empty(), "живых записей пока нет");
        assert_eq!(created.items.len(), 1, "внутри одна стартовая папка");
        assert_eq!(created.items[0].type_name.as_deref(), Some(FOLDER_TYPE));

        // Главное: файл должен пережить перезапуск приложения.
        let reopened = Pif::from_file(root.join("data.1pif")).unwrap();
        assert!(reopened.alive().is_empty());
        assert_eq!(reopened.items.len(), 1);

        let _ = std::fs::remove_dir_all(&root);
    }

    /// Чужой экспорт не затирается.
    #[test]
    fn создание_не_затирает_существующий_файл() {
        let root = std::env::temp_dir().join(format!("pif-create-exists-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        std::fs::write(root.join("data.1pif"), " precious\n").unwrap();

        let err = Pif::create(&root).unwrap_err();
        assert!(
            matches!(err, PifError::Exists { .. }),
            "ждём отказ, а не затирание"
        );
        assert_eq!(
            std::fs::read_to_string(root.join("data.1pif")).unwrap(),
            " precious\n",
            "содержимое чужого файла не должно меняться"
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

    /// Реальная запись `webforms.WebForm`: в ней несколько полей типа `P`,
    /// и канонический пароль помечен `designation`.
    #[test]
    fn webform_prefers_designated_password() {
        let raw = r#"{"uuid":"u1","typeName":"webforms.WebForm","title":"Banggood","locationKey":"banggood.com","secureContents":{"URLs":[{"url":"https://www.banggood.com"}],"fields":[{"name":"password","type":"P","value":"DECOY-FIRST"},{"name":"username","type":"T","value":""},{"name":"email","type":"T","value":"Enter email"},{"name":"email","type":"T","designation":"username","value":"me@example.com"},{"name":"password","type":"P","designation":"password","value":"REAL-SECRET"}]}}"#;
        let p = Pif::parse(raw).unwrap();
        let it = &p.items[0];

        assert_eq!(it.primary_password(), Some("REAL-SECRET"));
        assert_eq!(it.usernames(), vec!["me@example.com"]);
        assert_eq!(it.urls(), vec!["https://www.banggood.com"]);
    }

    /// Реальная запись `passwords.Password`: поля нет, пароль — строкой.
    #[test]
    fn password_item_reads_plain_password_field() {
        let raw = r#"{"uuid":"u2","typeName":"passwords.Password","title":"nocopyrightsounds.co.uk","locationKey":"nocopyrightsounds.co.uk","location":"http://nocopyrightsounds.co.uk/wp-login/","secureContents":{"password":"rg7qqLPhFTjQ"}}"#;
        let p = Pif::parse(raw).unwrap();
        let it = &p.items[0];

        assert_eq!(it.primary_password(), Some("rg7qqLPhFTjQ"));
        assert!(it.usernames().is_empty());
        assert_eq!(it.urls(), vec!["http://nocopyrightsounds.co.uk/wp-login/"]);
    }

    /// Пустое имя записи в выгрузке встречается — это норма, не ошибка.
    #[test]
    fn title_may_be_empty_string() {
        let raw = r#"{"uuid":"u3","typeName":"webforms.WebForm","title":"","secureContents":{}}"#;
        let p = Pif::parse(raw).unwrap();
        assert_eq!(p.items[0].title.as_deref(), Some(""));
    }

    /// Заметка: текст лежит в `notesPlain`.
    #[test]
    fn secure_note_reads_notes_plain() {
        let raw = r#"{"uuid":"u4","typeName":"securenotes.SecureNote","title":"WM","secureContents":{"notesPlain":"переводы на карту"}}"#;
        let p = Pif::parse(raw).unwrap();
        assert_eq!(p.items[0].notes(), Some("переводы на карту"));
    }

    /// Поле `password` и поле `secureContents.password` могут оба быть
    /// пустыми — тогда пароля у записи нет.
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

    /// Реальная запись `wallet.financial.CreditCard`: данных нет в `fields`,
    /// они лежат плоскими ключами и продублированы в секциях.
    const CARD: &str = r#"{"uuid":"C1","typeName":"wallet.financial.CreditCard","title":"Кредитная карта","secureContents":{"cardholder":"Vitalii","ccnum":"5314451117033352","expiry_yy":"2016","expiry_mm":"9","type":"mc","cvv":"712","sections":[{"fields":[{"k":"string","n":"cardholder","v":"Vitalii","t":"Имя владельца карты"},{"k":"string","n":"A90930AA80B1461EA634F666DACB517C","v":"5314 4511 1703 3352 712","t":"CVV"}],"title":"","name":""}]}}"#;

    #[test]
    fn карта_читается_по_плоским_ключам() {
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
    fn секретные_поля_помечены() {
        let p = Pif::parse(CARD).unwrap();
        let extras = p.items[0].extra_fields();
        let secret = |name: &str| {
            extras
                .iter()
                .find(|(l, _, _)| l == name)
                .map(|(_, _, s)| *s)
                .unwrap_or(false)
        };
        assert!(secret("Card Number"), "номер карты надо маскировать");
        assert!(secret("Security Code"));
        assert!(secret("Cardholder"));
        assert!(!secret("Expiry Year"));
    }

    #[test]
    fn внутренние_ключи_и_конфликты_не_показываются() {
        let p = Pif::parse(CARD).unwrap();
        let extras = p.items[0].extra_fields();
        // хеш-ключ и _conflict_1 отфильтрованы, значение не задвоилось
        assert!(!extras.iter().any(|(l, _, _)| l.len() == 32));
        assert!(!extras
            .iter()
            .any(|(_, v, _)| v == "5314 4511 1703 3352 712"));
    }

    /// Реальная запись `wallet.onlineservices.Email.v2`.
    const MAIL: &str = r#"{"uuid":"M1","typeName":"wallet.onlineservices.Email.v2","title":"Почта","secureContents":{"pop_password":"pop-secret","pop_server":"pop.example.com","pop_port":"995","pop_type":"tls","smtp_server":"smtp.example.com","smtp_port":"587","sections":[{"fields":[{"k":"concealed","n":"pop_password","v":"pop-secret","t":"Пароль","a":{"guarded":"yes"}}],"title":"POP"}]}}"#;

    #[test]
    fn почта_читается() {
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

    /// Логин сервера лежит плоским ключом, полей формы нет.
    #[test]
    fn сервер_отдаёт_логин_из_плоского_ключа() {
        let raw = r#"{"uuid":"S1","typeName":"wallet.computer.UnixServer","title":"Server","secureContents":{"username":"root","password":"toor"}}"#;
        let p = Pif::parse(raw).unwrap();
        assert_eq!(p.items[0].usernames(), vec!["root"]);
        assert_eq!(p.items[0].primary_password(), Some("toor"));
    }

    /// Веб-форма не должна обрастать полями кошелька.
    #[test]
    fn веб_форма_не_даёт_лишних_полей() {
        let raw = r#"{"uuid":"W1","typeName":"webforms.WebForm","title":"Сайт","secureContents":{"fields":[{"name":"username","type":"T","designation":"username","value":"me"},{"name":"password","type":"P","designation":"password","value":"pw"}]}}"#;
        let p = Pif::parse(raw).unwrap();
        assert!(p.items[0].extra_fields().is_empty());
    }

    /// Поля с `guarded` берутся из секций и считаются секретными.
    #[test]
    fn поле_из_секции_с_подписью() {
        let raw = r#"{"uuid":"X1","typeName":"wallet.computer.License","title":"Лицензия","secureContents":{"sections":[{"fields":[{"k":"concealed","n":"unknown_thing","v":"секрет","t":"Ключ продукта","a":{"guarded":"yes"}}]}]}}"#;
        let p = Pif::parse(raw).unwrap();
        let extras = p.items[0].extra_fields();
        assert_eq!(extras.len(), 1);
        assert_eq!(extras[0].0, "Ключ продукта");
        assert_eq!(extras[0].1, "секрет");
        assert!(extras[0].2, "guarded должен означать секрет");
    }
}

#[cfg(test)]
mod attachment_tests {
    use super::*;

    /// Собирает экспорт во временном каталоге: data.1pif + attachments/.
    fn build(
        tag: &str,
        item_uuid: &str,
        att_dir: Option<&str>,
        files: &[(&str, &[u8])],
    ) -> PathBuf {
        // Каталог должен быть свой у каждого теста: cargo запускает их
        // параллельно в одном процессе, pid у всех общий.
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
    fn вложения_привязываются_по_имени_каталога() {
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

        assert_eq!(files.len(), 2, "оба файла должны нашлись");
        assert_eq!(files[0].name, "IMG_1.JPG");
        assert_eq!(files[1].name, "doc.pdf");
        assert_eq!(files[0].size, 10);

        let _ = std::fs::remove_dir_all(path.parent().unwrap());
    }

    #[test]
    fn чужой_каталог_вложений_игнорируется() {
        let path = build(
            "foreign",
            "AAAA1111BBBB2222CCCC3333DDDD4444",
            Some("НЕ-НАШ"),
            &[],
        );
        let pif = Pif::from_file(&path).unwrap();
        assert!(pif.attachments.is_empty());
        let _ = std::fs::remove_dir_all(path.parent().unwrap());
    }

    #[test]
    fn без_каталога_вложений_всё_равно_читается() {
        let path = build("none", "AAAA1111BBBB2222CCCC3333DDDD4444", None, &[]);
        let pif = Pif::from_file(&path).unwrap();
        assert_eq!(pif.items.len(), 1);
        assert!(pif.attachments.is_empty());
        let _ = std::fs::remove_dir_all(path.parent().unwrap());
    }

    #[test]
    fn разделитель_записей_не_считается_вложением() {
        let text = "{\"uuid\":\"U1\",\"typeName\":\"securenotes.SecureNote\",\"title\":\"A\",\"secureContents\":{}}\n***5642bee8-a5ff-11dc-8314-0800200c9a66***\n";
        let pif = Pif::parse(text).unwrap();
        assert_eq!(pif.record_separators, 1);
        assert!(pif.attachments.is_empty());
    }

    #[test]
    fn размер_человекочитаемый() {
        assert_eq!(human_size(500), "500 B");
        assert_eq!(human_size(2048), "2 KB");
        assert_eq!(human_size(5 * 1024 * 1024), "5.0 MB");
    }
}

#[cfg(test)]
mod roundtrip_tests {
    use super::*;

    /// Настоящий экспорт, если он лежит рядом с workspace.
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

    /// Главная гарантия: чтение и немедленная запись дают тот же файл.
    #[test]
    fn чтение_и_запись_совпадают_побайтово() {
        let Some(src) = real_export() else {
            eprintln!("реальный экспорт не найден — проверка пропущена");
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
            "размер изменился: было {}, стало {}",
            before.len(),
            after.len()
        );
        assert_eq!(before, after, "файл изменился при чтении и записи");

        let _ = std::fs::remove_file(&work);
    }

    /// Правка одной записи не должна портить остальные.
    #[test]
    fn правка_одной_записи_не_трогает_остальные() {
        let Some(src) = real_export() else {
            return;
        };
        let work = tmp_copy(&src, "one-edit");

        let mut pif = Pif::from_file(&work).unwrap();
        let untouched: Vec<String> = pif.items.iter().map(|i| i.raw.clone()).collect();

        let target = pif.items[3].uuid.clone();
        pif.items[3].title = Some("ПРОВЕРКА".into());
        pif.touch(&target);
        assert!(pif.has_changes());
        pif.save(&work).unwrap();

        let again = Pif::from_file(&work).unwrap();
        assert_eq!(again.items[3].title.as_deref(), Some("ПРОВЕРКА"));
        let changed: Vec<usize> = (0..again.items.len())
            .filter(|&i| again.items[i].raw != untouched[i])
            .collect();
        assert_eq!(changed, vec![3], "измениться должна ровно одна запись");
        assert!(!again.has_changes());

        let _ = std::fs::remove_file(&work);
    }

    /// Резервные копии сдвигаются и не копятся бесконечно.
    #[test]
    fn ротация_хранит_пять_копий() {
        let Some(src) = real_export() else {
            return;
        };
        let work = tmp_copy(&src, "rotate");
        let mut pif = Pif::from_file(&work).unwrap();

        for i in 0..(BACKUP_KEEP + 3) {
            pif.items[3].title = Some(format!("правка {i}"));
            pif.touch(&pif.items[3].uuid.clone());
            pif.save(&work).unwrap();
        }

        for n in 1..=BACKUP_KEEP {
            assert!(
                backup_path(&work, n).exists(),
                "копия .bak{n} должна существовать"
            );
        }
        assert!(
            !backup_path(&work, BACKUP_KEEP + 1).exists(),
            "шестой копии быть не должно"
        );

        let _ = std::fs::remove_file(&work);
        for n in 1..=BACKUP_KEEP + 1 {
            let _ = std::fs::remove_file(backup_path(&work, n));
        }
    }

    /// Бэкап — это предыдущее состояние файла.
    #[test]
    fn бэкап_хранит_предыдущую_версию() {
        let Some(src) = real_export() else {
            return;
        };
        let work = tmp_copy(&src, "bakvalue");
        let original = std::fs::read(&work).unwrap();

        let mut pif = Pif::from_file(&work).unwrap();
        pif.items[3].title = Some("ПРОВЕРКА".into());
        pif.touch(&pif.items[3].uuid.clone());
        pif.save(&work).unwrap();

        let bak = std::fs::read(backup_path(&work, 1)).unwrap();
        assert_eq!(bak, original, "в бэкапе должен лежать исходный файл");

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
            notes: "рабочий аккаунт".into(),
            extra_a: String::new(),
            extra_b: String::new(),
        }
    }

    #[test]
    fn новая_запись_читается_как_логин() {
        assert!(Pif::parse("").is_err(), "пустой файл не должен разбираться");
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
        assert_eq!(it.notes(), Some("рабочий аккаунт"));
        assert!(it.dirty);
    }

    #[test]
    fn uuid_уникален_и_выглядит_как_в_экспорте() {
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
    fn правка_меняет_только_своё() {
        let mut pif = Pif::parse(
            "{\"uuid\":\"U1\",\"typeName\":\"securenotes.SecureNote\",\"title\":\"A\",\"secureContents\":{\"notesPlain\":\"старое\"}}\n",
        )
        .unwrap();
        let uuid = pif.create_login(&draft());
        pif.mark_saved();

        let mut d = EntryDraft::from_item(pif.find(&uuid).unwrap());
        d.password = "новый-пароль".into();
        d.apply(pif.find_mut(&uuid).unwrap());
        pif.touch(&uuid);

        let it = pif.find(&uuid).unwrap();
        assert_eq!(it.primary_password(), Some("новый-пароль"));
        assert_eq!(
            it.usernames(),
            vec!["me@example.com"],
            "логин не должен слететь"
        );
        // чужая запись не тронута
        assert_eq!(pif.find("U1").unwrap().notes(), Some("старое"));
        // поля не задваиваются при повторной правке
        let passes = it
            .secure_contents
            .as_ref()
            .unwrap()
            .fields
            .iter()
            .filter(|f| f.designation.as_deref() == Some("password"))
            .count();
        assert_eq!(passes, 1, "поле пароля должно остаться одно");
    }

    #[test]
    fn очистка_поля_убирает_его() {
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
    fn удаление_убирает_запись() {
        let mut pif = Pif::parse(
            "{\"uuid\":\"U1\",\"typeName\":\"securenotes.SecureNote\",\"title\":\"A\",\"secureContents\":{}}\n{\"uuid\":\"U2\",\"typeName\":\"securenotes.SecureNote\",\"title\":\"B\",\"secureContents\":{}}\n",
        )
        .unwrap();
        assert!(pif.remove("U2"));
        assert!(!pif.remove("НЕТ-ТАКОЙ"));
        assert_eq!(pif.items.len(), 1);
        assert!(pif.find("U2").is_none());
    }

    /// Полный путь: создать, сохранить в файл, перечитать, удалить.
    #[test]
    fn полный_путь_через_файл() {
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
            .expect("запись должна пережить сохранение");
        assert_eq!(it.primary_password(), Some("s3cret-pass"));
        assert_eq!(it.usernames(), vec!["me@example.com"]);

        again.remove(&uuid);
        again.save(&file).unwrap();
        let third = Pif::from_file(&file).unwrap();
        assert!(third.find(&uuid).is_none());
        assert_eq!(third.items.len(), 1);

        // после всех сохранений файл не разъехался
        let text = std::fs::read_to_string(&file).unwrap();
        let lines: Vec<&str> = text.lines().filter(|l| !l.is_empty()).collect();
        assert_eq!(lines.len(), 2, "должны остаться запись и разделитель");
        assert!(lines[1].starts_with("***"));

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn домен_берётся_из_адреса() {
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

    /// Экспорт с одной картинкой, готовый к проверке удаления.
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

    /// Внешний файл-картинка, который пользователь прикрепит.
    fn source_image(tag: &str) -> PathBuf {
        let p = std::env::temp_dir().join(format!("opclient-src-{tag}.png"));
        std::fs::write(&p, b"\x89PNG\r\n\x1a\n fake image bytes").unwrap();
        p
    }

    #[test]
    fn удаление_записи_уносит_файл_вложения() {
        let (file, root) = export("carry");
        let src = source_image("carry");

        let mut pif = Pif::from_file(&file).unwrap();
        let uuid = pif.create_login(&EntryDraft::default());
        pif.attach(&uuid, &src).unwrap();
        pif.save(&file).unwrap();

        let att_path = pif.attachments_of(&uuid)[0].path.clone();
        assert!(
            att_path.exists(),
            "после сохранения файл должен лежать в экспорте"
        );
        let record_gone_after = pif.attachments_of(&uuid).len();
        assert_eq!(record_gone_after, 1);

        // Удаляем запись и сохраняем.
        assert!(pif.remove(&uuid));
        pif.save(&file).unwrap();

        assert!(
            !att_path.exists(),
            "вложение удалено вместе с записью — отменять это нельзя"
        );

        let _ = std::fs::remove_file(&src);
        let _ = std::fs::remove_dir_all(&root);
    }

    /// Отмена удаления не должна трогать диск: файл удаляется только при
    /// сохранении, а не в момент нажатия.
    #[test]
    fn до_сохранения_файл_на_месте() {
        let (file, root) = export("pending");
        let src = source_image("pending");

        let mut pif = Pif::from_file(&file).unwrap();
        let uuid = pif.create_login(&EntryDraft::default());
        pif.attach(&uuid, &src).unwrap();
        pif.save(&file).unwrap();
        let att = pif.attachments_of(&uuid)[0].path.clone();

        pif.remove(&uuid);
        assert!(att.exists(), "до сохранения файл обязан остаться на диске");
        assert!(
            pif.attachments_changed(),
            "изменение должно быть отложенным"
        );

        let _ = std::fs::remove_file(&src);
        let _ = std::fs::remove_dir_all(&root);
    }

    /// Открепление отдельного файла не трогает остальные.
    #[test]
    fn открепление_удаляет_только_выбранный_файл() {
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

        assert!(!png.exists(), "откреплённый файл удалён");
        assert!(txt.exists(), "остальные вложения не тронуты");

        let _ = std::fs::remove_file(&a);
        let _ = std::fs::remove_file(&b);
        let _ = std::fs::remove_dir_all(&root);
    }

    /// Одинаковые имена не затирают друг друга.
    #[test]
    fn одинаковые_имена_не_затираются() {
        let (file, root) = export("dup");
        let a = std::env::temp_dir().join("opclient-dup-1.png");
        let b = std::env::temp_dir().join("opclient-dup-2.png");
        std::fs::write(&a, b"first").unwrap();
        std::fs::write(&b, b"second").unwrap();

        let mut pif = Pif::from_file(&file).unwrap();
        let uuid = pif.create_login(&EntryDraft::default());
        let first = pif.attach(&uuid, &a).unwrap();
        let second = pif.attach(&uuid, &b).unwrap();
        assert_ne!(first.name, second.name, "имена должны различаться");
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

    /// Папки видны, записи внутри них считаются, но в списке записей их нет.
    #[test]
    fn папки_отделены_от_записей() {
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

        // В общем списке записей папки быть не должно.
        assert_eq!(pif.alive().len(), 2);
        assert!(pif.alive().iter().all(|i| i.uuid != "F1"));

        assert_eq!(pif.folder_count("F1"), 1, "в папке одна запись");
        assert_eq!(pif.folder_count("F2"), 0, "несуществующей папки ноль");
        assert!(pif.folder("F1").is_some());
        assert!(pif.folder("U1").is_none(), "запись не папка");
    }

    /// Создание, переименование и удаление папки.
    #[test]
    fn папку_можно_создать_переименовать_и_удалить() {
        let mut pif = pif_of(&login_doc("U1", "GitHub", None));

        let uuid = pif.create_folder("  Work  ");
        assert_eq!(pif.folder(&uuid).unwrap().title.as_deref(), Some("Work"));
        assert!(
            pif.folder(&uuid).unwrap().dirty,
            "новая папка должна переписываться"
        );

        assert!(pif.rename_folder(&uuid, " Office "));
        assert_eq!(pif.folder(&uuid).unwrap().title.as_deref(), Some("Office"));
        assert!(
            !pif.rename_folder("нет-такой", "x"),
            "нет папки — нет правки"
        );

        // Удаление папки не должно уносить её содержимое.
        assert!(pif.set_folder("U1", Some(&uuid)));
        assert!(pif.remove_folder(&uuid));
        assert!(pif.folder(&uuid).is_none());
        assert_eq!(pif.alive().len(), 1, "запись осталась на месте");
        assert_eq!(pif.find("U1").unwrap().folder_uuid, None, "ссылка снята");
        assert!(!pif.remove_folder(&uuid), "повторно удалить нельзя");
    }

    /// Удалённая запись не попадает в счётчик папки.
    #[test]
    fn удалённая_запись_не_считается_в_папке() {
        let pif = pif_of(&[
            folder_doc("F1", "Work"),
            login_doc("U1", "GitHub", Some("F1")),
            r#"{"uuid":"U2","typeName":"webforms.WebForm","title":"Old","trashed":true,"folderUuid":"F1","secureContents":{}}"#.to_string(),
        ]
        .join("\n"));

        assert_eq!(pif.folder_count("F1"), 1, "удалённая не в счётчике");
        assert_eq!(pif.trashed().len(), 1);
    }

    /// Пустое имя папки заменяется заготовкой, а пробелы срезаются.
    #[test]
    fn пустое_имя_папки_заменяется_заготовкой() {
        let mut pif = pif_of(&login_doc("U1", "GitHub", None));
        let uuid = pif.create_folder("   ");
        assert_eq!(
            pif.folder(&uuid).unwrap().title.as_deref(),
            Some("Untitled Folder")
        );
    }

    /// Привязка к несуществующей папке и к самой папке — вхолостую.
    #[test]
    fn нельзя_привязать_запись_к_несуществующей_папке() {
        let mut pif =
            pif_of(&[folder_doc("F1", "Work"), login_doc("U1", "GitHub", None)].join("\n"));

        // Поле можно поставить в любую строку, это не проверяется: 1Password
        // при открытии сама раздаст записи по папкам.
        assert!(pif.set_folder("U1", Some("F1")));
        assert_eq!(pif.find("U1").unwrap().folder_uuid.as_deref(), Some("F1"));

        // Папку нельзя положить в папку.
        assert!(!pif.set_folder("F1", Some("F1")));
        assert!(!pif.set_folder("нет-такой", Some("F1")));
    }

    /// Папки переживают сохранение и повторное открытие файла.
    #[test]
    fn папки_переживают_сохранение() {
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
            title: "Тест".into(),
            username: "user@example.com".into(),
            password: "secret42".into(),
            url: "example.com".into(),
            notes: "заметка".into(),
            extra_a: "09/2027".into(),
            extra_b: "123".into(),
        }
    }

    fn created(kind: ItemKind) -> PifItem {
        let mut pif = Pif::parse("").unwrap_or_else(|_| {
            // Пустой разбор не проходит, поэтому берём заготовку.
            Pif::parse("{}\n").unwrap()
        });
        let uuid = pif.create_item(&draft_of(), kind);
        pif.find(&uuid).unwrap().clone()
    }

    #[test]
    fn тип_записи_пишется_в_type_name() {
        for kind in ItemKind::all() {
            let item = created(kind);
            assert_eq!(item.type_name.as_deref(), Some(kind.type_name()));
        }
    }

    #[test]
    fn логин_пишется_через_designation() {
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
    fn заметка_хранится_в_заметках() {
        let item = created(ItemKind::SecureNote);
        assert_eq!(
            item.secure_contents
                .as_ref()
                .unwrap()
                .notes_plain
                .as_deref(),
            Some("заметка")
        );
        assert!(item.secure_contents.as_ref().unwrap().extra.is_empty());
    }

    #[test]
    fn карта_пишет_номер_срок_и_код() {
        let item = created(ItemKind::CreditCard);
        let extra = &item.secure_contents.as_ref().unwrap().extra;
        assert_eq!(
            extra.get("cardholder"),
            Some(&serde_json::json!("user@example.com"))
        );
        assert_eq!(extra.get("ccnum"), Some(&serde_json::json!("secret42")));
        assert_eq!(extra.get("expiry_mm"), Some(&serde_json::json!("09")));
        // Год разворачивается в четыре цифры: иначе при импорте 27 может
        // прочитаться как 1927-й год.
        assert_eq!(extra.get("expiry_yy"), Some(&serde_json::json!("2027")));
        assert_eq!(extra.get("cvv"), Some(&serde_json::json!("123")));
    }

    #[test]
    fn почта_пишет_smtp_и_pop() {
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
    fn сервер_и_лицензия_пишут_свои_ключи() {
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
    fn паспорт_и_документ_пишут_номер() {
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

    /// Пустые поля в файл не попадают: незаполненного поля в выгрузке нет.
    #[test]
    fn пустые_поля_не_пишутся() {
        let draft = EntryDraft {
            title: "Пусто".into(),
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
    fn срок_разбирается_из_двух_и_четырёх_значного_года() {
        assert_eq!(
            split_expiry("09/2027"),
            ("09".to_string(), "2027".to_string())
        );
        assert_eq!(split_expiry("9/27"), ("9".to_string(), "2027".to_string()));
        assert_eq!(split_expiry(""), (String::new(), String::new()));
        assert_eq!(split_expiry("нет слеша"), (String::new(), String::new()));
    }

    /// Новая запись любого типа переживает сохранение и повторное чтение.
    #[test]
    fn записи_всех_типов_переживают_сохранение() {
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
                "запись типа {kind:?} не пережила сохранение"
            );
        }

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// У каждого типа подписи полей есть, и пустых среди них нет лишних.
    #[test]
    fn подписи_полей_у_каждого_типа() {
        for kind in ItemKind::all() {
            assert!(!kind.label().is_empty());
            let labels = kind.field_labels();
            assert!(
                labels.iter().any(|l| !l.is_empty()),
                "у {kind:?} не подписано ни одного поля"
            );
            for (slot, label) in labels.iter().enumerate() {
                let trimmed = label.trim();
                assert!(
                    trimmed.is_empty() || trimmed.len() <= 24,
                    "подпись поля слота {slot} у {kind:?} неуместно длинная: {trimmed}"
                );
            }
        }
    }
}

#[cfg(test)]
mod tests_common_unique {
    /// Каталог, уникальный для каждого вызова: тесты идут параллельно,
    /// а pid у них общий.
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

    /// Экспорт с одной записью и внешним файлом-картинкой.
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

    /// Старый файл: давно снятая фотография в mtime.
    fn backdate(path: &Path, days: u64) {
        let f = std::fs::OpenOptions::new().write(true).open(path).unwrap();
        let when = std::time::SystemTime::now() - std::time::Duration::from_secs(days * DAY);
        f.set_times(std::fs::FileTimes::new().set_modified(when))
            .unwrap();
    }

    #[test]
    fn удаление_кладёт_файл_в_корзину() {
        let (file, root, src) = fixture("trash-basic");

        let mut pif = Pif::from_file(&file).unwrap();
        let uuid = pif.create_login(&EntryDraft::default());
        pif.attach(&uuid, &src).unwrap();
        pif.save(&file).unwrap();
        let att = pif.attachments_of(&uuid)[0].path.clone();
        assert!(att.exists());

        pif.remove(&uuid);
        pif.save(&file).unwrap();

        assert!(!att.exists(), "файл исчез из вложений");
        let stats = pif.trash_stats();
        assert_eq!(stats.files, 1, "файл должен лежать в корзине");
        assert!(stats.bytes > 0, "размер должен считаться");

        let trashed = pif
            .trash_dir()
            .unwrap()
            .join(&uuid)
            .join("trash-basic-photo.jpg");
        assert!(trashed.exists(), "структура корзины повторяет attachments");

        let _ = std::fs::remove_file(&src);
        let _ = std::fs::remove_dir_all(&root);
    }

    /// Старая фотография не должна улететь из корзины сразу: её время
    /// выставляется заново при переносе.
    #[test]
    fn старая_фотография_ждёт_свое_срока() {
        let (file, root, src) = fixture("trash-old");
        backdate(&src, 5 * 365);

        let mut pif = Pif::from_file(&file).unwrap();
        let uuid = pif.create_login(&EntryDraft::default());
        pif.attach(&uuid, &src).unwrap();
        pif.save(&file).unwrap();

        pif.remove(&uuid);
        pif.save(&file).unwrap();

        let stats = pif.trash_stats();
        assert_eq!(stats.files, 1, "свежее удаление не должно исчезнуть сразу");
        assert_eq!(pif.purge_trash(), 0, "очистка не должна ничего убрать");

        let _ = std::fs::remove_file(&src);
        let _ = std::fs::remove_dir_all(&root);
    }

    /// Файл, пролежавший дольше 30 дней, убирается.
    #[test]
    fn просроченное_удаляется_по_сроку() {
        let (file, root, src) = fixture("trash-expiry");

        let mut pif = Pif::from_file(&file).unwrap();
        let uuid = pif.create_login(&EntryDraft::default());
        pif.attach(&uuid, &src).unwrap();
        pif.save(&file).unwrap();
        pif.remove(&uuid);
        pif.save(&file).unwrap();
        assert_eq!(pif.trash_stats().files, 1);

        // Ждём своего часа.
        let dir = pif.trash_dir().unwrap();
        backdate(
            &dir.join(&uuid).join("trash-expiry-photo.jpg"),
            TRASH_MAX_AGE_DAYS + 1,
        );

        assert_eq!(pif.purge_trash(), 1, "просроченный файл должен исчезнуть");
        assert_eq!(pif.trash_stats().files, 0);

        let _ = std::fs::remove_file(&src);
        let _ = std::fs::remove_dir_all(&root);
    }

    /// Ручная очистка убирает всё и сразу.
    #[test]
    fn ручная_очистка_убирает_всё() {
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

    /// До сохранения корзина не меняется: нажатие «Удалить» без «Сохранить»
    /// не должно никуда ничего двигать.
    #[test]
    fn до_сохранения_корзина_пуста() {
        let (file, root, src) = fixture("trash-lazy");

        let mut pif = Pif::from_file(&file).unwrap();
        let uuid = pif.create_login(&EntryDraft::default());
        pif.attach(&uuid, &src).unwrap();
        pif.save(&file).unwrap();

        pif.remove(&uuid);
        assert_eq!(pif.trash_stats().files, 0, "перенос только при сохранении");
        assert!(
            pif.attachments_changed(),
            "изменение должно быть отложенным"
        );

        let _ = std::fs::remove_file(&src);
        let _ = std::fs::remove_dir_all(&root);
    }

    /// Без корзины ничего не ломается: статистика пустая, очистка — ноль.
    #[test]
    fn без_корзины_всё_тихо() {
        let stats = TrashStats::default();
        assert_eq!(stats.files, 0);
        assert_eq!(stats.bytes, 0);
        let _ = collect_trash(Path::new("/нет/такого/пути"));
    }
}
