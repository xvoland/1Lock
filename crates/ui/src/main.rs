//! Клиент экспорта 1Password — интерфейс на iced.
//!
//! Источник данных — файл экспорта 1PIF, то есть снимок vault на момент
//! экспорта. Приложение работает **только на чтение** и ничего не пишет
//! в исходные данные.
//!
//! # Что показывает
//!
//! - список записей с поиском по названию, домену и URL;
//! - фильтр по типу записи;
//! - детали: заголовок, тип, логины, пароль, URL, заметки;
//! - копирование логина, пароля и URL в буфер обмена;
//! - TOTP-код с обратным отсчётом, если в записи есть `otpauth://`.
//!
//! # Открытие файла
//!
//! Путь можно задать аргументом командной строки. Если аргумента нет,
//! берётся путь из прошлого запуска. Файл выбирается кнопкой «Открыть…»
//! и запоминается, поэтому в следующий раз приложение откроет его само.
//!
//! # Приватность
//!
//! Пароль по умолчанию замаскирован. Раскрыть его можно явно, отдельной
//! кнопкой. Приложение ничего не логирует и не пишет на диск.

mod config;
mod icons;
mod menu;

use std::collections::HashMap;
use std::path::PathBuf;
use std::time::{Duration, Instant};

use iced::keyboard;
use iced::keyboard::key;
use iced::widget::operation::{focus_next, focus_previous};
use iced::widget::text_editor;
use iced::{Center, Color, Element, Length, Padding, Subscription, Task, Theme};

use opclient_core::pif::{EntryDraft, Pif, PifItem, TrashStats, FOLDER_TYPE};
use opclient_core::totp::{now_unix, Totp};

fn main() -> iced::Result {
    // Аргумент важнее запомненного пути: так можно открыть другой файл,
    // не залезая в настройки.
    let from_arg = std::env::args().nth(1).map(PathBuf::from);

    // Канал событий меню: до старта iced, иначе подписка его не увидит.
    menu::init();

    let app = iced::application(move || App::new(from_arg.clone()), App::update, App::view)
        .title(|_: &App| String::from(APP_TITLE))
        .theme(|_: &App| Theme::Dark)
        .subscription(App::subscription)
        .window_size((1150.0, 740.0));

    // SF Pro просим явно. По умолчанию iced берёт «безымянный sans-serif»,
    // а в системе это семейство не выставлено под своим именем: `atsutil`
    // показывает только Display-варианты и внутренние PostScript-имена.
    // Поэтому надёжнее прочитать сам системный шрифт.
    match system_font() {
        Some(bytes) => app.font(bytes).run(),
        None => app.run(),
    }
}

/// Системный шрифт macOS (SF Pro) для интерфейса.
///
/// Если файла нет — приложение всё равно запускается, просто остаётся со
/// шрифтом по умолчанию: это не повод отказываться в запуске.
fn system_font() -> Option<Vec<u8>> {
    std::fs::read("/System/Library/Fonts/SFNS.ttf").ok()
}

struct App {
    /// `None` — файл ещё не выбран.
    vault: Option<Pif>,
    /// Путь к открытому файлу.
    path: Option<PathBuf>,
    /// Что пошло не так при открытии.
    error: Option<String>,
    /// Индексы в `vault.items`, проходящие фильтр и поиск.
    entries: Vec<usize>,
    query_input: String,
    query: String,
    kind_filter: String,
    selected: Option<usize>,
    /// uuid -> раскрыт ли пароль.
    revealed: HashMap<String, bool>,
    /// Ширина панели списка в логических точках.
    list_width: f32,
    /// Идёт ли сейчас перетаскивание границы панели списка.
    resizing: bool,
    /// Наведён ли указатель на границу: без этого признака нажатие мыши
    /// в любом месте окна начинало бы перетаскивание.
    hover_resize: bool,
    /// Ширина окна в логических точках. Нужна, чтобы у третьей панели
    /// тоже был минимум: окно знает только про ширину списка.
    window_w: f32,
    /// Позиция указателя в момент, когда его последний раз двигали при
    /// перетаскивании. Нужна, чтобы считать смещение, а не абсолютную
    /// координату: иначе панель прыгала бы к курсору.
    resize_anchor: Option<f32>,
    toast: Option<(String, Instant)>,
    /// Открыт ли редактор.
    editing: Option<Editing>,
    /// Показывать корзину вместо обычных записей.
    show_trash: bool,
    /// Показывать отчёт аудита вместо деталей записи.
    show_audit: bool,
    /// Папка, ожидающая подтверждения удаления.
    ask_delete_folder: Option<String>,
    /// Текст поля ввода новой папки или её нового названия.
    folder_draft: String,
    /// Папка, к которой относится черновик. `None` — создаётся новая.
    folder_draft_for: Option<String>,
    /// Активная папка: пустая строка — «все записи без фильтра по папкам».
    ///
    /// Отдельное поле, а не часть `kind_filter`: категория и папка — разные
    /// вещи, и их можно применять вместе.
    folder_filter: String,
    /// Что сейчас лежит в корзине вложений.
    trash: TrashStats,
    /// Очистка корзины требует второго нажатия: очистка необратима.
    trash_armed: bool,
    /// Сколько файлов было удалено при последней очистке — для сообщения.
    trash_just_cleared: usize,
    /// Имя вложения, ожидающего подтверждения открепления: первое нажатие
    /// вооружает кнопку, второе — открепляет. Файл уезжает в корзину только
    /// при сохранении, но само открепление необратимо для черновика.
    detach_armed: Option<String>,
    /// Вложение, развёрнутое на большое превью.
    preview: Option<PathBuf>,
}

/// Версия приложения: последний тег git, иначе версия пакета.
///
/// Значение задаёт `crates/ui/build.rs` на этапе сборки. Держать версию
/// константой here было ошибкой: её забывали поднимать, и панель «О
/// приложении» показывала 1.0.0 при тегах до v1.5.0.
const APP_VERSION: &str = env!("OPCLIENT_VERSION");

/// Автор приложения.
const APP_AUTHOR: &str = "Vitalii Tereshchuk";

/// Сайт автора.
const APP_URL: &str = "https://dotoca.net";

/// Описание для панели «О приложении».
const APP_COMMENTS: &str =
    "Read and edit a 1Password export (1PIF).\nPasswords are stored in the export in plain text.";

/// Строка копирайта.
const APP_COPYRIGHT: &str = "© 2026 Vitalii Tereshchuk";

/// Лицензия.
const APP_LICENSE: &str =
    "Personal project, no warranty. Passwords in the export are not encrypted.";

/// Название приложения в заголовке окна.
const APP_TITLE: &str = "1Lock";

/// Иконка приложения для заголовка окна.
///
/// Копия `assets/app-icon.png` уменьшенная до 128 px и лежит внутри
/// репозитория: оригинал на 2048 px весит 3,5 МБ и лежит рядом с проектом,
/// а вшивать его в бинарник незачем — в заголовке значок рисуется в 26 px.
const APP_ICON: &[u8] = include_bytes!("../../../assets/app-icon.png");

/// Готовая картинка для заголовка окна.
///
/// `Handle` собирается один раз и дальше только клонируется. Если создавать
/// его прямо в `view`, то на каждом кадре получается новый handle: iced
/// опознаёт картинку по хешу содержимого, считает её новой и грузит заново —
/// значок в заголовке начинает мигать.
/// Высота полосы тулбара. Её набирают значки кнопок и иконка приложения,
/// а поле поиска имеет собственный размер и выравнивается по середине.
const TOOLBAR_H: f32 = 64.0;

/// Иконка приложения держит всю высоту полосы: отступ по вертикали у неё
/// нулевой, иначе рядом с ней остаётся пустое поле.
const APP_ICON_SIZE: f32 = TOOLBAR_H;

/// Ширина панели списка по умолчанию, и за неё же цепляется минимум и
/// максимум: за границами список перестаёт быть списком.
const LIST_WIDTH_DEFAULT: f32 = 340.0;
const LIST_WIDTH_MIN: f32 = 220.0;
const LIST_WIDTH_MAX: f32 = 720.0;

/// Минимальная ширина правой панели. Без неё список можно растянуть до
/// окна и закрыть всё, ради чего он и растягивается.
const PANEL3_MIN: f32 = 320.0;

/// Ширина боковой панели: она не двигается, и из неё считается всё
/// остальное. Совпадает с шириной во `view_sidebar`.
const SIDEBAR_W: f32 = 212.0;

/// Ширина полосы, за которую цепляется указатель. Уже самой линии в один
/// пиксель: иначе её почти невозможно ухватить.
const RESIZE_HANDLE_W: f32 = 6.0;

/// Ширина кнопки тулбара. Задана явно, чтобы все три были одного размера,
/// а не по ширине нарисованного значка.
const TOOLBAR_BTN_W: f32 = 44.0;

/// Размер значков на кнопках тулбара.
const ICON_BUTTON_SIZE: f32 = 28.0;

/// Кегль текста в поле поиска. От него зависит его высота: iced считает её
/// как `кегль * 1.3 + 2 * отступ`, поэтому отступ приходится считать самому.
const SEARCH_SIZE: f32 = 13.0;

/// Отступ поля поиска. Во всю высоту полосы тянется не поле, а значки
/// кнопок: поле остаётся обычного размера и только выравнивается по
/// середине полосы.
const SEARCH_PADDING: f32 = 5.0;

/// Размер значков у кнопок в списке и у полей: они мельче заголовка.
const ICON_FIELD_SIZE: f32 = 13.0;

fn app_icon_handle() -> iced::widget::image::Handle {
    static HANDLE: std::sync::OnceLock<iced::widget::image::Handle> = std::sync::OnceLock::new();
    HANDLE
        .get_or_init(|| iced::widget::image::Handle::from_bytes(APP_ICON.to_vec()))
        .clone()
}

/// Состояние формы редактирования.
struct Editing {
    /// uuid правимой записи; `None` — создаётся новая.
    uuid: Option<String>,
    /// Документ многострочного поля «Заметки».
    ///
    /// Текст живёт здесь, а не в строке: иначе при каждом нажатии клавиши
    /// пришлось бы пересоздавать весь редактор и терять позицию курсора.
    notes_doc: text_editor::Content,
    draft: EntryDraft,
    title: String,
    username: String,
    password: String,
    url: String,
    notes: String,
    /// Ждём подтверждения удаления.
    confirm_delete: bool,
    /// Папка, в которую положить запись; `None` — верхний уровень.
    folder: Option<String>,
    /// Тип новой записи. У существующей записи он берётся из `typeName`.
    kind: opclient_core::pif::ItemKind,
    /// Второй дополнительный слот: срок и код у карты, порт у сервера.
    extra_b: String,
}

#[derive(Clone)]
enum Message {
    /// Нажата кнопка «Открыть…».
    PickFile,
    /// Создать новое пустое хранилище 1PIF в выбранном каталоге.
    CreateVault,
    /// Открыть файл вложения в Finder или программе по умолчанию.
    OpenAttachment(PathBuf),
    /// Начать редактирование выбранной записи.
    StartEdit,
    /// Создать новую запись.
    StartCreate,
    /// Поле формы изменилось.
    DraftChanged(&'static str, String),
    /// Применить правку.
    ApplyEdit,
    /// Закрыть редактор без сохранения.
    CancelEdit,
    /// Удалить запись.
    DeleteItem,
    /// Подтвердить удаление или отменить его.
    ConfirmDelete(bool),
    /// Действие многострочного редактора заметок.
    EditNotes(text_editor::Action),
    /// Перевести фокус на следующее или предыдущее поле.
    MoveFocus(bool),
    /// Записать изменения в файл.
    SaveFile,
    /// Показать или скрыть корзину удалённых записей.
    /// Показать живые записи или корзину из боковой панели.
    ShowTrash(bool),
    /// Открыть или закрыть отчёт аудита.
    ToggleAudit,
    /// Переключить показ корзины.
    ToggleTrash,
    /// Показать записи папки; пустая строка — снять фильтр по папкам.
    PickFolder(String),
    /// Папка, ожидающая подтверждения удаления.
    AskDeleteFolder(String),
    /// Текст поля ввода папки.
    FolderDraftChanged(String),
    /// Выбрать папку записи в редакторе.
    DraftFolder(Option<String>),
    /// Выбрать тип новой записи.
    DraftKind(opclient_core::pif::ItemKind),
    /// Создать папку из черновика или переименовать ею активную.
    SubmitFolderDraft,
    /// Очистить корзину вложений целиком.
    EmptyTrash,
    /// Снять запрос на очистку.
    CancelEmptyTrash,
    /// Выбрать файлы и прикрепить их к текущей записи.
    AttachFile,
    /// Открепить вложение по имени; второе нажатие подтверждает.
    DetachAttachment(String),
    /// Снять запрос на открепление.
    CancelDetach,
    /// Развернуть или свернуть большое превью вложения-картинки.
    TogglePreview(PathBuf),
    /// Начали перетаскивать границу панели списка.
    ResizeStart,
    /// Указатель вошёл на границу или сошёл с неё.
    HoverResize(bool),
    /// Нажата левая кнопка мыши в любом месте окна.
    GlobalPress,
    /// Отпущена левая кнопка мыши в любом месте окна.
    GlobalRelease,
    /// Окно изменило размер.
    WindowResized(f32),
    /// Извлечь и закрыть открытое хранилище.
    EjectVault,
    /// Указатель сместился при перетаскивании; значение — координата X.
    ResizeMove(f32),
    SearchChanged(String),
    Filter(String),
    Select(usize),
    Copy(String, String),
    ToggleReveal(String),
    DismissToast,
    Tick(Instant),
}

impl Editing {
    /// Форма для новой записи.
    fn create() -> Self {
        Self::edit(String::new(), EntryDraft::default())
    }

    /// Форма для правки существующей записи.
    fn edit(uuid: String, draft: EntryDraft) -> Self {
        Self {
            folder: None,
            kind: opclient_core::pif::ItemKind::Login,
            extra_b: String::new(),
            notes_doc: text_editor::Content::with_text(&draft.notes),
            uuid: if uuid.is_empty() { None } else { Some(uuid) },
            title: draft.title.clone(),
            username: draft.username.clone(),
            password: draft.password.clone(),
            url: draft.url.clone(),
            notes: draft.notes.clone(),
            draft,
            confirm_delete: false,
        }
    }
}

impl App {
    fn new(from_arg: Option<PathBuf>) -> Self {
        let mut app = Self::blank();

        // Аргумент важнее запомненного пути.
        if let Some(p) = from_arg.or_else(config::last_path) {
            app.open(p);
        }

        app
    }

    /// Состояние без файла. Отделено от `new`, чтобы не зависеть от
    /// сохранённого на машине пути.
    fn blank() -> Self {
        Self {
            vault: None,
            path: None,
            error: None,
            entries: Vec::new(),
            query_input: String::new(),
            query: String::new(),
            kind_filter: String::new(),
            selected: None,
            revealed: HashMap::new(),
            list_width: LIST_WIDTH_DEFAULT,
            resizing: false,
            hover_resize: false,
            window_w: 0.0,
            resize_anchor: None,
            toast: None,
            editing: None,
            show_trash: false,
            show_audit: false,
            folder_filter: String::new(),
            ask_delete_folder: None,
            folder_draft: String::new(),
            folder_draft_for: None,
            trash: TrashStats::default(),
            trash_armed: false,
            trash_just_cleared: 0,
            detach_armed: None,
            preview: None,
        }
    }

    /// Открывает файл экспорта. Возвращает, удалось ли.
    fn open(&mut self, chosen: PathBuf) -> bool {
        let path = config::resolve_export(&chosen);

        match Pif::from_file(&path) {
            Ok(vault) => {
                self.trash = vault.trash_stats();
                self.vault = Some(vault);
                self.path = Some(path.clone());
                self.error = None;
                self.selected = None;
                self.revealed.clear();
                self.editing = None;
                self.preview = None;
                self.detach_armed = None;
                self.kind_filter.clear();
                self.query.clear();
                self.query_input.clear();
                self.refilter();
                config::remember(&path);
                true
            }
            Err(e) => {
                self.error = Some(format!("Cannot open {}\n{e}", path.display()));
                false
            }
        }
    }

    fn update(&mut self, msg: Message) -> Task<Message> {
        // Строка меню ставится здесь, а не в `main`: winit при старте цикла
        // событий ставит своё стандартное меню поверх. Первый `update`
        // вызывается уже после этого и на главном потоке, где muda и
        // требует работать. Повторные вызовы `install` ничего не делают.
        menu::install();

        match msg {
            Message::PickFile => {
                // Диалог вызывается прямо здесь: `update` выполняется в
                // главном потоке, а NSOpenPanel требует именно его.
                let chosen = rfd::FileDialog::new()
                    .set_title("Open 1Password export file")
                    .add_filter("1Password Export", &["1pif"])
                    .pick_file();
                if let Some(p) = chosen {
                    self.open(p);
                }
            }
            Message::CreateVault => {
                // Каталог, а не файл: рядом с data.1pif живёт attachments/.
                let Some(dir) = rfd::FileDialog::new()
                    .set_title("New vault: choose a folder")
                    .pick_folder()
                else {
                    return Task::none();
                };

                match Pif::create(&dir) {
                    Ok(vault) => {
                        self.error = None;
                        self.open_created(&dir, vault);
                        self.toast = Some((
                            format!("created in {}", short_path(&dir.join("data.1pif"))),
                            Instant::now(),
                        ));
                    }
                    Err(e) => {
                        self.error = Some(format!("Cannot create vault\n{e}"));
                    }
                }
            }
            Message::OpenAttachment(path) => {
                let ok = open_in_finder(&path);
                self.toast = Some((
                    if ok {
                        "attachment opened".to_string()
                    } else {
                        "cannot open the attachment".to_string()
                    },
                    Instant::now(),
                ));
            }
            Message::AttachFile => {
                self.detach_armed = None;

                let Some(uuid) = self.attachment_target() else {
                    self.toast = Some((
                        "save the item before attaching files".to_string(),
                        Instant::now(),
                    ));
                    return Task::none();
                };

                // Как и `PickFile`, диалог открывается прямо в `update`:
                // NSOpenPanel требует главного потока.
                let picked = rfd::FileDialog::new()
                    .set_title("Attach files to item")
                    .pick_files();
                let Some(files) = picked else {
                    return Task::none();
                };

                let (added, failed) = self.attach_paths(&uuid, &files);
                self.toast = Some((attach_toast(added, &failed), Instant::now()));
            }
            Message::DetachAttachment(name) => {
                let Some(uuid) = self.attachment_target() else {
                    return Task::none();
                };

                if self.detach_armed.as_deref() != Some(name.as_str()) {
                    self.detach_armed = Some(name);
                    return Task::none();
                }

                self.detach_armed = None;
                let ok = self.vault.as_mut().is_some_and(|v| v.detach(&uuid, &name));
                self.toast = Some((
                    if ok {
                        "file detached, remember to save".to_string()
                    } else {
                        "cannot detach the file".to_string()
                    },
                    Instant::now(),
                ));
            }
            Message::CancelDetach => {
                self.detach_armed = None;
            }
            Message::TogglePreview(path) => {
                // Повтор по тому же файлу сворачивает превью.
                self.preview = if self.preview.as_ref() == Some(&path) {
                    None
                } else {
                    Some(path)
                };
            }
            Message::ResizeStart | Message::GlobalPress => {
                // Нажатие мыши имеет смысл только над границей: иначе
                // перетаскивание начиналось бы в любом месте окна.
                if matches!(msg, Message::GlobalPress) && !self.hover_resize {
                    return Task::none();
                }
                self.resizing = true;
                // Якорь ставится по первому же смещению: в момент нажатия
                // указатель ещё не прислал координату.
                self.resize_anchor = None;
            }
            Message::EjectVault => {
                // Хранилище отпускается целиком: несохранённые правки
                // хранятся в памяти, и без этого они потерялись бы молча
                // вместе с файлом.
                if self.has_changes() {
                    self.error =
                        Some("Unsaved changes. Save the file before ejecting.".to_string());
                    return Task::none();
                }
                self.vault = None;
                self.path = None;
                self.entries.clear();
                self.selected = None;
                self.editing = None;
                self.preview = None;
                self.detach_armed = None;
                self.kind_filter.clear();
                self.folder_filter.clear();
                self.query.clear();
                self.query_input.clear();
                self.trash = TrashStats::default();
                self.trash_armed = false;
                self.revealed.clear();
                config::forget();
            }
            Message::HoverResize(inside) => {
                self.hover_resize = inside;
            }
            Message::GlobalRelease => {
                self.resizing = false;
                self.resize_anchor = None;
            }
            Message::WindowResized(width) => {
                self.window_w = width;
                self.clamp_list_width();
            }
            Message::ResizeMove(x) => {
                if self.resizing {
                    self.list_width = match self.resize_anchor {
                        None => {
                            self.resize_anchor = Some(x);
                            self.list_width
                        }
                        Some(anchor) => {
                            let next = self.list_width + (x - anchor);
                            self.resize_anchor = Some(x);
                            next
                        }
                    };
                    self.clamp_list_width();
                }
            }
            Message::DraftKind(kind) => {
                // Тип меняется только у новой записи: у существующей он
                // привязан к структуре, которая уже записана в файл.
                if let Some(e) = self.editing.as_mut() {
                    if e.uuid.is_none() {
                        e.kind = kind;
                    }
                }
            }
            Message::DraftFolder(folder) => {
                if let Some(e) = self.editing.as_mut() {
                    e.folder = folder;
                }
            }
            Message::StartEdit => {
                if let Some(it) = self.selected_item() {
                    let d = EntryDraft::from_item(it);
                    let mut editing = Editing::edit(it.uuid.clone(), d);
                    editing.folder = it.folder_uuid.clone();
                    editing.kind = item_kind_of(&it.type_name);
                    self.editing = Some(editing);
                }
            }
            Message::StartCreate => {
                self.editing = Some(Editing::create());
            }
            Message::DraftChanged(field, value) => {
                if let Some(e) = self.editing.as_mut() {
                    match field {
                        "title" => {
                            e.title = value.clone();
                            e.draft.title = value;
                        }
                        "username" => {
                            e.username = value.clone();
                            e.draft.username = value;
                        }
                        "password" => {
                            e.password = value.clone();
                            e.draft.password = value;
                        }
                        "url" => {
                            e.url = value.clone();
                            e.draft.url = value;
                        }
                        // Слоты типа: срок и код у карты, порт у сервера.
                        "extra_a" => e.draft.extra_a = value,
                        "extra_b" => {
                            e.extra_b = value.clone();
                            e.draft.extra_b = value;
                        }
                        _ => {
                            e.notes = value.clone();
                            e.draft.notes = value;
                        }
                    }
                }
            }
            Message::ApplyEdit => self.apply_edit(),
            Message::CancelEdit => {
                self.editing = None;
            }
            Message::DeleteItem => match self.editing.as_mut() {
                // Форма уже открыта — просто спрашиваем прямо в ней.
                Some(e) => e.confirm_delete = true,
                // Форма не открыта: открываем её на выбранной записи и
                // сразу показываем вопрос. Иначе кнопка «Удалить» вне
                // редактора молча ничего не делала.
                None => {
                    if let Some(uuid) = self.selected_item().map(|i| i.uuid.clone()) {
                        if let Some(it) = self.vault.as_ref().and_then(|v| v.find(&uuid)) {
                            let draft = EntryDraft::from_item(it);
                            let mut e = Editing::edit(uuid, draft);
                            e.confirm_delete = true;
                            self.editing = Some(e);
                        }
                    }
                }
            },
            Message::ConfirmDelete(yes) => {
                if yes {
                    // Подтверждение: удаляем запись, которую правили, иначе
                    // выбранную. В форме они совпадают, но полагаться на
                    // это нельзя — выделение могло уехать.
                    let target = self
                        .editing
                        .as_ref()
                        .and_then(|e| e.uuid.clone())
                        .or_else(|| self.selected_item().map(|i| i.uuid.clone()));
                    if let Some(uuid) = target {
                        self.delete_uuid(&uuid);
                    }
                } else if let Some(e) = self.editing.as_mut() {
                    // Просто убираем вопрос, ничего не удаляем.
                    e.confirm_delete = false;
                }
            }
            Message::EditNotes(action) => {
                if let Some(e) = self.editing.as_mut() {
                    e.notes_doc.perform(action);
                    let text = e.notes_doc.text();
                    e.notes = text.clone();
                    e.draft.notes = text;
                }
            }
            Message::MoveFocus(forward) => {
                // Готовые задачи перевода фокуса на следующее/предыдущее
                // поле из дерева виджетов.
                return if forward {
                    focus_next()
                } else {
                    focus_previous()
                };
            }
            Message::SaveFile => self.save_file(),
            Message::ShowTrash(yes) => {
                self.trash_armed = false;
                self.preview = None;
                self.detach_armed = None;
                // Корзина и категории — взаимоисключающие разделы: в корзине
                // показываются удалённые записи всех видов сразу.
                self.kind_filter.clear();
                self.show_trash = yes;
                self.refilter();
            }
            Message::EmptyTrash => {
                if self.trash.files == 0 {
                    self.toast = Some(("The attachment trash is empty".into(), Instant::now()));
                    self.trash_armed = false;
                    return Task::none();
                }
                if self.trash_armed {
                    // Второе нажатие — очищаем по-настоящему.
                    let was = self.trash.files;
                    if let Some(vault) = self.vault.as_ref() {
                        vault.empty_trash();
                    }
                    self.trash_just_cleared = was;
                    self.trash = TrashStats::default();
                    self.trash_armed = false;
                    self.toast = Some((
                        format!(
                            "Attachment trash cleared: {} removed",
                            plural_files(self.trash_just_cleared)
                        ),
                        Instant::now(),
                    ));
                    self.trash_just_cleared = 0;
                } else {
                    // Первое — только спрашиваем.
                    self.trash_armed = true;
                    self.toast = Some((
                        format!(
                            "Permanently delete {} attachments? Click again",
                            plural_files(self.trash.files)
                        ),
                        Instant::now(),
                    ));
                }
            }
            Message::CancelEmptyTrash => {
                self.trash_armed = false;
            }
            Message::SearchChanged(v) => {
                self.query_input = v.clone();
                self.query = v;
                self.refilter();
            }
            Message::Filter(kind) => {
                self.ask_delete_folder = None;
                // Повторный щелчок по активной категории снимает фильтр:
                // иначе из неё некуда выйти, кроме как в «Все элементы».
                // Логика живёт здесь, а не в панели, чтобы работала откуда
                // угодно, а не только из одного места.
                let same = !kind.is_empty() && kind == self.kind_filter;
                self.kind_filter = if same { String::new() } else { kind };
                if !self.kind_filter.is_empty() {
                    self.show_trash = false;
                }
                self.refilter();
            }
            Message::FolderDraftChanged(value) => {
                self.folder_draft = value;
            }
            Message::SubmitFolderDraft => {
                let title = self.folder_draft.trim().to_string();
                if title.is_empty() {
                    self.toast = Some(("Give the folder a name".into(), Instant::now()));
                    return Task::none();
                }

                match self.folder_draft_for.clone() {
                    // Переименование активной папки.
                    Some(uuid) => {
                        let ok = self
                            .vault
                            .as_mut()
                            .is_some_and(|v| v.rename_folder(&uuid, &title));
                        if ok {
                            self.toast =
                                Some(("Folder renamed, remember to save".into(), Instant::now()));
                        }
                    }
                    // Новая папка: сразу включаем фильтр на неё.
                    None => {
                        let Some(vault) = self.vault.as_mut() else {
                            return Task::none();
                        };
                        let uuid = vault.create_folder(&title);
                        self.folder_filter = uuid;
                        self.folder_draft_for = None;
                        self.toast =
                            Some(("Folder created, remember to save".into(), Instant::now()));
                    }
                }
                self.folder_draft.clear();
                self.refilter();
            }
            Message::PickFolder(uuid) => {
                // Повторный щелчок по активной папке снимает фильтр.
                self.folder_filter = if self.folder_filter == uuid {
                    String::new()
                } else {
                    uuid.clone()
                };
                // Корзина показывает удалённое независимо от папок.
                self.show_trash = false;
                // Поле ввода сразу показывает название выбранной папки: иначе
                // переименование пришлось бы вводить заново вслепую.
                let title = self
                    .vault
                    .as_ref()
                    .and_then(|v| v.folder(&uuid))
                    .and_then(|f| f.title.clone())
                    .unwrap_or_default();
                self.folder_draft = title;
                self.folder_draft_for = if self.folder_filter.is_empty() {
                    None
                } else {
                    Some(uuid)
                };
                self.refilter();
            }
            Message::AskDeleteFolder(uuid) => {
                // Второе нажатие подтверждает: содержимое папки останется, но
                // пропадёт из неё, и отменить это нельзя без правок вручную.
                if self.ask_delete_folder.as_deref() == Some(uuid.as_str()) {
                    let removed = self.vault.as_mut().is_some_and(|v| v.remove_folder(&uuid));
                    self.ask_delete_folder = None;
                    if self.folder_filter == uuid {
                        self.folder_filter.clear();
                    }
                    self.refilter();
                    self.toast = Some((
                        if removed {
                            "Folder deleted, remember to save".to_string()
                        } else {
                            "Folder not found".to_string()
                        },
                        Instant::now(),
                    ));
                } else {
                    self.ask_delete_folder = Some(uuid);
                }
            }
            Message::ToggleTrash => {
                self.ask_delete_folder = None;
                // Корзина и категории взаимоисключающие: показывать удалённое
                // вместе с фильтром по виду бессмысленно.
                self.trash_armed = false;
                self.show_audit = false;
                self.show_trash = !self.show_trash;
                if self.show_trash {
                    self.kind_filter.clear();
                }
                self.refilter();
            }
            Message::ToggleAudit => {
                self.ask_delete_folder = None;
                // Аудит — не раздел списка, а замена правой панели: выделение
                // с него снимается, а корзина закрывается.
                self.show_audit = !self.show_audit;
                if self.show_audit {
                    self.show_trash = false;
                    self.kind_filter.clear();
                    self.editing = None;
                    self.preview = None;
                }
                self.refilter();
            }
            Message::Select(i) => {
                // Выбор записи из отчёта аудита возвращает к обычному виду.
                self.show_audit = false;
                // Вооружённое открепление относится к конкретному файлу: при
                // уходе на другую запись подтверждение теряет смысл.
                self.detach_armed = None;
                self.preview = None;
                self.selected = Some(i);
            }
            Message::Copy(what, value) => {
                let ok = copy_to_clipboard(&value);
                self.toast = Some((
                    if ok {
                        format!("{what} copied")
                    } else {
                        format!("cannot copy {what}")
                    },
                    Instant::now(),
                ));
            }
            Message::ToggleReveal(uuid) => {
                let e = self.revealed.entry(uuid).or_insert(false);
                *e = !*e;
            }
            Message::DismissToast => {
                self.toast = None;
                self.trash_armed = false;
            }
            Message::Tick(now) => {
                if let Some((_, at)) = &self.toast {
                    if now.duration_since(*at) > Duration::from_secs(2) {
                        self.toast = None;
                    }
                }
            }
        }
        Task::none()
    }

    fn subscription(&self) -> Subscription<Message> {
        let tick = iced_futures::backend::native::smol::time::every(Duration::from_millis(500))
            .map(Message::Tick);
        let tab = keyboard::listen().filter_map(|event| match event {
            // Tab и Shift+Tab переводят фокус. Shift передаётся флагом
            // в третьем аргументе события.
            keyboard::Event::KeyPressed {
                key: key::Key::Named(key::Named::Tab),
                modifiers,
                ..
            } => Some(Message::MoveFocus(!modifiers.shift())),
            _ => None,
        });
        let menu_events = menu::events();

        // Мышь слушается глобально, а не через MouseArea: тот присылает
        // движение только пока курсор над ним самим. Уведённый на пару
        // пикселей в сторону указатель обрывал перетаскивание, и панель
        // почти не двигалась.
        let resize_events = iced_futures::event::listen_with(|event, _, _| match event {
            iced::Event::Mouse(iced::mouse::Event::ButtonPressed(iced::mouse::Button::Left)) => {
                Some(Message::GlobalPress)
            }
            iced::Event::Mouse(iced::mouse::Event::ButtonReleased(iced::mouse::Button::Left)) => {
                Some(Message::GlobalRelease)
            }
            iced::Event::Mouse(iced::mouse::Event::CursorMoved { position }) => {
                Some(Message::ResizeMove(position.x))
            }
            iced::Event::Window(iced::window::Event::Resized(size)) => {
                Some(Message::WindowResized(size.width))
            }
            _ => None,
        });

        Subscription::batch([tick, tab, menu_events, resize_events])
    }

    /// Выбранная запись.
    fn selected_item(&self) -> Option<&PifItem> {
        let idx = self.selected?;
        let pos = *self.entries.get(idx)?;
        self.vault.as_ref()?.items.get(pos)
    }

    /// Вносит правку из формы: новая запись или изменение существующей.
    fn apply_edit(&mut self) {
        let Some(editing) = self.editing.take() else {
            return;
        };
        let Some(vault) = self.vault.as_mut() else {
            return;
        };

        // Новая запись без явного выбора папки попадает в ту, что открыта в
        // боковой панели: иначе «новый элемент» из папки исчезал бы из неё же.
        let mut folder = editing.folder.clone();
        if folder.is_none() && editing.uuid.is_none() && !self.folder_filter.is_empty() {
            folder = Some(self.folder_filter.clone());
        }
        let folder = folder.as_deref();

        // Правку вносим в хранилище, а список пересобираем после того,
        // как заим mutable-доступ отпущен.
        let outcome: Result<Option<String>, ()> = match editing.uuid.clone() {
            Some(uuid) => match vault.find_mut(&uuid) {
                Some(item) => {
                    editing.draft.apply(item);
                    Ok(Some(uuid))
                }
                None => Err(()),
            },
            None => Ok(Some(vault.create_item(&editing.draft, editing.kind))),
        };

        if let Ok(Some(uuid)) = outcome.as_ref() {
            vault.touch(uuid);
            vault.set_folder(uuid, folder);
        }

        match outcome {
            Ok(uuid) => {
                if editing.uuid.is_none() {
                    self.revealed.clear();
                }
                self.editing = None;
                self.refilter();
                if let Some(uuid) = uuid {
                    // Выделить правленую или только что созданную запись.
                    self.select_uuid(&uuid);
                }
                let word = if editing.uuid.is_some() {
                    "Changed"
                } else {
                    "Item created"
                };
                self.toast = Some((format!("{word}, remember to save"), Instant::now()));
            }
            Err(()) => {
                self.editing = Some(editing);
                self.toast = Some(("Item not found".into(), Instant::now()));
            }
        }
    }

    /// Удаляет запись по uuid.
    fn delete_uuid(&mut self, uuid: &str) {
        let Some(vault) = self.vault.as_mut() else {
            return;
        };
        let removed = vault.remove(uuid);
        if removed {
            self.revealed.retain(|k, _| !k.starts_with(uuid));
            self.editing = None;
            self.refilter();
            self.toast = Some(("Item deleted, remember to save".into(), Instant::now()));
        }
    }

    /// Записывает файл вместе с резервной копией.
    fn save_file(&mut self) {
        let Some(path) = self.path.clone() else {
            return;
        };
        let Some(vault) = self.vault.as_mut() else {
            return;
        };
        match vault.save(&path) {
            Ok(()) => {
                self.trash = vault.trash_stats();
                vault.mark_saved();
                // Файлы разобраны и разложены по диску — вооружение сбрасываем.
                self.detach_armed = None;
                self.preview = None;
                self.toast = Some(("Saved".into(), Instant::now()));
            }
            Err(e) => {
                self.toast = Some((format!("Cannot save: {e}"), Instant::now()));
            }
        }
    }

    /// Пересобирает `entries` по текущему фильтру и поисковой строке.
    fn refilter(&mut self) {
        self.entries = match &self.vault {
            Some(v) => filter_indices(
                &v.items,
                &self.query,
                &self.kind_filter,
                self.show_trash,
                &self.folder_filter,
            ),
            None => Vec::new(),
        };

        self.selected = if self.entries.is_empty() {
            None
        } else {
            Some(self.selected.unwrap_or(0).min(self.entries.len() - 1))
        };
    }

    /// Уникальные типы записей для кнопок фильтра.
    fn view(&self) -> Element<'_, Message> {
        let body: Element<'_, Message> = match &self.vault {
            None => self.view_welcome(),
            Some(_) => self.view_browser(),
        };

        let page: Element<'_, Message> =
            iced::widget::column(vec![self.view_toolbar(), body, self.view_status()])
                .height(Length::Fill)
                .into();

        page
    }

    /// Форма редактирования: создание или правка.
    fn view_editor(&self) -> Element<'_, Message> {
        let Some(e) = &self.editing else {
            return center_text("Select an item");
        };

        let mut rows: Vec<Element<'_, Message>> = Vec::new();

        rows.push(
            iced::widget::text(if e.uuid.is_some() {
                "Edit Item"
            } else {
                "New Item"
            })
            .size(type_scale::LARGE)
            .color(TEXT_BRIGHT)
            .into(),
        );

        // Выбор типа — только у новой записи. У существующей тип привязан к
        // структуре, которая уже лежит в файле, и смена ничего бы не значила.
        if e.uuid.is_none() {
            let mut chips: Vec<Element<'_, Message>> = Vec::with_capacity(9);
            for kind in opclient_core::pif::ItemKind::all() {
                chips.push(
                    iced::widget::button(iced::widget::text(kind.label()).size(12.0).color(TEXT))
                        .on_press(Message::DraftKind(kind))
                        .style(if e.kind == kind {
                            chip_active
                        } else {
                            chip_idle
                        })
                        .into(),
                );
            }
            rows.push(field(
                "Type",
                iced::widget::row(chips).spacing(6.0).wrap().into(),
            ));
        }

        // Подписи полей зависят от типа: в карте «логин» — это владелец,
        // а в лицензии — ключ. Пустая подпись означает, что слот этому типу
        // не нужен и поле не рисуется.
        let labels = e.kind.field_labels();
        for (slot, (value, key)) in [
            (&e.username, "username"),
            (&e.password, "password"),
            (&e.url, "url"),
        ]
        .into_iter()
        .enumerate()
        {
            let label = labels[slot];
            if !label.is_empty() {
                rows.push(input_row(label, value, key));
            }
        }

        // Срок действия у карты вводится одной строкой «MM/YYYY» и
        // разворачивается в два ключа при сохранении. Идёт раньше кода: в
        // карточке человек читает номер, потом срок, и только потом код.
        if e.kind == opclient_core::pif::ItemKind::CreditCard {
            rows.push(input_row("Expiry Date", &e.draft.extra_a, "extra_a"));
        }
        // Второй дополнительный слот: код у карты, порт у сервера.
        if !labels[4].is_empty() {
            rows.push(input_row(labels[4], &e.extra_b, "extra_b"));
        }

        // Заметки многострочные: в выгрузке они почти всегда с переносами,
        // поэтому однострочное поле потеряло бы строки.
        let notes: Element<'_, Message> = iced::widget::text_editor(&e.notes_doc)
            .placeholder("Notes")
            .height(Length::Fixed(140.0))
            .size(13.0)
            .on_action(Message::EditNotes)
            .into();
        rows.push(field("Notes", notes));

        // Папка выбирается списком, а не вводом: названия папок уже есть в
        // хранилище, вводить их второй раз незачем.
        let folder_row: Element<'_, Message> = {
            let options: Vec<Element<'_, Message>> = self
                .vault
                .as_ref()
                .map(|v| -> Vec<Element<'_, Message>> {
                    let mut opts: Vec<Element<'_, Message>> = vec![iced::widget::button(
                        iced::widget::text("No folder").size(12.0).color(TEXT),
                    )
                    .on_press(Message::DraftFolder(None))
                    .style(if e.folder.is_none() {
                        chip_active
                    } else {
                        chip_idle
                    })
                    .into()];
                    for f in v.folders() {
                        let uuid = f.uuid.clone();
                        let active = e.folder.as_deref() == Some(uuid.as_str());
                        opts.push(
                            iced::widget::button(
                                iced::widget::text(
                                    f.title.clone().unwrap_or_else(|| "Untitled Folder".into()),
                                )
                                .size(12.0)
                                .color(TEXT),
                            )
                            .on_press(Message::DraftFolder(Some(uuid)))
                            .style(if active { chip_active } else { chip_idle })
                            .into(),
                        );
                    }
                    opts
                })
                .unwrap_or_default();

            if options.is_empty() {
                center_text("Create a folder in the sidebar first")
            } else {
                iced::widget::row(options).spacing(6.0).wrap().into()
            }
        };
        rows.push(field("Folder", folder_row));

        let save: Element<'_, Message> =
            iced::widget::button(iced::widget::text("Save").size(12.0).color(TEXT))
                .on_press(Message::ApplyEdit)
                .padding(10.0)
                .style(chip_active)
                .into();

        let cancel: Element<'_, Message> =
            iced::widget::button(iced::widget::text("Cancel").size(12.0).color(TEXT))
                .on_press(Message::CancelEdit)
                .padding(10.0)
                .style(chip_idle)
                .into();

        let mut buttons = vec![save, cancel];

        if e.uuid.is_some() {
            buttons.push(iced::widget::Space::new().width(Length::Fill).into());
            buttons.push(if e.confirm_delete {
                let yes: Element<'_, Message> = iced::widget::button(
                    iced::widget::text("Delete Forever").size(12.0).color(TEXT),
                )
                .on_press(Message::ConfirmDelete(true))
                .padding(10.0)
                .style(chip_danger)
                .into();
                let no: Element<'_, Message> =
                    iced::widget::button(iced::widget::text("Don't Delete").size(12.0).color(TEXT))
                        .on_press(Message::ConfirmDelete(false))
                        .padding(10.0)
                        .style(chip_idle)
                        .into();
                iced::widget::row(vec![yes, no]).spacing(6.0).into()
            } else {
                iced::widget::button(iced::widget::text("Delete").size(12.0).color(TEXT))
                    .on_press(Message::DeleteItem)
                    .padding(10.0)
                    .style(chip_idle)
                    .into()
            });
        }

        let bar: Element<'_, Message> = iced::widget::row(buttons)
            .spacing(8.0)
            .align_y(Center)
            .into();
        rows.push(bar);

        let hint: Element<'_, Message> =
            iced::widget::text("Changes reach the file only after you press “Save File” above.")
                .size(11.0)
                .color(TEXT_DIM)
                .into();
        rows.push(hint);

        iced::widget::scrollable(iced::widget::column(rows).spacing(10.0).padding(20.0)).into()
    }

    fn view_toolbar(&self) -> Element<'_, Message> {
        let title: Element<'_, Message> = iced::widget::text("1Password — Export")
            .size(type_scale::LARGE)
            .color(TEXT_BRIGHT)
            .into();

        let open: Element<'_, Message> = toolbar_icon_button(
            icons::Icon::Open,
            "Open export file",
            Message::PickFile,
            chip_toolbar,
        );

        // Путь и то, что набрано в поиске, — белые. На градиенте серый
        // текст терялся: тёмный справа, он почти сливался с фоном.
        // Путь и «no file selected» взяты в скобки: без них строка читалась
        // как часть названия «1Password — Export», а это сведения о файле.
        //
        // Перенос запрещён: на второй строке путь ломал высоту полосы, а
        // вместе с ней и общее положение заголовка. Длина ограничена
        // `PATH_MAX_CHARS`, а не шириной: `iced` не даёт измерить текст из
        // `view`, и многоточие на месте обреза поставить нечем.
        let file: Element<'_, Message> = match &self.path {
            Some(p) => iced::widget::text(ellipsize(
                &format!("({})", short_path(p)),
                PATH_MAX_CHARS,
            ))
            .size(11.0)
            .color(TEXT_BRIGHT)
            .wrapping(iced::widget::text::Wrapping::None)
            .into(),
            None => iced::widget::text("(no file selected)")
                .size(11.0)
                .color(TEXT_BRIGHT)
                .wrapping(iced::widget::text::Wrapping::None)
                .into(),
        };

        // Иконка приложения слева от названия, во всю высоту строки заголовка.
        // Отступ задан контейнером: прижатый к краю значок слипается с границей
        // окна и читается как элемент управления, а не как подпись.
        let mark: Element<'_, Message> = iced::widget::container(
            iced::widget::image(app_icon_handle())
                // Размер обязателен: без него картинка рисуется в исходных
                // 128 px и раздувает всю строку заголовка.
                .width(Length::Fixed(APP_ICON_SIZE))
                .height(Length::Fixed(APP_ICON_SIZE))
                .content_fit(iced::ContentFit::Contain),
        )
        .padding(Padding::new(0.0).horizontal(4.0))
        .width(Length::Shrink)
        .into();

        // Ширина задана контейнером с `Fill`, и это не косметика. Ряд слева
        // сам по себе `Shrink`, а `iced` раскладывает `Shrink` первым и
        // отдаёт ему всю оставшуюся ширину: заголовок и путь занимают
        // сколько могут, и до кнопок места уже не хватает. Тогда flex
        // ужимает последнего ребёнка, и «New vault» становится заметно уже
        // остальных, а значок в ней — ещё и мельче, потому что контейнер
        // сжимает содержимое. С `Fill` блок уходит на второй проход: сначала
        // раскладываются кнопки и получают свои размеры, и ужимается текст.
        //
        // Отдельного `Space::new().width(Fill)` в ряду больше нет: вместе с
        // этим блоком он делил остаток пополам, и путь получал вдвое меньше
        // места, чем раньше. Единственный `Fill` забирает остаток целиком, но
        // текст в нём выровнен по левому краю, так что на вид ничего не
        // меняется, а путь снова занимает всю доступную ширину.
        let left: Element<'_, Message> = iced::widget::container(
            iced::widget::row(vec![mark, title, file])
                .spacing(10.0)
                .align_y(Center),
        )
        .width(Length::Fill)
        // Бюджет знаков не может следить за шириной окна, поэтому на узком
        // окне путь окажется длиннее отведённого места. Без обрезки он
        // наезжал бы на поле поиска; с ней просто срезается по краю.
        .clip(true)
        .into();

        let head: Element<'_, Message> = if self.vault.is_some() {
            // Высота задаётся отступом самого поля, а не контейнером:
            // контейнер растягивает рамку, а рамка рисуется на своей
            // естественной высоте, и рядом с кнопками она садилась выше.
            let search = iced::widget::text_input("Search…", &self.query_input)
                .on_input(|v| Message::SearchChanged(v.clone()))
                .size(SEARCH_SIZE)
                .padding(Padding::new(SEARCH_PADDING).horizontal(10.0))
                .width(Length::Fixed(240.0))
                // Поле прозрачное: своя плашка поверх градиента выглядела
                // бы вставленной. Под наведением и при фокусе рамка
                // появляется, иначе искать нечем.
                .style(|_t: &Theme, status: iced::widget::text_input::Status| {
                    use iced::widget::text_input::Status as S;
                    let active = matches!(status, S::Focused { .. } | S::Hovered);
                    iced::widget::text_input::Style {
                        background: iced::Background::Color(Color::TRANSPARENT),
                        border: iced::border::Border {
                            color: if active {
                                Color::from_rgba(1.0, 1.0, 1.0, 0.38)
                            } else {
                                Color::from_rgba(1.0, 1.0, 1.0, 0.14)
                            },
                            width: 1.0,
                            radius: 4.0.into(),
                        },
                        icon: TEXT_BRIGHT,
                        placeholder: TEXT_BRIGHT,
                        value: TEXT_BRIGHT,
                        selection: Color::from_rgb(0.35, 0.55, 0.95),
                    }
                })
                .into();

            let new_item: Element<'_, Message> = toolbar_icon_button(
                icons::Icon::Plus,
                "New item",
                Message::StartCreate,
                chip_toolbar,
            );

            let mut buttons = vec![new_item];
            if self.has_changes() {
                buttons.push(toolbar_icon_button(
                    icons::Icon::Save,
                    "Save file",
                    Message::SaveFile,
                    chip_active,
                ));
            }
            buttons.push(toolbar_icon_button(
                icons::Icon::Eject,
                "Eject vault",
                Message::EjectVault,
                chip_toolbar,
            ));
            buttons.push(open);
            buttons.push(toolbar_icon_button(
                icons::Icon::NewVault,
                "New vault",
                Message::CreateVault,
                chip_toolbar,
            ));

            // Единообразный тулбар: та же поверхность и те же поля, что у
            // боковой панели, и волосяная линия снизу. Иначе стык тулбара с
            // панелью виден как разница в оттенке и в отступах.
            iced::widget::container(
                iced::widget::row(vec![
                    left,
                    search,
                    iced::widget::row(buttons)
                        .spacing(8.0)
                        .align_y(Center)
                        .into(),
                ])
                .spacing(10.0)
                // Без выравнивания по середине поле поиска прижимается к
                // верху полосы: её высоту набирают кнопки во всю высоту.
                .align_y(Center)
                .padding(Padding::new(8.0).horizontal(14.0).vertical(8.0)),
            )
            .width(Length::Fill)
            .style(|_: &Theme| iced::widget::container::Style {
                background: Some(toolbar_background()),
                border: iced::border::Border {
                    color: HAIRLINE,
                    width: 1.0,
                    ..iced::border::Border::default()
                },
                ..iced::widget::container::Style::default()
            })
            .into()
        } else {
            // Кнопки в пустом хранилище те же и того же размера: полоса не
            // должна менять вид после открытия файла.
            iced::widget::container(
                iced::widget::row(vec![
                    left,
                    toolbar_icon_button(
                        icons::Icon::Open,
                        "Open export file",
                        Message::PickFile,
                        chip_toolbar,
                    ),
                    toolbar_icon_button(
                        icons::Icon::NewVault,
                        "New vault",
                        Message::CreateVault,
                        chip_toolbar,
                    ),
                ])
                .spacing(8.0)
                .align_y(Center)
                .padding(Padding::new(8.0).horizontal(14.0).vertical(8.0)),
            )
            .width(Length::Fill)
            .style(|_: &Theme| iced::widget::container::Style {
                background: Some(toolbar_background()),
                border: iced::border::Border {
                    color: HAIRLINE,
                    width: 1.0,
                    ..iced::border::Border::default()
                },
                ..iced::widget::container::Style::default()
            })
            .into()
        };

        // Подписи «сколько записей и по чему отфильтровано» над списком
        // больше нет: то же самое пишет строка состояния внизу, а активный
        // раздел и так подсвечен в боковой панели, корзина видна там же.
        head
    }

    /// Стартовый экран: предложение выбрать файл.
    fn view_welcome(&self) -> Element<'_, Message> {
        let hint: Element<'_, Message> = match &self.error {
            Some(e) => iced::widget::text(e.clone()).size(12.0).color(Color::from_rgb(1.0, 0.5, 0.5)).into(),
            None => iced::widget::text(
                "Choose an export folder, or the data.1pif file inside it.\nIn 1Password: File → Export → All Items.",
            )
            .size(13.0)
            .color(TEXT_DIM)
            .into(),
        };

        let btn: Element<'_, Message> = iced::widget::button(
            iced::widget::text("Open export file…")
                .size(14.0)
                .color(TEXT),
        )
        .on_press(Message::PickFile)
        .padding(12.0)
        .style(chip_active)
        .into();

        let create: Element<'_, Message> = iced::widget::button(
            iced::widget::text("Create new vault…")
                .size(13.0)
                .color(TEXT),
        )
        .on_press(Message::CreateVault)
        .padding(10.0)
        .style(chip_idle)
        .into();

        iced::widget::center(
            iced::widget::column(vec![
                btn,
                iced::widget::Space::new().height(10.0).into(),
                create,
                iced::widget::Space::new().height(14.0).into(),
                hint,
            ])
            .spacing(0.0)
            .align_x(Center),
        )
        .width(Length::Fill)
        .height(Length::Fill)
        .into()
    }

    /// Основной экран: список и детали.
    fn view_browser(&self) -> Element<'_, Message> {
        // Через .get(): если список фильтра отстал от хранилища, экран
        // должен показаться пустым, а не упасть.
        let selected = self
            .selected
            .and_then(|i| self.entries.get(i).copied())
            .and_then(|i| self.vault.as_ref().and_then(|v| v.items.get(i)));

        let details: Element<'_, Message> = match selected {
            Some(it) => self.view_details(it),
            None => center_text("Select an item"),
        };

        let right: Element<'_, Message> = if self.show_audit {
            self.view_audit()
        } else {
            match &self.editing {
                Some(_) => self.view_editor(),
                None => details,
            }
        };

        // Волосяная линия между панелью и списком. У iced 0.14 у Border нет
        // граней по сторонам, поэтому линия рисуется отдельной полоской в
        // один пиксель.
        let hairline: Element<'_, Message> =
            iced::widget::container(iced::widget::text("").size(1.0))
                .width(Length::Fixed(1.0))
                .height(Length::Fill)
                .style(|_: &Theme| iced::widget::container::Style {
                    background: Some(HAIRLINE.into()),
                    ..iced::widget::container::Style::default()
                })
                .into();

        // Граница панели списка: за неё панель тянут мышью. Линия в один
        // пиксель осталась бы на месте, а полоса под неё даёт указателю
        // куда цепиться и меняет курсор на двустороннюю стрелку.
        let resize_handle: Element<'_, Message> = iced::widget::mouse_area(
            iced::widget::container(iced::widget::text("").size(1.0))
                .width(Length::Fill)
                .height(Length::Fill),
        )
        .on_enter(Message::HoverResize(true))
        .on_exit(Message::HoverResize(false))
        .on_press(Message::ResizeStart)
        .interaction(if self.resizing {
            iced::mouse::Interaction::ResizingHorizontally
        } else {
            iced::mouse::Interaction::Idle
        })
        .into();

        // Размер полосы задаёт контейнер: у MouseArea своего метода для
        // ширины нет.
        let resize_handle: Element<'_, Message> = iced::widget::container(resize_handle)
            .width(Length::Fixed(RESIZE_HANDLE_W))
            .height(Length::Fill)
            .into();

        iced::widget::row(vec![
            self.view_sidebar(),
            hairline,
            iced::widget::container(self.view_list())
                .width(Length::Fixed(self.list_width))
                .height(Length::Fill)
                .into(),
            resize_handle,
            iced::widget::container(right)
                .height(Length::Fill)
                .style(|_: &Theme| iced::widget::container::Style {
                    background: Some(SURFACE_RAISED.into()),
                    ..iced::widget::container::Style::default()
                })
                .into(),
        ])
        .height(Length::Fill)
        .into()
    }

    /// Принимает только что созданное хранилище.
    ///
    /// Повторяет [`App::open`], но берёт каталог: путь к файлу известен заранее
    /// и не подлежит разрешению, а открывать только что записанный файл с
    /// диска незачем — он уже в руках.
    fn open_created(&mut self, dir: &std::path::Path, vault: Pif) {
        let path = dir.join("data.1pif");

        self.trash = vault.trash_stats();
        self.vault = Some(vault);
        self.path = Some(path.clone());
        self.error = None;
        self.selected = None;
        self.revealed.clear();
        self.editing = None;
        self.preview = None;
        self.detach_armed = None;
        self.kind_filter.clear();
        self.show_trash = false;
        self.query.clear();
        self.query_input.clear();
        self.refilter();
        config::remember(&path);
    }

    /// Держит ширину списка в допустимых пределах.
    ///
    /// Верхняя граница считается от ширины окна, а не задана числом:
    /// панель справа тоже не должна схлопываться в узкую полоску.
    fn clamp_list_width(&mut self) {
        let mut max = LIST_WIDTH_MAX;
        if self.window_w > 0.0 {
            max = (self.window_w - SIDEBAR_W - 1.0 - RESIZE_HANDLE_W - PANEL3_MIN)
                .max(LIST_WIDTH_MIN);
        }
        self.list_width = self.list_width.clamp(LIST_WIDTH_MIN, max);
    }

    /// Сколько живых записей каждого вида.
    ///
    /// Считаются только живые: корзина — отдельный раздел, и в счётчиках
    /// категорий она бы сбивала толку.
    fn kind_counts(&self) -> Vec<(String, usize)> {
        use std::collections::BTreeMap;
        let Some(vault) = self.vault.as_ref() else {
            return Vec::new();
        };

        let mut counts: BTreeMap<String, usize> = BTreeMap::new();
        for it in &vault.items {
            if it.trashed.unwrap_or(false) || it.kind() == "Folder" {
                continue;
            }
            *counts.entry(it.kind().to_string()).or_default() += 1;
        }
        counts.into_iter().collect()
    }

    /// Строка записи в отчёте аудита: название и переход к самой записи.
    ///
    /// Записи может не быть в текущем списке — например, она отфильтрована
    /// категорией или лежит в корзине. Тогда строка некликабельна, и об этом
    /// сказано подсказкой, а не молчанием.
    fn entry_row<'a>(
        app: &'a App,
        vault: &'a Pif,
        entry: &opclient_core::audit::Ref,
        note: &str,
    ) -> Element<'a, Message> {
        let pos = app
            .entries
            .iter()
            .position(|&i| vault.items[i].uuid == entry.uuid);

        let label = iced::widget::row(vec![
            iced::widget::text(format!("· {}", entry.title))
                .size(12.0)
                .color(TEXT)
                .into(),
            iced::widget::Space::new().width(Length::Fill).into(),
            iced::widget::text(note.to_string())
                .size(10.0)
                .color(TEXT_DIM)
                .into(),
        ])
        .width(Length::Fill);

        let button = iced::widget::button(label).style(chip_idle);
        match pos {
            Some(p) => button.on_press(Message::Select(p)).into(),
            None => {
                let mut plain: Vec<Element<'a, Message>> =
                    vec![iced::widget::text(format!("· {}", entry.title))
                        .size(12.0)
                        .color(TEXT_DIM)
                        .into()];
                if !note.is_empty() {
                    plain.push(
                        iced::widget::text(note.to_string())
                            .size(10.0)
                            .color(TEXT_DIM)
                            .into(),
                    );
                }
                iced::widget::row(plain).spacing(8.0).into()
            }
        }
    }

    /// Отчёт аудита безопасности.
    ///
    /// Пароли наружу не выводятся: показываются только названия записей и
    /// счётчики, иначе панель аудита стала бы вторым местом, где секрет лежит
    /// открытым текстом.
    fn view_audit(&self) -> Element<'_, Message> {
        let Some(vault) = self.vault.as_ref() else {
            return center_text("No file open");
        };

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or_default();
        let report = opclient_core::audit::run(vault, now);

        let mut col: Vec<Element<'_, Message>> = Vec::new();

        // Значок щита слева от заголовка — тот же приём, что и в панели деталей:
        // у раздела свой значок, чтобы он не путался со значками записей.
        col.push(
            iced::widget::row(vec![
                icons::icon(icons::Icon::Audit, 26.0, TEXT_DIM).into(),
                iced::widget::text("Security Audit")
                    .size(type_scale::TITLE)
                    .color(TEXT_BRIGHT)
                    .into(),
            ])
            .spacing(12.0)
            .align_y(Center)
            .into(),
        );
        col.push(
            iced::widget::text(format!(
                "passwords across {} items, {} unique",
                report.with_password, report.unique
            ))
            .size(12.0)
            .color(TEXT_DIM)
            .into(),
        );
        col.push(iced::widget::Space::new().height(14.0).into());

        let tile = |value: usize, label: &str, color: Color| -> Element<'_, Message> {
            iced::widget::column(vec![
                iced::widget::text(value.to_string())
                    .size(22.0)
                    .color(color)
                    .into(),
                iced::widget::text(label.to_string())
                    .size(11.0)
                    .color(TEXT_DIM)
                    .into(),
            ])
            .width(Length::Fixed(140.0))
            .into()
        };

        col.push(
            iced::widget::row(vec![
                tile(report.reused, "reused", TEXT_WARN),
                tile(report.weak, "weak", TEXT_WARN),
                tile(report.stale, "old", TEXT_DIM),
            ])
            .spacing(10.0)
            .into(),
        );
        col.push(iced::widget::Space::new().height(18.0).into());

        // Списки названий. Переход к записи — обычный Select, аудит при этом
        // закрывается, чтобы пользователь увидел саму запись.
        let list = |title: &str, items: &[opclient_core::audit::Flagged], empty: &str| {
            let mut part: Vec<Element<'_, Message>> = vec![iced::widget::text(title.to_string())
                .size(14.0)
                .color(TEXT)
                .into()];

            if items.is_empty() {
                part.push(
                    iced::widget::text(empty.to_string())
                        .size(12.0)
                        .color(TEXT_DIM)
                        .into(),
                );
            } else {
                for f in items {
                    let entry = opclient_core::audit::Ref {
                        uuid: f.uuid.clone(),
                        title: f.title.clone(),
                    };
                    part.push(Self::entry_row(self, vault, &entry, ""));
                }
            }
            iced::widget::column(part).spacing(6.0).into()
        };

        col.push(list(
            "Weak Passwords",
            &report.weak_items,
            "No weak passwords found",
        ));
        col.push(iced::widget::Space::new().height(14.0).into());

        for group in &report.reuse_groups {
            let mut part: Vec<Element<'_, Message>> =
                vec![
                    iced::widget::text(format!("Reused across {} items", group.entries.len()))
                        .size(14.0)
                        .color(TEXT)
                        .into(),
                ];

            for entry in &group.entries {
                part.push(Self::entry_row(self, vault, entry, ""));
            }
            col.push(iced::widget::column(part).spacing(6.0).into());
            col.push(iced::widget::Space::new().height(10.0).into());
        }
        if report.reuse_groups.is_empty() {
            col.push(
                iced::widget::text("No reused passwords found")
                    .size(12.0)
                    .color(TEXT_DIM)
                    .into(),
            );
        }

        col.push(iced::widget::Space::new().height(14.0).into());
        col.push(list(
            "Not Changed Recently",
            &report.stale_items,
            "All passwords were changed recently",
        ));

        iced::widget::scrollable(iced::widget::column(col).spacing(4.0).padding(20.0)).into()
    }

    /// Боковая панель: разделы и категории, как в 1Password.
    fn view_sidebar(&self) -> Element<'_, Message> {
        let alive = self.vault.as_ref().map_or(0, |v| v.alive().len());
        let trashed = self.vault.as_ref().map_or(0, |v| v.trashed().len());

        let mut col: Vec<Element<'_, Message>> = Vec::new();

        // Заголовок секции: подпись мелким шрифтом, рядом значок секции.
        //
        // Значок ставится здесь, а не в каждой строке: иначе значок папки
        // повторился бы напротив каждой папки, а значок сетки — напротив
        // каждого вида записи. Это ровно то, как разделяют секции 1Password.
        let heading = |t: &str, mark: icons::Icon| -> Element<'_, Message> {
            iced::widget::row(vec![
                icons::icon(mark, 14.0, TEXT_DIM).into(),
                iced::widget::text(t.to_string())
                    .size(type_scale::CAPTION)
                    .color(TEXT_DIM)
                    .into(),
            ])
            .spacing(6.0)
            .into()
        };

        // Строка раздела: значок, подпись, счётчик.
        //
        // Значок опционален только для папок: они названы пользователем, и
        // рисовать напротив каждой одинаковый значок папки незачем. У видов
        // значок совпадает с типом записи, поэтому он несёт смысл, а не
        // украшает.
        let section = |label: String,
                       count: Option<usize>,
                       active: bool,
                       msg: Message,
                       mark: Option<icons::Icon>|
         -> Element<'_, Message> {
            let tint = if active { TEXT_BRIGHT } else { TEXT_DIM };
            let mut cells: Vec<Element<'_, Message>> = Vec::with_capacity(3);

            if let Some(mark) = mark {
                cells.push(icons::icon(mark, 14.0, tint).into());
            }
            cells.push(
                iced::widget::text(label)
                    .size(type_scale::BODY)
                    .color(TEXT)
                    .into(),
            );
            cells.push(iced::widget::Space::new().width(Length::Fill).into());
            // У разделов без счётчика (Tools) числа нет: ноль означал бы
            // «ничего не нашлось», а это не так.
            if let Some(count) = count {
                cells.push(
                    iced::widget::text(count.to_string())
                        .size(type_scale::SECONDARY)
                        .color(TEXT_DIM)
                        .into(),
                );
            }

            iced::widget::button(
                iced::widget::row(cells)
                    .width(Length::Fill)
                    .spacing(if mark.is_some() { 7.0 } else { 0.0 }),
            )
            .width(Length::Fill)
            .on_press(msg)
            .style(if active { row_active } else { row_idle })
            .into()
        };

        col.push(section(
            "All Items".to_string(),
            Some(alive),
            self.kind_filter.is_empty() && !self.show_trash,
            Message::ShowTrash(false),
            Some(icons::Icon::AllItems),
        ));

        col.push(heading("Categories", icons::Icon::Categories));
        for (kind, count) in self.kind_counts() {
            let active = self.kind_filter == kind && !self.show_trash;
            let msg = Message::Filter(kind.clone());
            // Значок вычисляем до передачи подписи: `section` забирает строку
            // по значению, и обращение к ней после этого невозможно.
            let mark = icons::Icon::for_kind(&kind);
            col.push(section(kind, Some(count), active, msg, Some(mark)));
        }

        // Папки — единственное, что пользователь может завести сам: это
        // обычные записи system.folder.Regular, а не проекция типа записи.
        let folders: Vec<(String, String, usize)> = self
            .vault
            .as_ref()
            .map(|v| {
                v.folders()
                    .into_iter()
                    .map(|f| {
                        (
                            f.uuid.clone(),
                            f.title.clone().unwrap_or_else(|| "Untitled Folder".into()),
                            v.folder_count(&f.uuid),
                        )
                    })
                    .collect()
            })
            .unwrap_or_default();

        // Виджеты нельзя использовать дважды, поэтому каждый раз собираем их
        // заново: строка ввода нужна и для новой папки, и для переименования.
        let make_input = |placeholder: &str| -> Element<'_, Message> {
            iced::widget::text_input(placeholder, &self.folder_draft)
                .on_input(Message::FolderDraftChanged)
                .on_submit(Message::SubmitFolderDraft)
                .size(12)
                .width(Length::Fill)
                .into()
        };
        let make_submit = || -> Element<'_, Message> {
            iced::widget::button(iced::widget::text("Save").size(11.0).color(TEXT))
                .on_press(Message::SubmitFolderDraft)
                .style(chip_idle)
                .into()
        };

        let selected_folder = self.folder_filter.clone();

        if !folders.is_empty() {
            col.push(heading("Folders", icons::Icon::Folders));
            for (uuid, title, count) in &folders {
                let active = *uuid == selected_folder && !self.show_trash;
                col.push(section(
                    title.clone(),
                    Some(*count),
                    active,
                    Message::PickFolder(uuid.clone()),
                    None,
                ));
            }
        }

        // Строка ввода: при выбранной папке переименовывает её, иначе
        // создаёт новую.
        let placeholder = if selected_folder.is_empty() {
            "New folder"
        } else {
            "Rename folder"
        };
        let mut folder_row = vec![make_input(placeholder), make_submit()];

        if !selected_folder.is_empty() {
            let armed = self.ask_delete_folder.as_deref() == Some(selected_folder.as_str());
            folder_row.push(
                iced::widget::button(
                    iced::widget::text(if armed { "Really delete?" } else { "Delete" })
                        .size(11.0)
                        .color(TEXT),
                )
                .on_press(Message::AskDeleteFolder(selected_folder.clone()))
                .style(if armed { chip_danger } else { chip_idle })
                .into(),
            );
        }

        col.push(iced::widget::row(folder_row).spacing(6.0).into());

        if self.ask_delete_folder.is_some() {
            col.push(
                iced::widget::text("Items stay, but leave the folder")
                    .size(10.0)
                    .color(TEXT_DIM)
                    .into(),
            );
        }

        col.push(heading("Tools", icons::Icon::Tools));
        col.push(section(
            "Security Audit".to_string(),
            None,
            self.show_audit,
            Message::ToggleAudit,
            Some(icons::Icon::Audit),
        ));

        col.push(iced::widget::Space::new().height(Length::Fill).into());

        if trashed > 0 {
            col.push(section(
                "Trash".to_string(),
                Some(trashed),
                self.show_trash,
                Message::ShowTrash(!self.show_trash),
                Some(icons::Icon::Trash),
            ));
        }

        // От края до края: панель идёт во всю высоту окна, поля только по
        // бокам, а справа — волосяная линия вместо рамки. В macOS 27 так же
        // оформлены боковые панели.
        iced::widget::container(
            iced::widget::column(col)
                .spacing(4.0)
                .padding(Padding::new(8.0).horizontal(10.0).vertical(10.0)),
        )
        .width(Length::Fixed(212.0))
        .height(Length::Fill)
        .style(|_: &Theme| iced::widget::container::Style {
            background: Some(SURFACE.into()),
            ..iced::widget::container::Style::default()
        })
        .into()
    }

    fn view_list(&self) -> Element<'_, Message> {
        if self.entries.is_empty() {
            return center_text("Nothing found");
        }
        let Some(vault) = &self.vault else {
            return center_text("No file open");
        };

        let mut items: Vec<Element<'_, Message>> = Vec::with_capacity(self.entries.len());
        // Буква, для которой уже напечатан разделитель. Список отсортирован по
        // названию, поэтому одинаковые буквы идут подряд.
        let mut last_letter: Option<char> = None;

        for (pos, &idx) in self.entries.iter().enumerate() {
            // Пропускаем индексы, уже несуществующие в хранилище.
            let Some(it) = vault.items.get(idx) else {
                continue;
            };
            let is_sel = self.selected == Some(pos);
            let title = display_title(it);
            let sub = it.location_key.clone().unwrap_or_default();

            let title_line: Element<'_, Message> = iced::widget::text(truncate(&title, 40))
                .size(13.0)
                .color(if it.trashed.unwrap_or(false) {
                    TEXT_DIM
                } else if is_sel {
                    TEXT_BRIGHT
                } else {
                    TEXT
                })
                .into();

            let sub_line: Element<'_, Message> = iced::widget::row(vec![
                iced::widget::text(truncate(&sub, 24))
                    .size(11.0)
                    .color(TEXT_DIM)
                    .into(),
                iced::widget::Space::new().width(Length::Fill).into(),
                iced::widget::text(it.kind())
                    .size(10.0)
                    .color(TEXT_DIM)
                    .into(),
            ])
            .spacing(6.0)
            .into();

            // Значок вида слева от названия и на всю высоту строки: так он
            // читается как метка типа, а не как украшение.
            let mark: Element<'_, Message> =
                icons::icon(icons::Icon::for_kind(it.kind()), 17.0, TEXT_DIM).into();

            let body: Element<'_, Message> = iced::widget::row(vec![
                mark,
                iced::widget::column(vec![title_line, sub_line])
                    .spacing(3.0)
                    .into(),
            ])
            .spacing(10.0)
            .align_y(Center)
            .into();

            items.push(
                iced::widget::button(body)
                    .width(Length::Fill)
                    .on_press(Message::Select(pos))
                    .style(if is_sel { row_active } else { row_idle })
                    .into(),
            );

            let letter = title
                .trim_start_matches([' ', '·', '.', '-', '_'])
                .chars()
                .next()
                .filter(|c| c.is_alphanumeric());

            // Группа меняется и на цифрах, но заголовок для них не рисуется:
            // «1Password» и «35AWARDS» в 1Password идут подряд без буквы.
            if letter != last_letter {
                if letter.is_some_and(char::is_alphabetic) {
                    items.push(
                        iced::widget::text(letter.unwrap_or(' ').to_uppercase().to_string())
                            .size(12.0)
                            .color(TEXT_DIM)
                            .into(),
                    );
                }
                last_letter = letter;
            }
        }

        iced::widget::scrollable(iced::widget::column(items).spacing(2.0).padding(6.0)).into()
    }

    fn view_details(&self, it: &PifItem) -> Element<'_, Message> {
        let mut b: Vec<Element<'_, Message>> = Vec::new();

        // Первая строка панели: значок вида слева от названия.
        b.push(
            iced::widget::row(vec![
                icons::icon(icons::Icon::for_kind(it.kind()), 26.0, TEXT_DIM).into(),
                iced::widget::text(display_title(it))
                    .size(22.0)
                    .color(TEXT_BRIGHT)
                    .into(),
            ])
            .spacing(12.0)
            .align_y(Center)
            .into(),
        );
        b.push(
            iced::widget::text(format!("{}  ·  {}", it.kind(), it.uuid))
                .size(11.0)
                .color(TEXT_DIM)
                .into(),
        );

        let edit: Element<'_, Message> =
            iced::widget::button(iced::widget::text("Edit").size(12.0).color(TEXT))
                .on_press(Message::StartEdit)
                .padding(8.0)
                .style(chip_idle)
                .into();
        let del: Element<'_, Message> =
            iced::widget::button(iced::widget::text("Delete").size(12.0).color(TEXT))
                .on_press(Message::DeleteItem)
                .padding(8.0)
                .style(chip_idle)
                .into();
        b.push(
            iced::widget::row(vec![
                edit,
                del,
                iced::widget::Space::new().width(Length::Fill).into(),
            ])
            .spacing(8.0)
            .into(),
        );

        let users = it.usernames();
        if !users.is_empty() {
            let joined = users.join(", ");
            b.push(copy_row(
                "Username",
                &joined.clone(),
                Message::Copy("Username".into(), joined),
            ));
        }

        if let Some(pw) = it.primary_password() {
            let revealed = self.revealed.get(&it.uuid).copied().unwrap_or(false);
            let shown = if revealed { pw.to_string() } else { masked(pw) };

            let value: Element<'_, Message> = iced::widget::text(shown)
                .size(14.0)
                .color(TEXT_BRIGHT)
                .into();

            let reveal_btn: Element<'_, Message> = icon_button(
                if revealed {
                    icons::Icon::EyeOff
                } else {
                    icons::Icon::Eye
                },
                if revealed { "Hide" } else { "Show" },
                Message::ToggleReveal(it.uuid.clone()),
                chip_idle,
            );

            let copy_btn: Element<'_, Message> = icon_button(
                icons::Icon::Copy,
                "Copy",
                Message::Copy("Passwords".into(), pw.to_string()),
                chip_idle,
            );

            let line: Element<'_, Message> = iced::widget::row(vec![
                value,
                reveal_btn,
                copy_btn,
                iced::widget::Space::new().width(Length::Fill).into(),
            ])
            .spacing(8.0)
            .align_y(Center)
            .into();

            b.push(field("Passwords", line));
        }

        for u in it.urls() {
            b.push(copy_row(
                "Website",
                u,
                Message::Copy("Website".into(), u.to_string()),
            ));
        }

        if let Some(uri) = it.totp() {
            match Totp::parse(uri) {
                Ok(t) => {
                    let now = now_unix();
                    let code = t.code_at(now);
                    let left = t.seconds_remaining(now);

                    let code_el: Element<'_, Message> = iced::widget::text(code.clone())
                        .size(26.0)
                        .color(Color::from_rgb(0.35, 0.85, 1.0))
                        .into();
                    let copy_btn: Element<'_, Message> = icon_button(
                        icons::Icon::Copy,
                        "Copy code",
                        Message::Copy("Code".into(), code),
                        chip_idle,
                    );
                    let left_el: Element<'_, Message> = iced::widget::text(format!("{left}s"))
                        .size(12.0)
                        .color(TEXT_DIM)
                        .into();

                    let line: Element<'_, Message> = iced::widget::row(vec![
                        code_el,
                        copy_btn,
                        left_el,
                        iced::widget::Space::new().width(Length::Fill).into(),
                    ])
                    .spacing(10.0)
                    .align_y(Center)
                    .into();

                    b.push(field("One-Time Code", line));
                }
                Err(e) => b.push(
                    iced::widget::text(format!("TOTP: error — {e}"))
                        .size(12.0)
                        .color(TEXT_DIM)
                        .into(),
                ),
            }
        }

        if let Some(n) = it.notes() {
            if !n.trim().is_empty() {
                let body: Element<'_, Message> = iced::widget::text(n.to_string())
                    .size(12.0)
                    .color(TEXT)
                    .into();
                b.push(field("Notes", body));
            }
        }

        // Поля, специфичные для типа: номер карты, срок, POP/SMTP, ключ
        // лицензии. У веб-форм их нет, у кошелька — основная часть записи.
        for (label, value, secret) in it.extra_fields() {
            b.push(self.extra_row(&it.uuid, &label, &value, secret));
        }

        // Блок рисуется всегда, а не только когда вложения уже есть:
        // иначе к первому файлу негде добраться.
        let attachable = self.attachment_target();
        let mut attach_row: Vec<Element<'_, Message>> = Vec::new();

        if attachable.is_some() {
            attach_row.push(
                iced::widget::button(iced::widget::text("Attach File…").size(12.0).color(TEXT))
                    .on_press(Message::AttachFile)
                    .style(chip_active)
                    .into(),
            );
        } else {
            attach_row.push(
                iced::widget::text("Save the item before attaching files")
                    .size(11.0)
                    .color(TEXT_DIM)
                    .into(),
            );
        }

        if self.attachments_pending() {
            attach_row.push(
                iced::widget::text("· files pending save")
                    .size(11.0)
                    .color(TEXT_WARN)
                    .into(),
            );
        }
        attach_row.push(iced::widget::Space::new().width(Length::Fill).into());
        let head: Element<'_, Message> = iced::widget::row(attach_row)
            .spacing(8.0)
            .align_y(Center)
            .into();

        let mut block: Vec<Element<'_, Message>> = vec![head];

        if let Some(files) = self.attachments_of(&attachable.clone().unwrap_or_default()) {
            let mut rows: Vec<Element<'_, Message>> = Vec::with_capacity(files.len());
            for a in files {
                let armed = self.detach_armed.as_deref() == Some(a.name.as_str());

                let mut name_text =
                    format!("{}  ·  {}", a.name, opclient_core::pif::human_size(a.size));
                if a.pending_source.is_some() {
                    name_text.push_str("  ·  not written yet");
                }
                let label: Element<'_, Message> =
                    iced::widget::text(name_text).size(13.0).color(TEXT).into();

                let open: Element<'_, Message> = icon_button(
                    icons::Icon::Open,
                    "Open",
                    Message::OpenAttachment(a.path.clone()),
                    chip_idle,
                );

                let drop: Element<'_, Message> = icon_button(
                    icons::Icon::Detach,
                    "Detach",
                    Message::DetachAttachment(a.name.clone()),
                    if armed { chip_danger } else { chip_idle },
                );

                let mut widgets = vec![label, open, drop];

                // Миниатюра есть только у файла, который уже лежит на диске:
                // несохранённый прикреплённый файл превью показать неоткуда.
                let viewable = a.pending_source.is_none() && is_image(&a.path) && a.path.exists();
                if viewable {
                    let thumb: Element<'_, Message> =
                        iced::widget::button(thumbnail(&a.path, 36.0))
                            .on_press(Message::TogglePreview(a.path.clone()))
                            .style(chip_idle)
                            .into();
                    widgets.insert(0, thumb);
                }

                if armed {
                    widgets.push(
                        iced::widget::text("the file goes to trash on save")
                            .size(11.0)
                            .color(TEXT_DIM)
                            .into(),
                    );
                    widgets.push(icon_button(
                        icons::Icon::Cancel,
                        "Cancel",
                        Message::CancelDetach,
                        chip_idle,
                    ));
                }
                widgets.push(iced::widget::Space::new().width(Length::Fill).into());

                let row: Element<'_, Message> = iced::widget::row(widgets)
                    .spacing(8.0)
                    .align_y(Center)
                    .into();

                // Развёрнутое превью живёт под своей строкой, а не поверх
                // списка: так не нужно гадать, какому файлу оно принадлежит.
                if viewable && self.preview.as_ref() == Some(&a.path) {
                    rows.push(row);
                    rows.push(
                        iced::widget::row(vec![
                            thumbnail(&a.path, 320.0).into(),
                            iced::widget::text(a.path.display().to_string())
                                .size(10.0)
                                .color(TEXT_DIM)
                                .into(),
                        ])
                        .spacing(10.0)
                        .align_y(Center)
                        .into(),
                    );
                } else {
                    rows.push(row);
                }
            }
            let list: Element<'_, Message> = iced::widget::column(rows).spacing(6.0).into();
            block.push(list);
        }

        b.push(field(
            "Attachments",
            iced::widget::column(block).spacing(10.0).into(),
        ));

        iced::widget::scrollable(iced::widget::column(b).spacing(12.0).padding(20.0)).into()
    }

    /// Выделяет запись по uuid.
    ///
    /// Позиция ищется именно в отфильтрованном и отсортированном списке,
    /// который видит пользователь: в хранилище записи лежат в порядке
    /// файла, а показываются по алфавиту.
    fn select_uuid(&mut self, uuid: &str) -> bool {
        let Some(vault) = &self.vault else {
            return false;
        };
        let pos = self
            .entries
            .iter()
            .position(|&i| vault.items[i].uuid == uuid);
        match pos {
            Some(p) => {
                self.selected = Some(p);
                true
            }
            None => false,
        }
    }

    /// Есть ли несохранённые изменения.
    fn has_changes(&self) -> bool {
        self.vault.as_ref().is_some_and(Pif::has_changes)
    }

    /// Файлы вложений записи.
    fn attachments_of(&self, uuid: &str) -> Option<Vec<opclient_core::pif::Attachment>> {
        let files = self.vault.as_ref()?.attachments.get(uuid)?;
        (!files.is_empty()).then(|| files.clone())
    }

    /// Есть ли вложения, которые ещё не записаны на диск.
    fn attachments_pending(&self) -> bool {
        self.vault
            .as_ref()
            .is_some_and(opclient_core::pif::Pif::attachments_changed)
    }

    /// Прикрепляет файлы к записи без диалога: вынесено отдельно, чтобы
    /// перенос проверялся тестом — `NSOpenPanel` в тесте не открыть.
    ///
    /// Возвращает, сколько прикрепилось и имена тех, кто не прикрепился.
    fn attach_paths(&mut self, uuid: &str, sources: &[PathBuf]) -> (usize, Vec<String>) {
        let mut added = 0usize;
        let mut failed = Vec::new();

        for source in sources {
            let name = source
                .file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_default();
            match self.vault.as_mut().map(|v| v.attach(uuid, source)) {
                Some(Ok(_)) => added += 1,
                // Отдельно отличать «нет хранилища» от «ошибка чтения» смысла
                // нет: пользователю в обоих случаях нужно одно и то же.
                _ => failed.push(name),
            }
        }

        (added, failed)
    }

    /// Запись, к которой относятся действия над вложениями.
    ///
    /// Пока открыт редактор, subject — именно он: правимая запись важнее
    /// выделенной, иначе файл из формы новой записи ушёл бы в соседнюю.
    /// `None` у создаваемой записи — у неё ещё нет uuid, а каталог
    /// вложений называется именно по нему.
    fn attachment_target(&self) -> Option<String> {
        match self.editing.as_ref() {
            Some(e) => e.uuid.clone(),
            None => self.selected_item().map(|i| i.uuid.clone()),
        }
    }

    /// Строка специфичного поля. Секретные значения замаскированы, пока их
    /// явно не раскрыли; обычные показываются сразу.
    fn extra_row(
        &self,
        uuid: &str,
        label: &str,
        value: &str,
        secret: bool,
    ) -> Element<'_, Message> {
        let key = format!("{uuid}::{label}");
        let revealed = self.revealed.get(&key).copied().unwrap_or(false);
        let shown = if secret && !revealed {
            masked(value)
        } else {
            value.to_string()
        };

        let value_el: Element<'_, Message> = iced::widget::text(shown)
            .size(13.0)
            .color(TEXT_BRIGHT)
            .into();

        let mut row: Vec<Element<'_, Message>> = vec![value_el];

        if secret {
            row.push(icon_button(
                if revealed {
                    icons::Icon::EyeOff
                } else {
                    icons::Icon::Eye
                },
                if revealed { "Hide" } else { "Show" },
                Message::ToggleReveal(key),
                chip_idle,
            ));
        }
        row.push(icon_button(
            icons::Icon::Copy,
            "Copy",
            Message::Copy(label.to_string(), value.to_string()),
            chip_idle,
        ));
        row.push(iced::widget::Space::new().width(Length::Fill).into());

        let line: Element<'_, Message> = iced::widget::row(row).spacing(8.0).align_y(Center).into();
        field(label, line)
    }

    fn view_status(&self) -> Element<'_, Message> {
        let (text, color) = match &self.toast {
            Some((t, _)) => (t.clone(), Color::from_rgb(0.40, 0.85, 0.50)),
            None => match (&self.vault, &self.path) {
                (Some(v), Some(p)) => (
                    format!(
                        "{} · showing {} of {} items · {}",
                        short_path(p),
                        self.entries.len(),
                        v.alive().len(),
                        match v.trashed().len() {
                            0 => format!(
                                "attachments: {}",
                                v.attachments.values().map(Vec::len).sum::<usize>()
                            ),
                            n => format!("in item trash: {n}"),
                        },
                    ),
                    TEXT_DIM,
                ),
                _ => ("No file open".to_string(), TEXT_DIM),
            },
        };

        let label_el: Element<'_, Message> =
            iced::widget::text(text).size(11.0).color(color).into();

        let mut right: Vec<Element<'_, Message>> = Vec::new();

        // Корзина вложений: сколько лежит и чем очистить.
        if self.trash.files > 0 {
            right.push(
                iced::widget::text(format!(
                    "· attachment trash: {}, {}",
                    plural_files(self.trash.files),
                    human_size(self.trash.bytes)
                ))
                .size(11.0)
                .color(TEXT_DIM)
                .into(),
            );
            right.push(
                iced::widget::button(
                    iced::widget::text(if self.trash_armed {
                        "Really clear?"
                    } else {
                        "Empty Trash"
                    })
                    .size(11.0)
                    .color(TEXT),
                )
                .on_press(Message::EmptyTrash)
                .style(if self.trash_armed {
                    chip_danger
                } else {
                    chip_idle
                })
                .into(),
            );
            if self.trash_armed {
                right.push(
                    iced::widget::button(iced::widget::text("Cancel").size(11.0).color(TEXT))
                        .on_press(Message::CancelEmptyTrash)
                        .style(chip_idle)
                        .into(),
                );
            }
        }

        right.push(iced::widget::Space::new().width(Length::Fill).into());

        // Кнопка закрывает всплывающее уведомление, поэтому без него она бессмысленна.
        if self.toast.is_some() {
            right.push(
                iced::widget::button(iced::widget::text("Clear").size(11.0).color(TEXT))
                    .on_press(Message::DismissToast)
                    .style(chip_idle)
                    .into(),
            );
        }

        iced::widget::row({
            let mut all = vec![label_el];
            all.append(&mut right);
            all
        })
        .padding(Padding::new(6.0).horizontal(14.0).vertical(4.0))
        .into()
    }
}

/// Отбирает индексы записей под поисковую строку и фильтр по типу.
///
/// Папки в список не попадают. Поиск регистронезависим и смотрит в название,
/// домен и полный адрес. Записи без названия уходят в конец, иначе пять
/// пустых веб-форм из выгрузки занимали бы весь верх списка.
///
/// `folder` — uuid папки; пустая строка означает «все папки и верхний
/// уровень», а не «только верхний уровень»: так папки работают как фильтр,
/// а не как единственный способ увидеть запись.
fn filter_indices(
    items: &[PifItem],
    query: &str,
    kind: &str,
    trash: bool,
    folder: &str,
) -> Vec<usize> {
    let q = query.trim().to_lowercase();

    let mut out: Vec<usize> = items
        .iter()
        .enumerate()
        .filter(|(_, it)| it.type_name.as_deref() != Some(FOLDER_TYPE))
        // Корзина — отдельный раздел: в обычном списке удалённых записей нет.
        .filter(|(_, it)| it.trashed.unwrap_or(false) == trash)
        .filter(|(_, it)| kind.is_empty() || it.kind() == kind)
        .filter(|(_, it)| folder.is_empty() || it.folder_uuid.as_deref() == Some(folder))
        .filter(|(_, it)| {
            if q.is_empty() {
                return true;
            }
            let hit =
                |v: &Option<String>| v.as_ref().is_some_and(|s| s.to_lowercase().contains(&q));
            hit(&it.title) || hit(&it.location_key) || hit(&it.location)
                // Номер карты, код лицензии и прочее — тоже ищется.
                || it
                    .extra_fields()
                    .iter()
                    .any(|(_, v, _)| v.to_lowercase().contains(&q))
        })
        .map(|(i, _)| i)
        .collect();

    out.sort_by(|&a, &b| {
        let x = items[a].title.as_deref().unwrap_or("").trim();
        let y = items[b].title.as_deref().unwrap_or("").trim();
        match (x.is_empty(), y.is_empty()) {
            (true, true) => std::cmp::Ordering::Equal,
            (true, false) => std::cmp::Ordering::Greater,
            (false, true) => std::cmp::Ordering::Less,
            (false, false) => x.to_lowercase().cmp(&y.to_lowercase()),
        }
    });

    out
}

/// Заголовок для показа: пустая строка в выгрузке равносильна отсутствию.
fn display_title(it: &PifItem) -> String {
    it.title
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .unwrap_or("(untitled)")
        .to_string()
}

/// Поле «ПОДПИСЬ» + содержимое.
fn field<'a>(name: &str, content: Element<'a, Message>) -> Element<'a, Message> {
    iced::widget::column(vec![
        iced::widget::text(name.to_uppercase())
            .size(10.0)
            .color(TEXT_DIM)
            .into(),
        content,
    ])
    .spacing(4.0)
    .into()
}

/// Строка «подпись: значение» с кнопкой копирования.
/// Кнопка со значком вместо подписи.
///
/// Подпись убрана, чтобы рядом со значением не стояло лишнего текста. Имя
/// действия возвращается подсказкой: без неё значок пришлось бы угадывать, а
/// у canvas-интерфейса нет другого способа объявить, что кнопка делает.
fn icon_button<'a>(
    mark: icons::Icon,
    tip: &'a str,
    msg: Message,
    style: fn(&Theme, iced::widget::button::Status) -> iced::widget::button::Style,
) -> Element<'a, Message> {
    let button = iced::widget::button(icons::icon(mark, ICON_FIELD_SIZE, TEXT))
        .on_press(msg)
        .style(style);

    iced::widget::Tooltip::new(
        button,
        iced::widget::text(tip.to_string()).size(11.0).color(TEXT),
        iced::widget::tooltip::Position::Bottom,
    )
    .into()
}

/// То же, что [`icon_button`], но крупнее: кнопки тулбара стоят в строке
/// заголовка и должны читаться наравне с ним.
#[allow(clippy::too_many_arguments)]
fn toolbar_icon_button<'a>(
    mark: icons::Icon,
    tip: &'a str,
    msg: Message,
    style: fn(&Theme, iced::widget::button::Status) -> iced::widget::button::Style,
) -> Element<'a, Message> {
    // Размер задаёт содержимое, а не сама кнопка. У кнопки height()
    // ограничен лимитами родителя и в строке тулбара отрабатывает как
    // «не больше, чем дали», поэтому кнопка оставалась в 23 px. Контейнер
    // внутри задаёт размер напрямую, и кнопка становится ровно такой.
    // Отступ нулевой, чтобы не прибавлять к высоте лишние пиксели.
    let button = iced::widget::button(
        iced::widget::container(icons::icon_thin(mark, ICON_BUTTON_SIZE, TEXT))
            .width(Length::Fixed(TOOLBAR_BTN_W))
            .height(Length::Fixed(TOOLBAR_H))
            .align_x(Center)
            .align_y(Center),
    )
    .padding(Padding::new(0.0))
    .on_press(msg)
    .style(style);

    iced::widget::Tooltip::new(
        button,
        iced::widget::text(tip.to_string()).size(11.0).color(TEXT),
        iced::widget::tooltip::Position::Bottom,
    )
    .into()
}

fn copy_row<'a>(name: &str, value: &str, copy: Message) -> Element<'a, Message> {
    let value_el: Element<'a, Message> = iced::widget::text(value.to_string())
        .size(13.0)
        .color(TEXT_BRIGHT)
        .into();
    let btn: Element<'a, Message> = icon_button(icons::Icon::Copy, "Copy", copy, chip_idle);
    let line: Element<'a, Message> = iced::widget::row(vec![
        value_el,
        btn,
        iced::widget::Space::new().width(Length::Fill).into(),
    ])
    .spacing(8.0)
    .align_y(Center)
    .into();
    field(name, line)
}

fn center_text(s: &'static str) -> Element<'static, Message> {
    iced::widget::center(iced::widget::text(s).size(14.0).color(TEXT_DIM))
        .width(Length::Fill)
        .height(Length::Fill)
        .into()
}

fn chip_idle(_t: &Theme, s: iced::widget::button::Status) -> iced::widget::button::Style {
    let bg = match s {
        iced::widget::button::Status::Hovered | iced::widget::button::Status::Pressed => {
            Color::from_rgb(0.20, 0.28, 0.40)
        }
        _ => Color::from_rgb(0.14, 0.16, 0.20),
    };
    iced::widget::button::Style::default().with_background(bg)
}

/// Кнопка тулбара. Отступ задан явно: у кнопки по умолчанию он такой, что
/// значок внутри сжимается и перестаёт читаться наравне с полем поиска.
fn chip_toolbar(_t: &Theme, s: iced::widget::button::Status) -> iced::widget::button::Style {
    // Плашки нет: кнопка показывает тот же градиент, что и полоса. Свой
    // серый фон выглядел бы вставленным чужеродным прямоугольником.
    // Под наведением проступает лёгкая подсветка, иначе нажать не на что.
    match s {
        // Подсветка под наведением едва различима: кнопка должна читаться
        // как нажимаемая, но не выглядеть плашкой поверх градиента.
        iced::widget::button::Status::Hovered => iced::widget::button::Style::default()
            .with_background(Color::from_rgba(1.0, 1.0, 1.0, 0.07)),
        _ => iced::widget::button::Style::default(),
    }
}

fn chip_active(_t: &Theme, _s: iced::widget::button::Status) -> iced::widget::button::Style {
    iced::widget::button::Style::default().with_background(Color::from_rgb(0.20, 0.40, 0.75))
}

fn row_idle(_t: &Theme, s: iced::widget::button::Status) -> iced::widget::button::Style {
    let bg = match s {
        iced::widget::button::Status::Hovered | iced::widget::button::Status::Pressed => {
            Color::from_rgb(0.16, 0.18, 0.22)
        }
        _ => Color::from_rgba(0.0, 0.0, 0.0, 0.0),
    };
    iced::widget::button::Style::default().with_background(bg)
}

fn row_active(_t: &Theme, _s: iced::widget::button::Status) -> iced::widget::button::Style {
    iced::widget::button::Style::default().with_background(Color::from_rgb(0.15, 0.19, 0.26))
}

/// Картинка, вписанная в квадрат `side`.
fn thumbnail(path: &std::path::Path, side: f32) -> iced::widget::Image {
    iced::widget::image(iced::widget::image::Handle::from_path(path.to_path_buf()))
        .width(Length::Fixed(side))
        .height(Length::Fixed(side))
        .content_fit(iced::ContentFit::Contain)
        .filter_method(iced::widget::image::FilterMethod::Linear)
}

/// Похоже ли содержимое файла на картинку.
///
/// Решение по расширению, а не по содержимому: `iced` сам разбирает формат по
/// данным, но показывать превью имеет смысл только для заведомо поддерживаемых
/// расширений. `heic` сюда не входит — `iced` его не декодирует, и вместо
/// картинки получился бы пустой прямоугольник.
fn is_image(path: &std::path::Path) -> bool {
    let Some(ext) = path
        .extension()
        .map(|e| e.to_string_lossy().to_ascii_lowercase())
    else {
        return false;
    };
    matches!(
        ext.as_str(),
        "jpg" | "jpeg" | "png" | "gif" | "bmp" | "webp" | "tif" | "tiff" | "ico" | "pnm" | "tga"
    )
}

/// Текст уведомления о прикреплении файлов.
fn attach_toast(added: usize, failed: &[String]) -> String {
    if failed.is_empty() {
        format!("{} attached, remember to save", plural_files(added))
    } else if added == 0 {
        "cannot attach the files".to_string()
    } else {
        format!(
            "attached {}, failed: {}",
            plural_files(added),
            failed.join(", ")
        )
    }
}

/// Тип записи по значению `typeName`, как он приходит из выгрузки.
///
/// Неизвестный тип трактуется как логин: это самый безобидный вариант, поле
/// `designation` у него читается однозначно.
fn item_kind_of(type_name: &Option<String>) -> opclient_core::pif::ItemKind {
    use opclient_core::pif::ItemKind;

    ItemKind::all()
        .into_iter()
        .find(|k| Some(k.type_name()) == type_name.as_deref())
        .unwrap_or(ItemKind::Login)
}

/// «1 file», «2 files».
///
/// По-русски здесь была тройная форма — «файл», «файла», «файлов», — и
/// приходилось считать по последним цифрам. По-английски различие только
/// между единицей и всем остальным, поэтому и функция стала короче.
fn plural_files(n: usize) -> String {
    if n == 1 {
        "1 file".to_string()
    } else {
        format!("{n} files")
    }
}

/// «3 MB».
fn human_size(bytes: u64) -> String {
    opclient_core::pif::human_size(bytes)
}

fn truncate(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        s.to_string()
    } else {
        let t: String = s.chars().take(max.saturating_sub(1)).collect();
        format!("{t}…")
    }
}

fn masked(v: &str) -> String {
    let n = v.chars().count();
    if n <= 6 {
        return "•".repeat(n);
    }
    let head: String = v.chars().take(3).collect();
    let tail: String = v.chars().skip(n - 2).collect();
    format!("{head}{}{tail}", "•".repeat((n - 5).min(20)))
}

/// Сколько знаков пути помещается в тулбар до поля поиска.
///
/// Бюджет в знаках, а не в пикселях: `iced` не даёт измерить ширину текста
/// из `view`, а без ограничения длинное имя файла переносит путь на вторую
/// строку и ломает высоту полосы.
const PATH_MAX_CHARS: usize = 46;

/// Обрезает строку по длине, сохраняя начало и конец.
///
/// Конец важнее начала: в пути это имя файла, ради которого строку читают.
fn ellipsize(s: &str, max: usize) -> String {
    let n = s.chars().count();
    if n <= max || max < 3 {
        return s.to_string();
    }
    let head = (max - 1) * 2 / 3;
    let tail = max - 1 - head;
    let mut out: String = s.chars().take(head).collect();
    out.push('…');
    out.extend(s.chars().skip(n - tail));
    out
}

/// Схлопывает длинный путь до «…/папка/файл».
fn short_path(p: &std::path::Path) -> String {
    let s = p.to_string_lossy().to_string();
    let parts: Vec<&str> = s.rsplitn(3, '/').collect();
    if parts.len() == 3 {
        format!("…/{}/{}", parts[1], parts[0])
    } else {
        s
    }
}

/// Открывает файл связанной программой macOS.
#[cfg(target_os = "macos")]
fn open_in_finder(path: &std::path::Path) -> bool {
    std::process::Command::new("open").arg(path).spawn().is_ok()
}

#[cfg(not(target_os = "macos"))]
fn open_in_finder(_path: &std::path::Path) -> bool {
    false
}

/// Строка формы: подпись и поле ввода.
fn input_row<'a>(name: &'a str, value: &str, key: &'static str) -> Element<'a, Message> {
    let input: Element<'a, Message> = iced::widget::text_input(name, value)
        .on_input(move |v| Message::DraftChanged(key, v.clone()))
        .width(Length::Fill)
        .into();
    field(name, input)
}

fn chip_danger(_t: &Theme, _s: iced::widget::button::Status) -> iced::widget::button::Style {
    iced::widget::button::Style::default().with_background(Color::from_rgb(0.55, 0.15, 0.15))
}

const TEXT: Color = Color::from_rgb(0.86, 0.88, 0.92);
const TEXT_BRIGHT: Color = Color::from_rgb(1.0, 1.0, 1.0);
const TEXT_DIM: Color = Color::from_rgb(0.48, 0.52, 0.58);
/// Предупреждение о несохранённых изменениях.
const TEXT_WARN: Color = Color::from_rgb(0.95, 0.72, 0.30);

// Поверхности. Боковая панель и тулбар в macOS 27 выглядят как одна
// непрерывнаяmaterial-поверхность, разделённая волосяной линией, поэтому
// фон у них один и тот же — иначе стык сразу бросается в глаза.
const SURFACE: Color = Color::from_rgb(0.113, 0.125, 0.149);
/// Основное поле: чуть светлее, чтобы панели читались как выемки.
const SURFACE_RAISED: Color = Color::from_rgb(0.141, 0.156, 0.184);
/// Волосяная линия между панелью и содержимым.
const HAIRLINE: Color = Color::from_rgba(1.0, 1.0, 1.0, 0.07);

/// Левый край полосы заголовка: #4065b9.
const TOOLBAR_LEFT: Color = Color::from_rgb(0.251, 0.396, 0.725);

/// Правый край полосы заголовка: #0d122c.
const TOOLBAR_RIGHT: Color = Color::from_rgb(0.051, 0.071, 0.173);

/// Направление градиента в градусах: 90° — слева направо, 135° — из
/// левого верхнего угла в правый нижний.
///
/// Градиент принимает радианы, поэтому градусы переводятся явно. Раньше
/// здесь стояло голое число 90, то есть 90 радиан, и направление
/// получалось случайным.
const TOOLBAR_GRADIENT_DEG: f32 = 135.0;

/// Фон тулбара: переход от #4065b9 в левом верхнем углу к #0d122c в
/// правом нижнем.
fn toolbar_background() -> iced::Background {
    iced::Background::Gradient(iced::Gradient::Linear(
        iced::gradient::Linear::new(TOOLBAR_GRADIENT_DEG.to_radians())
            .add_stop(0.0, TOOLBAR_LEFT)
            .add_stop(1.0, TOOLBAR_RIGHT),
    ))
}

// Кегли. Размеры текста в интерфейсе разбросаны по коду десятками магических
// чисел; macOS держит шкалу фиксированной, и без неё сходятся только
// заголовки, а мелкий текст — нет.
mod type_scale {
    /// Заголовок окна и крупные названия.
    pub const LARGE: f32 = 20.0;
    /// Заголовок панели.
    pub const TITLE: f32 = 15.0;
    /// Обычный текст строк.
    pub const BODY: f32 = 13.0;
    /// Второстепенный текст: счётчики, подписи полей.
    pub const SECONDARY: f32 = 11.0;
    /// Заголовки секций в боковой панели.
    pub const CAPTION: f32 = 10.0;
}

#[cfg(target_os = "macos")]
fn copy_to_clipboard(text: &str) -> bool {
    arboard::Clipboard::new()
        .and_then(|mut c| c.set_text(text.to_owned()))
        .is_ok()
}

#[cfg(not(target_os = "macos"))]
fn copy_to_clipboard(_text: &str) -> bool {
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Перетаскивание границы меняет ширину панели списка на смещение
    /// указателя, а не на его абсолютную координату.
    #[test]
    fn перетаскивание_меняет_ширину_списка() {
        let mut app = App::blank();
        assert_eq!(app.list_width, LIST_WIDTH_DEFAULT);

        let _ = app.update(Message::ResizeStart);
        // Первое движение только запоминает точку опоры, ширину не трогая.
        let _ = app.update(Message::ResizeMove(100.0));
        assert_eq!(app.list_width, LIST_WIDTH_DEFAULT);

        let _ = app.update(Message::ResizeMove(160.0));
        assert_eq!(app.list_width, LIST_WIDTH_DEFAULT + 60.0);

        // Движение влево уменьшает, и обратно без рывка.
        let _ = app.update(Message::ResizeMove(110.0));
        assert_eq!(app.list_width, LIST_WIDTH_DEFAULT + 10.0);
    }

    /// Ширина не уезжает за пределы: узкий список и зажатая правую панель
    /// бесполезны обе.
    #[test]
    fn ширина_списка_ограничена() {
        let mut app = App::blank();
        let _ = app.update(Message::ResizeStart);
        let _ = app.update(Message::ResizeMove(0.0));

        let _ = app.update(Message::ResizeMove(5000.0));
        assert_eq!(app.list_width, LIST_WIDTH_MAX);

        let _ = app.update(Message::ResizeMove(-5000.0));
        assert_eq!(app.list_width, LIST_WIDTH_MIN);
    }

    /// После отпускания указателя список перестаёт меняться.
    #[test]
    fn после_отпускания_список_не_двигается() {
        let mut app = App::blank();
        let _ = app.update(Message::ResizeStart);
        let _ = app.update(Message::ResizeMove(100.0));
        let _ = app.update(Message::ResizeMove(200.0));
        let width = app.list_width;

        let _ = app.update(Message::GlobalRelease);
        let _ = app.update(Message::ResizeMove(400.0));
        assert_eq!(app.list_width, width, "список изменился без перетаскивания");
    }

    /// У правой панели тоже есть минимум: список нельзя растянуть до
    /// окна и закрыть всё, ради чего он растягивается.
    #[test]
    fn у_правой_панели_есть_минимум() {
        let mut app = App::blank();
        let _ = app.update(Message::WindowResized(1000.0));

        let _ = app.update(Message::ResizeStart);
        let _ = app.update(Message::ResizeMove(0.0));
        let _ = app.update(Message::ResizeMove(5000.0));

        let panel3 = 1000.0 - SIDEBAR_W - 1.0 - RESIZE_HANDLE_W - app.list_width;
        assert_eq!(panel3, PANEL3_MIN, "правая панель схлопнулась");
        assert!(app.list_width < 1000.0, "список занял всё окно");
    }

    /// Узкое окно не должно ломать расчёт: минимумы просто сталкиваются.
    #[test]
    fn узкое_окно_не_ломает_ширину() {
        let mut app = App::blank();
        let _ = app.update(Message::WindowResized(200.0));

        let _ = app.update(Message::ResizeStart);
        let _ = app.update(Message::ResizeMove(0.0));
        let _ = app.update(Message::ResizeMove(9999.0));

        assert_eq!(app.list_width, LIST_WIDTH_MIN);
        assert!(app.list_width.is_finite(), "ширина стала не числом");
    }

    fn item(title: &str, kind: &str, key: Option<&str>) -> PifItem {
        PifItem {
            uuid: title.to_string(),
            type_name: Some(kind.to_string()),
            title: Some(title.to_string()),
            location_key: key.map(str::to_string),
            location: None,
            secure_contents: None,
            contents_hash: None,
            security_level: None,
            created_at: None,
            updated_at: None,
            folder_uuid: None,
            trashed: None,
            open_contents: None,
            tx_timestamp: None,
            raw: String::new(),
            dirty: false,
        }
    }

    #[test]
    fn поиск_по_названию_и_домену_регистронезависим() {
        let items = vec![
            item("GitHub", "webforms.WebForm", Some("github.com")),
            item("Банк", "webforms.WebForm", Some("sberbank.ru")),
        ];
        assert_eq!(filter_indices(&items, "github", "", false, ""), vec![0]);
        assert_eq!(filter_indices(&items, "GITHUB", "", false, ""), vec![0]);
        assert_eq!(filter_indices(&items, "sberbank", "", false, ""), vec![1]);
        assert!(filter_indices(&items, "нет-такого", "", false, "").is_empty());
    }

    #[test]
    fn фильтр_по_типу_работает() {
        let items = vec![
            item("A", "webforms.WebForm", None),
            item("B", "securenotes.SecureNote", None),
            item("C", "webforms.WebForm", None),
        ];
        assert_eq!(filter_indices(&items, "", "Logins", false, ""), vec![0, 2]);
        assert_eq!(
            filter_indices(&items, "", "Secure Notes", false, ""),
            vec![1]
        );
        assert_eq!(filter_indices(&items, "", "", false, "").len(), 3);
    }

    #[test]
    fn папки_не_попадают_в_список() {
        let items = vec![
            item("Личное", FOLDER_TYPE, None),
            item("Запись", "webforms.WebForm", None),
        ];
        assert_eq!(filter_indices(&items, "", "", false, ""), vec![1]);
    }

    #[test]
    fn пустые_заголовки_уходят_в_конец() {
        let items = vec![
            item("", "webforms.WebForm", None),
            item("", "webforms.WebForm", None),
            item("Alpha", "webforms.WebForm", None),
            item("Beta", "webforms.WebForm", None),
        ];
        assert_eq!(filter_indices(&items, "", "", false, ""), vec![2, 3, 0, 1]);
    }

    #[test]
    fn маска_пароля_не_выдаёт_середину() {
        // 16 символов: 3 первых + 11 точек (16-5) + 2 последних
        assert_eq!(masked("gu3SecretValue99"), "gu3•••••••••••99");
        assert_eq!(masked("abc"), "•••");
        assert_eq!(masked(""), "");
        // длинный пароль не превращается в простыню точек
        assert_eq!(
            masked(&"x".repeat(100))
                .chars()
                .filter(|c| *c == '•')
                .count(),
            20
        );
    }

    #[test]
    fn путь_схлопывается() {
        assert_eq!(
            short_path(std::path::Path::new(
                "/Users/x/Downloads/1Password (5).1pif/data.1pif"
            )),
            "…/1Password (5).1pif/data.1pif"
        );
    }

    #[test]
    fn без_файла_список_пуст() {
        let app = App::blank();
        assert!(app.vault.is_none());
        assert!(app.entries.is_empty());
        // Категории берутся из хранилища: без файла их быть не должно.
        assert!(app.kind_counts().is_empty());
    }
}

#[cfg(test)]
mod wallet_view_tests {
    use super::*;

    fn card() -> PifItem {
        let raw = r#"{"uuid":"C1","typeName":"wallet.financial.CreditCard","title":"Кредитная карта","secureContents":{"cardholder":"Vitalii","ccnum":"5314451117033352","cvv":"712"}}"#;
        Pif::parse(raw).unwrap().items.remove(0)
    }

    #[test]
    fn карта_находится_по_номеру() {
        let items = vec![card()];
        assert_eq!(filter_indices(&items, "5314451", "", false, ""), vec![0]);
        assert_eq!(filter_indices(&items, "карта", "", false, ""), vec![0]);
        assert!(filter_indices(&items, "9999", "", false, "").is_empty());
    }

    #[test]
    fn карта_фильтруется_по_типу() {
        let items = vec![card()];
        assert_eq!(
            filter_indices(&items, "", "Credit Cards", false, ""),
            vec![0]
        );
        assert!(filter_indices(&items, "", "Logins", false, "").is_empty());
    }
}

#[cfg(test)]
mod render_tests {
    use super::*;

    /// Приложение с одним файлом во временном каталоге.
    fn app_with(name: &str, contents: &str) -> (App, PathBuf) {
        let path = std::env::temp_dir().join(format!("opclient-render-{name}.1pif"));
        std::fs::write(&path, contents).unwrap();
        let mut app = App::blank();
        assert!(app.open(path.clone()), "файл должен открыться");
        (app, path)
    }

    /// Извлечение закрывает хранилище и чистит всё, что к нему относилось.
    #[test]
    fn извлечение_закрывает_хранилище() {
        let (mut app, path) = app_with("eject", "{\"uuid\":\"U1\",\"typeName\":\"webforms.WebForm\",\"title\":\"Demo\",\"secureContents\":{}}");
        assert!(app.vault.is_some());

        let _ = app.update(Message::EjectVault);

        assert!(app.vault.is_none(), "хранилище осталось открытым");
        assert!(app.path.is_none(), "путь остался в состоянии");
        assert!(app.entries.is_empty(), "список остался непустым");
        let _ = std::fs::remove_file(path);
    }

    /// С несохранёнными правками извлечение не проходит: они живут в
    /// памяти и потерялись бы молча.
    #[test]
    fn извлечение_не_теряет_правки() {
        let (mut app, path) = app_with("eject-dirty", "{\"uuid\":\"U1\",\"typeName\":\"webforms.WebForm\",\"title\":\"Demo\",\"secureContents\":{}}");
        app.vault.as_mut().unwrap().items[0].dirty = true;
        assert!(app.has_changes());

        let _ = app.update(Message::EjectVault);

        assert!(
            app.vault.is_some(),
            "хранилище закрылось несмотря на правки"
        );
        let _ = std::fs::remove_file(path);
    }

    const CARD: &str = r#"{"uuid":"C1","typeName":"wallet.financial.CreditCard","title":"Кредитная карта","secureContents":{"cardholder":"Vitalii","ccnum":"5314451117033352","cvv":"712","expiry_mm":"9","expiry_yy":"2016"}}
{"uuid":"W1","typeName":"webforms.WebForm","title":"Website","secureContents":{"fields":[{"name":"username","type":"T","designation":"username","value":"me"},{"name":"password","type":"P","designation":"password","value":"pw"}]}}"#;

    /// Вид карты должен собираться: раньше эти данные вообще не читались.
    #[test]
    fn вид_карты_собирается() {
        let (app, path) = app_with("card-view", CARD);
        let it = app
            .vault
            .as_ref()
            .unwrap()
            .items
            .iter()
            .find(|i| i.kind() == "Credit Cards")
            .unwrap()
            .clone();

        let _element = app.view_details(&it);
        let _ = std::fs::remove_file(path);
    }

    /// Вид всей страницы на данных кошелька тоже должен собираться.
    #[test]
    fn страница_собирается() {
        let (app, path) = app_with("page", CARD);
        let _element = app.view();
        let _ = std::fs::remove_file(path);
    }

    /// После открытия нового файла раскрытые пароли не должны сохраняться.
    #[test]
    fn открытие_нового_файла_сбрасывает_раскрытое() {
        let (mut app, path) = app_with("reset", CARD);
        app.revealed.insert("C1::Пароль".into(), true);
        assert!(app.open(path.clone()));
        assert!(app.revealed.is_empty(), "раскрытые пароли надо сбросить");
        let _ = std::fs::remove_file(path);
    }
}

#[cfg(test)]
mod tests_common {
    use std::path::PathBuf;

    /// Каталог, уникальный для каждого вызова в этом процессе.
    /// pid у параллельных тестов общий, поэтому нужен счётчик.
    pub fn unique_dir(prefix: &str) -> PathBuf {
        use std::sync::atomic::{AtomicUsize, Ordering};
        static N: AtomicUsize = AtomicUsize::new(0);
        let n = N.fetch_add(1, Ordering::Relaxed);
        std::env::temp_dir().join(format!("{prefix}-{}-{n}", std::process::id()))
    }
}

#[cfg(test)]
mod attachment_view_tests {
    use super::tests_common::*;
    use super::*;

    /// Экспорт с одним вложением рядом с data.1pif.
    fn export_with_attachment() -> PathBuf {
        let root = unique_dir("opclient-ui-att");
        let _ = std::fs::remove_dir_all(&root);
        let dir = root
            .join("attachments")
            .join("AAAA1111BBBB2222CCCC3333DDDD4444");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("invoice.pdf"), b"%PDF-1.4 test").unwrap();
        std::fs::write(
            root.join("data.1pif"),
            "{\"uuid\":\"AAAA1111BBBB2222CCCC3333DDDD4444\",\"typeName\":\"securenotes.SecureNote\",\"title\":\"Счёт\",\"secureContents\":{\"notesPlain\":\"n\"}}",
        )
        .unwrap();
        root.join("data.1pif")
    }

    #[test]
    fn вложение_находится_для_записи() {
        let path = export_with_attachment();
        let mut app = App::blank();
        assert!(app.open(path.clone()));

        let files = app
            .attachments_of("AAAA1111BBBB2222CCCC3333DDDD4444")
            .unwrap();
        assert_eq!(files.len(), 1);
        assert_eq!(files[0].name, "invoice.pdf");
        assert!(files[0].path.exists());

        // вид записи с вложением должен собираться
        let it = app.vault.as_ref().unwrap().items[0].clone();
        let _element = app.view_details(&it);

        let _ = std::fs::remove_dir_all(path.parent().unwrap());
    }

    #[test]
    fn у_записи_без_вложений_пусто() {
        let path = export_with_attachment();
        let mut app = App::blank();
        app.open(path.clone());
        assert!(app.attachments_of("НЕТ-ТАКОЙ").is_none());
        let _ = std::fs::remove_dir_all(path.parent().unwrap());
    }
}

#[cfg(test)]
mod editing_tests {
    use super::tests_common::*;
    use super::*;

    /// Приложение с копией настоящего экспорта (либо с крошечной заглушкой).
    fn app_with_export(tag: &str) -> (App, PathBuf) {
        let src = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../../golden")
            .join("1Password 2026-10-13, 03_54 PM (533 items and 2 folders).1pif/data.1pif");
        let root = unique_dir(&format!("opclient-ui-{tag}"));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        let file = root.join("data.1pif");
        if src.exists() {
            std::fs::copy(&src, &file).unwrap();
        } else {
            std::fs::write(&file, "{\"uuid\":\"U1\",\"typeName\":\"securenotes.SecureNote\",\"title\":\"A\",\"secureContents\":{}}\n").unwrap();
        }
        let mut app = App::blank();
        assert!(app.open(file.clone()));
        (app, root)
    }

    #[test]
    fn новая_запись_создаётся_и_сохраняется() {
        let (mut app, root) = app_with_export("create");
        let before = app.vault.as_ref().unwrap().items.len();

        let _ = app.update(Message::StartCreate);
        assert!(app.editing.is_some(), "форма должна открыться");
        let _ = app.update(Message::DraftChanged("title", "Новый вход".into()));
        let _ = app.update(Message::DraftChanged("username", "user@example.com".into()));
        let _ = app.update(Message::DraftChanged("password", "pass-1234".into()));
        let _ = app.update(Message::DraftChanged(
            "url",
            "https://example.com/login".into(),
        ));
        let _ = app.update(Message::ApplyEdit);

        assert!(app.editing.is_none(), "форма должна закрыться");
        assert!(app.has_changes(), "появились несохранённые изменения");
        assert_eq!(app.vault.as_ref().unwrap().items.len(), before + 1);

        let _ = app.update(Message::SaveFile);
        assert!(!app.has_changes(), "после сохранения правок не остаётся");

        let again = Pif::from_file(root.join("data.1pif")).unwrap();
        let created = again
            .items
            .iter()
            .find(|i| i.title.as_deref() == Some("Новый вход"))
            .expect("запись должна пережить сохранение");
        assert_eq!(created.primary_password(), Some("pass-1234"));
        assert_eq!(created.usernames(), vec!["user@example.com"]);

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn правка_существующей_записи() {
        let (mut app, root) = app_with_export("edit");
        let _ = app.update(Message::Select(1));
        let uuid = app.selected_item().unwrap().uuid.clone();

        let _ = app.update(Message::StartEdit);
        let editing = app.editing.as_ref().unwrap();
        assert_eq!(editing.uuid.as_deref(), Some(uuid.as_str()));

        let _ = app.update(Message::DraftChanged("password", "совсем-другой".into()));
        let _ = app.update(Message::ApplyEdit);
        let _ = app.update(Message::SaveFile);

        let again = Pif::from_file(root.join("data.1pif")).unwrap();
        let it = again.find(&uuid).expect("запись должна остаться");
        assert_eq!(it.primary_password(), Some("совсем-другой"));

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn отмена_правки_ничего_не_меняет() {
        let (mut app, root) = app_with_export("cancel");
        let _ = app.update(Message::Select(2));
        let uuid = app.selected_item().unwrap().uuid.clone();
        let was = app
            .vault
            .as_ref()
            .unwrap()
            .find(&uuid)
            .unwrap()
            .primary_password()
            .map(str::to_string);

        let _ = app.update(Message::StartEdit);
        let _ = app.update(Message::DraftChanged(
            "password",
            "НЕ ДОЛЖНО ЗАПИСАТЬСЯ".into(),
        ));
        let _ = app.update(Message::CancelEdit);

        assert!(app.editing.is_none());
        assert!(!app.has_changes(), "отмена не должна оставлять изменений");
        assert_eq!(
            app.vault
                .as_ref()
                .unwrap()
                .find(&uuid)
                .unwrap()
                .primary_password()
                .map(str::to_string),
            was
        );

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn удаление_требует_подтверждения() {
        let (mut app, root) = app_with_export("delete");
        let _ = app.update(Message::Select(1));
        let uuid = app.selected_item().unwrap().uuid.clone();

        let _ = app.update(Message::StartEdit);
        let _ = app.update(Message::DeleteItem);
        assert!(app.editing.as_ref().unwrap().confirm_delete);
        let _ = app.update(Message::ConfirmDelete(false));
        assert!(
            !app.editing.as_ref().unwrap().confirm_delete,
            "отмена снимает вопрос"
        );
        assert!(app.vault.as_ref().unwrap().find(&uuid).is_some());

        let _ = app.update(Message::StartEdit);
        let _ = app.update(Message::DeleteItem);
        let _ = app.update(Message::ConfirmDelete(true));
        let _ = app.update(Message::ApplyEdit);
        assert!(
            app.vault.as_ref().unwrap().find(&uuid).is_none(),
            "после подтверждения запись должна исчезнуть"
        );

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn форма_и_страница_собираются() {
        let (app, root) = app_with_export("render");
        let mut app = app;
        let _ = app.update(Message::Select(0));
        let _ = app.view();

        let _ = app.update(Message::StartEdit);
        let _ = app.view_editor();
        let _ = app.view();

        let _ = app.update(Message::StartCreate);
        let _ = app.view_editor();

        let _ = app.update(Message::DeleteItem);
        let _ = app.view_editor();

        let _ = std::fs::remove_dir_all(&root);
    }

    /// Кнопка сохранения появляется только при несохранённых правках.
    #[test]
    fn кнопка_сохранения_появляется_по_необходимости() {
        let (mut app, root) = app_with_export("button");
        assert!(!app.has_changes());
        let _ = app.update(Message::StartCreate);
        let _ = app.update(Message::DraftChanged("title", "X".into()));
        let _ = app.update(Message::ApplyEdit);
        assert!(app.has_changes());
        let _ = app.update(Message::SaveFile);
        assert!(!app.has_changes());
        let _ = std::fs::remove_dir_all(&root);
    }

    /// Экспорт с записями разных видов, одной удалённой и папкой.
    fn app_with_kinds(tag: &str) -> (App, PathBuf) {
        let root = unique_dir(tag);
        std::fs::create_dir_all(&root).unwrap();
        let rows = [
            ("U1", "webforms.WebForm", "Adobe", false),
            ("U2", "securenotes.SecureNote", "Банк", false),
            ("U3", "webforms.WebForm", "Alibaba", false),
            ("U4", "webforms.WebForm", "Удалённая", true),
            ("U5", FOLDER_TYPE, "Folder", false),
        ];
        let text: String = rows
            .iter()
            .map(|(uuid, ty, title, trashed)| {
                format!(
                    r#"{{"uuid":"{uuid}","typeName":"{ty}","title":"{title}","trashed":{trashed}}}"#,
                )
            })
            .collect::<Vec<_>>()
            .join("\n")
            + "\n";
        std::fs::write(root.join("data.1pif"), text).unwrap();

        let mut app = App::blank();
        assert!(app.open(root.join("data.1pif")));
        (app, root)
    }

    /// Счётчики категорий считают только живые записи и не папки.
    #[test]
    fn счётчики_категорий_считают_живое() {
        let (app, root) = app_with_kinds("sidebar-counts");

        let counts = app.kind_counts();
        let web = counts.iter().find(|(k, _)| k == "Logins").map(|(_, c)| *c);
        assert_eq!(web, Some(2), "две живые веб-формы");

        assert!(
            !counts.iter().any(|(k, _)| k == "Folder"),
            "папки в категориях быть не должно"
        );
        assert_eq!(
            counts.iter().map(|(_, c)| c).sum::<usize>(),
            3,
            "удалённая запись в счётчики не попадает"
        );

        let _ = std::fs::remove_dir_all(&root);
    }

    /// Корзина — взаимоисключающий раздел с категориями.
    #[test]
    fn корзина_снимает_фильтр_по_виду() {
        let (mut app, root) = app_with_kinds("sidebar-trash");

        let _ = app.update(Message::Filter("Logins".into()));
        assert_eq!(app.kind_filter, "Logins");

        let _ = app.update(Message::ShowTrash(true));
        assert!(app.show_trash);
        assert!(
            app.kind_filter.is_empty(),
            "в корзине показываются записи всех видов сразу"
        );

        let _ = std::fs::remove_dir_all(&root);
    }

    /// Возврат из корзины тоже снимает фильтр.
    #[test]
    fn возврат_из_корзины_снимает_фильтр() {
        let (mut app, root) = app_with_kinds("sidebar-back");

        let _ = app.update(Message::ShowTrash(true));
        let _ = app.update(Message::Filter("Logins".into()));
        let _ = app.update(Message::ShowTrash(false));

        assert!(!app.show_trash);
        assert!(app.kind_filter.is_empty());
        assert!(
            !app.entries.is_empty(),
            "после возврата список снова наполнен"
        );

        let _ = std::fs::remove_dir_all(&root);
    }

    /// Категории сходятся по алфавиту и повторный щелчок снимает фильтр.
    #[test]
    fn категории_упорядочены_и_переключаются() {
        let (mut app, root) = app_with_kinds("sidebar-order");

        let kinds: Vec<String> = app.kind_counts().into_iter().map(|(k, _)| k).collect();
        let mut sorted = kinds.clone();
        sorted.sort();
        assert_eq!(kinds, sorted, "категории идут по алфавиту");

        let first = kinds.first().cloned().unwrap();
        let _ = app.update(Message::Filter(first.clone()));
        assert_eq!(app.kind_filter, first);
        assert!(!app.entries.is_empty(), "категория что-то показывает");

        let _ = app.update(Message::Filter(first));
        assert!(
            app.kind_filter.is_empty(),
            "повторный щелчок снимает фильтр"
        );

        let _ = std::fs::remove_dir_all(&root);
    }

    /// Боковая панель и список с разделителями собираются.
    #[test]
    fn панель_и_разделители_собираются() {
        let (mut app, root) = app_with_kinds("sidebar-render");
        let _ = app.view_sidebar();
        let _ = app.view_list();
        let _ = app.view_browser();
        let _ = app.update(Message::Select(0));
        let _ = app.view_browser();

        let _ = std::fs::remove_dir_all(&root);
    }

    /// Созданное хранилище сразу становится текущим и пустым.
    #[test]
    fn новое_хранилище_открывается_пустым() {
        let dir = unique_dir("create-ui");
        let vault = Pif::create(&dir).unwrap();

        let mut app = App::blank();
        app.open_created(&dir, vault);

        assert!(app.error.is_none());
        assert_eq!(app.path, Some(dir.join("data.1pif")));
        assert!(app.entries.is_empty(), "список пока пуст");
        assert!(app.kind_counts().is_empty(), "категорий пока нет");
        assert!(!app.show_trash, "корзина закрыта");
        assert!(app.kind_filter.is_empty(), "фильтр сброшен");

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// В новом хранилище можно создать запись и сохранить её на диск.
    #[test]
    fn в_новом_хранилище_создаётся_запись() {
        let dir = unique_dir("create-record");
        let vault = Pif::create(&dir).unwrap();

        let mut app = App::blank();
        app.open_created(&dir, vault);
        let _ = app.update(Message::StartCreate);
        assert!(app.editing.is_some());

        let _ = app.update(Message::DraftChanged("title", "Первый вход".into()));
        let _ = app.update(Message::DraftChanged("username", "user".into()));
        let _ = app.update(Message::DraftChanged("password", "pass".into()));
        let _ = app.update(Message::ApplyEdit);

        assert_eq!(app.entries.len(), 1, "запись появилась в списке");
        assert!(app.has_changes(), "есть что сохранять");

        let _ = app.update(Message::SaveFile);
        assert!(!app.has_changes(), "после сохранения всё чисто");

        let reread = Pif::from_file(dir.join("data.1pif")).unwrap();
        assert_eq!(
            reread
                .items
                .iter()
                .filter(|i| i.title.as_deref() == Some("Первый вход"))
                .count(),
            1,
            "запись пережила сохранение и переоткрытие"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Стартовый экран и тулбар предлагают создать хранилище.
    #[test]
    fn создание_доступно_с_обоих_экранов() {
        let mut app = App::blank();
        let _ = app.view();

        // С файлом открытым тулбар тоже предлагает создать новое хранилище.
        let dir = unique_dir("create-toolbar");
        let vault = Pif::create(&dir).unwrap();
        app.open_created(&dir, vault);
        let _ = app.view_toolbar();

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Экспорт с двумя папками: в одной лежит запись, в другой нет.
    fn app_with_folders(tag: &str) -> (App, PathBuf) {
        let root = unique_dir(tag);
        std::fs::create_dir_all(&root).unwrap();
        let rows = [
            r#"{"uuid":"F1","typeName":"system.folder.Regular","title":"Work","secureContents":{}}"#,
            r#"{"uuid":"F2","typeName":"system.folder.Regular","title":"EMails","secureContents":{}}"#,
            r#"{"uuid":"U1","typeName":"webforms.WebForm","title":"GitHub","folderUuid":"F1","secureContents":{}}"#,
            r#"{"uuid":"U2","typeName":"webforms.WebForm","title":"Forum","secureContents":{}}"#,
        ]
        .join("\n");
        std::fs::write(root.join("data.1pif"), format!("{rows}\n")).unwrap();

        let mut app = App::blank();
        assert!(app.open(root.join("data.1pif")));
        (app, root)
    }

    /// Папки видны в боковой панели со своими счётчиками.
    #[test]
    fn папки_показываются_со_счётчиками() {
        let (app, root) = app_with_folders("folders-panel");

        assert_eq!(app.folder_filter, "");
        let _ = app.view_sidebar();
        let counts: Vec<usize> = app
            .vault
            .as_ref()
            .unwrap()
            .folders()
            .iter()
            .map(|f| app.vault.as_ref().unwrap().folder_count(&f.uuid))
            .collect();
        assert_eq!(counts, vec![1, 0], "в Work одна запись, в EMails пусто");

        let _ = std::fs::remove_dir_all(&root);
    }

    /// Выбор папки фильтрует список, повторный щелчок снимает фильтр.
    #[test]
    fn выбор_папки_фильтрует_список() {
        let (mut app, root) = app_with_folders("folders-filter");
        assert_eq!(app.entries.len(), 2, "изначально обе записи");

        let _ = app.update(Message::PickFolder("F1".into()));
        assert_eq!(app.folder_filter, "F1");
        assert_eq!(app.entries.len(), 1, "в папке только GitHub");

        let _ = app.update(Message::PickFolder("F1".into()));
        assert_eq!(app.folder_filter, "", "повторный щелчок снимает");
        assert_eq!(app.entries.len(), 2);

        let _ = std::fs::remove_dir_all(&root);
    }

    /// Новая папка создаётся из поля ввода и сразу становится активной.
    #[test]
    fn папка_создаётся_из_поля_ввода() {
        let (mut app, root) = app_with_folders("folders-create");

        let _ = app.update(Message::FolderDraftChanged("  Home  ".into()));
        let _ = app.update(Message::SubmitFolderDraft);

        let folders = app.vault.as_ref().unwrap().folders();
        assert_eq!(folders.len(), 3, "папка добавилась");
        assert!(
            folders.iter().any(|f| f.title.as_deref() == Some("Home")),
            "название обрезано от пробелов"
        );
        assert!(!app.folder_filter.is_empty(), "новая папка выбрана");
        assert!(app.folder_draft.is_empty(), "поле очищено");

        let _ = std::fs::remove_dir_all(&root);
    }

    /// Пустое название папки не создаёт её.
    #[test]
    fn пустое_название_папки_отклоняется() {
        let (mut app, root) = app_with_folders("folders-empty");

        let _ = app.update(Message::FolderDraftChanged("   ".into()));
        let _ = app.update(Message::SubmitFolderDraft);

        assert_eq!(app.vault.as_ref().unwrap().folders().len(), 2);
        let (text, _) = app.toast.clone().unwrap();
        assert!(
            text.contains("name"),
            "пользователю сказано, в чём дело: {text}"
        );

        let _ = std::fs::remove_dir_all(&root);
    }

    /// Выбранная папка подставляется в поле ввода, и переименование работает.
    #[test]
    fn папка_переименовывается() {
        let (mut app, root) = app_with_folders("folders-rename");

        let _ = app.update(Message::PickFolder("F2".into()));
        assert_eq!(app.folder_draft, "EMails", "поле показало название папки");
        assert_eq!(app.folder_draft_for.as_deref(), Some("F2"));

        let _ = app.update(Message::FolderDraftChanged("Mail".into()));
        let _ = app.update(Message::SubmitFolderDraft);

        let renamed = app.vault.as_ref().unwrap().folder("F2").unwrap();
        assert_eq!(renamed.title.as_deref(), Some("Mail"));
        // Папка остаётся выбранной и списка отфильтрованной: после
        // переименования обычно хотят убедиться, что всё на месте.
        assert_eq!(app.folder_draft_for.as_deref(), Some("F2"));
        assert_eq!(app.folder_filter, "F2");

        let _ = std::fs::remove_dir_all(&root);
    }

    /// Удаление папки спрашивает подтверждение и не уносит её содержимое.
    #[test]
    fn удаление_папки_спрашивает_и_сохраняет_записи() {
        let (mut app, root) = app_with_folders("folders-delete");

        let _ = app.update(Message::PickFolder("F1".into()));
        let _ = app.update(Message::AskDeleteFolder("F1".into()));
        assert!(
            app.vault.as_ref().unwrap().folder("F1").is_some(),
            "первое нажатие только спрашивает"
        );

        let _ = app.update(Message::AskDeleteFolder("F1".into()));
        assert!(
            app.vault.as_ref().unwrap().folder("F1").is_none(),
            "второе удаляет"
        );
        assert_eq!(app.folder_filter, "", "удалённая папка снимает фильтр");
        assert_eq!(app.entries.len(), 2, "записи остались на месте");

        let _ = std::fs::remove_dir_all(&root);
    }

    /// Новая запись, созданная из папки, попадает в неё.
    #[test]
    fn новая_запись_попадает_в_открытую_папку() {
        let (mut app, root) = app_with_folders("folders-new-item");

        let _ = app.update(Message::PickFolder("F1".into()));
        let _ = app.update(Message::StartCreate);
        let _ = app.update(Message::DraftChanged("title", "Новая".into()));
        let _ = app.update(Message::ApplyEdit);

        let in_folder = app
            .vault
            .as_ref()
            .unwrap()
            .items
            .iter()
            .filter(|i| i.folder_uuid.as_deref() == Some("F1"))
            .count();
        assert_eq!(in_folder, 2, "GitHub и новая запись в папке Work");

        let _ = std::fs::remove_dir_all(&root);
    }

    /// Папка выбирается и в редакторе существующей записи.
    #[test]
    fn папка_меняется_в_редакторе() {
        let (mut app, root) = app_with_folders("folders-editor");

        // U2 лежит без папки; выберем его и положим в Work.
        let pos = app
            .entries
            .iter()
            .position(|&i| app.vault.as_ref().unwrap().items[i].uuid == "U2")
            .unwrap();
        let _ = app.update(Message::Select(pos));
        let _ = app.update(Message::StartEdit);
        let _ = app.update(Message::DraftFolder(Some("F1".into())));
        let _ = app.update(Message::ApplyEdit);

        assert_eq!(
            app.vault
                .as_ref()
                .unwrap()
                .find("U2")
                .unwrap()
                .folder_uuid
                .as_deref(),
            Some("F1"),
            "папка записалась в запись"
        );

        // И обратно на верхний уровень.
        let _ = app.update(Message::Select(pos));
        let _ = app.update(Message::StartEdit);
        let _ = app.update(Message::DraftFolder(None));
        let _ = app.update(Message::ApplyEdit);
        assert_eq!(
            app.vault.as_ref().unwrap().find("U2").unwrap().folder_uuid,
            None
        );

        let _ = std::fs::remove_dir_all(&root);
    }
}

#[cfg(test)]
mod scenario_tests {
    use super::tests_common::*;
    use super::*;

    /// Сценарий на копии настоящего экспорта: правка, создание, удаление,
    /// сохранение, откат из бэкапа.
    #[test]
    fn полный_сценарий_на_настоящем_экспорте() {
        let src = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../../golden")
            .join("1Password 2026-10-13, 03_54 PM (533 items and 2 folders).1pif/data.1pif");
        if !src.exists() {
            eprintln!("реальный экспорт не найден");
            return;
        }
        let root = unique_dir("opclient-scenario");
        std::fs::create_dir_all(&root).unwrap();
        let file = root.join("data.1pif");
        std::fs::copy(&src, &file).unwrap();
        let before = std::fs::read(&file).unwrap();

        let mut app = App::blank();
        assert!(app.open(file.clone()));
        let count = app.vault.as_ref().unwrap().items.len();

        // 1. правка существующей записи
        let target = app.vault.as_ref().unwrap().items[10].uuid.clone();
        let _ = app.update(Message::Select(10));
        let _ = app.update(Message::StartEdit);
        let _ = app.update(Message::DraftChanged(
            "notes",
            "правка из приложения".into(),
        ));
        let _ = app.update(Message::ApplyEdit);

        // 2. создание новой
        let _ = app.update(Message::StartCreate);
        let _ = app.update(Message::DraftChanged("title", "Проверка сценария".into()));
        let _ = app.update(Message::DraftChanged("username", "scen@example.com".into()));
        let _ = app.update(Message::DraftChanged("password", "pass-9999".into()));
        let _ = app.update(Message::DraftChanged(
            "url",
            "https://scenario.test/x".into(),
        ));
        let _ = app.update(Message::ApplyEdit);

        // 3. удаление: сначала выбираем запись, потом жмём «Удалить»
        let victim = app.vault.as_ref().unwrap().items[20].uuid.clone();
        assert!(
            app.select_uuid(&victim),
            "запись должна быть видна в списке"
        );
        let _ = app.update(Message::DeleteItem);
        // вопрос должен появиться в открытой форме
        assert!(
            app.editing.as_ref().is_some_and(|e| e.confirm_delete),
            "удаление обязано спрашивать подтверждение"
        );
        let _ = app.update(Message::ConfirmDelete(true));
        assert!(app.editing.is_none(), "после удаления форма закрывается");

        assert!(app.has_changes());
        let _ = app.update(Message::SaveFile);
        assert!(!app.has_changes());

        // 4. файл валиден и изменения на месте
        let after = Pif::from_file(&file).unwrap();
        assert_eq!(
            after.items.len(),
            count,
            "создание и удаление должны уравняться"
        );
        assert!(after.find(&target).is_some());
        assert!(
            after.find(&victim).is_none(),
            "удалённая запись не должна вернуться"
        );
        let created = after
            .items
            .iter()
            .find(|i| i.title.as_deref() == Some("Проверка сценария"))
            .expect("новая запись обязана сохраниться");
        assert_eq!(created.primary_password(), Some("pass-9999"));
        assert_eq!(created.usernames(), vec!["scen@example.com"]);

        // 5. бэкап — это исходный файл
        let bak = std::fs::read(backup_of(&file)).unwrap();
        assert_eq!(bak, before, "бэкап должен содержать исходное содержимое");

        // 6. откат: вернуть бэкап и убедиться, что всё как было
        std::fs::write(&file, &bak).unwrap();
        let restored = Pif::from_file(&file).unwrap();
        assert_eq!(restored.items.len(), count);
        assert!(restored.find(&target).is_some());
        assert!(
            restored.find(&victim).is_some(),
            "после отката запись должна вернуться"
        );
        assert!(!restored.has_changes());

        let _ = std::fs::remove_dir_all(&root);
    }

    fn backup_of(p: &std::path::Path) -> std::path::PathBuf {
        let mut s = p.as_os_str().to_os_string();
        s.push(".bak1");
        std::path::PathBuf::from(s)
    }
}

#[cfg(test)]
mod notes_and_focus_tests {
    use super::tests_common::*;
    use super::*;

    fn editor_with_notes(tag: &str, notes: &str) -> (App, PathBuf) {
        let root = unique_dir(tag);
        std::fs::create_dir_all(&root).unwrap();
        let file = root.join("data.1pif");
        let mut esc = String::new();
        for ch in notes.chars() {
            match ch {
                '"' => esc.push_str("\\\""),
                '\n' => esc.push_str("\\n"),
                '\\' => esc.push_str("\\\\"),
                other => esc.push(other),
            }
        }
        let line = format!(
            "{{\"uuid\":\"U1\",\"typeName\":\"securenotes.SecureNote\",\"title\":\"Z\",\"secureContents\":{{\"notesPlain\":\"{esc}\"}}}}"
        );
        std::fs::write(&file, format!("{line}\n")).unwrap();
        let mut app = App::blank();
        assert!(app.open(file));
        (app, root)
    }

    /// Заметки с переносами должны попадать в форму и обратно в файл.
    #[test]
    fn заметки_с_переносами_правятся() {
        let original = "первая строка\nвторая строка\nтретья";
        let (mut app, root) = editor_with_notes("notes", original);

        let uuid = app.vault.as_ref().unwrap().items[0].uuid.clone();
        let _ = app.update(Message::StartEdit);
        assert_eq!(
            app.editing.as_ref().unwrap().notes,
            original,
            "форма должна показать заметки как есть"
        );

        let changed = "новая первая\nновая вторая";
        // Пользователь стёр текст и набрал новый: сначала выделяем всё,
        // потом вставляем. Так работает реальное редактирование.
        let _ = app.update(Message::EditNotes(text_editor::Action::SelectAll));
        let _ = app.update(Message::EditNotes(text_editor::Action::Edit(
            text_editor::Edit::Paste(std::sync::Arc::new(changed.to_string())),
        )));

        let _ = app.update(Message::ApplyEdit);
        let _ = app.update(Message::SaveFile);

        let again = Pif::from_file(root.join("data.1pif")).unwrap();
        let it = again.find(&uuid).unwrap();
        assert_eq!(it.notes(), Some(changed), "переносы обязаны сохраниться");

        let _ = std::fs::remove_dir_all(&root);
    }

    /// Документ редактора и черновик не должны расходиться.
    #[test]
    fn документ_и_черновик_совпадают() {
        let (mut app, root) = editor_with_notes("sync", "исходный текст");
        let _ = app.update(Message::StartEdit);
        let e = app.editing.as_ref().unwrap();
        assert_eq!(e.notes, e.notes_doc.text());

        // Пустое действие не должно ничего портить.
        let _ = app.update(Message::EditNotes(text_editor::Action::Move(
            text_editor::Motion::End,
        )));
        let e = app.editing.as_ref().unwrap();
        assert_eq!(e.notes, e.notes_doc.text());
        assert_eq!(e.draft.notes, e.notes);

        let _ = std::fs::remove_dir_all(&root);
    }

    /// Форма собирается вместе с многострочным редактором.
    #[test]
    fn форма_с_редактором_собирается() {
        let (mut app, root) = editor_with_notes("render", "текст");
        let _ = app.update(Message::StartEdit);
        let _ = app.view_editor();
        let _ = app.view();
        let _ = std::fs::remove_dir_all(&root);
    }

    /// Подписка на клавиатуру должна существовать и не падать.
    #[test]
    fn подписка_клавиатуры_строится() {
        let app = App::blank();
        let _ = app.subscription();
    }
}

#[cfg(test)]
mod trash_ui_tests {
    use super::tests_common::*;
    use super::*;

    fn export_with_trashed(tag: &str) -> (App, PathBuf) {
        let root = unique_dir(tag);
        std::fs::create_dir_all(&root).unwrap();
        let file = root.join("data.1pif");
        std::fs::write(
            &file,
            concat!(
                "{\"uuid\":\"LIVE1\",\"typeName\":\"securenotes.SecureNote\",\"title\":\"Живая\",\"secureContents\":{}}\n",
                "{\"uuid\":\"GONE1\",\"typeName\":\"securenotes.SecureNote\",\"title\":\"Удалённая\",\"trashed\":true,\"secureContents\":{}}\n",
                "{\"uuid\":\"GONE2\",\"typeName\":\"securenotes.SecureNote\",\"title\":\"Тоже удалённая\",\"trashed\":true,\"secureContents\":{}}\n",
            ),
        )
        .unwrap();
        let mut app = App::blank();
        assert!(app.open(file.clone()));
        (app, root)
    }

    /// Обычный список не показывает удалённые записи.
    #[test]
    fn из_обычного_списка_корзина_скрыта() {
        let (app, root) = export_with_trashed("trash-hidden");
        assert!(!app.show_trash);
        let titles: Vec<String> = app
            .entries
            .iter()
            .map(|&i| app.vault.as_ref().unwrap().items[i].title.clone().unwrap())
            .collect();
        assert_eq!(titles, vec!["Живая".to_string()]);
        let _ = std::fs::remove_dir_all(&root);
    }

    /// Раздел «Корзина» показывает только удалённые.
    #[test]
    fn в_корзине_только_удалённые() {
        let (mut app, root) = export_with_trashed("trash-only");
        let _ = app.update(Message::ShowTrash(!app.show_trash));
        assert!(app.show_trash);
        assert_eq!(app.entries.len(), 2);
        let _ = app.view();
        let _ = std::fs::remove_dir_all(&root);
    }

    /// Переключение корзины туда-обратно возвращает обычный список.
    #[test]
    fn переключение_корзины_туда_обратно() {
        let (mut app, root) = export_with_trashed("trash-toggle");
        let normal = app.entries.len();
        let _ = app.update(Message::ShowTrash(!app.show_trash));
        assert_ne!(app.entries.len(), normal);
        let _ = app.update(Message::ShowTrash(!app.show_trash));
        assert_eq!(app.entries.len(), normal);
        let _ = std::fs::remove_dir_all(&root);
    }

    /// Очистка пустой корзины вложений безвредна.
    #[test]
    fn очистка_пустой_корзины_безвредна() {
        let (mut app, root) = export_with_trashed("trash-empty-ui");
        assert_eq!(app.trash.files, 0);
        let _ = app.update(Message::EmptyTrash);
        assert_eq!(app.trash.files, 0);
        assert!(app.toast.is_some(), "должно быть уведомление");
        let _ = std::fs::remove_dir_all(&root);
    }

    /// Склонение считается по-русски.
    #[test]
    fn склонение_файлов() {
        assert_eq!(plural_files(0), "0 files");
        assert_eq!(plural_files(1), "1 file");
        assert_eq!(plural_files(2), "2 files");
        // По-английски 21 и 102 — это просто «files», без склонения.
        assert_eq!(plural_files(21), "21 files");
        assert_eq!(plural_files(102), "102 files");
    }

    /// Счётчики в интерфейсе совпадают с разобранными данными.
    #[test]
    fn счётчики_корзины_из_данных() {
        let src = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../../golden")
            .join("1Password 2026-10-13, 03_54 PM (533 items and 2 folders).1pif/data.1pif");
        if !src.exists() {
            return;
        }
        let pif = Pif::from_file(src).unwrap();
        let alive = pif.alive().len();
        let trashed = pif.trashed().len();
        assert_eq!(
            alive + trashed,
            533,
            "живые плюс удалённые должны дать все записи"
        );
        assert_eq!(trashed, 57, "в выгрузке помечено 57 удалённых записей");
        assert_eq!(
            alive, 476,
            "столько же показывает 1Password в разделе All Items"
        );
    }
}

#[cfg(test)]
mod trash_confirm_tests {
    use super::tests_common::*;
    use super::*;

    /// Приложение с непустой корзиной вложений.
    fn app_with_trash(tag: &str) -> (App, PathBuf) {
        let root = unique_dir(tag);
        std::fs::create_dir_all(root.join("attachments").join("U1")).unwrap();
        std::fs::write(root.join("attachments/U1/photo.jpg"), b"jpeg").unwrap();
        std::fs::write(
            root.join("data.1pif"),
            "{\"uuid\":\"U1\",\"typeName\":\"securenotes.SecureNote\",\"title\":\"A\",\"secureContents\":{}}\n",
        )
        .unwrap();
        let mut app = App::blank();
        assert!(app.open(root.join("data.1pif")));
        // Кладём файл в корзину, как это сделало бы удаление записи.
        let src = std::env::temp_dir().join(format!("{tag}-src.jpg"));
        std::fs::write(&src, b"jpeg2").unwrap();
        let uuid = app.vault.as_ref().unwrap().items[0].uuid.clone();
        if let Some(v) = app.vault.as_mut() {
            v.remove(&uuid);
        }
        if let Some(v) = app.vault.as_mut() {
            v.attachments_to_trash
                .push((uuid, root.join("attachments/U1/photo.jpg")));
            v.save(root.join("data.1pif")).unwrap();
        }
        app.trash = app.vault.as_ref().unwrap().trash_stats();
        let _ = std::fs::remove_file(&src);
        (app, root)
    }

    /// Очистка не происходит с первого нажатия.
    #[test]
    fn первое_нажатие_только_спрашивает() {
        let (mut app, root) = app_with_trash("trash-ask");
        assert_eq!(app.trash.files, 1);
        let _ = app.update(Message::EmptyTrash);
        assert!(app.trash_armed, "после первого нажатия ждём подтверждения");
        assert_eq!(app.trash.files, 1, "корзина должна остаться на месте");
        let _ = std::fs::remove_dir_all(&root);
    }

    /// Второе нажатие очищает.
    #[test]
    fn второе_нажатие_очищает() {
        let (mut app, root) = app_with_trash("trash-do");
        let _ = app.update(Message::EmptyTrash);
        let _ = app.update(Message::EmptyTrash);
        assert_eq!(app.trash.files, 0, "корзина должна быть очищена");
        assert!(!app.trash_armed);
        assert!(!root.join("trash").exists(), "каталог корзины убран");
        let _ = std::fs::remove_dir_all(&root);
    }

    /// Отмена снимает вопрос.
    #[test]
    fn отмена_снимает_вопрос() {
        let (mut app, root) = app_with_trash("trash-cancel");
        let _ = app.update(Message::EmptyTrash);
        assert!(app.trash_armed);
        let _ = app.update(Message::CancelEmptyTrash);
        assert!(!app.trash_armed);
        assert_eq!(app.trash.files, 1);
        let _ = app.update(Message::EmptyTrash);
        assert!(app.trash_armed, "вопрос должен задаваться заново");
        let _ = std::fs::remove_dir_all(&root);
    }

    /// Переключение раздела снимает вопрос, чтобы он не «завис».
    #[test]
    fn переключение_раздела_снимает_вопрос() {
        let (mut app, root) = app_with_trash("trash-switch");
        let _ = app.update(Message::EmptyTrash);
        let _ = app.update(Message::ShowTrash(!app.show_trash));
        assert!(!app.trash_armed);
        let _ = std::fs::remove_dir_all(&root);
    }

    /// Панель собирается и в вооружённом состоянии.
    #[test]
    fn панель_собирается_с_подтверждением() {
        let (mut app, root) = app_with_trash("trash-render");
        let _ = app.view();
        let _ = app.update(Message::EmptyTrash);
        let _ = app.view();
        let _ = std::fs::remove_dir_all(&root);
    }

    /// Версия в панели «О приложении» и в Info.plist обязана совпадать
    /// Версия приходит из тега git, а не из константы, но всё равно должна
    /// быть похожа на версию. Раньше здесь стояло сравнение с
    /// `CARGO_PKG_VERSION`, и оно пропустило расхождение 1.0.0 против
    /// тега v1.5.0: обе величины были настоящими, просто разными.
    #[test]
    fn версия_похожа_на_версию() {
        let parts: Vec<&str> = APP_VERSION.split('.').collect();
        assert_eq!(
            parts.len(),
            3,
            "ожидается вид X.Y.Z, получено {APP_VERSION:?}"
        );
        for part in parts {
            assert!(
                !part.is_empty() && part.chars().all(|c| c.is_ascii_digit()),
                "часть версии должна быть числом: {part:?} в {APP_VERSION:?}"
            );
        }
        assert!(APP_VERSION.starts_with('1'), "версия 1.x");
    }

    /// Приложение с одной живой записью и без вложений.
    fn app_with_one_entry(tag: &str) -> (App, PathBuf, PathBuf) {
        let root = unique_dir(tag);
        std::fs::create_dir_all(&root).unwrap();
        std::fs::write(
            root.join("data.1pif"),
            concat!(
                "{\"uuid\":\"U1\",\"typeName\":\"webforms.WebForm\",\"title\":\"A\",",
                "\"secureContents\":{}}\n"
            ),
        )
        .unwrap();

        let source = root.join("источник.jpg");
        std::fs::write(&source, b"jpeg-bytes").unwrap();

        let mut app = App::blank();
        assert!(app.open(root.join("data.1pif")));
        (app, root, source)
    }

    /// Файл появляется в каталоге записи только после сохранения.
    #[test]
    fn прикреплённый_файл_попадает_на_диск_при_save() {
        let (mut app, root, source) = app_with_one_entry("attach-save");
        let uuid = app.vault.as_ref().unwrap().items[0].uuid.clone();

        let (added, failed) = app.attach_paths(&uuid, std::slice::from_ref(&source));
        assert_eq!(added, 1, "файл должен прикрепиться");
        assert!(failed.is_empty(), "ошибок быть не должно: {failed:?}");

        // До сохранения каталога вложений на диске нет.
        assert!(!root.join("attachments").exists(), "нечего копировать");

        let _ = app.update(Message::SaveFile);

        let copied = root.join("attachments").join(&uuid).join("источник.jpg");
        assert!(copied.exists(), "файл должен лежать в attachments/<uuid>/");
        assert_eq!(std::fs::read(&copied).unwrap(), b"jpeg-bytes");
        assert!(!app.attachments_pending(), "после сохранения ждать нечего");

        let _ = std::fs::remove_dir_all(&root);
    }

    /// Открепление требует второго нажатия.
    #[test]
    fn открепление_требует_подтверждения() {
        let (mut app, root, source) = app_with_one_entry("detach-two-step");
        let uuid = app.vault.as_ref().unwrap().items[0].uuid.clone();
        app.attach_paths(&uuid, std::slice::from_ref(&source));
        let _ = app.update(Message::SaveFile);

        // Первое нажатие только вооружает кнопку.
        let _ = app.update(Message::DetachAttachment("источник.jpg".into()));
        assert_eq!(app.detach_armed.as_deref(), Some("источник.jpg"));
        assert_eq!(
            app.vault.as_ref().unwrap().attachments_of(&uuid).len(),
            1,
            "файл не должен исчезнуть после первого нажатия"
        );

        // Второе — открепляет.
        let _ = app.update(Message::DetachAttachment("источник.jpg".into()));
        assert!(app.detach_armed.is_none(), "вооружение снимается");
        assert!(app.vault.as_ref().unwrap().attachments_of(&uuid).is_empty());
        assert!(app.attachments_pending(), "файл ждёт корзины");

        // До сохранения файл на диске ещё лежит.
        assert!(root
            .join("attachments")
            .join(&uuid)
            .join("источник.jpg")
            .exists());

        let _ = app.update(Message::SaveFile);
        assert!(
            !root
                .join("attachments")
                .join(&uuid)
                .join("источник.jpg")
                .exists(),
            "после сохранения файл должен уйти в корзину"
        );

        let _ = std::fs::remove_dir_all(&root);
    }

    /// Отмена вооружения ничего не удаляет.
    #[test]
    fn отмена_открепления_ничего_не_делает() {
        let (mut app, root, source) = app_with_one_entry("detach-cancel");
        let uuid = app.vault.as_ref().unwrap().items[0].uuid.clone();
        app.attach_paths(&uuid, std::slice::from_ref(&source));
        let _ = app.update(Message::SaveFile);

        let _ = app.update(Message::DetachAttachment("источник.jpg".into()));
        let _ = app.update(Message::CancelDetach);
        assert!(app.detach_armed.is_none());
        assert_eq!(app.vault.as_ref().unwrap().attachments_of(&uuid).len(), 1);

        let _ = std::fs::remove_dir_all(&root);
    }

    /// Уход на другую запись сбрасывает вооружение: подтверждение относилось
    /// к файлу в прежнем контексте.
    #[test]
    fn выбор_другой_записи_снимает_вооружение() {
        let (mut app, root, source) = app_with_one_entry("detach-select");
        let uuid = app.vault.as_ref().unwrap().items[0].uuid.clone();
        app.attach_paths(&uuid, std::slice::from_ref(&source));
        let _ = app.update(Message::SaveFile);

        let _ = app.update(Message::DetachAttachment("источник.jpg".into()));
        assert!(app.detach_armed.is_some());

        let _ = app.update(Message::Select(0));
        assert!(
            app.detach_armed.is_none(),
            "вооружение не должно пережить смену записи"
        );

        let _ = std::fs::remove_dir_all(&root);
    }

    /// У новой записи нет uuid, поэтому прикреплять пока некуда.
    #[test]
    fn новая_запись_не_принимает_вложения() {
        let (mut app, root, _source) = app_with_one_entry("attach-new");
        app.editing = Some(Editing::create());
        assert!(
            app.attachment_target().is_none(),
            "у создаваемой записи нет uuid"
        );

        let _ = app.update(Message::AttachFile);
        let (text, _) = app.toast.clone().unwrap();
        assert!(
            text.contains("save the item"),
            "пользователю нужно объяснить, а не молчать: {text}"
        );

        let _ = std::fs::remove_dir_all(&root);
    }

    /// Одноимённые файлы не затирают друг друга.
    #[test]
    fn одноимённые_вложения_не_затираются() {
        let (mut app, root, source) = app_with_one_entry("attach-dupe");
        let uuid = app.vault.as_ref().unwrap().items[0].uuid.clone();

        let second = root.join("второй");
        std::fs::create_dir_all(&second).unwrap();
        let same_name = second.join("источник.jpg");
        std::fs::write(&same_name, b"other-bytes").unwrap();

        let (added, failed) = app.attach_paths(&uuid, &[source, same_name]);
        assert_eq!(added, 2);
        assert!(failed.is_empty());

        let names: Vec<String> = app
            .vault
            .as_ref()
            .unwrap()
            .attachments_of(&uuid)
            .iter()
            .map(|a| a.name.clone())
            .collect();
        assert_eq!(names.len(), 2, "оба файла на месте");
        assert_ne!(names[0], names[1], "имена должны различаться");

        let _ = app.update(Message::SaveFile);
        let dir = root.join("attachments").join(&uuid);
        let on_disk = std::fs::read_dir(&dir).unwrap().count();
        assert_eq!(on_disk, 2, "на диске тоже два разных файла");

        let _ = std::fs::remove_dir_all(&root);
    }

    /// Текст уведомления не должен вручить пользователю пустоту.
    #[test]
    fn тексты_уведомлений_про_вложения_осмысленны() {
        assert!(attach_toast(0, &[]).contains("0"));
        assert!(attach_toast(1, &[]).contains("file"));
        assert!(attach_toast(3, &[]).contains("files"));
        assert!(attach_toast(0, &["a.jpg".into()]).contains("cannot attach"));
        assert!(attach_toast(1, &["b.jpg".into()]).contains("b.jpg"));
    }

    /// Показываем только те расширения, которые `iced` действительно умеет.
    #[test]
    fn картинки_опознаются_по_расширению() {
        for name in [
            "a.jpg", "a.JPEG", "a.png", "a.gif", "a.bmp", "a.webp", "a.tiff",
        ] {
            assert!(
                is_image(std::path::Path::new(name)),
                "{name} должен считаться картинкой"
            );
        }
        for name in [
            "a.pdf",
            "a.txt",
            "a.zip",
            "a.docx",
            "a.heic",
            "без_расширения",
        ] {
            assert!(
                !is_image(std::path::Path::new(name)),
                "{name} не должен считаться картинкой"
            );
        }
    }

    /// Повтор по тому же файлу сворачивает превью.
    #[test]
    fn превью_переключается() {
        let (mut app, root, _source) = app_with_one_entry("preview-toggle");
        let path = root.join("avatar.png");

        let _ = app.update(Message::TogglePreview(path.clone()));
        assert_eq!(
            app.preview.as_ref(),
            Some(&path),
            "первое нажатие разворачивает"
        );

        let _ = app.update(Message::TogglePreview(path));
        assert!(app.preview.is_none(), "второе нажатие сворачивает");

        let _ = std::fs::remove_dir_all(&root);
    }

    /// Уход на другую запись закрывает превью: показывать файл чужой записи
    /// после переключения незачем.
    #[test]
    fn смена_записи_закрывает_превью() {
        let (mut app, root, _source) = app_with_one_entry("preview-select");
        let _ = app.update(Message::Select(0));
        let _ = app.update(Message::TogglePreview(root.join("avatar.png")));
        assert!(app.preview.is_some());

        let _ = app.update(Message::Select(0));
        assert!(
            app.preview.is_none(),
            "смена записи должна закрывать превью"
        );

        let _ = std::fs::remove_dir_all(&root);
    }

    /// Панель записи собирается вместе с превью.
    #[test]
    fn панель_собирается_с_превью() {
        let (mut app, root, _source) = app_with_one_entry("preview-render");
        let _ = app.update(Message::Select(0));
        let _ = app.update(Message::TogglePreview(root.join("avatar.png")));
        let _ = app.view();

        let _ = std::fs::remove_dir_all(&root);
    }

    /// Хранилище с одной пустой записью-заготовкой.
    fn app_with_one_login(tag: &str) -> (App, PathBuf) {
        let root = unique_dir(tag);
        std::fs::create_dir_all(&root).unwrap();
        std::fs::write(root.join("data.1pif"), "{}\n").unwrap();

        let mut app = App::blank();
        assert!(app.open(root.join("data.1pif")));
        (app, root)
    }

    /// Новая запись создаётся того типа, который выбран в редакторе.
    #[test]
    fn тип_новой_записи_выбирается_и_применяется() {
        use opclient_core::pif::ItemKind;

        let (mut app, root) = app_with_one_login("kind-pick");
        let _ = app.update(Message::StartCreate);
        assert_eq!(app.editing.as_ref().unwrap().kind, ItemKind::Login);

        let _ = app.update(Message::DraftKind(ItemKind::CreditCard));
        assert_eq!(app.editing.as_ref().unwrap().kind, ItemKind::CreditCard);

        let _ = app.update(Message::DraftChanged("title", "Карта".into()));
        let _ = app.update(Message::DraftChanged("username", "Vitalii".into()));
        let _ = app.update(Message::DraftChanged("password", "4111111111111111".into()));
        let _ = app.update(Message::DraftChanged("extra_a", "09/2027".into()));
        let _ = app.update(Message::DraftChanged("extra_b", "123".into()));
        let _ = app.update(Message::ApplyEdit);

        let created = app
            .vault
            .as_ref()
            .unwrap()
            .items
            .iter()
            .find(|i| i.title.as_deref() == Some("Карта"))
            .expect("запись создана");

        assert_eq!(
            created.type_name.as_deref(),
            Some(ItemKind::CreditCard.type_name()),
            "тип записи взят из редактора"
        );

        let sc = created.secure_contents.as_ref().unwrap();
        assert_eq!(
            sc.extra.get("cardholder").and_then(|v| v.as_str()),
            Some("Vitalii")
        );
        assert_eq!(
            sc.extra.get("expiry_mm").and_then(|v| v.as_str()),
            Some("09")
        );
        assert_eq!(
            sc.extra.get("expiry_yy").and_then(|v| v.as_str()),
            Some("2027")
        );
        assert_eq!(sc.extra.get("cvv").and_then(|v| v.as_str()), Some("123"));

        let _ = std::fs::remove_dir_all(&root);
    }

    /// Тип у уже существующей записи не меняется: он привязан к структуре,
    /// которая уже записана в файл.
    #[test]
    fn тип_существующей_записи_не_меняется() {
        use opclient_core::pif::ItemKind;

        let (mut app, root) = app_with_one_login("kind-existing");
        let _ = app.update(Message::StartCreate);
        let _ = app.update(Message::DraftKind(ItemKind::Server));
        let _ = app.update(Message::DraftChanged("title", "Сервер".into()));
        let _ = app.update(Message::ApplyEdit);

        let _ = app.update(Message::Select(0));
        let _ = app.update(Message::StartEdit);
        assert_eq!(app.editing.as_ref().unwrap().kind, ItemKind::Server);

        let _ = app.update(Message::DraftKind(ItemKind::Login));
        assert_eq!(
            app.editing.as_ref().unwrap().kind,
            ItemKind::Server,
            "тип записи, уже лежащей в файле, трогать нельзя"
        );

        let _ = std::fs::remove_dir_all(&root);
    }

    /// Заметка создаётся без логина и пароля и читается обратно.
    #[test]
    fn заметка_создаётся_и_читается() {
        use opclient_core::pif::ItemKind;

        let (mut app, root) = app_with_one_login("kind-note");
        let _ = app.update(Message::StartCreate);
        let _ = app.update(Message::DraftKind(ItemKind::SecureNote));
        let _ = app.update(Message::DraftChanged("title", "Коды восстановления".into()));
        let _ = app.update(Message::EditNotes(text_editor::Action::Edit(
            text_editor::Edit::Paste(std::sync::Arc::new("код: 1234".to_string())),
        )));
        let _ = app.update(Message::ApplyEdit);

        let item = app
            .vault
            .as_ref()
            .unwrap()
            .items
            .iter()
            .find(|i| i.title.as_deref() == Some("Коды восстановления"))
            .expect("заметка создана");
        assert_eq!(
            item.type_name.as_deref(),
            Some(ItemKind::SecureNote.type_name())
        );
        assert_eq!(
            item.secure_contents
                .as_ref()
                .unwrap()
                .notes_plain
                .as_deref(),
            Some("код: 1234")
        );

        let _ = std::fs::remove_dir_all(&root);
    }
}
