//! 1Password export browser — an iced interface.
//!
//! The data source is a 1PIF export file, i.e. a snapshot of a vault taken at
//! export time. The application is **read-only** and never writes back into
//! the source data.
//!
//! # What it shows
//!
//! - the item list, searchable by title, domain and URL;
//! - a filter by item kind;
//! - details: title, kind, logins, password, URL, notes;
//! - copying the login, password and URL to the clipboard;
//! - a TOTP code with a countdown, when the item carries an `otpauth://`.
//!
//! # Opening the file
//!
//! The path can be given as a command-line argument. With no argument the
//! path from the previous run is used. The file is chosen with the "Open…"
//! button and remembered, so next time the application opens it on its own.
//!
//! # Privacy
//!
//! The password is masked by default. Revealing it takes an explicit, separate
//! button. The application logs nothing and writes nothing to disk.

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
    // A command-line argument outranks the remembered path: that way you can
    // open a different file without digging through settings.
    let from_arg = std::env::args().nth(1).map(PathBuf::from);

    // Menu event channel: it must exist before iced starts or the subscription misses it.
    menu::init();

    let app = iced::application(move || App::new(from_arg.clone()), App::update, App::view)
        .title(|_: &App| String::from(APP_TITLE))
        .theme(|_: &App| Theme::Dark)
        .subscription(App::subscription)
        .window_size((1150.0, 740.0));

    // SF Pro is requested explicitly. By default iced takes the "nameless
    // sans-serif", and the system does not expose that family under a name
    // of its own: `atsutil` shows only the Display variants and the internal
    // PostScript names. So it is more reliable to read the system font file.
    match system_font() {
        Some(bytes) => app.font(bytes).run(),
        None => app.run(),
    }
}

/// The macOS system font (SF Pro) for the interface.
///
/// If the file is missing the application still starts, it just keeps the
/// default font: that is no reason to refuse to run.
fn system_font() -> Option<Vec<u8>> {
    std::fs::read("/System/Library/Fonts/SFNS.ttf").ok()
}

struct App {
    /// `None` — no file picked yet.
    vault: Option<Pif>,
    /// Path of the open file.
    path: Option<PathBuf>,
    /// What went wrong while opening.
    error: Option<String>,
    /// Indices into `vault.items` that pass the filter and the search.
    entries: Vec<usize>,
    query_input: String,
    query: String,
    kind_filter: String,
    selected: Option<usize>,
    /// uuid -> whether the password is revealed.
    revealed: HashMap<String, bool>,
    /// Width of the list panel in logical points.
    list_width: f32,
    /// Whether the list panel border is being dragged right now.
    resizing: bool,
    /// Whether the pointer is over the border: without this flag a mouse press
    /// anywhere in the window would start a drag.
    hover_resize: bool,
    /// Window width in logical points. Needed so the third panel has a
    /// minimum too: the window only knows the list width.
    window_w: f32,
    /// Pointer position at the moment it last moved during a drag. Needed to
    /// measure the offset rather than an absolute coordinate, otherwise the
    /// panel would jump to the cursor.
    resize_anchor: Option<f32>,
    toast: Option<(String, Instant)>,
    /// Whether the editor is open.
    editing: Option<Editing>,
    /// Show the trash instead of regular items.
    show_trash: bool,
    /// Show the audit report instead of the item details.
    show_audit: bool,
    /// Folder awaiting delete confirmation.
    ask_delete_folder: Option<String>,
    /// Text of the new-folder / rename input.
    folder_draft: String,
    /// Folder the draft belongs to. `None` — a new one is created.
    folder_draft_for: Option<String>,
    /// Active folder: an empty string means "all items, no folder filter".
    ///
    /// A field of its own rather than part of `kind_filter`: category and
    /// folder are different things and can be applied together.
    folder_filter: String,
    /// What currently sits in the attachment trash.
    trash: TrashStats,
    /// Emptying the trash takes a second press: it cannot be undone.
    trash_armed: bool,
    /// How many files the last emptying removed — for the message.
    trash_just_cleared: usize,
    /// Attachment awaiting detach confirmation: the first press arms the
    /// button, the second detaches. The file only goes to the trash on save,
    /// but the detach itself cannot be undone for the draft.
    detach_armed: Option<String>,
    /// Attachment expanded into a large preview.
    preview: Option<PathBuf>,
}

/// Application version: the latest git tag, otherwise the package version.
///
/// The value is supplied by `crates/ui/build.rs` at build time. Keeping the
/// version as a hardcoded constant here was a mistake: it kept being
/// forgotten, and the "About" panel showed 1.0.0 at tags up to v1.5.0.
const APP_VERSION: &str = env!("OPCLIENT_VERSION");

/// Application author.
const APP_AUTHOR: &str = "Vitalii Tereshchuk";

/// Application home page.
///
/// This used to be the author's whole website, but the "About" panel needs
/// the 1Lock page specifically: that is the reason someone opens this link.
const APP_URL: &str = "https://dotoca.net/1lock";

/// Caption next to the link in the "About" panel.
///
/// macOS renders "title (URL)", and the title was the URL itself — it got
/// printed twice. A single word is shorter and makes it clear it is a link.
const APP_URL_LABEL: &str = "Homepage";

/// Description for the "About" panel.
const APP_COMMENTS: &str =
    "Read and edit a 1Password export (1PIF).\nPasswords are stored in the export in plain text.";

/// Copyright line.
const APP_COPYRIGHT: &str = "© 2026, Vitalii Tereshchuk / xVoLAnD";

/// License.
const APP_LICENSE: &str =
    "Personal project, no warranty. Passwords in the export are not encrypted.";

/// Application name in the window title.
const APP_TITLE: &str = "1Lock";

/// Application icon for the window title.
///
/// A copy of `assets/app-icon.png` scaled down to 128 px is kept inside the
/// repository: the 2048 px original weighs 3.5 MB and sits next to the project,
/// and embedding it in the binary is pointless — the icon is drawn at 26 px.
const APP_ICON: &[u8] = include_bytes!("../../../assets/app-icon.png");

/// A ready-made image for the window title.
///
/// The `Handle` is built once and only cloned afterwards. Building it inside
/// `view` produces a new handle on every frame: iced identifies an image by
/// the hash of its contents, considers it new and loads it again — the icon
/// in the title bar starts flickering.
/// Height of the toolbar strip. The button icons and the app icon set it,
/// while the search field keeps its own size and is centred.
const TOOLBAR_H: f32 = 64.0;

/// The app icon spans the full toolbar height: its vertical padding is
/// zero, otherwise empty space is left beside it.
const APP_ICON_SIZE: f32 = TOOLBAR_H;

/// Default list panel width, and the minimum and maximum hang off it too:
/// past those bounds the list stops being a list.
const LIST_WIDTH_DEFAULT: f32 = 340.0;
const LIST_WIDTH_MIN: f32 = 220.0;
const LIST_WIDTH_MAX: f32 = 720.0;

/// Minimum width of the right panel. Without it the list could be stretched
/// to the full window and cover everything it was stretched for.
const PANEL3_MIN: f32 = 320.0;

/// Sidebar width: it does not move, and everything else is measured from it.
/// Matches the width in `view_sidebar`.
const SIDEBAR_W: f32 = 212.0;

/// Width of the strip the pointer grabs. Already wider than the one-pixel
/// line itself: otherwise it is nearly impossible to catch.
const RESIZE_HANDLE_W: f32 = 6.0;

/// Toolbar button width. Set explicitly so all three are the same size
/// instead of following the width of the drawn icon.
const TOOLBAR_BTN_W: f32 = 44.0;

/// Icon size on toolbar buttons.
const ICON_BUTTON_SIZE: f32 = 28.0;

/// Font size in the search field. The field height follows from it: iced computes
/// it as `size * 1.3 + 2 * padding`, so the padding has to be worked out by hand.
const SEARCH_SIZE: f32 = 13.0;

/// Search field padding. It is not the field that spans the full strip
/// height but the button icons: the field keeps its normal size and is only
/// centred vertically.
const SEARCH_PADDING: f32 = 5.0;

/// Icon size on list buttons and fields: smaller than the heading.
const ICON_FIELD_SIZE: f32 = 13.0;

fn app_icon_handle() -> iced::widget::image::Handle {
    static HANDLE: std::sync::OnceLock<iced::widget::image::Handle> = std::sync::OnceLock::new();
    HANDLE
        .get_or_init(|| iced::widget::image::Handle::from_bytes(APP_ICON.to_vec()))
        .clone()
}

/// Editing form state.
struct Editing {
    /// uuid of the item being edited; `None` — a new one is created.
    uuid: Option<String>,
    /// Document behind the multi-line "Notes" field.
    ///
    /// The text lives here rather than in a string: otherwise every keypress
    /// would have to rebuild the whole editor and lose the cursor position.
    notes_doc: text_editor::Content,
    draft: EntryDraft,
    title: String,
    username: String,
    password: String,
    url: String,
    notes: String,
    /// Waiting for delete confirmation.
    confirm_delete: bool,
    /// Folder to put the item into; `None` — the top level.
    folder: Option<String>,
    /// Kind of a new item. For an existing one it is taken from `typeName`.
    kind: opclient_core::pif::ItemKind,
    /// Second extra slot: expiry and code for a card, port for a server.
    extra_b: String,
}

#[derive(Clone)]
enum Message {
    /// The "Open…" button was pressed.
    PickFile,
    /// Create a new empty 1PIF vault in the chosen directory.
    CreateVault,
    /// Open the attachment in Finder or the default app.
    OpenAttachment(PathBuf),
    /// Start editing the selected item.
    StartEdit,
    /// Create a new item.
    StartCreate,
    /// A form field changed.
    DraftChanged(&'static str, String),
    /// Commit the edit.
    ApplyEdit,
    /// Close the editor without saving.
    CancelEdit,
    /// Delete the item.
    DeleteItem,
    /// Confirm the deletion or cancel it.
    ConfirmDelete(bool),
    /// Action from the multi-line notes editor.
    EditNotes(text_editor::Action),
    /// Move focus to the next or the previous field.
    MoveFocus(bool),
    /// Write the changes to the file.
    SaveFile,
    /// Show or hide the trash of deleted items.
    /// Show live items or the trash, from the sidebar.
    ShowTrash(bool),
    /// Open or close the audit report.
    ToggleAudit,
    /// Toggle the trash view.
    ToggleTrash,
    /// Show the items of a folder; an empty string clears the folder filter.
    PickFolder(String),
    /// Folder awaiting delete confirmation.
    AskDeleteFolder(String),
    /// Text of the folder input.
    FolderDraftChanged(String),
    /// Pick the item's folder in the editor.
    DraftFolder(Option<String>),
    /// Pick the kind of the new item.
    DraftKind(opclient_core::pif::ItemKind),
    /// Create a folder from the draft, or rename the active one with it.
    SubmitFolderDraft,
    /// Empty the attachment trash completely.
    EmptyTrash,
    /// Cancel the emptying request.
    CancelEmptyTrash,
    /// Pick files and attach them to the current item.
    AttachFile,
    /// Detach the attachment by name; a second press confirms.
    DetachAttachment(String),
    /// Cancel the detach request.
    CancelDetach,
    /// Expand or collapse the large preview of an image attachment.
    TogglePreview(PathBuf),
    /// Started dragging the list panel border.
    ResizeStart,
    /// The pointer entered or left the border.
    HoverResize(bool),
    /// Left mouse button pressed anywhere in the window.
    GlobalPress,
    /// Left mouse button released anywhere in the window.
    GlobalRelease,
    /// The window was resized.
    WindowResized(f32),
    /// Detach and close the open vault.
    EjectVault,
    /// The pointer moved during a drag; the value is the X coordinate.
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
    /// Form for a new item.
    fn create() -> Self {
        Self::edit(String::new(), EntryDraft::default())
    }

    /// Form for editing an existing item.
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

        // A command-line argument outranks the remembered path.
        if let Some(p) = from_arg.or_else(config::last_path) {
            app.open(p);
        }

        app
    }

    /// State without a file. Split out of `new` so it does not depend on a
    /// path saved on the machine.
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

    /// Opens the export file. Returns whether it succeeded.
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
        // The menu is installed here rather than in `main`: at the start of the
        // event loop winit puts its own default menu on top. The first
        // `update` runs after that, on the main thread where muda requires it
        // to work. Repeated `install` calls do nothing.
        menu::install();

        match msg {
            Message::PickFile => {
                // The dialog is opened right here: `update` runs on the main
                // thread, and NSOpenPanel requires exactly that.
                let chosen = rfd::FileDialog::new()
                    .set_title("Open 1Password export file")
                    .add_filter("1Password Export", &["1pif"])
                    .pick_file();
                if let Some(p) = chosen {
                    self.open(p);
                }
            }
            Message::CreateVault => {
                // A directory, not a file: data.1pif lives next to attachments/.
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

                // As with `PickFile`, the dialog opens right inside `update`:
                // NSOpenPanel requires the main thread.
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
                // Pressing the same file again collapses the preview.
                self.preview = if self.preview.as_ref() == Some(&path) {
                    None
                } else {
                    Some(path)
                };
            }
            Message::ResizeStart | Message::GlobalPress => {
                // A mouse press only means something over the border:
                // otherwise the drag would start anywhere in the window.
                if matches!(msg, Message::GlobalPress) && !self.hover_resize {
                    return Task::none();
                }
                self.resizing = true;
                // The anchor is set on the first movement: at the moment of the
                // press the pointer has not sent a coordinate yet.
                self.resize_anchor = None;
            }
            Message::EjectVault => {
                // The vault is released wholesale: unsaved edits live in
                // memory, and without this they would be silently lost along
                // with the file.
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
                // The kind only changes for a new item: an existing one is
                // bound to a structure that is already written to the file.
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
                        // Kind-specific slots: expiry and code for a card, port for a server.
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
                // The form is already open — just ask right inside it.
                Some(e) => e.confirm_delete = true,
                // The form is not open: open it on the selected item and show
                // the question right away. Otherwise the "Delete" button
                // outside the editor silently did nothing.
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
                    // On confirm, delete the item that was edited, not the
                    // selected one. In the form they coincide, but relying on
                    // that is unsafe — the selection may have drifted.
                    let target = self
                        .editing
                        .as_ref()
                        .and_then(|e| e.uuid.clone())
                        .or_else(|| self.selected_item().map(|i| i.uuid.clone()));
                    if let Some(uuid) = target {
                        self.delete_uuid(&uuid);
                    }
                } else if let Some(e) = self.editing.as_mut() {
                    // Simply drop the question, delete nothing.
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
                // Ready-made tasks for moving focus to the next/previous field
                // from the widget tree.
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
                // Trash and categories are mutually exclusive sections: the
                // trash shows deleted items of every kind at once.
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
                    // The second press really empties it.
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
                    // The first one only asks.
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
                // Clicking the active category again clears the filter:
                // otherwise there is no way out of it except "All Items". The
                // logic lives here rather than in the panel so it works from
                // anywhere, not just from one place.
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
                    // Renaming the active folder.
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
                    // New folder: switch the filter to it right away.
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
                // Clicking the active folder again clears the filter.
                self.folder_filter = if self.folder_filter == uuid {
                    String::new()
                } else {
                    uuid.clone()
                };
                // The trash shows deletions regardless of folders.
                self.show_trash = false;
                // The input immediately shows the name of the selected folder:
                // otherwise renaming would have to be retyped blind.
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
                // The second press confirms: the contents of the folder survive,
                // but leave it, and that cannot be undone without manual edits.
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
                // Trash and categories are mutually exclusive: showing
                // deletions together with a kind filter makes no sense.
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
                // Audit is not a list section but a replacement for the right
                // panel: the selection is cleared and the trash is closed.
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
                // Selecting an item from the audit report returns to the normal view.
                self.show_audit = false;
                // An armed detach belongs to one specific file: moving to
                // another item makes the confirmation meaningless.
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
            // Tab and Shift+Tab move focus. Shift arrives as a flag in the
            // third argument of the event.
            keyboard::Event::KeyPressed {
                key: key::Key::Named(key::Named::Tab),
                modifiers,
                ..
            } => Some(Message::MoveFocus(!modifiers.shift())),
            _ => None,
        });
        let menu_events = menu::events();

        // The mouse is listened to globally rather than through a MouseArea:
        // the latter only sends movement while the cursor is over it itself.
        // A pointer nudged a couple of pixels aside cut the drag short, and
        // the panel barely moved.
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

    /// The selected item.
    fn selected_item(&self) -> Option<&PifItem> {
        let idx = self.selected?;
        let pos = *self.entries.get(idx)?;
        self.vault.as_ref()?.items.get(pos)
    }

    /// Applies the edit from the form: a new item or a change to an existing one.
    fn apply_edit(&mut self) {
        let Some(editing) = self.editing.take() else {
            return;
        };
        let Some(vault) = self.vault.as_mut() else {
            return;
        };

        // A new item with no explicit folder choice lands in the folder open in
        // the sidebar: otherwise a "new item" made from a folder would vanish.
        let mut folder = editing.folder.clone();
        if folder.is_none() && editing.uuid.is_none() && !self.folder_filter.is_empty() {
            folder = Some(self.folder_filter.clone());
        }
        let folder = folder.as_deref();

        // The edit goes into the vault, and the list is rebuilt only after the
        // mutable borrow has been released.
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
                    // Select the edited or just-created item.
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

    /// Deletes an item by uuid.
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

    /// Writes the file along with a backup copy.
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
                // The files are unpacked and laid out on disk — disarm.
                self.detach_armed = None;
                self.preview = None;
                self.toast = Some(("Saved".into(), Instant::now()));
            }
            Err(e) => {
                self.toast = Some((format!("Cannot save: {e}"), Instant::now()));
            }
        }
    }

    /// Rebuilds `entries` from the current filter and search string.
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

    /// Unique item kinds for the filter buttons.
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

    /// Editing form: creation or modification.
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

        // The kind is picked only for a new item. An existing one is bound to a
        // structure that is already in the file, and a change would mean nothing.
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

        // Field captions depend on the kind: in a card "login" is the holder,
        // in a licence it is the key. An empty caption means the kind does not
        // need that slot and the field is not drawn.
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

        // Card expiry is entered as a single "MM/YYYY" line and expands into
        // two keys on save. It comes before the code: in a card people read
        // the number, then the expiry, and only then the code.
        if e.kind == opclient_core::pif::ItemKind::CreditCard {
            rows.push(input_row("Expiry Date", &e.draft.extra_a, "extra_a"));
        }
        // Second extra slot: code for a card, port for a server.
        if !labels[4].is_empty() {
            rows.push(input_row(labels[4], &e.extra_b, "extra_b"));
        }

        // Notes are multi-line: in an export they almost always contain line
        // breaks, so a single-line field would swallow them.
        let notes: Element<'_, Message> = iced::widget::text_editor(&e.notes_doc)
            .placeholder("Notes")
            .height(Length::Fixed(140.0))
            .size(13.0)
            .on_action(Message::EditNotes)
            .into();
        rows.push(field("Notes", notes));

        // The folder is picked from a list rather than typed: the folder names
        // are already in the vault, there is no point entering them again.
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

        // The path and whatever is typed into search are white. Grey text was lost
        // against the gradient: dark on the right, it nearly merged into the background.
        // The path and "no file selected" are parenthesised: without them the line read
        // as part of the "1Password — Export" title, when it is really file information.
        //
        // Wrapping is off: on a second line the path broke the bar's height, and with it
        // the title's whole position. The length is capped by `PATH_MAX_CHARS` rather
        // than by width, because `iced` offers no way to measure text inside `view`, so
        // there is nothing to hang an ellipsis on at the cut.
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

        // The app icon sits left of the title, at the full height of the title
        // row. The padding comes from the container: an icon flush against the
        // edge melts into the window border and reads as a control, not a label.
        let mark: Element<'_, Message> = iced::widget::container(
            iced::widget::image(app_icon_handle())
                // The size is mandatory: without it the image draws at its
                // native 128 px and inflates the entire title row.
                .width(Length::Fixed(APP_ICON_SIZE))
                .height(Length::Fixed(APP_ICON_SIZE))
                .content_fit(iced::ContentFit::Contain),
        )
        .padding(Padding::new(0.0).horizontal(4.0))
        .width(Length::Shrink)
        .into();

        // The width is set by the `Fill` container, and that is not cosmetic. The
        // row on the left is `Shrink` on its own, and `iced` lays out `Shrink`
        // first and hands it all the remaining width: the title and the path take
        // as much as they can, and there is no room left for the buttons. Flex then
        // shrinks the last child, so "New vault" ends up noticeably narrower than
        // the rest and its icon smaller still, because the container squeezes its
        // contents. With `Fill` the block moves to the second pass: the buttons are
        // laid out first and get their sizes, and the text is what gets squeezed.
        //
        // There is no longer a separate `Space::new().width(Fill)` in the
        // row: alongside this block it split the remainder in half, so the
        // path got half the room it used to. The single `Fill` takes the
        // whole remainder, but the text in it is left-aligned, so nothing
        // looks different and the path again gets all the available width.
        let left: Element<'_, Message> = iced::widget::container(
            iced::widget::row(vec![mark, title, file])
                .spacing(10.0)
                .align_y(Center),
        )
        .width(Length::Fill)
        // A character budget cannot follow the window width, so on a narrow window
        // the path ends up longer than the room allotted. Without clipping it would
        // run into the search field; with it, the path is simply cut off at the edge.
        .clip(true)
        .into();

        let head: Element<'_, Message> = if self.vault.is_some() {
            // The height comes from the field's own padding, not from the container:
            // the container stretches the border box, while the border draws at its
            // natural height, and next to the buttons it then sat too high.
            let search = iced::widget::text_input("Search…", &self.query_input)
                .on_input(|v| Message::SearchChanged(v.clone()))
                .size(SEARCH_SIZE)
                .padding(Padding::new(SEARCH_PADDING).horizontal(10.0))
                .width(Length::Fixed(240.0))
                // The field is transparent: a plate of its own laid over the
                // gradient would look pasted on. The border appears on hover
                // and on focus — otherwise there is nothing to search with.
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

            // One uniform toolbar: the same surface and the same insets as the
            // sidebar, plus a hairline along the bottom. Otherwise the seam between
            // toolbar and panel shows up as a difference in shade and in padding.
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
                // Without centring, the search field sticks to the top of the
                // bar: its height is set by the buttons at full height.
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
            // The buttons in an empty vault are the same ones at the same
            // size: the bar must not change its look once a file is opened.
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

        // The caption above the list saying how many entries there are and what they are
        // filtered by is gone: the status line at the bottom says the same, the active section
        // is highlighted in the sidebar anyway, and the trash is visible right there too.
        head
    }

    /// Start screen: an invitation to pick a file.
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

    /// Main screen: the list and the details.
    fn view_browser(&self) -> Element<'_, Message> {
        // Through .get(): if the filtered list lags behind the vault, the
        // screen should come up empty rather than panic.
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

        // The hairline between the panel and the list. In iced 0.14 Border has
        // no per-side faces, so the line is drawn as a separate one-pixel
        // strip.
        let hairline: Element<'_, Message> =
            iced::widget::container(iced::widget::text("").size(1.0))
                .width(Length::Fixed(1.0))
                .height(Length::Fill)
                .style(|_: &Theme| iced::widget::container::Style {
                    background: Some(HAIRLINE.into()),
                    ..iced::widget::container::Style::default()
                })
                .into();

        // The edge of the list panel: the panel is dragged by it. A one-pixel
        // line would stay put, while the strip behind it gives the pointer
        // something to grab and turns the cursor into a two-headed arrow.
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

        // The container sets the strip's size: MouseArea has no width
        // method of its own.
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

    /// Adopts the vault that was just created.
    ///
    /// Mirrors [`App::open`] but takes a directory: the file path is known up
    /// front and needs no resolving, and re-reading a file we have only just
    /// written from disk is pointless — we are already holding it.
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

    /// Keeps the list width within the allowed range.
    ///
    /// The upper bound is computed from the window width instead of being a fixed
    /// number: the panel on the right must not collapse into a narrow strip either.
    fn clamp_list_width(&mut self) {
        let mut max = LIST_WIDTH_MAX;
        if self.window_w > 0.0 {
            max = (self.window_w - SIDEBAR_W - 1.0 - RESIZE_HANDLE_W - PANEL3_MIN)
                .max(LIST_WIDTH_MIN);
        }
        self.list_width = self.list_width.clamp(LIST_WIDTH_MIN, max);
    }

    /// How many live entries of each kind there are.
    ///
    /// Only live ones are counted: the trash is a separate section, and in
    /// the per-category counters it would throw the numbers off.
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

    /// An entry row in the audit report: the name, and a jump to the entry.
    ///
    /// The entry may not be in the current list — filtered out by category,
    /// or sitting in the trash, say. Then the row is not clickable, and the
    /// note says so rather than falling silent.
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

    /// The security audit report.
    ///
    /// Passwords are never printed: only entry names and counters are shown,
    /// otherwise the audit panel would become a second place where the
    /// secret sits in plain text.
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

        // The shield icon left of the heading is the same device as in the details panel:
        // the section gets an icon of its own so it cannot be mistaken for an entry icon.
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

        // Lists of names. Jumping to an entry is an ordinary Select, and the audit
        // closes along the way so the user actually gets to see the entry itself.
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

    /// Sidebar: sections and categories, as in 1Password.
    fn view_sidebar(&self) -> Element<'_, Message> {
        let alive = self.vault.as_ref().map_or(0, |v| v.alive().len());
        let trashed = self.vault.as_ref().map_or(0, |v| v.trashed().len());

        let mut col: Vec<Element<'_, Message>> = Vec::new();

        // Section heading: a small-type caption with the section icon next to it.
        //
        // The icon is placed here rather than in every row: otherwise the folder
        // icon would repeat next to every folder, and the grid icon next to every
        // kind of item. That is exactly how 1Password separates its sections.
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

        // Section row: icon, label, counter.
        //
        // The icon is optional only for folders: they are named by the user,
        // and painting the same folder icon beside each of them is pointless.
        // For kinds the icon matches the item type, so it carries meaning
        // rather than decoration.
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
            // Sections with no counter (Tools) get no number: a zero would
            // read as "nothing found", which is not the case here.
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
            // Compute the icon before handing over the label: `section` takes
            // the string by value, so it cannot be referenced afterwards.
            let mark = icons::Icon::for_kind(&kind);
            col.push(section(kind, Some(count), active, msg, Some(mark)));
        }

        // Folders are the only thing the user can create by hand: they are ordinary
        // system.folder.Regular records, not a projection of an item type.
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

        // Widgets cannot be used twice, so they are rebuilt each time: the
        // input row is needed both to create a new folder and to rename one.
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

        // The input row: with a folder selected it renames that folder,
        // otherwise it creates a new one.
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

        // Edge to edge: the panel runs the full height of the window, is
        // inset only at the sides, and on the right gets a hairline instead
        // of a border. macOS 27 dresses its sidebars the same way.
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
        // The letter whose divider has already been printed. The list is
        // sorted by title, so identical letters come in runs.
        let mut last_letter: Option<char> = None;

        for (pos, &idx) in self.entries.iter().enumerate() {
            // Skip indices that no longer exist in the vault.
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

            // The kind's icon sits left of the title and spans the full row
            // height: that way it reads as a type label rather than as decoration.
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

            // The group also changes on digits, but no heading is drawn for them: "1Password"
            // and "35AWARDS" sit next to each other in 1Password without a letter between them.
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

        // The panel's first row: the kind's icon left of the title.
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

        // Type-specific fields: card number, expiry, POP/SMTP, licence key.
        // A web form has none of them; a wallet is mostly them.
        for (label, value, secret) in it.extra_fields() {
            b.push(self.extra_row(&it.uuid, &label, &value, secret));
        }

        // The block is always drawn, not only once attachments exist:
        // otherwise there is nowhere to reach the first file from.
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

                // Only a file already sitting on disk gets a thumbnail: there is nowhere
                // to render a preview of an attachment that has not been saved yet.
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

                // The expanded preview lives under its own row rather than over the
                // list, so there is never any doubt about which file it belongs to.
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

    /// Selects an entry by uuid.
    ///
    /// The position is looked up in the filtered and sorted list the user
    /// actually sees: in the vault the entries sit in file order, while they
    /// are displayed alphabetically.
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

    /// Whether there are unsaved changes.
    fn has_changes(&self) -> bool {
        self.vault.as_ref().is_some_and(Pif::has_changes)
    }

    /// The attachment files of an entry.
    fn attachments_of(&self, uuid: &str) -> Option<Vec<opclient_core::pif::Attachment>> {
        let files = self.vault.as_ref()?.attachments.get(uuid)?;
        (!files.is_empty()).then(|| files.clone())
    }

    /// Whether there are attachments that have not been written to disk yet.
    fn attachments_pending(&self) -> bool {
        self.vault
            .as_ref()
            .is_some_and(opclient_core::pif::Pif::attachments_changed)
    }

    /// Attaches files to an entry without a dialog: split out separately so that the
    /// copy itself can be covered by a test — `NSOpenPanel` cannot be opened in a test.
    ///
    /// Returns how many were attached and the names of those that were not.
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
                // Telling "no vault" apart from "read error" would serve no
                // purpose: the user needs the same thing in both cases.
                _ => failed.push(name),
            }
        }

        (added, failed)
    }

    /// The entry that attachment actions apply to.
    ///
    /// While the editor is open, the subject is that one: the item being edited
    /// matters more than the selected one, otherwise a file attached from a new-entry
    /// form would land on its neighbour. `None` for an entry being created — it has
    /// no uuid yet, and the attachment directory is named after exactly that.
    fn attachment_target(&self) -> Option<String> {
        match self.editing.as_ref() {
            Some(e) => e.uuid.clone(),
            None => self.selected_item().map(|i| i.uuid.clone()),
        }
    }

    /// A row for one specific field. Secret values stay masked until they are
    /// explicitly revealed; ordinary ones are shown right away.
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

        // Attachment trash: how much is in there, and how to clear it.
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

        // The button dismisses the toast, so without one it would be pointless.
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

/// Picks the entry indices that match a search string and a kind filter.
///
/// Folders never make it into the list. The search is case-insensitive and looks at the
/// title, the domain and the full URL. Entries with no title sink to the bottom, otherwise
/// the five blank web forms in an export would take over the whole top of the list.
///
/// `folder` is a folder uuid; an empty string means "all folders
/// and the top level", not "top level only": that way folders work
/// as a filter rather than as the only way to reach an entry.
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
        // The trash is a separate section: deleted entries are not in the normal list.
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
                // Card number, licence key and the rest are searched too.
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

/// The title to display: an empty string in the export is as good as none.
fn display_title(it: &PifItem) -> String {
    it.title
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .unwrap_or("(untitled)")
        .to_string()
}

/// A "LABEL" field plus its content.
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

/// A "label: value" row with a copy button: an icon button standing in
/// for the label.
///
/// The label is dropped so that no stray text sits next to the value. The action's
/// name comes back in a tooltip: without it the icon would have to be guessed at,
/// and a canvas interface has no other way to announce what a button does.
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

/// The same as [`icon_button`] but larger: toolbar buttons sit in the title
/// row and have to read as its peers.
#[allow(clippy::too_many_arguments)]
fn toolbar_icon_button<'a>(
    mark: icons::Icon,
    tip: &'a str,
    msg: Message,
    style: fn(&Theme, iced::widget::button::Status) -> iced::widget::button::Style,
) -> Element<'a, Message> {
    // The content sets the size, not the button itself. A button's height()
    // is capped by the parent and in a toolbar row behaves as "no more than
    // you were given", so the button stayed at 23 px. The inner container
    // sets the size directly and the button becomes exactly that. The
    // padding is zero so it adds no extra pixels to the height.
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

/// Toolbar button. The padding is set explicitly: the default is such that the
/// icon inside gets squeezed and stops reading as a peer of the search field.
fn chip_toolbar(_t: &Theme, s: iced::widget::button::Status) -> iced::widget::button::Style {
    // No plate: the button shows the same gradient as the bar. A grey
    // background of its own would look like a foreign rectangle dropped in.
    // A faint highlight shows on hover, otherwise there is nothing to press.
    match s {
        // The hover highlight is barely perceptible: the button has to read
        // as pressable without looking like a plate laid over the gradient.
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

/// An image fitted into a `side`-sized square.
fn thumbnail(path: &std::path::Path, side: f32) -> iced::widget::Image {
    iced::widget::image(iced::widget::image::Handle::from_path(path.to_path_buf()))
        .width(Length::Fixed(side))
        .height(Length::Fixed(side))
        .content_fit(iced::ContentFit::Contain)
        .filter_method(iced::widget::image::FilterMethod::Linear)
}

/// Whether a file's contents look like a picture.
///
/// The decision is made by extension rather than by content: `iced` does sniff
/// the format from the data itself, but a preview only makes sense for
/// extensions known to be supported. `heic` is not in the list — `iced` cannot
/// decode it, and you would get an empty rectangle instead of a picture.
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

/// The toast text for attaching files.
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

/// The item kind for a `typeName` value, as it arrives from the export.
///
/// An unknown type is treated as a login: it is the least surprising option,
/// and its `designation` field reads unambiguously.
fn item_kind_of(type_name: &Option<String>) -> opclient_core::pif::ItemKind {
    use opclient_core::pif::ItemKind;

    ItemKind::all()
        .into_iter()
        .find(|k| Some(k.type_name()) == type_name.as_deref())
        .unwrap_or(ItemKind::Login)
}

/// "1 file", "2 files".
///
/// In Russian this needed three separate forms and had to branch on the last
/// digits. English only draws a line between one and everything else, which
/// is why the function got shorter too.
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

/// How many path characters fit in the toolbar before the search field.
///
/// The budget is in characters, not pixels: `iced` gives no way to measure
/// text width from `view`, and with no limit a long file name wraps the path
/// onto a second line and breaks the bar's height.
const PATH_MAX_CHARS: usize = 46;

/// Shortens a string by length while keeping its head and its tail.
///
/// The tail matters more than the head: in a path it is the file name, the very reason anyone reads the line.
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

/// Collapses a long path down to "…/folder/file".
fn short_path(p: &std::path::Path) -> String {
    let s = p.to_string_lossy().to_string();
    let parts: Vec<&str> = s.rsplitn(3, '/').collect();
    if parts.len() == 3 {
        format!("…/{}/{}", parts[1], parts[0])
    } else {
        s
    }
}

/// Opens a file with the macOS app associated with it.
#[cfg(target_os = "macos")]
fn open_in_finder(path: &std::path::Path) -> bool {
    std::process::Command::new("open").arg(path).spawn().is_ok()
}

#[cfg(not(target_os = "macos"))]
fn open_in_finder(_path: &std::path::Path) -> bool {
    false
}

/// A form row: a label and an input field.
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
/// The warning colour for unsaved changes.
const TEXT_WARN: Color = Color::from_rgb(0.95, 0.72, 0.30);

// Surfaces. In macOS 27 the sidebar and the toolbar read as one continuous
// material surface split by a hairline, so they share the same background —
// otherwise the seam jumps out at you immediately.
const SURFACE: Color = Color::from_rgb(0.113, 0.125, 0.149);
/// The main field: a touch lighter, so the panels read as recesses.
const SURFACE_RAISED: Color = Color::from_rgb(0.141, 0.156, 0.184);
/// The hairline between the panel and the content.
const HAIRLINE: Color = Color::from_rgba(1.0, 1.0, 1.0, 0.07);

/// Left edge of the title bar: #4065b9.
const TOOLBAR_LEFT: Color = Color::from_rgb(0.251, 0.396, 0.725);

/// Right edge of the title bar: #0d122c.
const TOOLBAR_RIGHT: Color = Color::from_rgb(0.051, 0.071, 0.173);

/// Gradient direction in degrees: 90° is left to right, 135° is from the top
/// left corner to the bottom right.
///
/// The gradient takes radians, so the degrees are converted explicitly. This
/// used to hold a bare 90 — that is, 90 radians — which made the direction
/// effectively arbitrary.
const TOOLBAR_GRADIENT_DEG: f32 = 135.0;

/// Toolbar background: a blend from #4065b9 in the top left corner to
/// #0d122c in the bottom right.
fn toolbar_background() -> iced::Background {
    iced::Background::Gradient(iced::Gradient::Linear(
        iced::gradient::Linear::new(TOOLBAR_GRADIENT_DEG.to_radians())
            .add_stop(0.0, TOOLBAR_LEFT)
            .add_stop(1.0, TOOLBAR_RIGHT),
    ))
}

// Type sizes. Text sizes are scattered across the codebase as dozens of
// magic numbers; macOS keeps a fixed scale, and without it only the
// headings line up, while the small text does not.
mod type_scale {
    /// Window title and large headings.
    pub const LARGE: f32 = 20.0;
    /// Panel heading.
    pub const TITLE: f32 = 15.0;
    /// Ordinary row text.
    pub const BODY: f32 = 13.0;
    /// Secondary text: counters, field captions.
    pub const SECONDARY: f32 = 11.0;
    /// Section headings in the sidebar.
    pub const CAPTION: f32 = 10.0;
}

fn copy_to_clipboard(text: &str) -> bool {
    arboard::Clipboard::new()
        .and_then(|mut c| c.set_text(text.to_owned()))
        .is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Dragging the divider resizes the list panel by the pointer's
    /// delta, not by its absolute position.
    #[test]
    fn dragging_divider_resizes_list() {
        let mut app = App::blank();
        assert_eq!(app.list_width, LIST_WIDTH_DEFAULT);

        let _ = app.update(Message::ResizeStart);
        // The first move only records the anchor; the width stays put.
        let _ = app.update(Message::ResizeMove(100.0));
        assert_eq!(app.list_width, LIST_WIDTH_DEFAULT);

        let _ = app.update(Message::ResizeMove(160.0));
        assert_eq!(app.list_width, LIST_WIDTH_DEFAULT + 60.0);

        // Moving left shrinks it, and back again without a jerk.
        let _ = app.update(Message::ResizeMove(110.0));
        assert_eq!(app.list_width, LIST_WIDTH_DEFAULT + 10.0);
    }

    /// The width stays within bounds: a list that is too narrow and a
    /// right panel that is too squeezed are both useless.
    #[test]
    fn list_width_is_clamped() {
        let mut app = App::blank();
        let _ = app.update(Message::ResizeStart);
        let _ = app.update(Message::ResizeMove(0.0));

        let _ = app.update(Message::ResizeMove(5000.0));
        assert_eq!(app.list_width, LIST_WIDTH_MAX);

        let _ = app.update(Message::ResizeMove(-5000.0));
        assert_eq!(app.list_width, LIST_WIDTH_MIN);
    }

    /// Once the pointer is released the list stops changing.
    #[test]
    fn releasing_pointer_freezes_list_width() {
        let mut app = App::blank();
        let _ = app.update(Message::ResizeStart);
        let _ = app.update(Message::ResizeMove(100.0));
        let _ = app.update(Message::ResizeMove(200.0));
        let width = app.list_width;

        let _ = app.update(Message::GlobalRelease);
        let _ = app.update(Message::ResizeMove(400.0));
        assert_eq!(app.list_width, width, "list width changed without a drag");
    }

    /// The right panel has a minimum too: the list must not be stretched
    /// to fill the window and hide everything it is stretched to show.
    #[test]
    fn right_panel_keeps_its_minimum() {
        let mut app = App::blank();
        let _ = app.update(Message::WindowResized(1000.0));

        let _ = app.update(Message::ResizeStart);
        let _ = app.update(Message::ResizeMove(0.0));
        let _ = app.update(Message::ResizeMove(5000.0));

        let panel3 = 1000.0 - SIDEBAR_W - 1.0 - RESIZE_HANDLE_W - app.list_width;
        assert_eq!(panel3, PANEL3_MIN, "right panel collapsed");
        assert!(app.list_width < 1000.0, "list took over the whole window");
    }

    /// A narrow window must not break the calculation: minimums just meet.
    #[test]
    fn narrow_window_keeps_width_math_valid() {
        let mut app = App::blank();
        let _ = app.update(Message::WindowResized(200.0));

        let _ = app.update(Message::ResizeStart);
        let _ = app.update(Message::ResizeMove(0.0));
        let _ = app.update(Message::ResizeMove(9999.0));

        assert_eq!(app.list_width, LIST_WIDTH_MIN);
        assert!(app.list_width.is_finite(), "width stopped being a finite number");
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
    fn search_by_title_and_domain_is_case_insensitive() {
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
    fn filter_by_kind_works() {
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
    fn folders_are_excluded_from_list() {
        let items = vec![
            item("Личное", FOLDER_TYPE, None),
            item("Запись", "webforms.WebForm", None),
        ];
        assert_eq!(filter_indices(&items, "", "", false, ""), vec![1]);
    }

    #[test]
    fn empty_titles_sort_to_the_end() {
        let items = vec![
            item("", "webforms.WebForm", None),
            item("", "webforms.WebForm", None),
            item("Alpha", "webforms.WebForm", None),
            item("Beta", "webforms.WebForm", None),
        ];
        assert_eq!(filter_indices(&items, "", "", false, ""), vec![2, 3, 0, 1]);
    }

    #[test]
    fn password_mask_hides_the_middle() {
        // 16 chars: first 3 + 11 dots (16-5) + last 2
        assert_eq!(masked("gu3SecretValue99"), "gu3•••••••••••99");
        assert_eq!(masked("abc"), "•••");
        assert_eq!(masked(""), "");
        // a long password must not become a sheet of dots
        assert_eq!(
            masked(&"x".repeat(100))
                .chars()
                .filter(|c| *c == '•')
                .count(),
            20
        );
    }

    #[test]
    fn long_path_is_elided() {
        assert_eq!(
            short_path(std::path::Path::new(
                "/Users/x/Downloads/1Password (5).1pif/data.1pif"
            )),
            "…/1Password (5).1pif/data.1pif"
        );
    }

    #[test]
    fn without_a_file_the_list_is_empty() {
        let app = App::blank();
        assert!(app.vault.is_none());
        assert!(app.entries.is_empty());
        // Categories come from the vault: with no file there must be none.
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
    fn card_is_found_by_number() {
        let items = vec![card()];
        assert_eq!(filter_indices(&items, "5314451", "", false, ""), vec![0]);
        assert_eq!(filter_indices(&items, "карта", "", false, ""), vec![0]);
        assert!(filter_indices(&items, "9999", "", false, "").is_empty());
    }

    #[test]
    fn card_is_filtered_by_kind() {
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

    /// An app holding a single file in a temp directory.
    fn app_with(name: &str, contents: &str) -> (App, PathBuf) {
        let path = std::env::temp_dir().join(format!("opclient-render-{name}.1pif"));
        std::fs::write(&path, contents).unwrap();
        let mut app = App::blank();
        assert!(app.open(path.clone()), "the file should open");
        (app, path)
    }

    /// Ejecting closes the vault and clears everything that belonged to it.
    #[test]
    fn ejecting_closes_the_vault() {
        let (mut app, path) = app_with("eject", "{\"uuid\":\"U1\",\"typeName\":\"webforms.WebForm\",\"title\":\"Demo\",\"secureContents\":{}}");
        assert!(app.vault.is_some());

        let _ = app.update(Message::EjectVault);

        assert!(app.vault.is_none(), "the vault stayed open");
        assert!(app.path.is_none(), "the path stayed in the state");
        assert!(app.entries.is_empty(), "the list stayed non-empty");
        let _ = std::fs::remove_file(path);
    }

    /// With unsaved edits ejecting is refused: they live in memory and
    /// would be lost silently.
    #[test]
    fn ejecting_refuses_to_discard_edits() {
        let (mut app, path) = app_with("eject-dirty", "{\"uuid\":\"U1\",\"typeName\":\"webforms.WebForm\",\"title\":\"Demo\",\"secureContents\":{}}");
        app.vault.as_mut().unwrap().items[0].dirty = true;
        assert!(app.has_changes());

        let _ = app.update(Message::EjectVault);

        assert!(
            app.vault.is_some(),
            "the vault closed despite the edits"
        );
        let _ = std::fs::remove_file(path);
    }

    const CARD: &str = r#"{"uuid":"C1","typeName":"wallet.financial.CreditCard","title":"Кредитная карта","secureContents":{"cardholder":"Vitalii","ccnum":"5314451117033352","cvv":"712","expiry_mm":"9","expiry_yy":"2016"}}
{"uuid":"W1","typeName":"webforms.WebForm","title":"Website","secureContents":{"fields":[{"name":"username","type":"T","designation":"username","value":"me"},{"name":"password","type":"P","designation":"password","value":"pw"}]}}"#;

    /// The card view must build: this data used to be unread entirely.
    #[test]
    fn card_view_builds() {
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

    /// The whole-page view must build on wallet data too.
    #[test]
    fn page_view_builds() {
        let (app, path) = app_with("page", CARD);
        let _element = app.view();
        let _ = std::fs::remove_file(path);
    }

    /// Opening a new file must not carry over revealed passwords.
    #[test]
    fn opening_a_new_file_resets_revealed() {
        let (mut app, path) = app_with("reset", CARD);
        app.revealed.insert("C1::Пароль".into(), true);
        assert!(app.open(path.clone()));
        assert!(app.revealed.is_empty(), "revealed passwords must be reset");
        let _ = std::fs::remove_file(path);
    }
}

#[cfg(test)]
mod tests_common {
    use std::path::PathBuf;

    /// A directory unique to each call within this process.
    /// The pid is shared by parallel tests, so a counter is needed.
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

    /// An export with a single attachment next to data.1pif.
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
    fn attachment_is_found_for_item() {
        let path = export_with_attachment();
        let mut app = App::blank();
        assert!(app.open(path.clone()));

        let files = app
            .attachments_of("AAAA1111BBBB2222CCCC3333DDDD4444")
            .unwrap();
        assert_eq!(files.len(), 1);
        assert_eq!(files[0].name, "invoice.pdf");
        assert!(files[0].path.exists());

        // the item view with an attachment must build
        let it = app.vault.as_ref().unwrap().items[0].clone();
        let _element = app.view_details(&it);

        let _ = std::fs::remove_dir_all(path.parent().unwrap());
    }

    #[test]
    fn item_without_attachments_has_none() {
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

    /// An app with a copy of the real export (or with a stub).
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
            std::fs::write(&file, STUB_EXPORT).unwrap();
        }
        let mut app = App::blank();
        assert!(app.open(file.clone()));
        (app, root)
    }

    /// A stub for when the real export is missing.
    ///
    /// It holds exactly as many items as the tests need: they pick the
    /// second and third, and with a single item the selection came up empty
    /// and `unwrap()` on `None` took down three tests. That used to go
    /// unnoticed — a real 533-item export sat right there and got substituted
    /// for the stub instead. But it lives outside the repo and is missing in
    /// CI, so the failure only surfaced on a clean machine.
    const STUB_EXPORT: &str = concat!(
        r#"{"uuid":"U1","typeName":"securenotes.SecureNote","title":"A","secureContents":{}}"#,
        "\n",
        r#"{"uuid":"U2","typeName":"securenotes.SecureNote","title":"B","secureContents":{}}"#,
        "\n",
        r#"{"uuid":"U3","typeName":"securenotes.SecureNote","title":"C","secureContents":{}}"#,
        "\n",
    );

    #[test]
    fn new_item_is_created_and_saved() {
        let (mut app, root) = app_with_export("create");
        let before = app.vault.as_ref().unwrap().items.len();

        let _ = app.update(Message::StartCreate);
        assert!(app.editing.is_some(), "the form should open");
        let _ = app.update(Message::DraftChanged("title", "Новый вход".into()));
        let _ = app.update(Message::DraftChanged("username", "user@example.com".into()));
        let _ = app.update(Message::DraftChanged("password", "pass-1234".into()));
        let _ = app.update(Message::DraftChanged(
            "url",
            "https://example.com/login".into(),
        ));
        let _ = app.update(Message::ApplyEdit);

        assert!(app.editing.is_none(), "the form should close");
        assert!(app.has_changes(), "unsaved changes appeared");
        assert_eq!(app.vault.as_ref().unwrap().items.len(), before + 1);

        let _ = app.update(Message::SaveFile);
        assert!(!app.has_changes(), "no edits remain after saving");

        let again = Pif::from_file(root.join("data.1pif")).unwrap();
        let created = again
            .items
            .iter()
            .find(|i| i.title.as_deref() == Some("Новый вход"))
            .expect("the item should survive the save");
        assert_eq!(created.primary_password(), Some("pass-1234"));
        assert_eq!(created.usernames(), vec!["user@example.com"]);

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn editing_an_existing_item() {
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
        let it = again.find(&uuid).expect("the item should still be there");
        assert_eq!(it.primary_password(), Some("совсем-другой"));

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn cancelling_an_edit_changes_nothing() {
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
        assert!(!app.has_changes(), "cancelling should leave no changes");
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
    fn deleting_requires_confirmation() {
        let (mut app, root) = app_with_export("delete");
        let _ = app.update(Message::Select(1));
        let uuid = app.selected_item().unwrap().uuid.clone();

        let _ = app.update(Message::StartEdit);
        let _ = app.update(Message::DeleteItem);
        assert!(app.editing.as_ref().unwrap().confirm_delete);
        let _ = app.update(Message::ConfirmDelete(false));
        assert!(
            !app.editing.as_ref().unwrap().confirm_delete,
            "cancelling clears the prompt"
        );
        assert!(app.vault.as_ref().unwrap().find(&uuid).is_some());

        let _ = app.update(Message::StartEdit);
        let _ = app.update(Message::DeleteItem);
        let _ = app.update(Message::ConfirmDelete(true));
        let _ = app.update(Message::ApplyEdit);
        assert!(
            app.vault.as_ref().unwrap().find(&uuid).is_none(),
            "after confirming, the item should be gone"
        );

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn editor_and_page_views_build() {
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

    /// The save button only shows up when there are unsaved edits.
    #[test]
    fn save_button_appears_only_when_needed() {
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

    /// An export with items of several kinds, one trashed item, and a folder.
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

    /// Category counters count only live items, never folders.
    #[test]
    fn category_counts_ignore_folders_and_trashed() {
        let (app, root) = app_with_kinds("sidebar-counts");

        let counts = app.kind_counts();
        let web = counts.iter().find(|(k, _)| k == "Logins").map(|(_, c)| *c);
        assert_eq!(web, Some(2), "two live web forms");

        assert!(
            !counts.iter().any(|(k, _)| k == "Folder"),
            "folders should not appear in categories"
        );
        assert_eq!(
            counts.iter().map(|(_, c)| c).sum::<usize>(),
            3,
            "a trashed item should not be counted"
        );

        let _ = std::fs::remove_dir_all(&root);
    }

    /// The trash is a section that excludes the kind categories.
    #[test]
    fn trash_clears_the_kind_filter() {
        let (mut app, root) = app_with_kinds("sidebar-trash");

        let _ = app.update(Message::Filter("Logins".into()));
        assert_eq!(app.kind_filter, "Logins");

        let _ = app.update(Message::ShowTrash(true));
        assert!(app.show_trash);
        assert!(
            app.kind_filter.is_empty(),
            "the trash shows items of every kind at once"
        );

        let _ = std::fs::remove_dir_all(&root);
    }

    /// Leaving the trash clears the filter too.
    #[test]
    fn leaving_trash_clears_the_kind_filter() {
        let (mut app, root) = app_with_kinds("sidebar-back");

        let _ = app.update(Message::ShowTrash(true));
        let _ = app.update(Message::Filter("Logins".into()));
        let _ = app.update(Message::ShowTrash(false));

        assert!(!app.show_trash);
        assert!(app.kind_filter.is_empty());
        assert!(
            !app.entries.is_empty(),
            "the list is populated again after coming back"
        );

        let _ = std::fs::remove_dir_all(&root);
    }

    /// Categories come out alphabetically, and a second click clears the filter.
    #[test]
    fn categories_are_sorted_and_toggle() {
        let (mut app, root) = app_with_kinds("sidebar-order");

        let kinds: Vec<String> = app.kind_counts().into_iter().map(|(k, _)| k).collect();
        let mut sorted = kinds.clone();
        sorted.sort();
        assert_eq!(kinds, sorted, "categories are in alphabetical order");

        let first = kinds.first().cloned().unwrap();
        let _ = app.update(Message::Filter(first.clone()));
        assert_eq!(app.kind_filter, first);
        assert!(!app.entries.is_empty(), "the category shows something");

        let _ = app.update(Message::Filter(first));
        assert!(
            app.kind_filter.is_empty(),
            "a second click clears the filter"
        );

        let _ = std::fs::remove_dir_all(&root);
    }

    /// The sidebar and the list with their separators build.
    #[test]
    fn sidebar_and_list_build() {
        let (mut app, root) = app_with_kinds("sidebar-render");
        let _ = app.view_sidebar();
        let _ = app.view_list();
        let _ = app.view_browser();
        let _ = app.update(Message::Select(0));
        let _ = app.view_browser();

        let _ = std::fs::remove_dir_all(&root);
    }

    /// A newly created vault becomes current and empty right away.
    #[test]
    fn new_vault_opens_empty() {
        let dir = unique_dir("create-ui");
        let vault = Pif::create(&dir).unwrap();

        let mut app = App::blank();
        app.open_created(&dir, vault);

        assert!(app.error.is_none());
        assert_eq!(app.path, Some(dir.join("data.1pif")));
        assert!(app.entries.is_empty(), "the list is still empty");
        assert!(app.kind_counts().is_empty(), "there are no categories yet");
        assert!(!app.show_trash, "the trash is off");
        assert!(app.kind_filter.is_empty(), "the filter is cleared");

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// In a fresh vault you can create an item and save it to disk.
    #[test]
    fn item_can_be_created_in_a_new_vault() {
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

        assert_eq!(app.entries.len(), 1, "the item showed up in the list");
        assert!(app.has_changes(), "there is something to save");

        let _ = app.update(Message::SaveFile);
        assert!(!app.has_changes(), "everything is clean after saving");

        let reread = Pif::from_file(dir.join("data.1pif")).unwrap();
        assert_eq!(
            reread
                .items
                .iter()
                .filter(|i| i.title.as_deref() == Some("Первый вход"))
                .count(),
            1,
            "the item survived the save and reopen"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The start screen and the toolbar both offer to create a vault.
    #[test]
    fn creation_is_available_from_both_screens() {
        let mut app = App::blank();
        let _ = app.view();

        // With a file open the toolbar offers a new vault too.
        let dir = unique_dir("create-toolbar");
        let vault = Pif::create(&dir).unwrap();
        app.open_created(&dir, vault);
        let _ = app.view_toolbar();

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// An export with two folders: one holds an item, the other does not.
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

    /// Folders show in the sidebar with their own counters.
    #[test]
    fn folders_show_with_counts() {
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
        assert_eq!(counts, vec![1, 0], "Work has one item, EMails is empty");

        let _ = std::fs::remove_dir_all(&root);
    }

    /// Picking a folder filters the list; a second click clears the filter.
    #[test]
    fn picking_a_folder_filters_the_list() {
        let (mut app, root) = app_with_folders("folders-filter");
        assert_eq!(app.entries.len(), 2, "both items to start with");

        let _ = app.update(Message::PickFolder("F1".into()));
        assert_eq!(app.folder_filter, "F1");
        assert_eq!(app.entries.len(), 1, "the folder holds only GitHub");

        let _ = app.update(Message::PickFolder("F1".into()));
        assert_eq!(app.folder_filter, "", "a second click clears it");
        assert_eq!(app.entries.len(), 2);

        let _ = std::fs::remove_dir_all(&root);
    }

    /// A new folder is created from the input field and becomes active at once.
    #[test]
    fn folder_is_created_from_the_draft_field() {
        let (mut app, root) = app_with_folders("folders-create");

        let _ = app.update(Message::FolderDraftChanged("  Home  ".into()));
        let _ = app.update(Message::SubmitFolderDraft);

        let folders = app.vault.as_ref().unwrap().folders();
        assert_eq!(folders.len(), 3, "the folder was added");
        assert!(
            folders.iter().any(|f| f.title.as_deref() == Some("Home")),
            "the name was trimmed of spaces"
        );
        assert!(!app.folder_filter.is_empty(), "the new folder is selected");
        assert!(app.folder_draft.is_empty(), "the field was cleared");

        let _ = std::fs::remove_dir_all(&root);
    }

    /// An empty folder name does not create one.
    #[test]
    fn empty_folder_name_is_rejected() {
        let (mut app, root) = app_with_folders("folders-empty");

        let _ = app.update(Message::FolderDraftChanged("   ".into()));
        let _ = app.update(Message::SubmitFolderDraft);

        assert_eq!(app.vault.as_ref().unwrap().folders().len(), 2);
        let (text, _) = app.toast.clone().unwrap();
        assert!(
            text.contains("name"),
            "the user is told what went wrong: {text}"
        );

        let _ = std::fs::remove_dir_all(&root);
    }

    /// The picked folder is filled into the input field, and renaming works.
    #[test]
    fn folder_can_be_renamed() {
        let (mut app, root) = app_with_folders("folders-rename");

        let _ = app.update(Message::PickFolder("F2".into()));
        assert_eq!(app.folder_draft, "EMails", "the field showed the folder name");
        assert_eq!(app.folder_draft_for.as_deref(), Some("F2"));

        let _ = app.update(Message::FolderDraftChanged("Mail".into()));
        let _ = app.update(Message::SubmitFolderDraft);

        let renamed = app.vault.as_ref().unwrap().folder("F2").unwrap();
        assert_eq!(renamed.title.as_deref(), Some("Mail"));
        // The folder stays selected and the list stays filtered: after a
        // rename you normally want to confirm everything is in place.
        assert_eq!(app.folder_draft_for.as_deref(), Some("F2"));
        assert_eq!(app.folder_filter, "F2");

        let _ = std::fs::remove_dir_all(&root);
    }

    /// Deleting a folder asks first and does not take its contents with it.
    #[test]
    fn deleting_a_folder_asks_and_keeps_items() {
        let (mut app, root) = app_with_folders("folders-delete");

        let _ = app.update(Message::PickFolder("F1".into()));
        let _ = app.update(Message::AskDeleteFolder("F1".into()));
        assert!(
            app.vault.as_ref().unwrap().folder("F1").is_some(),
            "the first press only asks"
        );

        let _ = app.update(Message::AskDeleteFolder("F1".into()));
        assert!(
            app.vault.as_ref().unwrap().folder("F1").is_none(),
            "the second deletes"
        );
        assert_eq!(app.folder_filter, "", "the deleted folder clears the filter");
        assert_eq!(app.entries.len(), 2, "the items are still there");

        let _ = std::fs::remove_dir_all(&root);
    }

    /// A new item created from the folder lands inside it.
    #[test]
    fn new_item_lands_in_the_open_folder() {
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
        assert_eq!(in_folder, 2, "GitHub and the new item are in the Work folder");

        let _ = std::fs::remove_dir_all(&root);
    }

    /// The folder can also be chosen in the existing-item editor.
    #[test]
    fn folder_can_be_changed_in_the_editor() {
        let (mut app, root) = app_with_folders("folders-editor");

        // U2 sits in no folder; pick it and put it into Work.
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
            "the folder was written onto the item"
        );

        // And back to the top level.
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

    /// An end-to-end scenario on a copy of the real export: edit, create,
    /// delete, save, and roll back from the backup.
    #[test]
    fn full_scenario_on_the_real_export() {
        let src = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../../golden")
            .join("1Password 2026-10-13, 03_54 PM (533 items and 2 folders).1pif/data.1pif");
        if !src.exists() {
            eprintln!("real export not found");
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

        // 1. edit an existing item
        let target = app.vault.as_ref().unwrap().items[10].uuid.clone();
        let _ = app.update(Message::Select(10));
        let _ = app.update(Message::StartEdit);
        let _ = app.update(Message::DraftChanged(
            "notes",
            "правка из приложения".into(),
        ));
        let _ = app.update(Message::ApplyEdit);

        // 2. create a new one
        let _ = app.update(Message::StartCreate);
        let _ = app.update(Message::DraftChanged("title", "Проверка сценария".into()));
        let _ = app.update(Message::DraftChanged("username", "scen@example.com".into()));
        let _ = app.update(Message::DraftChanged("password", "pass-9999".into()));
        let _ = app.update(Message::DraftChanged(
            "url",
            "https://scenario.test/x".into(),
        ));
        let _ = app.update(Message::ApplyEdit);

        // 3. delete: pick the item first, then hit "Delete"
        let victim = app.vault.as_ref().unwrap().items[20].uuid.clone();
        assert!(
            app.select_uuid(&victim),
            "the item should be visible in the list"
        );
        let _ = app.update(Message::DeleteItem);
        // the prompt should appear in the open form
        assert!(
            app.editing.as_ref().is_some_and(|e| e.confirm_delete),
            "deleting must ask for confirmation"
        );
        let _ = app.update(Message::ConfirmDelete(true));
        assert!(app.editing.is_none(), "the form closes after the delete");

        assert!(app.has_changes());
        let _ = app.update(Message::SaveFile);
        assert!(!app.has_changes());

        // 4. the file parses and the changes are in place
        let after = Pif::from_file(&file).unwrap();
        assert_eq!(
            after.items.len(),
            count,
            "the create and the delete should cancel out"
        );
        assert!(after.find(&target).is_some());
        assert!(
            after.find(&victim).is_none(),
            "the deleted item should not come back"
        );
        let created = after
            .items
            .iter()
            .find(|i| i.title.as_deref() == Some("Проверка сценария"))
            .expect("the new item must be saved");
        assert_eq!(created.primary_password(), Some("pass-9999"));
        assert_eq!(created.usernames(), vec!["scen@example.com"]);

        // 5. the backup is the original file
        let bak = std::fs::read(backup_of(&file)).unwrap();
        assert_eq!(bak, before, "the backup should hold the original contents");

        // 6. roll back: restore the backup and confirm everything is as before
        std::fs::write(&file, &bak).unwrap();
        let restored = Pif::from_file(&file).unwrap();
        assert_eq!(restored.items.len(), count);
        assert!(restored.find(&target).is_some());
        assert!(
            restored.find(&victim).is_some(),
            "after the rollback the item should come back"
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

    /// Notes with embedded newlines must reach the form and go back into the file.
    #[test]
    fn multiline_notes_round_trip_through_save() {
        let original = "первая строка\nвторая строка\nтретья";
        let (mut app, root) = editor_with_notes("notes", original);

        let uuid = app.vault.as_ref().unwrap().items[0].uuid.clone();
        let _ = app.update(Message::StartEdit);
        assert_eq!(
            app.editing.as_ref().unwrap().notes,
            original,
            "the form must show the notes verbatim"
        );

        let changed = "новая первая\nновая вторая";
        // The user wiped the text and typed a new one: select everything first,
        // then paste. That is how real editing behaves.
        let _ = app.update(Message::EditNotes(text_editor::Action::SelectAll));
        let _ = app.update(Message::EditNotes(text_editor::Action::Edit(
            text_editor::Edit::Paste(std::sync::Arc::new(changed.to_string())),
        )));

        let _ = app.update(Message::ApplyEdit);
        let _ = app.update(Message::SaveFile);

        let again = Pif::from_file(root.join("data.1pif")).unwrap();
        let it = again.find(&uuid).unwrap();
        assert_eq!(it.notes(), Some(changed), "line breaks must survive the save");

        let _ = std::fs::remove_dir_all(&root);
    }

    /// The editor document and the draft must never drift apart.
    #[test]
    fn document_and_draft_stay_in_sync() {
        let (mut app, root) = editor_with_notes("sync", "исходный текст");
        let _ = app.update(Message::StartEdit);
        let e = app.editing.as_ref().unwrap();
        assert_eq!(e.notes, e.notes_doc.text());

        // A no-op action must not corrupt anything.
        let _ = app.update(Message::EditNotes(text_editor::Action::Move(
            text_editor::Motion::End,
        )));
        let e = app.editing.as_ref().unwrap();
        assert_eq!(e.notes, e.notes_doc.text());
        assert_eq!(e.draft.notes, e.notes);

        let _ = std::fs::remove_dir_all(&root);
    }

    /// The form builds together with the multiline editor.
    #[test]
    fn form_with_editor_renders() {
        let (mut app, root) = editor_with_notes("render", "текст");
        let _ = app.update(Message::StartEdit);
        let _ = app.view_editor();
        let _ = app.view();
        let _ = std::fs::remove_dir_all(&root);
    }

    /// The keyboard subscription must exist without panicking.
    #[test]
    fn keyboard_subscription_builds() {
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

    /// The regular list never shows trashed entries.
    #[test]
    fn regular_list_hides_trashed_entries() {
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

    /// The Trash section shows only trashed entries.
    #[test]
    fn trash_section_lists_only_trashed() {
        let (mut app, root) = export_with_trashed("trash-only");
        let _ = app.update(Message::ShowTrash(!app.show_trash));
        assert!(app.show_trash);
        assert_eq!(app.entries.len(), 2);
        let _ = app.view();
        let _ = std::fs::remove_dir_all(&root);
    }

    /// Toggling trash on and off restores the regular list.
    #[test]
    fn toggling_trash_round_trip_restores_list() {
        let (mut app, root) = export_with_trashed("trash-toggle");
        let normal = app.entries.len();
        let _ = app.update(Message::ShowTrash(!app.show_trash));
        assert_ne!(app.entries.len(), normal);
        let _ = app.update(Message::ShowTrash(!app.show_trash));
        assert_eq!(app.entries.len(), normal);
        let _ = std::fs::remove_dir_all(&root);
    }

    /// Emptying an already empty attachment trash is harmless.
    #[test]
    fn emptying_empty_trash_is_harmless() {
        let (mut app, root) = export_with_trashed("trash-empty-ui");
        assert_eq!(app.trash.files, 0);
        let _ = app.update(Message::EmptyTrash);
        assert_eq!(app.trash.files, 0);
        assert!(app.toast.is_some(), "a toast should be shown");
        let _ = std::fs::remove_dir_all(&root);
    }

    /// Plurals are computed with Russian rules.
    #[test]
    fn file_plural_forms() {
        assert_eq!(plural_files(0), "0 files");
        assert_eq!(plural_files(1), "1 file");
        assert_eq!(plural_files(2), "2 files");
        // In English 21 and 102 are just "files", no plural distinction.
        assert_eq!(plural_files(21), "21 files");
        assert_eq!(plural_files(102), "102 files");
    }

    /// The UI counters must match the parsed data.
    #[test]
    fn trash_counters_match_parsed_data() {
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
            "alive plus trashed must account for every record"
        );
        assert_eq!(trashed, 57, "the export marks 57 trashed records");
        assert_eq!(
            alive, 476,
            "1Password's All Items view shows the same number"
        );
    }
}

#[cfg(test)]
mod trash_confirm_tests {
    use super::tests_common::*;
    use super::*;

    /// An app with a non-empty attachment trash.
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
        // Queue the file for the trash the way removing an entry would.
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

    /// Emptying must not happen on the first press.
    #[test]
    fn first_press_only_asks() {
        let (mut app, root) = app_with_trash("trash-ask");
        assert_eq!(app.trash.files, 1);
        let _ = app.update(Message::EmptyTrash);
        assert!(app.trash_armed, "after the first press we wait for confirmation");
        assert_eq!(app.trash.files, 1, "the trash must stay intact");
        let _ = std::fs::remove_dir_all(&root);
    }

    /// The second press empties.
    #[test]
    fn second_press_empties() {
        let (mut app, root) = app_with_trash("trash-do");
        let _ = app.update(Message::EmptyTrash);
        let _ = app.update(Message::EmptyTrash);
        assert_eq!(app.trash.files, 0, "the trash must be emptied");
        assert!(!app.trash_armed);
        assert!(!root.join("trash").exists(), "the trash directory is gone");
        let _ = std::fs::remove_dir_all(&root);
    }

    /// Cancelling clears the question.
    #[test]
    fn cancel_clears_the_prompt() {
        let (mut app, root) = app_with_trash("trash-cancel");
        let _ = app.update(Message::EmptyTrash);
        assert!(app.trash_armed);
        let _ = app.update(Message::CancelEmptyTrash);
        assert!(!app.trash_armed);
        assert_eq!(app.trash.files, 1);
        let _ = app.update(Message::EmptyTrash);
        assert!(app.trash_armed, "the prompt must be asked again");
        let _ = std::fs::remove_dir_all(&root);
    }

    /// Switching sections clears the prompt so it cannot get "stuck".
    #[test]
    fn switching_sections_clears_the_prompt() {
        let (mut app, root) = app_with_trash("trash-switch");
        let _ = app.update(Message::EmptyTrash);
        let _ = app.update(Message::ShowTrash(!app.show_trash));
        assert!(!app.trash_armed);
        let _ = std::fs::remove_dir_all(&root);
    }

    /// The panel builds in the armed state too.
    #[test]
    fn panel_renders_while_armed() {
        let (mut app, root) = app_with_trash("trash-render");
        let _ = app.view();
        let _ = app.update(Message::EmptyTrash);
        let _ = app.view();
        let _ = std::fs::remove_dir_all(&root);
    }

    /// The About panel and Info.plist must agree on the version.
    /// The version comes from a git tag rather than a constant, but it still
    /// has to look like a version. There used to be a comparison against
    /// `CARGO_PKG_VERSION` here, and it let a 1.0.0 vs v1.5.0 mismatch
    /// through: both values were genuine, just different.
    #[test]
    fn version_looks_like_a_version() {
        let parts: Vec<&str> = APP_VERSION.split('.').collect();
        assert_eq!(
            parts.len(),
            3,
            "expected X.Y.Z, got {APP_VERSION:?}"
        );
        for part in parts {
            assert!(
                !part.is_empty() && part.chars().all(|c| c.is_ascii_digit()),
                "version part must be numeric: {part:?} in {APP_VERSION:?}"
            );
        }
        assert!(APP_VERSION.starts_with('1'), "version 1.x");
    }

    /// An app with one live entry and no attachments.
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

    /// The file lands in the entry's directory only after a save.
    #[test]
    fn attached_file_lands_on_disk_on_save() {
        let (mut app, root, source) = app_with_one_entry("attach-save");
        let uuid = app.vault.as_ref().unwrap().items[0].uuid.clone();

        let (added, failed) = app.attach_paths(&uuid, std::slice::from_ref(&source));
        assert_eq!(added, 1, "the file should attach");
        assert!(failed.is_empty(), "there should be no failures: {failed:?}");

        // Before the save there is no attachments directory on disk.
        assert!(!root.join("attachments").exists(), "there is nothing to copy yet");

        let _ = app.update(Message::SaveFile);

        let copied = root.join("attachments").join(&uuid).join("источник.jpg");
        assert!(copied.exists(), "the file should live in attachments/<uuid>/");
        assert_eq!(std::fs::read(&copied).unwrap(), b"jpeg-bytes");
        assert!(!app.attachments_pending(), "nothing is pending after the save");

        let _ = std::fs::remove_dir_all(&root);
    }

    /// Detaching requires a second press.
    #[test]
    fn detaching_requires_confirmation() {
        let (mut app, root, source) = app_with_one_entry("detach-two-step");
        let uuid = app.vault.as_ref().unwrap().items[0].uuid.clone();
        app.attach_paths(&uuid, std::slice::from_ref(&source));
        let _ = app.update(Message::SaveFile);

        // The first press only arms the button.
        let _ = app.update(Message::DetachAttachment("источник.jpg".into()));
        assert_eq!(app.detach_armed.as_deref(), Some("источник.jpg"));
        assert_eq!(
            app.vault.as_ref().unwrap().attachments_of(&uuid).len(),
            1,
            "the file must not vanish after the first press"
        );

        // The second one detaches.
        let _ = app.update(Message::DetachAttachment("источник.jpg".into()));
        assert!(app.detach_armed.is_none(), "arming is cleared");
        assert!(app.vault.as_ref().unwrap().attachments_of(&uuid).is_empty());
        assert!(app.attachments_pending(), "the file is awaiting the trash");

        // Until the save, the file is still on disk.
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
            "after the save the file must go to the trash"
        );

        let _ = std::fs::remove_dir_all(&root);
    }

    /// Cancelling the arming deletes nothing.
    #[test]
    fn cancelling_detach_does_nothing() {
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

    /// Moving to another entry resets the arming: the confirmation belonged
    /// to the file in the previous context.
    #[test]
    fn selecting_another_entry_clears_arming() {
        let (mut app, root, source) = app_with_one_entry("detach-select");
        let uuid = app.vault.as_ref().unwrap().items[0].uuid.clone();
        app.attach_paths(&uuid, std::slice::from_ref(&source));
        let _ = app.update(Message::SaveFile);

        let _ = app.update(Message::DetachAttachment("источник.jpg".into()));
        assert!(app.detach_armed.is_some());

        let _ = app.update(Message::Select(0));
        assert!(
            app.detach_armed.is_none(),
            "arming must not survive an entry change"
        );

        let _ = std::fs::remove_dir_all(&root);
    }

    /// A new entry has no uuid yet, so there is nowhere to attach to.
    #[test]
    fn new_entry_rejects_attachments() {
        let (mut app, root, _source) = app_with_one_entry("attach-new");
        app.editing = Some(Editing::create());
        assert!(
            app.attachment_target().is_none(),
            "the entry being created has no uuid"
        );

        let _ = app.update(Message::AttachFile);
        let (text, _) = app.toast.clone().unwrap();
        assert!(
            text.contains("save the item"),
            "the user needs an explanation, not silence: {text}"
        );

        let _ = std::fs::remove_dir_all(&root);
    }

    /// Same-named files must not clobber each other.
    #[test]
    fn same_named_attachments_do_not_clobber() {
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
        assert_eq!(names.len(), 2, "both files are present");
        assert_ne!(names[0], names[1], "the names must differ");

        let _ = app.update(Message::SaveFile);
        let dir = root.join("attachments").join(&uuid);
        let on_disk = std::fs::read_dir(&dir).unwrap().count();
        assert_eq!(on_disk, 2, "two distinct files on disk too");

        let _ = std::fs::remove_dir_all(&root);
    }

    /// The toast text must not hand the user nothing at all.
    #[test]
    fn attachment_toast_texts_are_meaningful() {
        assert!(attach_toast(0, &[]).contains("0"));
        assert!(attach_toast(1, &[]).contains("file"));
        assert!(attach_toast(3, &[]).contains("files"));
        assert!(attach_toast(0, &["a.jpg".into()]).contains("cannot attach"));
        assert!(attach_toast(1, &["b.jpg".into()]).contains("b.jpg"));
    }

    /// We only offer extensions `iced` can really decode.
    #[test]
    fn images_are_recognized_by_extension() {
        for name in [
            "a.jpg", "a.JPEG", "a.png", "a.gif", "a.bmp", "a.webp", "a.tiff",
        ] {
            assert!(
                is_image(std::path::Path::new(name)),
                "{name} should be treated as an image"
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
                "{name} should not be treated as an image"
            );
        }
    }

    /// Repeating the same file collapses the preview.
    #[test]
    fn preview_toggles() {
        let (mut app, root, _source) = app_with_one_entry("preview-toggle");
        let path = root.join("avatar.png");

        let _ = app.update(Message::TogglePreview(path.clone()));
        assert_eq!(
            app.preview.as_ref(),
            Some(&path),
            "the first press expands it"
        );

        let _ = app.update(Message::TogglePreview(path));
        assert!(app.preview.is_none(), "the second press collapses it");

        let _ = std::fs::remove_dir_all(&root);
    }

    /// Moving to another entry closes the preview: there is no point showing
    /// another entry's file after the switch.
    #[test]
    fn changing_entry_closes_preview() {
        let (mut app, root, _source) = app_with_one_entry("preview-select");
        let _ = app.update(Message::Select(0));
        let _ = app.update(Message::TogglePreview(root.join("avatar.png")));
        assert!(app.preview.is_some());

        let _ = app.update(Message::Select(0));
        assert!(
            app.preview.is_none(),
            "changing the entry must close the preview"
        );

        let _ = std::fs::remove_dir_all(&root);
    }

    /// The entry panel builds with the preview in place.
    #[test]
    fn panel_renders_with_preview() {
        let (mut app, root, _source) = app_with_one_entry("preview-render");
        let _ = app.update(Message::Select(0));
        let _ = app.update(Message::TogglePreview(root.join("avatar.png")));
        let _ = app.view();

        let _ = std::fs::remove_dir_all(&root);
    }

    /// A vault holding a single empty draft entry.
    fn app_with_one_login(tag: &str) -> (App, PathBuf) {
        let root = unique_dir(tag);
        std::fs::create_dir_all(&root).unwrap();
        std::fs::write(root.join("data.1pif"), "{}\n").unwrap();

        let mut app = App::blank();
        assert!(app.open(root.join("data.1pif")));
        (app, root)
    }

    /// A new entry is created as the kind chosen in the editor.
    #[test]
    fn new_entry_kind_is_selected_and_applied() {
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
            .expect("entry was created");

        assert_eq!(
            created.type_name.as_deref(),
            Some(ItemKind::CreditCard.type_name()),
            "the entry kind comes from the editor"
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

    /// The kind of an existing entry never changes: it is bound to the
    /// structure already written into the file.
    #[test]
    fn existing_entry_kind_does_not_change() {
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
            "the kind of an entry already in the file must not be touched"
        );

        let _ = std::fs::remove_dir_all(&root);
    }

    /// A note is created without a login and password and reads back.
    #[test]
    fn secure_note_is_created_and_read_back() {
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
            .expect("note was created");
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
