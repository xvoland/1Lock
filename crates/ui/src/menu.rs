//! Application menu.
//!
//! iced 0.14 has no menu support at all — the `Application` builder has no
//! such method. The menu is built with `muda`: on macOS the app gets a normal
//! menu bar where "About" opens the system panel, on Windows a system-style
//! menu bar with "About" under Help.
//!
//! The panel is filled from [`crate::APP_*`], not from Info.plist: that way the
//! text lives in one place together with the "About" window and ends up in
//! tests. Info.plist keeps the same values for Launch Services.

use muda::accelerator::Accelerator;
use muda::{AboutMetadataBuilder, Menu, MenuId, MenuItem, PredefinedMenuItem, Submenu};

use iced::Subscription;

/// Identifiers of the items the application handles.
///
/// They match the last segment of a `Message` name: one source of truth
/// instead of writing the same string twice.
pub mod id {
    pub const NEW_VAULT: &str = "file.new_vault";
    pub const NEW_ITEM: &str = "file.new_item";
    pub const OPEN: &str = "file.open";
    pub const SAVE: &str = "file.save";
    pub const TRASH: &str = "view.trash";
    pub const AUDIT: &str = "view.audit";
}

/// Builds the menu and attaches it to the application.
///
/// It has to be called **after** the event loop starts, that is from the first
/// `update`: on init winit puts its own standard menu on `NSApplication` and
/// overwrites whatever was installed earlier. It cannot be turned off —
/// `default_menu` is a private field in winit. So our menu is simply installed
/// later and stays.
///
/// The menu has to be kept alive: if the object is dropped, macOS shows an empty
/// menu bar. `Menu` is built on `Rc` internally and is not `Sync`, so it cannot
/// go into a `static` — we keep a reference for the whole lifetime of the
/// program.
///
/// Submenus have to be kept alive too: a `Submenu` is the sole owner of its
/// NSMenu, and when it is dropped its items simply vanish from the menu bar.
/// Earlier only `Menu` was leaked, and a single app item was left in the bar.
/// Prepares the event channel. Called from `main`, before iced starts.
///
/// Separate from [`install`] because the iced subscription is created before
/// the first `update`: if the channel were created where the menu is
/// installed, the subscription would already have missed it and would stay
/// silent forever.
pub fn init() {
    let (tx, rx) = async_channel::unbounded();
    // The receiver has to live as long as the sender, otherwise the channel
    // closes right away and the subscription silently stops arriving.
    if EVENTS
        .set(Channel {
            sender: tx,
            receiver: rx,
        })
        .is_err()
    {
        return;
    }

    muda::MenuEvent::set_event_handler(Some(|event: muda::MenuEvent| {
        let Some(message) = message_for(event.id()) else {
            return;
        };
        if let Some(channel) = EVENTS.get() {
            // The channel is unbounded, but a non-blocking send can still fail
            // when it is closed: the item then simply does nothing.
            let _ = channel.sender.try_send(message);
        }
    }));
}

/// Builds the menu and attaches it to the application.
///
/// It has to be called **after** the event loop starts, that is from the first
/// `update`: on init winit puts its own standard menu on `NSApplication` and
/// overwrites whatever was installed earlier. It cannot be turned off —
/// `default_menu` is a private field in winit. So our menu is simply installed
/// later and stays.
pub fn install() {
    // Tests drive `update` on a worker thread, while `muda` demands the main
    // one and panics without an extra check. The menu does not exist in tests
    // anyway.
    if cfg!(test) {
        return;
    }

    static INSTALLED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
    if INSTALLED.swap(true, std::sync::atomic::Ordering::SeqCst) {
        return;
    }
    // The leak is deliberate: the reference lives until the program ends.
    let _menu: &'static Menu = Box::leak(Box::new(build_and_install()));
}

#[cfg(target_os = "macos")]
fn build_and_install() -> Menu {
    let app: &'static Submenu = Box::leak(Box::new(
        Submenu::with_items(
            crate::APP_TITLE,
            true,
            &[
                &PredefinedMenuItem::about(
                    Some(&format!("About {}", crate::APP_TITLE)),
                    Some(about_metadata()),
                ),
                &PredefinedMenuItem::separator(),
                &PredefinedMenuItem::hide(Some("Hide")),
                &PredefinedMenuItem::hide_others(Some("Hide Others")),
                &PredefinedMenuItem::separator(),
                &PredefinedMenuItem::quit(Some(&format!("Quit {}", crate::APP_TITLE))),
            ],
        )
        .expect("app menu"),
    ));

    let menu = Menu::with_items(&[app, file_menu(), edit_menu(), view_menu(), window_menu()])
        .expect("menu bar");
    // macOS only: the method exists exclusively under this platform.
    menu.init_for_nsapp();
    menu
}

/// Windows: the system has no app menu, "About" lives under Help and Quit
/// under File. The menu build itself is shared with macOS, only the order and
/// the platform-specific installation differ.
#[cfg(not(target_os = "macos"))]
fn build_and_install() -> Menu {
    Menu::with_items(&[file_menu(), edit_menu(), view_menu(), window_menu(), help_menu()])
        .expect("menu bar")
}

/// "Help" menu with the same "About" panel as on macOS.
#[cfg(not(target_os = "macos"))]
fn help_menu() -> &'static Submenu {
    Box::leak(Box::new(
        Submenu::with_items(
            "Help",
            true,
            &[
                &PredefinedMenuItem::about(
                    Some(&format!("About {}", crate::APP_TITLE)),
                    Some(about_metadata()),
                ),
                &PredefinedMenuItem::separator(),
                &PredefinedMenuItem::quit(Some(&format!("Quit {}", crate::APP_TITLE))),
            ],
        )
        .expect("help menu"),
    ))
}

/// The system needs the "Edit" menu: without it ⌘C/⌘V/⌘A on macOS and
/// Ctrl+C/Ctrl+V/Ctrl+A on Windows do not work everywhere.
fn edit_menu() -> &'static Submenu {
    Box::leak(Box::new(
        Submenu::with_items(
            "Edit",
            true,
            &[
                &PredefinedMenuItem::undo(Some("Undo")),
                &PredefinedMenuItem::separator(),
                &PredefinedMenuItem::cut(Some("Cut")),
                &PredefinedMenuItem::copy(Some("Copy")),
                &PredefinedMenuItem::paste(Some("Paste")),
                &PredefinedMenuItem::select_all(Some("Select All")),
            ],
        )
        .expect("edit menu"),
    ))
}

/// File: without it ⌘N/⌘O/⌘S on macOS and Ctrl+N/Ctrl+O/Ctrl+S on Windows do
/// not work, and opening, saving and creating live only in the window's
/// buttons.
fn file_menu() -> &'static Submenu {
    Box::leak(Box::new(
        Submenu::with_items(
            "File",
            true,
            &[
                &MenuItem::with_id(
                    id::NEW_VAULT,
                    "New Vault…",
                    true,
                    Accelerator::try_from("CmdOrCtrl+Shift+N").ok(),
                ),
                &MenuItem::with_id(
                    id::NEW_ITEM,
                    "New Item",
                    true,
                    Accelerator::try_from("CmdOrCtrl+N").ok(),
                ),
                &PredefinedMenuItem::separator(),
                &MenuItem::with_id(
                    id::OPEN,
                    "Open…",
                    true,
                    Accelerator::try_from("CmdOrCtrl+O").ok(),
                ),
                &MenuItem::with_id(
                    id::SAVE,
                    "Save File",
                    true,
                    Accelerator::try_from("CmdOrCtrl+S").ok(),
                ),
                &PredefinedMenuItem::separator(),
                &PredefinedMenuItem::close_window(Some("Close Window")),
            ],
        )
        .expect("file menu"),
    ))
}

fn view_menu() -> &'static Submenu {
    Box::leak(Box::new(
        Submenu::with_items(
            "View",
            true,
            &[
                &MenuItem::with_id(id::TRASH, "Show Trash", true, None),
                &MenuItem::with_id(id::AUDIT, "Security Audit", true, None),
            ],
        )
        .expect("view menu"),
    ))
}

fn window_menu() -> &'static Submenu {
    Box::leak(Box::new(
        Submenu::with_items(
            "Window",
            true,
            &[
                &PredefinedMenuItem::minimize(Some("Minimize")),
                &PredefinedMenuItem::fullscreen(Some("Enter Full Screen")),
                &PredefinedMenuItem::separator(),
                &PredefinedMenuItem::close_window(Some("Close Window")),
            ],
        )
        .expect("window menu"),
    ))
}

/// The channel menu events reach iced through.
///
/// Subscribing directly is impossible: on macOS `muda` dispatches events via
/// `crossbeam_channel`, whose `recv()` blocks and which has no `Hash` — while
/// `Subscription::run_with` requires `Hash`. So events are intercepted via the
/// stock `set_event_handler` and put into `async_channel`, which can already be
/// awaited asynchronously.
struct Channel {
    sender: async_channel::Sender<crate::Message>,
    receiver: async_channel::Receiver<crate::Message>,
}

static EVENTS: std::sync::OnceLock<Channel> = std::sync::OnceLock::new();

/// Receiver wrapper: `Subscription::run_with` requires `Hash` and the channel
/// itself does not implement it.
///
/// There is one channel in the program and it never changes, so its hash is
/// constant: there is no reason to rebuild the subscription with a different
/// one.
#[derive(Clone)]
struct Rx(Option<async_channel::Receiver<crate::Message>>);

impl std::hash::Hash for Rx {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        0usize.hash(state);
    }
}

/// The iced subscription to menu events.
pub fn events() -> Subscription<crate::Message> {
    let rx = Rx(EVENTS.get().map(|c| c.receiver.clone()));
    Subscription::run_with(rx, build_events)
}

/// The subscription's stream. Built once and lives as long as the program.
fn build_events(
    rx: &Rx,
) -> std::pin::Pin<Box<dyn iced::futures::stream::Stream<Item = crate::Message> + Send>> {
    match &rx.0 {
        Some(rx) => Box::pin(iced::futures::stream::unfold(rx.clone(), |rx| async move {
            // The channel is closed only when the program exits, which is
            // exactly when the stream is supposed to end.
            rx.recv().await.ok().map(|msg| (msg, rx))
        })),
        // No menu installed: wait forever so the subscription stays silent
        // instead of disappearing and thrashing the UI through recreation.
        None => Box::pin(iced::futures::stream::pending()),
    }
}

/// A menu event as an application message.
fn message_for(id: &MenuId) -> Option<crate::Message> {
    use crate::Message;

    match id.as_ref() {
        id::NEW_VAULT => Some(Message::CreateVault),
        id::NEW_ITEM => Some(Message::StartCreate),
        id::OPEN => Some(Message::PickFile),
        id::SAVE => Some(Message::SaveFile),
        id::TRASH => Some(Message::ToggleTrash),
        id::AUDIT => Some(Message::ToggleAudit),
        _ => None,
    }
}

/// Data for the system "About" panel.
fn about_metadata() -> muda::AboutMetadata {
    AboutMetadataBuilder::new()
        .name(Some(crate::APP_TITLE))
        .version(Some(crate::APP_VERSION.to_string()))
        .authors(Some(vec![crate::APP_AUTHOR.to_string()]))
        .comments(Some(crate::APP_COMMENTS))
        .copyright(Some(crate::APP_COPYRIGHT))
        .website(Some(crate::APP_URL))
        .website_label(Some(crate::APP_URL_LABEL))
        .license(Some(crate::APP_LICENSE))
        .build()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The "About" panel data must carry the author and the address.
    #[test]
    fn about_panel_has_author_and_website() {
        let m = about_metadata();
        assert_eq!(m.name.as_deref(), Some(crate::APP_TITLE));
        assert_eq!(
            m.authors.as_deref(),
            Some([crate::APP_AUTHOR.to_string()].as_slice())
        );
        assert_eq!(m.website.as_deref(), Some(crate::APP_URL));
        assert_eq!(m.website_label.as_deref(), Some(crate::APP_URL_LABEL));
        assert!(m.version.as_deref().is_some_and(|v| !v.is_empty()));
        assert!(m
            .copyright
            .as_deref()
            .is_some_and(|c| c.contains("Vitalii") && c.contains("xVoLAnD")));
    }

    /// The panel is built twice without a panic: the data is not mutable.
    #[test]
    fn metadata_can_be_built_repeatedly() {
        let a = about_metadata();
        let b = about_metadata();
        assert_eq!(a.website, b.website);
        assert_eq!(a.authors, b.authors);
    }
}
