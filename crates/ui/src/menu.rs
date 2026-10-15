//! Меню приложения.
//!
//! iced 0.14 меню не умеет вовсе — билдер `Application` такого метода не
//! имеет. Меню собирается через `muda`: на macOS приложение получает обычную
//! строку меню, где «О приложении» открывает системную панель, на Windows —
//! строку в стиле системы с «О приложении» в Help.
//!
//! Панель наполняется из [`crate::APP_*`], а не из Info.plist: так текст
//! виден в одном месте вместе с окном «О приложении» и попадает в
//! тесты. В Info.plist те же сведения остаются для Launch Services.

use muda::accelerator::Accelerator;
use muda::{AboutMetadataBuilder, Menu, MenuId, MenuItem, PredefinedMenuItem, Submenu};

use iced::Subscription;

/// Идентификаторы пунктов, которые обрабатывает приложение.
///
/// Совпадают с последним сегментом имени `Message`: один список источников
/// правды вместо того, чтобы в двух местах писать одно и то же строкой.
pub mod id {
    pub const NEW_VAULT: &str = "file.new_vault";
    pub const NEW_ITEM: &str = "file.new_item";
    pub const OPEN: &str = "file.open";
    pub const SAVE: &str = "file.save";
    pub const TRASH: &str = "view.trash";
    pub const AUDIT: &str = "view.audit";
}

/// Собирает меню и вешает его на приложение.
///
/// Звать надо **после** старта цикла событий, то есть из первого `update`:
/// winit при инициализации ставит на `NSApplication` своё стандартное меню
/// и перетирает то, что было поставлено раньше. Отключить его нельзя —
/// поле `default_menu` в winit внутреннее. Поэтому наше меню просто
/// ставится позже и остаётся.
///
/// Меню нужно удерживать: если объект освободится, macOS покажет пустую
/// строку. `Menu` внутри устроен на `Rc` и не является `Sync`, поэтому в
/// `static` его не положить — заводим ссылку на всё время работы
/// программы.
///
/// Удерживать нужно и подменю: `Submenu` — самостоятельный владелец
/// NSMenu, и когда он освобождается, его пункты просто исчезают из строки
/// меню. Раньше утекал только `Menu`, и в строке оставался один пункт
/// приложения.
/// Готовит канал событий. Вызывается из `main`, до запуска iced.
///
/// Отдельно от [`install`], потому что подписка iced создаётся раньше первого
/// `update`: если завести канал там же, где ставится меню, подписка успела бы
/// его не увидеть и молчала бы навсегда.
pub fn init() {
    let (tx, rx) = async_channel::unbounded();
    // Получатель обязан жить вместе с отправителем, иначе канал сразу
    // закроется и подписка молча перестанет приходить.
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
            // Канал не ограничен, но отправка без ожидания всё же может
            // отказать при закрытии: тогда пункт просто не сработает.
            let _ = channel.sender.try_send(message);
        }
    }));
}

/// Собирает меню и вешает его на приложение.
///
/// Звать надо **после** старта цикла событий, то есть из первого `update`:
/// winit при инициализации ставит на `NSApplication` своё стандартное меню
/// и перетирает то, что было поставлено раньше. Отключить его нельзя —
/// поле `default_menu` в winit внутреннее. Поэтому наше меню просто
/// ставится позже и остаётся.
pub fn install() {
    // Тесты гоняют `update` в рабочем потоке, а `muda` требует главный и
    // без лишней проверки паникует. В тестах меню всё равно не существует.
    if cfg!(test) {
        return;
    }

    static INSTALLED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
    if INSTALLED.swap(true, std::sync::atomic::Ordering::SeqCst) {
        return;
    }
    // Утечка намеренная: ссылка живёт до конца программы.
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
    // Только macOS: метод есть исключительно под этой платформой.
    menu.init_for_nsapp();
    menu
}

/// Windows: у системы нет меню приложения, «О приложении» живёт в Help,
/// а выход — в File. Сама сборка меню общая с macOS, различаются только
/// порядок и платформенная установка.
#[cfg(not(target_os = "macos"))]
fn build_and_install() -> Menu {
    Menu::with_items(&[file_menu(), edit_menu(), view_menu(), window_menu(), help_menu()])
        .expect("menu bar")
}

/// Меню «Help» с той же панелью «О приложении», что и на macOS.
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

/// Меню «Edit» нужно системе: без него ⌘C/⌘V/⌘A на macOS и Ctrl+C/Ctrl+V/
/// Ctrl+A на Windows работают не везде.
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

/// Файл: без этого меню не работают ⌘N/⌘O/⌘S на macOS и Ctrl+N/Ctrl+O/
/// Ctrl+S на Windows, а открытие, сохранение и создание живут только
/// кнопками в окне.
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

/// Канал, через который события меню попадают в iced.
///
/// Напрямую подписаться не выйдет: на macOS `muda` раздаёт события через
/// `crossbeam_channel`, у которого блокирующий `recv()` и нет `Hash` — а
/// `Subscription::run_with` требует именно `Hash`. Поэтому события
/// перехватываются штатным `set_event_handler` и кладутся в
/// `async_channel`, который уже можно ждать асинхронно.
struct Channel {
    sender: async_channel::Sender<crate::Message>,
    receiver: async_channel::Receiver<crate::Message>,
}

static EVENTS: std::sync::OnceLock<Channel> = std::sync::OnceLock::new();

/// Обёртка получателя: `Subscription::run_with` требует `Hash`, а сам канал
/// его не реализует.
///
/// Канал в программе один и больше не меняется, поэтому хеш у него
/// постоянный: пересоздавать подписку с другим хешем незачем.
#[derive(Clone)]
struct Rx(Option<async_channel::Receiver<crate::Message>>);

impl std::hash::Hash for Rx {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        0usize.hash(state);
    }
}

/// Подписка iced на события меню.
pub fn events() -> Subscription<crate::Message> {
    let rx = Rx(EVENTS.get().map(|c| c.receiver.clone()));
    Subscription::run_with(rx, build_events)
}

/// Поток подписки. Собирается один раз и живёт вместе с программой.
fn build_events(
    rx: &Rx,
) -> std::pin::Pin<Box<dyn iced::futures::stream::Stream<Item = crate::Message> + Send>> {
    match &rx.0 {
        Some(rx) => Box::pin(iced::futures::stream::unfold(rx.clone(), |rx| async move {
            // Канал закрыт только если программа выходит; на этом поток и
            // должен закончиться.
            rx.recv().await.ok().map(|msg| (msg, rx))
        })),
        // Меню не установлено: ждём вечно, чтобы подписка молчала, а не
        // исчезла и дёргала интерфейс пересозданием.
        None => Box::pin(iced::futures::stream::pending()),
    }
}

/// Событие меню в сообщение приложения.
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

/// Данные для системной панели «О приложении».
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

    /// Данные панели «О приложении» должны содержать автора и адрес.
    #[test]
    fn в_панели_есть_автор_и_сайт() {
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

    /// Панель собирается дважды без паники: данные не изменяются.
    #[test]
    fn метаданные_собираются_повторно() {
        let a = about_metadata();
        let b = about_metadata();
        assert_eq!(a.website, b.website);
        assert_eq!(a.authors, b.authors);
    }
}
