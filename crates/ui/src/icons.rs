//! Значки разделов боковой панели.
//!
//! Начертания взяты из набора Lucide (лицензия ISC): контурные, сетка 24×24,
//! обводка 2 с закруглёнными концами. SF Symbols нативными быть не могут —
//! лицензия разрешает использовать символы только внутри приложения на
//! платформе Apple и прямо запрещает их извлекать и распространять, так что
//! положить файл символов в репозиторий нельзя.
//!
//! Цвет запекается прямо в SVG, потому что резолвер не понимает
//! `currentColor`, а значок в боковой панели должен сереть вместе с подписью
//! и загораться вместе с выделением.
//!
//! Каждый путь пишется одной строкой **намеренно**. Перенос строки через
//! обратный слэш работает в обычных строках Rust, но не в raw-строках
//! `r#"…"#`: там `\` и новая строка попадают внутрь атрибута `d="…"`, путь
//! обрывается, и значок рисуется частично — молча, без ошибки компиляции.

use iced::{Color, Length};

use iced::widget::svg::{Handle, Style, Svg};

/// Значки, которые рисуются в интерфейсе.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Icon {
    /// Раздел «Все элементы».
    AllItems,
    /// Раздел «Категории».
    Categories,
    /// Раздел «Папки».
    Folders,
    /// Раздел «Инструменты».
    Tools,
    /// Корзина.
    Trash,
    /// Аудит безопасности.
    Audit,
    /// Логин.
    Login,
    /// Заметка.
    SecureNote,
    /// Пароль.
    Password,
    /// Банковская карта.
    CreditCard,
    /// Почтовая учётная запись.
    Email,
    /// Документ личности.
    Identity,
    /// Паспорт.
    Passport,
    /// Сервер.
    Server,
    /// Лицензия на программу.
    Licence,
    /// Показать секретное поле.
    Eye,
    /// Скрыть секретное поле.
    EyeOff,
    /// Скопировать значение в буфер обмена: два наложенных листочка.
    Copy,
    /// Открыть вложение.
    Open,
    /// Отсоединить вложение от записи.
    Detach,
    /// Отменить действие.
    Cancel,
    /// Создать: плюс.
    Plus,
    /// Сохранить файл.
    Save,
    /// Извлечь и закрыть хранилище.
    Eject,
    /// Создать новое хранилище: папка со знаком плюс.
    NewVault,
}

impl Icon {
    /// Внутренняя геометрия значка в системе координат 24×24.
    fn body(self) -> &'static str {
        match self {
            Icon::AllItems => {
                r#"<rect x="2" y="3" width="20" height="5" rx="1"/><path d="M4 8v11a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8"/><path d="M10 12h4"/>"#
            }
            Icon::Categories => {
                r#"<rect width="7" height="7" x="3" y="3" rx="1"/><rect width="7" height="7" x="14" y="3" rx="1"/><rect width="7" height="7" x="14" y="14" rx="1"/><rect width="7" height="7" x="3" y="14" rx="1"/>"#
            }
            Icon::Folders => {
                r#"<path d="M20 20a2 2 0 0 0 2-2V8a2 2 0 0 0-2-2h-7.9a2 2 0 0 1-1.69-.9L9.6 3.9A2 2 0 0 0 7.93 3H4a2 2 0 0 0-2 2v13a2 2 0 0 0 2 2Z"/>"#
            }
            Icon::Tools => {
                r#"<path d="M14.7 6.3a1 1 0 0 0 0 1.4l1.6 1.6a1 1 0 0 0 1.4 0l3.77-3.77a6 6 0 0 1-7.94 7.94l-6.91 6.91a2.12 2.12 0 0 1-3-3l6.91-6.91a6 6 0 0 1 7.94-7.94l-3.76 3.76z"/>"#
            }
            Icon::Trash => {
                r#"<path d="M3 6h18"/><path d="M19 6v14c0 1-1 2-2 2H7c-1 0-2-1-2-2V6"/><path d="M8 6V4c0-1 1-2 2-2h4c1 0 2 1 2 2v2"/><path d="M10 11v6"/><path d="M14 11v6"/>"#
            }
            Icon::Audit => {
                r#"<path d="M20 13c0 5-3.5 7.5-7.66 8.95a1 1 0 0 1-.67-.01C7.5 20.5 4 18 4 13V6a1 1 0 0 1 1-1c2 0 4.5-1.2 6.24-2.72a1.17 1.17 0 0 1 1.52 0C14.51 3.81 17 5 19 5a1 1 0 0 1 1 1z"/><path d="m9 12 2 2 4-4"/>"#
            }
            Icon::Login => {
                r#"<circle cx="12" cy="12" r="10"/><path d="M12 2a14.5 14.5 0 0 0 0 20 14.5 14.5 0 0 0 0-20"/><path d="M2 12h20"/>"#
            }
            Icon::SecureNote => {
                r#"<path d="M13.4 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2v-7.4"/><path d="M2 6h4"/><path d="M2 10h4"/><path d="M2 14h4"/><path d="M2 18h4"/><path d="M21.378 5.626a1 1 0 1 0-3.004-3.004l-5.01 5.012a2 2 0 0 0-.506.854l-.837 2.87a.5.5 0 0 0 .62.62l2.87-.837a2 2 0 0 0 .854-.506z"/>"#
            }
            Icon::Password => {
                r#"<path d="M2.586 17.414A2 2 0 0 0 2 18.828V21a1 1 0 0 0 1 1h3a1 1 0 0 0 1-1v-1a1 1 0 0 1 1-1h1a1 1 0 0 0 1-1v-1a1 1 0 0 1 1-1h.172a2 2 0 0 0 1.414-.586l.814-.814a6.5 6.5 0 1 0-4-4z"/>"#
            }
            Icon::CreditCard => {
                r#"<rect width="20" height="14" x="2" y="5" rx="2"/><line x1="2" x2="22" y1="10" y2="10"/><path d="M6 14h2"/>"#
            }
            Icon::Email => {
                r#"<path d="m22 7-8.991 5.727a2 2 0 0 1-2.009 0L2 7"/><rect x="2" y="4" width="20" height="16" rx="2"/>"#
            }
            Icon::Identity => {
                r#"<path d="M13 19a4 4 0 00-8 0"/><path d="M16 10h2"/><path d="M16 14h2"/><circle cx="9" cy="12" r="3"/><rect x="2" y="5" width="20" height="14" rx="2"/>"#
            }
            Icon::Passport => {
                r#"<path d="M15 13a3 3 0 1 0-6 0"/><path d="M4 19.5v-15A2.5 2.5 0 0 1 6.5 2H19a1 1 0 0 1 1 1v18a1 1 0 0 1-1 1H6.5a1 1 0 0 1 0-5H20"/><circle cx="12" cy="8" r="2"/>"#
            }
            Icon::Server => {
                r#"<rect width="20" height="8" x="2" y="2" rx="2" ry="2"/><rect width="20" height="8" x="2" y="14" rx="2" ry="2"/><line x1="6" x2="6.01" y1="6" y2="6"/><line x1="6" x2="6.01" y1="18" y2="18"/>"#
            }
            Icon::Licence => {
                r#"<path d="M15 12h-5"/><path d="M15 8h-5"/><path d="M19 17V5a2 2 0 0 0-2-2H4"/><path d="M8 21h12a2 2 0 0 0 2-2v-1a2 2 0 0 0-1-1H11a2 2 0 0 0-1 1v1a2 2 0 0 1-4 0V5a2 2 0 0 1 4 0v2a2 2 0 0 0 1 1h3"/>"#
            }
            Icon::Eye => {
                r#"<path d="M2.062 12.348a1 1 0 0 1 0-.696 10.75 10.75 0 0 1 19.876 0 1 1 0 0 1 0 .696 10.75 10.75 0 0 1-19.876 0"/><circle cx="12" cy="12" r="3"/>"#
            }
            Icon::EyeOff => {
                r#"<path d="M10.733 5.076a10.744 10.744 0 0 1 11.205 6.575 1 1 0 0 1 0 .696 10.747 10.747 0 0 1-1.444 2.49"/><path d="M14.084 14.158a3 3 0 0 1-4.242-4.242"/><path d="M17.479 17.499a10.75 10.75 0 0 1-15.417-5.151 1 1 0 0 1 0-.696 10.75 10.75 0 0 1 4.446-5.143"/><path d="m2 2 20 20"/>"#
            }
            Icon::Copy => {
                r#"<rect width="14" height="14" x="8" y="8" rx="2"/><path d="M4 16c-1.1 0-2-.9-2-2V4c0-1.1.9-2 2-2h10c1.1 0 2 .9 2 2"/>"#
            }
            Icon::Open => {
                r#"<path d="m6 14 1.5-2.9A2 2 0 0 1 9.24 10H20a2 2 0 0 1 1.94 2.5l-1.54 6a2 2 0 0 1-1.95 1.5H4a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h3.9a2 2 0 0 1 1.69.9l.81 1.2a2 2 0 0 0 1.67.9H18a2 2 0 0 1 2 2v2"/>"#
            }
            Icon::Detach => {
                r#"<path d="m18.84 12.25 1.72-1.71h-.02a5.004 5.004 0 0 0-.12-7.07 5.006 5.006 0 0 0-6.95 0l-1.72 1.71"/><path d="m5.17 11.78-1.71 1.71h.01a5.004 5.004 0 0 0 .12 7.07 5.006 5.006 0 0 0 6.95 0l1.71-1.71"/><path d="m8 2 3 3"/><path d="m16 22-3-3"/><path d="m9 15 3-3"/>"#
            }
            Icon::Cancel => r#"<path d="M18 6 6 18"/><path d="m6 6 12 12"/>"#,
            Icon::Plus => r#"<path d="M5 12h14"/><path d="M12 5v14"/>"#,
            Icon::Eject => r#"<path d="m18 10-6-6-6 6"/><path d="M12 4v10"/><path d="m5 20h14"/>"#,
            Icon::Save => {
                r#"<path d="M15.2 3a2 2 0 0 1 1.4.6l3.8 3.8a2 2 0 0 1 .6 1.4V19a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2z"/><path d="M17 21v-7a1 1 0 0 0-1-1H8a1 1 0 0 0-1 1v7"/><path d="M7 3v4a1 1 0 0 0 1 1h7"/>"#
            }
            Icon::NewVault => {
                r#"<path d="M20 20a2 2 0 0 0 2-2V8a2 2 0 0 0-2-2h-7.9a2 2 0 0 1-1.69-.9L9.6 3.9A2 2 0 0 0 7.93 3H4a2 2 0 0 0-2 2v13a2 2 0 0 0 2 2Z"/><path d="M12 10v6"/><path d="M9 13h6"/>"#
            }
        }
    }
}

impl Icon {
    /// Значок для названия вида записи, как его возвращает `PifItem::kind()`.
    ///
    /// Родной `typeName` не берётся: он машинный, а в боковой панели
    /// показывается перевод, и значок должен соответствовать тому, что видит
    /// человек.
    pub fn for_kind(kind: &str) -> Icon {
        match kind {
            "Logins" => Icon::Login,
            "Secure Notes" => Icon::SecureNote,
            "Passwords" => Icon::Password,
            "Credit Cards" => Icon::CreditCard,
            "Email Accounts" => Icon::Email,
            "Identities" => Icon::Identity,
            "Passports" => Icon::Passport,
            "Servers" => Icon::Server,
            "Software Licences" => Icon::Licence,
            _ => Icon::Folders,
        }
    }
}

fn hex(color: Color) -> String {
    let channel = |v: f32| {
        // После интерполяции компонент может выйти за 0..=1: такой hex был бы
        // невалидным, и SVG не разобрался бы.
        let v = v.clamp(0.0, 1.0);
        format!("{:02x}", (v * 255.0).round() as u8)
    };
    format!(
        "#{}{}{}",
        channel(color.r),
        channel(color.g),
        channel(color.b)
    )
}

/// Значок заданного размера и цвета.
///
/// Строка собирается на каждый вызов, но это дёшево: идентификатор handle у
/// iced считается хешем содержимого, поэтому разобранный SVG берётся из кэша
/// рендерера, а не парсится заново.
pub fn icon<'a>(name: Icon, size: f32, color: Color) -> Svg<'a> {
    svg(name, size, color, STROKE)
}

/// Толщина обводки в системе координат значка, 24×24.
///
/// Две единицы — это исходная толщина набора. Крупные значки в тулбаре
/// рисуются с [`STROKE_THIN`]: при размере 28 px обводка в две единицы
/// даёт около 2,3 px на экране, а 0,8 — около 0,9; на Retina разница
/// втрое и заметна глазом.
pub const STROKE: f32 = 2.0;
pub const STROKE_THIN: f32 = 0.8;

/// Значок с заданной толщиной обводки.
pub fn icon_thin<'a>(name: Icon, size: f32, color: Color) -> Svg<'a> {
    svg(name, size, color, STROKE_THIN)
}

fn svg<'a>(name: Icon, size: f32, color: Color, stroke: f32) -> Svg<'a> {
    // У корня SVG нет width/height — только viewBox. Если задать и их, resvg
    // считает размер документа по этим атрибутам, а виджет по своим, и
    // значок начинает обрезаться рамкой.
    let svg = format!(
        r#"<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="{}" stroke-width="{}" stroke-linecap="round" stroke-linejoin="round">{}</svg>"#,
        hex(color),
        trim_float(stroke),
        name.body(),
    );

    Svg::new(Handle::from_memory(svg.into_bytes()))
        .width(Length::Fixed(size))
        .height(Length::Fixed(size))
        .style(move |_, _| Style { color: Some(color) })
}

/// Толщина попадает в атрибут как текст, поэтому лишние нули убираются:
/// иначе в разметке было бы `stroke-width="2.0000001"`, и кэш iced по
/// содержимому набирал бы новый handle на каждый вызов.
fn trim_float(v: f32) -> String {
    let s = format!("{v}");
    if s.contains('.') {
        s.trim_end_matches('0').trim_end_matches('.').to_string()
    } else {
        s
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ALL: [Icon; 25] = [
        Icon::AllItems,
        Icon::Categories,
        Icon::Folders,
        Icon::Tools,
        Icon::Trash,
        Icon::Audit,
        Icon::Login,
        Icon::SecureNote,
        Icon::Password,
        Icon::CreditCard,
        Icon::Email,
        Icon::Identity,
        Icon::Passport,
        Icon::Server,
        Icon::Licence,
        Icon::Eye,
        Icon::EyeOff,
        Icon::Copy,
        Icon::Open,
        Icon::Detach,
        Icon::Cancel,
        Icon::Plus,
        Icon::Save,
        Icon::Eject,
        Icon::NewVault,
    ];

    #[test]
    fn каждый_значок_даёт_разметку() {
        for icon in ALL {
            let body = icon.body();
            assert!(body.starts_with('<'), "у {icon:?} пустое тело");
            assert!(body.ends_with("/>"), "у {icon:?} путь не закрыт: {body}");
        }
    }

    /// Обратный слэш внутри пути обрывает его молча.
    #[test]
    fn в_геометрии_нет_обратных_слэшей() {
        for icon in ALL {
            let body = icon.body();
            assert!(
                !body.contains('\\'),
                "у {icon:?} в пути остался обратный слэш, путь обрежется: {body}"
            );
        }
    }

    /// Переносов строки быть не должно: в атрибуте `d` они допустимы, но
    /// именно из-за них сюда попал сломанный путь.
    #[test]
    fn путь_значка_однострочный() {
        for icon in ALL {
            let body = icon.body();
            assert!(
                !body.contains('\n'),
                "у {icon:?} путь разбит на несколько строк"
            );
        }
    }

    /// Резолвер не понимает `currentColor`: цвет запекается в разметку.
    #[test]
    fn current_color_не_остался() {
        for icon in ALL {
            assert!(
                !icon.body().contains("currentColor"),
                "у {icon:?} остался currentColor, который резолвер не понимает"
            );
        }
    }

    /// У каждого вида записи из боковой панели есть свой значок, и разные виды
    /// не делят один на всех: иначе весь смысл значка теряется.
    #[test]
    fn у_каждого_вида_свой_значок() {
        let kinds = [
            ("Logins", Icon::Login),
            ("Secure Notes", Icon::SecureNote),
            ("Passwords", Icon::Password),
            ("Credit Cards", Icon::CreditCard),
            ("Email Accounts", Icon::Email),
            ("Identities", Icon::Identity),
            ("Passports", Icon::Passport),
            ("Servers", Icon::Server),
            ("Software Licences", Icon::Licence),
        ];

        for (kind, expected) in kinds {
            assert_eq!(
                Icon::for_kind(kind),
                expected,
                "вид {kind} получил не тот значок"
            );
        }

        // Значки разных видов не должны совпадать.
        let mut seen: Vec<Icon> = kinds.iter().map(|(_, icon)| *icon).collect();
        seen.sort_by_key(|i| format!("{i:?}"));
        seen.dedup();
        assert_eq!(seen.len(), kinds.len(), "значки видов повторяются");
    }

    /// Неизвестный вид не должен ломать отрисовку: показываем папку.
    #[test]
    fn неизвестный_вид_даёт_запасной_значок() {
        assert_eq!(Icon::for_kind("Какая-то новая категория"), Icon::Folders);
    }

    #[test]
    fn цвет_преобразуется_в_шестизначный_hex() {
        assert_eq!(hex(Color::from_rgb(1.0, 0.0, 0.0)), "#ff0000");
        assert_eq!(hex(Color::from_rgb(0.0, 0.0, 0.0)), "#000000");
        assert_eq!(hex(Color::from_rgb(1.0, 1.0, 1.0)), "#ffffff");
    }

    #[test]
    fn цвет_обрезается_к_допустимому_диапазону() {
        // После интерполяции компонент действительно выходит за 0..=1.
        // `Color::from_rgb` такой ввод отвергает, поэтому структура
        // собирается напрямую — ровно как это делает интерполяция.
        let raw = Color {
            r: 1.4,
            g: -0.2,
            b: 0.5,
            a: 1.0,
        };
        assert_eq!(hex(raw), "#ff0080");
    }
}
