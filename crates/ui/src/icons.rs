//! Sidebar section icons.
//!
//! The glyphs come from the Lucide set (ISC licence): outlines, 24×24 grid,
//! 2-wide stroke with rounded caps. SF Symbols cannot be used natively — the
//! licence only permits the symbols inside an app on Apple platforms and
//! explicitly forbids extracting and redistributing them, so the symbol file
//! cannot be committed to the repository.
//!
//! The colour is baked straight into the SVG because the resolver does not
//! understand `currentColor`, and a sidebar icon has to grey out together with
//! its label and light up together with the selection.
//!
//! Every path is written on a single line **on purpose**. A backslash line
//! continuation works in ordinary Rust strings but not in raw strings
//! `r#"…"#`: there the `\` and the newline land inside the `d="…"` attribute,
//! the path is cut short, and the icon renders partially — silently, with no
//! compile error.

use iced::{Color, Length};

use iced::widget::svg::{Handle, Style, Svg};

/// Icons drawn in the UI.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Icon {
    /// "All Items" section.
    AllItems,
    /// "Categories" section.
    Categories,
    /// "Folders" section.
    Folders,
    /// "Tools" section.
    Tools,
    /// Trash.
    Trash,
    /// Security audit.
    Audit,
    /// Login.
    Login,
    /// Secure note.
    SecureNote,
    /// Password.
    Password,
    /// Bank card.
    CreditCard,
    /// Email account.
    Email,
    /// Identity document.
    Identity,
    /// Passport.
    Passport,
    /// Server.
    Server,
    /// Software licence.
    Licence,
    /// Reveal a secret field.
    Eye,
    /// Hide a secret field.
    EyeOff,
    /// Copy a value to the clipboard: two overlapping sheets.
    Copy,
    /// Open an attachment.
    Open,
    /// Detach an attachment from the item.
    Detach,
    /// Cancel an action.
    Cancel,
    /// Create: plus.
    Plus,
    /// Save the file.
    Save,
    /// Unlock and close the vault.
    Eject,
    /// Create a new vault: a folder with a plus.
    NewVault,
}

impl Icon {
    /// The icon's inner geometry in the 24×24 coordinate system.
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
    /// Icon for an item kind name, as returned by `PifItem::kind()`.
    ///
    /// The raw `typeName` is not used: it is machine-oriented, while the
    /// sidebar shows a translation, so the icon has to match what the person
    /// actually sees.
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
        // After interpolation a component can fall outside 0..=1: such a hex
        // would be invalid and the SVG would fail to parse.
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

/// An icon of the given size and colour.
///
/// The string is rebuilt on every call, but that is cheap: iced treats the
/// handle id as a hash of the contents, so the parsed SVG comes from the
/// renderer's cache instead of being parsed again.
pub fn icon<'a>(name: Icon, size: f32, color: Color) -> Svg<'a> {
    svg(name, size, color, STROKE)
}

/// Stroke width in the icon's 24×24 coordinate system.
///
/// Two units is the set's native width. Large toolbar icons are drawn with
/// [`STROKE_THIN`]: at 28 px a two-unit stroke gives about 2.3 px on screen
/// and 0.8 gives about 0.9; on Retina the difference triples and is obvious
/// to the eye.
pub const STROKE: f32 = 2.0;
pub const STROKE_THIN: f32 = 0.8;

/// An icon with an explicit stroke width.
pub fn icon_thin<'a>(name: Icon, size: f32, color: Color) -> Svg<'a> {
    svg(name, size, color, STROKE_THIN)
}

fn svg<'a>(name: Icon, size: f32, color: Color, stroke: f32) -> Svg<'a> {
    // The SVG root has no width/height — only viewBox. Set those too and resvg
    // takes the document size from those attributes while the widget uses its
    // own, and the icon starts being clipped by the frame.
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

/// The width goes into the attribute as text, so trailing zeros are trimmed:
/// otherwise the markup would carry `stroke-width="2.0000001"` and iced's
/// content-keyed cache would pick a new handle on every call.
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
    fn every_icon_has_markup() {
        for icon in ALL {
            let body = icon.body();
            assert!(body.starts_with('<'), "{icon:?} has an empty body");
            assert!(body.ends_with("/>"), "{icon:?} has an unclosed path: {body}");
        }
    }

    /// A backslash inside a path cuts it short, silently.
    #[test]
    fn no_backslashes_in_geometry() {
        for icon in ALL {
            let body = icon.body();
            assert!(
                !body.contains('\\'),
                "{icon:?} still has a backslash in its path, the path will be cut: {body}"
            );
        }
    }

    /// There must be no line breaks: they are legal in the `d` attribute, but
    /// a broken path slipped in here precisely because of them.
    #[test]
    fn icon_path_is_single_line() {
        for icon in ALL {
            let body = icon.body();
            assert!(
                !body.contains('\n'),
                "{icon:?} has a path split across several lines"
            );
        }
    }

    /// The resolver does not understand `currentColor`: the colour is baked
    /// into the markup.
    #[test]
    fn no_current_color_left() {
        for icon in ALL {
            assert!(
                !icon.body().contains("currentColor"),
                "{icon:?} still has a currentColor the resolver does not understand"
            );
        }
    }

    /// Every item kind in the sidebar has its own icon, and different kinds do
    /// not share one: otherwise the whole point of the icon is lost.
    #[test]
    fn every_kind_has_its_own_icon() {
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
                "kind {kind} got the wrong icon"
            );
        }

        // Icons of different kinds must not collide.
        let mut seen: Vec<Icon> = kinds.iter().map(|(_, icon)| *icon).collect();
        seen.sort_by_key(|i| format!("{i:?}"));
        seen.dedup();
        assert_eq!(seen.len(), kinds.len(), "kind icons are duplicated");
    }

    /// An unknown kind must not break rendering: show a folder.
    #[test]
    fn unknown_kind_falls_back_to_an_icon() {
        assert_eq!(Icon::for_kind("Some brand new category"), Icon::Folders);
    }

    #[test]
    fn color_becomes_six_digit_hex() {
        assert_eq!(hex(Color::from_rgb(1.0, 0.0, 0.0)), "#ff0000");
        assert_eq!(hex(Color::from_rgb(0.0, 0.0, 0.0)), "#000000");
        assert_eq!(hex(Color::from_rgb(1.0, 1.0, 1.0)), "#ffffff");
    }

    #[test]
    fn color_is_clamped_to_the_valid_range() {
        // After interpolation a component really does fall outside 0..=1.
        // `Color::from_rgb` rejects such input, so the struct is built
        // directly — exactly what interpolation does.
        let raw = Color {
            r: 1.4,
            g: -0.2,
            b: 0.5,
            a: 1.0,
        };
        assert_eq!(hex(raw), "#ff0080");
    }
}
