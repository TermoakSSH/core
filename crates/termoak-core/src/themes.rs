//! Terminal colour themes shared by every app (the desktop, iOS and Android
//! terminals and the FFI emulator): background, text, cursor and the 16 ANSI
//! colours (the 8 normal and the 8 bright ones), in `0xRRGGBB`.
//!
//! The ids are stored in settings and in `HostSettings::theme`: keep them.
//! The palettes are the ones their authors publish (MIT or similar
//! licenses). `dark` and `light` are what the desktop's host editor saves:
//! [`for_host`] maps them to a theme of that kind.

/// A terminal colour theme.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TerminalTheme {
    /// Stable id (stored in settings).
    pub id: &'static str,
    /// Display name (product names are not translated).
    pub name: &'static str,
    pub background: u32,
    pub foreground: u32,
    pub cursor: u32,
    /// Normal (0–7) and bright (8–15) ANSI colours.
    pub ansi: [u32; 16],
}

impl TerminalTheme {
    /// A light background (relative luminance above one half).
    pub fn is_light(&self) -> bool {
        luminance(self.background) > 0.5
    }

    /// Colour of the selection: the cursor colour over the background.
    pub fn selection(&self) -> u32 {
        blend(self.background, self.cursor, if self.is_light() { 0.25 } else { 0.38 })
    }
}

/// Id of the default dark theme.
pub const DEFAULT_DARK: &str = "termoak";
/// Id of the default light theme.
pub const DEFAULT_LIGHT: &str = "claro";

/// Every theme, in the order the pickers show them.
pub const THEMES: &[TerminalTheme] = &[
    TerminalTheme {
        id: "termoak",
        name: "Termoak",
        background: 0x12151D,
        foreground: 0xD6DBE4,
        cursor: 0x3FB27F,
        ansi: [
            0x1B1F2A, 0xE06C75, 0x3FB27F, 0xE5C07B, 0x61AFEF, 0xC678DD, 0x56B6C2, 0xD6DBE4, 0x5C6370,
            0xFF7A85, 0x5FD39C, 0xFFD68A, 0x7CC4FF, 0xDA8EF0, 0x6FD3DF, 0xFFFFFF,
        ],
    },
    TerminalTheme {
        id: "claro",
        name: "Termoak Light",
        background: 0xFFFFFF,
        foreground: 0x24292F,
        cursor: 0x1F883D,
        ansi: [
            0x24292F, 0xCF222E, 0x116329, 0x4D2D00, 0x0969DA, 0x8250DF, 0x1B7C83, 0x6E7781, 0x57606A,
            0xA40E26, 0x1A7F37, 0x633C01, 0x218BFF, 0xA475F9, 0x3192AA, 0x8C959F,
        ],
    },
    TerminalTheme {
        id: "dracula",
        name: "Dracula",
        background: 0x282A36,
        foreground: 0xF8F8F2,
        cursor: 0xF8F8F2,
        ansi: [
            0x21222C, 0xFF5555, 0x50FA7B, 0xF1FA8C, 0xBD93F9, 0xFF79C6, 0x8BE9FD, 0xF8F8F2, 0x6272A4,
            0xFF6E6E, 0x69FF94, 0xFFFFA5, 0xD6ACFF, 0xFF92DF, 0xA4FFFF, 0xFFFFFF,
        ],
    },
    TerminalTheme {
        id: "nord",
        name: "Nord",
        background: 0x2E3440,
        foreground: 0xD8DEE9,
        cursor: 0xD8DEE9,
        ansi: [
            0x3B4252, 0xBF616A, 0xA3BE8C, 0xEBCB8B, 0x81A1C1, 0xB48EAD, 0x88C0D0, 0xE5E9F0, 0x4C566A,
            0xBF616A, 0xA3BE8C, 0xEBCB8B, 0x81A1C1, 0xB48EAD, 0x8FBCBB, 0xECEFF4,
        ],
    },
    TerminalTheme {
        id: "onedark",
        name: "One Dark",
        background: 0x282C34,
        foreground: 0xABB2BF,
        cursor: 0x528BFF,
        ansi: [
            0x282C34, 0xE06C75, 0x98C379, 0xE5C07B, 0x61AFEF, 0xC678DD, 0x56B6C2, 0xABB2BF, 0x5C6370,
            0xE06C75, 0x98C379, 0xE5C07B, 0x61AFEF, 0xC678DD, 0x56B6C2, 0xFFFFFF,
        ],
    },
    TerminalTheme {
        id: "tokyonight",
        name: "Tokyo Night",
        background: 0x1A1B26,
        foreground: 0xC0CAF5,
        cursor: 0xC0CAF5,
        ansi: [
            0x15161E, 0xF7768E, 0x9ECE6A, 0xE0AF68, 0x7AA2F7, 0xBB9AF7, 0x7DCFFF, 0xA9B1D6, 0x414868,
            0xF7768E, 0x9ECE6A, 0xE0AF68, 0x7AA2F7, 0xBB9AF7, 0x7DCFFF, 0xC0CAF5,
        ],
    },
    TerminalTheme {
        id: "gruvbox",
        name: "Gruvbox Dark",
        background: 0x282828,
        foreground: 0xEBDBB2,
        cursor: 0xEBDBB2,
        ansi: [
            0x282828, 0xCC241D, 0x98971A, 0xD79921, 0x458588, 0xB16286, 0x689D6A, 0xA89984, 0x928374,
            0xFB4934, 0xB8BB26, 0xFABD2F, 0x83A598, 0xD3869B, 0x8EC07C, 0xEBDBB2,
        ],
    },
    TerminalTheme {
        id: "solarized-dark",
        name: "Solarized Dark",
        background: 0x002B36,
        foreground: 0x839496,
        cursor: 0x93A1A1,
        ansi: [
            0x073642, 0xDC322F, 0x859900, 0xB58900, 0x268BD2, 0xD33682, 0x2AA198, 0xEEE8D5, 0x002B36,
            0xCB4B16, 0x586E75, 0x657B83, 0x839496, 0x6C71C4, 0x93A1A1, 0xFDF6E3,
        ],
    },
    TerminalTheme {
        id: "solarized-light",
        name: "Solarized Light",
        background: 0xFDF6E3,
        foreground: 0x657B83,
        cursor: 0x586E75,
        ansi: [
            0x073642, 0xDC322F, 0x859900, 0xB58900, 0x268BD2, 0xD33682, 0x2AA198, 0xEEE8D5, 0x002B36,
            0xCB4B16, 0x586E75, 0x657B83, 0x839496, 0x6C71C4, 0x93A1A1, 0xFDF6E3,
        ],
    },
    TerminalTheme {
        id: "catppuccin-mocha",
        name: "Catppuccin Mocha",
        background: 0x1E1E2E,
        foreground: 0xCDD6F4,
        cursor: 0xF5E0DC,
        ansi: [
            0x45475A, 0xF38BA8, 0xA6E3A1, 0xF9E2AF, 0x89B4FA, 0xF5C2E7, 0x94E2D5, 0xBAC2DE, 0x585B70,
            0xF38BA8, 0xA6E3A1, 0xF9E2AF, 0x89B4FA, 0xF5C2E7, 0x94E2D5, 0xA6ADC8,
        ],
    },
    TerminalTheme {
        id: "catppuccin-latte",
        name: "Catppuccin Latte",
        background: 0xEFF1F5,
        foreground: 0x4C4F69,
        cursor: 0xDC8A78,
        ansi: [
            0x5C5F77, 0xD20F39, 0x40A02B, 0xDF8E1D, 0x1E66F5, 0xEA76CB, 0x179299, 0xACB0BE, 0x6C6F85,
            0xD20F39, 0x40A02B, 0xDF8E1D, 0x1E66F5, 0xEA76CB, 0x179299, 0xBCC0CC,
        ],
    },
    TerminalTheme {
        id: "flexoki-dark",
        name: "Flexoki Dark",
        background: 0x100F0F,
        foreground: 0xCECDC3,
        cursor: 0xCECDC3,
        ansi: [
            0x100F0F, 0xAF3029, 0x66800B, 0xAD8301, 0x205EA6, 0xA02F6F, 0x24837B, 0x878580, 0x575653,
            0xD14D41, 0x879A39, 0xD0A215, 0x4385BE, 0xCE5D97, 0x3AA99F, 0xCECDC3,
        ],
    },
    TerminalTheme {
        id: "flexoki-light",
        name: "Flexoki Light",
        background: 0xFFFCF0,
        foreground: 0x100F0F,
        cursor: 0x100F0F,
        ansi: [
            0x100F0F, 0xAF3029, 0x66800B, 0xAD8301, 0x205EA6, 0xA02F6F, 0x24837B, 0x6F6E69, 0xB7B5AC,
            0xD14D41, 0x879A39, 0xD0A215, 0x4385BE, 0xCE5D97, 0x3AA99F, 0xCECDC3,
        ],
    },
    TerminalTheme {
        id: "kanagawa-wave",
        name: "Kanagawa Wave",
        background: 0x1F1F28,
        foreground: 0xDCD7BA,
        cursor: 0xC8C093,
        ansi: [
            0x16161D, 0xC34043, 0x76946A, 0xC0A36E, 0x7E9CD8, 0x957FB8, 0x6A9589, 0xC8C093, 0x727169,
            0xE82424, 0x98BB6C, 0xE6C384, 0x7FB4CA, 0x938AA9, 0x7AA89F, 0xDCD7BA,
        ],
    },
    TerminalTheme {
        id: "kanagawa-dragon",
        name: "Kanagawa Dragon",
        background: 0x181616,
        foreground: 0xC5C9C5,
        cursor: 0xC8C093,
        ansi: [
            0x0D0C0C, 0xC4746E, 0x8A9A7B, 0xC4B28A, 0x8BA4B0, 0xA292A3, 0x8EA4A2, 0xC8C093, 0xA6A69C,
            0xE46876, 0x87A987, 0xE6C384, 0x7FB4CA, 0x938AA9, 0x7AA89F, 0xC5C9C5,
        ],
    },
];

/// The theme with that id (case and surrounding spaces ignored).
pub fn by_id(id: &str) -> Option<&'static TerminalTheme> {
    let id = id.trim();
    THEMES.iter().find(|t| t.id.eq_ignore_ascii_case(id))
}

/// The theme with that id, or the default dark one.
pub fn by_id_or_default(id: &str) -> &'static TerminalTheme {
    by_id(id).unwrap_or(&THEMES[0])
}

/// Theme of a host's terminal: `value` is the host's effective
/// `HostSettings::theme` and `app` the app's theme id. `dark` and `light`
/// keep the app's theme when it is of that kind and otherwise use
/// Termoak's; the id of a theme uses it; anything else (or nothing) follows
/// the app.
pub fn for_host(value: Option<&str>, app: &str) -> &'static TerminalTheme {
    let app = by_id_or_default(app);
    let Some(v) = value.map(str::trim).filter(|v| !v.is_empty()) else {
        return app;
    };
    match v.to_ascii_lowercase().as_str() {
        "dark" if app.is_light() => by_id_or_default(DEFAULT_DARK),
        "dark" => app,
        "light" if app.is_light() => app,
        "light" => by_id_or_default(DEFAULT_LIGHT),
        other => by_id(other).unwrap_or(app),
    }
}

fn components(rgb: u32) -> (f64, f64, f64) {
    (
        f64::from((rgb >> 16) & 0xFF) / 255.0,
        f64::from((rgb >> 8) & 0xFF) / 255.0,
        f64::from(rgb & 0xFF) / 255.0,
    )
}

/// Relative luminance (0 black, 1 white).
pub fn luminance(rgb: u32) -> f64 {
    let (r, g, b) = components(rgb);
    0.2126 * r + 0.7152 * g + 0.0722 * b
}

/// `a` blended with `b` in the proportion `t` (0 = `a`, 1 = `b`).
pub fn blend(a: u32, b: u32, t: f64) -> u32 {
    let (ar, ag, ab) = components(a);
    let (br, bg, bb) = components(b);
    let c = |x: f64, y: f64| ((x + (y - x) * t.clamp(0.0, 1.0)) * 255.0).round() as u32;
    (c(ar, br) << 16) | (c(ag, bg) << 8) | c(ab, bb)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ids_are_unique_and_found() {
        for (i, t) in THEMES.iter().enumerate() {
            assert!(THEMES[i + 1..].iter().all(|o| o.id != t.id), "{}", t.id);
            assert_eq!(by_id(&format!(" {} ", t.id.to_uppercase())), Some(t));
        }
        assert_eq!(THEMES.len(), 15);
        assert!(by_id("nope").is_none());
        assert_eq!(by_id_or_default("nope").id, DEFAULT_DARK);
        assert!(by_id(DEFAULT_LIGHT).unwrap().is_light());
        assert!(!by_id(DEFAULT_DARK).unwrap().is_light());
    }

    #[test]
    fn host_themes() {
        assert_eq!(for_host(None, "nord").id, "nord");
        assert_eq!(for_host(Some("  "), "nord").id, "nord");
        assert_eq!(for_host(Some("dracula"), "nord").id, "dracula");
        assert_eq!(for_host(Some("unknown"), "nord").id, "nord");
        // `dark` / `light` keep the app's theme when it is of that kind.
        assert_eq!(for_host(Some("dark"), "nord").id, "nord");
        assert_eq!(for_host(Some("Dark"), "solarized-light").id, "termoak");
        assert_eq!(for_host(Some("light"), "nord").id, "claro");
        assert_eq!(
            for_host(Some("light"), "catppuccin-latte").id,
            "catppuccin-latte"
        );
    }

    #[test]
    fn colours() {
        assert_eq!(blend(0x000000, 0xFFFFFF, 0.5), 0x808080);
        assert_eq!(blend(0x102030, 0x102030, 0.3), 0x102030);
        assert!(luminance(0xFFFFFF) > 0.99 && luminance(0) < 0.01);
        let t = by_id("termoak").unwrap();
        assert_ne!(t.selection(), t.background);
    }
}
