//! Terminal emulator for the mobile apps, with the same engine as the
//! desktop app (`alacritty_terminal`).
//!
//! The app passes the terminal output (from `TerminalListener::on_output` or
//! `ServerTerminalEvent::Output`) to [`TerminalScreen::feed`], sends back to
//! the terminal whatever it returns (answers to the remote program's
//! queries) and paints [`TerminalScreen::snapshot`]: rows with runs of
//! same-style text and colors already resolved to ARGB. Special keys are
//! translated with [`TerminalScreen::key`], which honours the program's
//! modes (application cursor, bracketed paste...).

use std::sync::Arc;

use alacritty_terminal::event::{Event, EventListener, WindowSize};
use alacritty_terminal::grid::{Dimensions, Scroll};
use alacritty_terminal::index::{Column, Line, Point};
use alacritty_terminal::term::cell::Flags;
use alacritty_terminal::term::color::Colors;
use alacritty_terminal::term::{Config, Term, TermMode};
use alacritty_terminal::vte::ansi::{Color, CursorShape, NamedColor, Processor};
use parking_lot::Mutex;

/// Default scrollback (lines).
const DEFAULT_SCROLLBACK: u32 = 10_000;

#[derive(Clone, Copy)]
struct Size {
    cols: usize,
    lines: usize,
}

impl Size {
    fn new(cols: u32, rows: u32) -> Self {
        Self {
            cols: cols.clamp(2, 1000) as usize,
            lines: rows.clamp(1, 1000) as usize,
        }
    }
}

impl Dimensions for Size {
    fn total_lines(&self) -> usize {
        self.lines
    }
    fn screen_lines(&self) -> usize {
        self.lines
    }
    fn columns(&self) -> usize {
        self.cols
    }
}

#[derive(Clone, Default)]
struct Proxy(Arc<Mutex<Vec<Event>>>);

impl EventListener for Proxy {
    fn send_event(&self, event: Event) {
        self.0.lock().push(event);
    }
}

/// What the remote program asks for after its output is processed.
#[derive(Debug, Clone, PartialEq, uniffi::Enum)]
pub enum ScreenEvent {
    /// Bytes to send to the terminal (answer to a query).
    Write {
        data: Vec<u8>,
    },
    Title {
        title: String,
    },
    ResetTitle,
    Bell,
    /// Copy to the clipboard (OSC 52).
    Copy {
        text: String,
    },
}

/// Run of consecutive cells with the same style.
#[derive(Debug, Clone, PartialEq, uniffi::Record)]
pub struct ScreenRun {
    /// Column where it starts.
    pub col: u32,
    /// Cells it takes (a wide character takes 2).
    pub cells: u32,
    /// Text; one character per cell except wide ones, which get a run of their own.
    pub text: String,
    /// Colors in ARGB (`0xAARRGGBB`).
    pub fg: u32,
    /// `None`: the terminal background.
    pub bg: Option<u32>,
    pub bold: bool,
    pub italic: bool,
    pub underline: bool,
    pub strike: bool,
    pub wide: bool,
}

#[derive(Debug, Clone, PartialEq, uniffi::Record)]
pub struct ScreenLine {
    pub runs: Vec<ScreenRun>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum ScreenCursorShape {
    Block,
    Beam,
    Underline,
    Hollow,
}

#[derive(Debug, Clone, PartialEq, uniffi::Record)]
pub struct ScreenCursor {
    pub row: u32,
    pub col: u32,
    pub shape: ScreenCursorShape,
}

/// Visible screen, ready to paint.
#[derive(Debug, Clone, PartialEq, uniffi::Record)]
pub struct ScreenSnapshot {
    pub cols: u32,
    pub rows: u32,
    pub lines: Vec<ScreenLine>,
    /// `None` if the program hides it or it is out of view (scrollback).
    pub cursor: Option<ScreenCursor>,
    /// Scrollback lines above the view (0: at the bottom).
    pub display_offset: u32,
    pub background: u32,
    pub foreground: u32,
    pub cursor_color: u32,
}

/// Keys that are not text.
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum TerminalKey {
    Up,
    Down,
    Left,
    Right,
    Home,
    End,
    PageUp,
    PageDown,
    Insert,
    Delete,
    Enter,
    Tab,
    Backspace,
    Escape,
    /// F1 to F12.
    Function {
        number: u8,
    },
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, uniffi::Record)]
pub struct KeyModifiers {
    pub shift: bool,
    pub alt: bool,
    pub ctrl: bool,
}

struct Inner {
    term: Term<Proxy>,
    processor: Processor,
    events: Proxy,
    size: Size,
    scrollback: usize,
}

impl Inner {
    fn new(size: Size, scrollback: usize) -> Self {
        let events = Proxy::default();
        let config = Config {
            scrolling_history: scrollback,
            ..Config::default()
        };
        Self {
            term: Term::new(config, &size, events.clone()),
            processor: Processor::new(),
            events,
            size,
            scrollback,
        }
    }
}

/// Terminal emulator (VT100/xterm). Thread-safe: output can arrive from the
/// terminal's thread and be painted from the main one.
#[derive(uniffi::Object)]
pub struct TerminalScreen {
    inner: Mutex<Inner>,
}

#[uniffi::export]
impl TerminalScreen {
    /// `scrollback`: scrollback lines (0: 10,000).
    #[uniffi::constructor]
    pub fn new(cols: u32, rows: u32, scrollback: u32) -> Arc<Self> {
        let scrollback = if scrollback == 0 {
            DEFAULT_SCROLLBACK
        } else {
            scrollback
        };
        Arc::new(Self {
            inner: Mutex::new(Inner::new(Size::new(cols, rows), scrollback as usize)),
        })
    }

    /// Processes terminal output. What it returns must be handled: `Write`
    /// events are sent to the terminal as is.
    pub fn feed(&self, data: Vec<u8>) -> Vec<ScreenEvent> {
        let mut guard = self.inner.lock();
        let inner = &mut *guard;
        inner.processor.advance(&mut inner.term, &data);
        let size = inner.size;
        let colors = *inner.term.colors();
        let raw = std::mem::take(&mut *inner.events.0.lock());
        raw.into_iter()
            .filter_map(|ev| match ev {
                Event::PtyWrite(s) => Some(ScreenEvent::Write {
                    data: s.into_bytes(),
                }),
                Event::Title(title) => Some(ScreenEvent::Title { title }),
                Event::ResetTitle => Some(ScreenEvent::ResetTitle),
                Event::Bell => Some(ScreenEvent::Bell),
                Event::ClipboardStore(_, text) => Some(ScreenEvent::Copy { text }),
                Event::TextAreaSizeRequest(format) => Some(ScreenEvent::Write {
                    data: format(WindowSize {
                        num_lines: size.lines as u16,
                        num_cols: size.cols as u16,
                        cell_width: 8,
                        cell_height: 16,
                    })
                    .into_bytes(),
                }),
                Event::ColorRequest(index, format) => {
                    let argb = match index {
                        256 => resolve(Color::Named(NamedColor::Foreground), &colors, true),
                        257 => resolve(Color::Named(NamedColor::Background), &colors, false),
                        258 => CURSOR,
                        i if i < 256 => resolve(Color::Indexed(i as u8), &colors, true),
                        _ => FOREGROUND,
                    };
                    Some(ScreenEvent::Write {
                        data: format(alacritty_terminal::vte::ansi::Rgb {
                            r: (argb >> 16) as u8,
                            g: (argb >> 8) as u8,
                            b: argb as u8,
                        })
                        .into_bytes(),
                    })
                }
                _ => None,
            })
            .collect()
    }

    /// Changes the size (the terminal must also be told with `resize`).
    pub fn resize(&self, cols: u32, rows: u32) {
        let mut inner = self.inner.lock();
        let size = Size::new(cols, rows);
        if size.cols != inner.size.cols || size.lines != inner.size.lines {
            inner.size = size;
            inner.term.resize(size);
        }
    }

    pub fn cols(&self) -> u32 {
        self.inner.lock().size.cols as u32
    }

    pub fn rows(&self) -> u32 {
        self.inner.lock().size.lines as u32
    }

    /// Clears screen and scrollback (e.g. on `ServerTerminalEvent::Resync`).
    pub fn reset(&self) {
        let mut inner = self.inner.lock();
        let (size, scrollback) = (inner.size, inner.scrollback);
        *inner = Inner::new(size, scrollback);
    }

    /// Scrolls the view through the scrollback (`lines` > 0 scrolls up).
    pub fn scroll(&self, lines: i32) {
        if lines != 0 {
            self.inner.lock().term.scroll_display(Scroll::Delta(lines));
        }
    }

    pub fn scroll_to_bottom(&self) {
        self.inner.lock().term.scroll_display(Scroll::Bottom);
    }

    /// The remote program uses the alternate screen (vim, htop, less...):
    /// there, scrolling translates into arrow keys, not scrollback.
    pub fn alternate_screen(&self) -> bool {
        self.inner.lock().term.mode().contains(TermMode::ALT_SCREEN)
    }

    /// Text of the visible screen, without trailing spaces on each line.
    pub fn screen_text(&self) -> String {
        let inner = self.inner.lock();
        let offset = inner.term.grid().display_offset() as i32;
        let start = Point::new(Line(-offset), Column(0));
        let end = Point::new(
            Line(inner.size.lines as i32 - 1 - offset),
            Column(inner.size.cols - 1),
        );
        inner
            .term
            .bounds_to_string(start, end)
            .lines()
            .map(str::trim_end)
            .collect::<Vec<_>>()
            .join("\n")
            .trim_end()
            .to_string()
    }

    /// Link at the visible cell `row`, `col`: the one the program marks
    /// (OSC 8) or a URL written in the line. Used to open it on tap.
    pub fn link_at(&self, row: u32, col: u32) -> Option<String> {
        let inner = self.inner.lock();
        let offset = inner.term.grid().display_offset() as i32;
        let row = (row as usize).min(inner.size.lines.saturating_sub(1)) as i32;
        let col = (col as usize).min(inner.size.cols.saturating_sub(1));
        let point = Point::new(Line(row - offset), Column(col));
        let grid = inner.term.grid();
        if let Some(link) = grid[point].hyperlink() {
            return Some(link.uri().to_string());
        }
        let line = &grid[point.line];
        let chars: Vec<char> = (0..inner.size.cols)
            .map(|c| match line[Column(c)].c {
                '\0' | '\t' => ' ',
                ch => ch,
            })
            .collect();
        find_url(&chars, col)
    }

    /// Bytes of a special key, according to the remote program's mode.
    pub fn key(&self, key: TerminalKey, modifiers: KeyModifiers) -> Vec<u8> {
        let app_cursor = self.inner.lock().term.mode().contains(TermMode::APP_CURSOR);
        key_bytes(key, modifiers, app_cursor)
    }

    /// Bytes of a character typed with Ctrl and/or Alt (Ctrl+C → 0x03,
    /// Alt+x → ESC x). Without modifiers, the character in UTF-8.
    pub fn character(&self, ch: String, modifiers: KeyModifiers) -> Vec<u8> {
        char_bytes(&ch, modifiers)
    }

    /// Pasted text: bracketed if the program asked for it, with line breaks
    /// sent as Enter.
    pub fn paste(&self, text: String) -> Vec<u8> {
        let bracketed = self
            .inner
            .lock()
            .term
            .mode()
            .contains(TermMode::BRACKETED_PASTE);
        let body = text.replace("\r\n", "\r").replace('\n', "\r");
        if bracketed {
            // No closing sequences inside the pasted text.
            let body = body.replace("\x1b[201~", "");
            format!("\x1b[200~{body}\x1b[201~").into_bytes()
        } else {
            body.into_bytes()
        }
    }

    /// The visible screen, ready to paint.
    pub fn snapshot(&self) -> ScreenSnapshot {
        let inner = self.inner.lock();
        let content = inner.term.renderable_content();
        let offset = content.display_offset as i32;
        let lines = inner.size.lines;
        let colors = content.colors;
        let mut out: Vec<ScreenLine> = vec![ScreenLine { runs: Vec::new() }; lines];

        let cursor_point = content.cursor.point;
        let cursor_row = cursor_point.line.0 + offset;
        let cursor = (content.cursor.shape != CursorShape::Hidden
            && cursor_row >= 0
            && (cursor_row as usize) < lines)
            .then_some(ScreenCursor {
                row: cursor_row as u32,
                col: cursor_point.column.0 as u32,
                shape: match content.cursor.shape {
                    CursorShape::Beam => ScreenCursorShape::Beam,
                    CursorShape::Underline => ScreenCursorShape::Underline,
                    CursorShape::HollowBlock => ScreenCursorShape::Hollow,
                    _ => ScreenCursorShape::Block,
                },
            });

        for indexed in content.display_iter {
            let row = indexed.point.line.0 + offset;
            if row < 0 || row as usize >= lines {
                continue;
            }
            let cell = indexed.cell;
            if cell
                .flags
                .intersects(Flags::WIDE_CHAR_SPACER | Flags::LEADING_WIDE_CHAR_SPACER)
            {
                continue;
            }
            let col = indexed.point.column.0 as u32;
            let wide = cell.flags.contains(Flags::WIDE_CHAR);
            let mut fg = resolve(cell.fg, colors, true);
            let mut bg = (cell.bg != Color::Named(NamedColor::Background))
                .then(|| resolve(cell.bg, colors, false));
            if cell.flags.contains(Flags::INVERSE) {
                let back = bg.unwrap_or(BACKGROUND);
                bg = Some(fg);
                fg = back;
            }
            if cell.flags.contains(Flags::DIM) {
                fg = dim(fg);
            }
            if cell.flags.contains(Flags::HIDDEN) {
                fg = bg.unwrap_or(BACKGROUND);
            }
            let mut text = String::new();
            text.push(match cell.c {
                '\0' | '\t' => ' ',
                c => c,
            });
            if let Some(extra) = cell.zerowidth() {
                text.extend(extra.iter());
            }
            let run = ScreenRun {
                col,
                cells: if wide { 2 } else { 1 },
                text,
                fg,
                bg,
                bold: cell.flags.contains(Flags::BOLD),
                italic: cell.flags.contains(Flags::ITALIC),
                underline: cell.flags.intersects(Flags::ALL_UNDERLINES),
                strike: cell.flags.contains(Flags::STRIKEOUT),
                wide,
            };
            let runs = &mut out[row as usize].runs;
            match runs.last_mut() {
                Some(last)
                    if !wide
                        && !last.wide
                        && last.col + last.cells == col
                        && same_style(last, &run) =>
                {
                    last.text.push_str(&run.text);
                    last.cells += 1;
                }
                _ => runs.push(run),
            }
        }
        // Trailing spaces of a run with no background or decoration are
        // invisible: drop them (and any runs left empty).
        for line in &mut out {
            for r in &mut line.runs {
                if r.bg.is_none() && !r.underline && !r.strike && !r.wide {
                    let trimmed = r.text.trim_end_matches(' ').len();
                    r.cells -= (r.text.len() - trimmed) as u32;
                    r.text.truncate(trimmed);
                }
            }
            line.runs.retain(|r| r.cells > 0);
        }

        ScreenSnapshot {
            cols: inner.size.cols as u32,
            rows: lines as u32,
            lines: out,
            cursor,
            display_offset: content.display_offset as u32,
            background: BACKGROUND,
            foreground: FOREGROUND,
            cursor_color: CURSOR,
        }
    }
}

/// URL in `chars` containing column `col`, without the trailing punctuation
/// that usually follows it in text (as on desktop).
fn find_url(chars: &[char], col: usize) -> Option<String> {
    const SCHEMES: [&str; 4] = ["https://", "http://", "ftp://", "file://"];
    let lower: Vec<char> = chars
        .iter()
        .collect::<String>()
        .to_lowercase()
        .chars()
        .collect();
    let mut start = 0;
    while start < lower.len() {
        let rest: String = lower[start..].iter().collect();
        let Some(scheme) = SCHEMES.iter().find(|s| rest.starts_with(**s)) else {
            start += 1;
            continue;
        };
        let mut end = start + scheme.len();
        while end < chars.len() && !chars[end].is_whitespace() && !"<>\"'`".contains(chars[end]) {
            end += 1;
        }
        while end > start {
            let last = chars[end - 1];
            let open = chars[start..end].iter().filter(|c| **c == '(').count();
            let close = chars[start..end].iter().filter(|c| **c == ')').count();
            if ".,;:!?]}".contains(last) || (last == ')' && close > open) {
                end -= 1;
            } else {
                break;
            }
        }
        if end > start + scheme.len() && (start..end).contains(&col) {
            return Some(chars[start..end].iter().collect());
        }
        start = end.max(start + 1);
    }
    None
}

fn same_style(a: &ScreenRun, b: &ScreenRun) -> bool {
    a.fg == b.fg
        && a.bg == b.bg
        && a.bold == b.bold
        && a.italic == b.italic
        && a.underline == b.underline
        && a.strike == b.strike
}

// ----- Colors (the desktop's dark palette) -----

const FOREGROUND: u32 = 0xFFD6DBE4;
const BACKGROUND: u32 = 0xFF12151D;
const CURSOR: u32 = 0xFF6A90FF;
const ANSI: [u32; 16] = [
    0xFF1C2029, 0xFFF07178, 0xFF8BD49C, 0xFFFFCB6B, 0xFF5B9DFF, 0xFFC792EA, 0xFF5FD7D7, 0xFFC8CCD4,
    0xFF5C6370, 0xFFFF8A8A, 0xFFA8E6A3, 0xFFFFE08A, 0xFF82B1FF, 0xFFE0A8FF, 0xFF89DDFF, 0xFFFFFFFF,
];

fn rgb(r: u8, g: u8, b: u8) -> u32 {
    0xFF00_0000 | (r as u32) << 16 | (g as u32) << 8 | b as u32
}

/// Color `idx` of xterm's 256-color palette.
fn indexed(idx: u8) -> u32 {
    match idx {
        0..=15 => ANSI[idx as usize],
        16..=231 => {
            let i = idx - 16;
            let level = |v: u8| if v == 0 { 0 } else { 55 + v * 40 };
            rgb(level(i / 36), level((i / 6) % 6), level(i % 6))
        }
        _ => {
            let v = 8 + (idx - 232) * 10;
            rgb(v, v, v)
        }
    }
}

fn dim(argb: u32) -> u32 {
    let f = |shift: u32| (((argb >> shift) & 0xFF) * 2 / 3) << shift;
    0xFF00_0000 | f(16) | f(8) | f(0)
}

/// Emulator color in ARGB: those changed by the program (OSC 4/10/11) or,
/// otherwise, the palette's.
fn resolve(color: Color, colors: &Colors, is_fg: bool) -> u32 {
    match color {
        Color::Spec(c) => rgb(c.r, c.g, c.b),
        Color::Indexed(i) => colors[i as usize].map_or_else(|| indexed(i), |c| rgb(c.r, c.g, c.b)),
        Color::Named(named) => {
            let idx = named as usize;
            if let Some(c) = colors[idx] {
                return rgb(c.r, c.g, c.b);
            }
            match named {
                NamedColor::Foreground | NamedColor::BrightForeground => FOREGROUND,
                NamedColor::Background => BACKGROUND,
                NamedColor::Cursor => CURSOR,
                NamedColor::DimForeground => dim(FOREGROUND),
                NamedColor::DimBlack => dim(ANSI[0]),
                NamedColor::DimRed => dim(ANSI[1]),
                NamedColor::DimGreen => dim(ANSI[2]),
                NamedColor::DimYellow => dim(ANSI[3]),
                NamedColor::DimBlue => dim(ANSI[4]),
                NamedColor::DimMagenta => dim(ANSI[5]),
                NamedColor::DimCyan => dim(ANSI[6]),
                NamedColor::DimWhite => dim(ANSI[7]),
                _ if idx < 16 => ANSI[idx],
                _ if is_fg => FOREGROUND,
                _ => BACKGROUND,
            }
        }
    }
}

// ----- Keyboard (like the desktop app, TermoakSSH/desktop: src/terminal/input.rs) -----

fn key_bytes(key: TerminalKey, m: KeyModifiers, app_cursor: bool) -> Vec<u8> {
    // xterm modifier parameter: 1 + shift + 2·alt + 4·ctrl.
    let modifier = 1 + m.shift as u8 + 2 * m.alt as u8 + 4 * m.ctrl as u8;
    let csi_letter = |letter: char| {
        if modifier > 1 {
            format!("\x1b[1;{modifier}{letter}")
        } else if app_cursor {
            format!("\x1bO{letter}")
        } else {
            format!("\x1b[{letter}")
        }
        .into_bytes()
    };
    let csi_tilde = |code: u8| {
        if modifier > 1 {
            format!("\x1b[{code};{modifier}~")
        } else {
            format!("\x1b[{code}~")
        }
        .into_bytes()
    };
    let ss3 = |letter: char| {
        if modifier > 1 {
            format!("\x1b[1;{modifier}{letter}")
        } else {
            format!("\x1bO{letter}")
        }
        .into_bytes()
    };
    match key {
        TerminalKey::Up => csi_letter('A'),
        TerminalKey::Down => csi_letter('B'),
        TerminalKey::Right => csi_letter('C'),
        TerminalKey::Left => csi_letter('D'),
        TerminalKey::Home => csi_letter('H'),
        TerminalKey::End => csi_letter('F'),
        TerminalKey::Insert => csi_tilde(2),
        TerminalKey::Delete => csi_tilde(3),
        TerminalKey::PageUp => csi_tilde(5),
        TerminalKey::PageDown => csi_tilde(6),
        TerminalKey::Enter => {
            if m.alt {
                b"\x1b\r".to_vec()
            } else {
                b"\r".to_vec()
            }
        }
        TerminalKey::Tab => {
            if m.shift {
                b"\x1b[Z".to_vec()
            } else {
                b"\t".to_vec()
            }
        }
        TerminalKey::Escape => b"\x1b".to_vec(),
        TerminalKey::Backspace => {
            if m.ctrl {
                vec![0x08]
            } else if m.alt {
                b"\x1b\x7f".to_vec()
            } else {
                vec![0x7f]
            }
        }
        TerminalKey::Function { number } => match number {
            1 => ss3('P'),
            2 => ss3('Q'),
            3 => ss3('R'),
            4 => ss3('S'),
            5 => csi_tilde(15),
            6 => csi_tilde(17),
            7 => csi_tilde(18),
            8 => csi_tilde(19),
            9 => csi_tilde(20),
            10 => csi_tilde(21),
            11 => csi_tilde(23),
            12 => csi_tilde(24),
            _ => Vec::new(),
        },
    }
}

fn char_bytes(ch: &str, m: KeyModifiers) -> Vec<u8> {
    let mut chars = ch.chars();
    let (Some(c), None) = (chars.next(), chars.next()) else {
        // Several characters (e.g. from a predictive keyboard): text.
        return ch.as_bytes().to_vec();
    };
    if m.ctrl {
        let code = match c.to_ascii_lowercase() {
            c @ 'a'..='z' => Some(c as u8 - b'a' + 1),
            '@' | '2' | ' ' => Some(0x00),
            '[' | '3' => Some(0x1b),
            '\\' | '4' => Some(0x1c),
            ']' | '5' => Some(0x1d),
            '^' | '6' => Some(0x1e),
            '_' | '-' | '7' | '/' => Some(0x1f),
            '?' | '8' => Some(0x7f),
            _ => None,
        };
        if let Some(code) = code {
            return if m.alt { vec![0x1b, code] } else { vec![code] };
        }
    }
    let mut out = Vec::new();
    if m.alt {
        out.push(0x1b);
    }
    let mut buf = [0u8; 4];
    out.extend_from_slice(c.encode_utf8(&mut buf).as_bytes());
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    const NONE: KeyModifiers = KeyModifiers {
        shift: false,
        alt: false,
        ctrl: false,
    };

    #[test]
    fn feed_and_text() {
        let s = TerminalScreen::new(20, 5, 100);
        s.feed(b"hello\r\nworld".to_vec());
        assert_eq!(s.screen_text(), "hello\nworld");
        let snap = s.snapshot();
        assert_eq!((snap.cols, snap.rows), (20, 5));
        assert_eq!(snap.lines[0].runs[0].text, "hello");
        let cursor = snap.cursor.unwrap();
        assert_eq!((cursor.row, cursor.col), (1, 5));
    }

    #[test]
    fn colors_attributes_and_wide_chars() {
        let s = TerminalScreen::new(20, 3, 100);
        s.feed(
            "\x1b[1;31mred\x1b[0m \x1b[48;2;1;2;3mX\x1b[0m 日"
                .as_bytes()
                .to_vec(),
        );
        let runs = &s.snapshot().lines[0].runs;
        let red = runs.iter().find(|r| r.text == "red").unwrap();
        assert_eq!((red.col, red.fg, red.bold), (0, ANSI[1], true));
        let x = runs.iter().find(|r| r.text == "X").unwrap();
        assert_eq!(x.bg, Some(0xFF010203));
        let nichi = runs.iter().find(|r| r.text == "日").unwrap();
        assert_eq!((nichi.col, nichi.cells, nichi.wide), (6, 2, true));
    }

    #[test]
    fn answers_cursor_position_query() {
        let s = TerminalScreen::new(20, 5, 100);
        let events = s.feed(b"ab\x1b[6n".to_vec());
        assert_eq!(
            events,
            vec![ScreenEvent::Write {
                data: b"\x1b[1;3R".to_vec()
            }]
        );
    }

    #[test]
    fn title_and_resize() {
        let s = TerminalScreen::new(20, 5, 100);
        let events = s.feed(b"\x1b]0;web-1\x07".to_vec());
        assert_eq!(
            events,
            vec![ScreenEvent::Title {
                title: "web-1".into()
            }]
        );
        s.resize(40, 10);
        assert_eq!((s.cols(), s.rows()), (40, 10));
    }

    #[test]
    fn scrollback_and_reset() {
        let s = TerminalScreen::new(10, 2, 100);
        s.feed(b"1\r\n2\r\n3\r\n4".to_vec());
        assert_eq!(s.screen_text(), "3\n4");
        s.scroll(2);
        assert_eq!(s.snapshot().display_offset, 2);
        assert_eq!(s.screen_text(), "1\n2");
        assert!(s.snapshot().cursor.is_none(), "the cursor is out of view");
        s.scroll_to_bottom();
        s.reset();
        assert_eq!(s.screen_text(), "");
    }

    #[test]
    fn keys_follow_cursor_mode() {
        let s = TerminalScreen::new(20, 5, 100);
        assert_eq!(s.key(TerminalKey::Up, NONE), b"\x1b[A");
        s.feed(b"\x1b[?1h".to_vec()); // application cursor (vim, less...)
        assert_eq!(s.key(TerminalKey::Up, NONE), b"\x1bOA");
        let ctrl = KeyModifiers { ctrl: true, ..NONE };
        assert_eq!(s.key(TerminalKey::Right, ctrl), b"\x1b[1;5C");
        assert_eq!(
            s.key(TerminalKey::Function { number: 5 }, NONE),
            b"\x1b[15~"
        );
        assert_eq!(s.character("c".into(), ctrl), vec![0x03]);
        let alt = KeyModifiers { alt: true, ..NONE };
        assert_eq!(s.character("x".into(), alt), b"\x1bx");
        assert_eq!(s.character("ñ".into(), NONE), "ñ".as_bytes());
    }

    #[test]
    fn links_under_a_tap() {
        let s = TerminalScreen::new(60, 3, 100);
        s.feed(b"see https://termoak.com/download, thanks".to_vec());
        assert_eq!(
            s.link_at(0, 10).as_deref(),
            Some("https://termoak.com/download")
        );
        assert_eq!(s.link_at(0, 1), None);
        s.feed(b"\r\n\x1b]8;;https://ohz.es\x1b\\click\x1b]8;;\x1b\\".to_vec());
        assert_eq!(s.link_at(1, 3).as_deref(), Some("https://ohz.es"));
    }

    #[test]
    fn paste_modes() {
        let s = TerminalScreen::new(20, 5, 100);
        assert_eq!(s.paste("a\nb".into()), b"a\rb");
        s.feed(b"\x1b[?2004h".to_vec());
        assert_eq!(s.paste("ls\n".into()), b"\x1b[200~ls\r\x1b[201~");
        assert!(!s.alternate_screen());
        s.feed(b"\x1b[?1049h".to_vec());
        assert!(s.alternate_screen());
    }
}
