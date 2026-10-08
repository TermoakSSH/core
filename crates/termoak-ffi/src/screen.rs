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
//!
//! Also: colour themes ([`terminal_themes`], [`TerminalScreen::set_theme`],
//! [`TerminalScreen::set_colors`]), find in the screen and the scrollback
//! ([`TerminalScreen::find`], highlights in the snapshot), text of any part
//! of the scrollback for selections ([`TerminalScreen::text_range`],
//! [`TerminalScreen::word_at`], [`TerminalScreen::line_at`]) and the
//! program's modes ([`TerminalScreen::modes`]).
//!
//! Coordinates: a viewport `row` is what the snapshot paints (0 at the top
//! of the view). A [`ScreenPoint`] is a cell of the whole grid: `line` 0 is
//! the top of the screen when scrolled to the bottom, the scrollback is
//! above it (negative lines, down to `-history_size`); `line = row -
//! display_offset`. New output scrolling into the history moves the lines
//! up: points taken before it refer to other text afterwards.

use std::sync::Arc;

use alacritty_terminal::event::{Event, EventListener, WindowSize};
use alacritty_terminal::grid::{Dimensions, Scroll};
use alacritty_terminal::index::{Column, Direction, Line, Point, Side};
use alacritty_terminal::selection::{Selection, SelectionType};
use alacritty_terminal::term::cell::Flags;
use alacritty_terminal::term::color::Colors;
use alacritty_terminal::term::search::{RegexIter, RegexSearch};
use alacritty_terminal::term::{Config, Term, TermMode};
use alacritty_terminal::vte::ansi::{Color, CursorShape, NamedColor, Processor};
use parking_lot::Mutex;
use termoak_client::find::{self as cf, FindOptions};
use termoak_core::themes;

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
    /// The program asked for a blinking cursor (DECSCUSR 1/3/5, `CSI ?12h`).
    #[uniffi(default)]
    pub blinking: bool,
}

/// Cells to paint over a find match on screen (one per row it covers).
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Record)]
pub struct ScreenHighlight {
    pub row: u32,
    pub col: u32,
    pub cells: u32,
    /// The current match (paint it differently).
    pub current: bool,
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
    /// Find matches on screen (empty without a search: see
    /// [`TerminalScreen::find`]).
    #[uniffi(default)]
    pub highlights: Vec<ScreenHighlight>,
}

/// A cell of the grid (screen and scrollback): see the module docs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Record)]
pub struct ScreenPoint {
    /// 0: the top of the screen at the bottom of the scrollback; negative:
    /// the scrollback.
    pub line: i32,
    pub col: u32,
}

/// A range of cells (inclusive) and its text.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct ScreenRange {
    pub start: ScreenPoint,
    pub end: ScreenPoint,
    pub text: String,
}

/// Mouse events the program asked for.
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum MouseMode {
    /// No reporting: the app scrolls and selects.
    Off,
    /// Presses and releases (1000).
    Click,
    /// Also motion with a button down (1002).
    Drag,
    /// Every motion (1003).
    Motion,
}

/// How mouse events are encoded.
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum MouseEncoding {
    /// `CSI M` with bytes (X10, coordinates up to 223).
    Default,
    /// `CSI M` with UTF-8 coordinates (1005).
    Utf8,
    /// `CSI < b;x;y M/m` (1006).
    Sgr,
}

/// What the remote program has turned on.
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Record)]
pub struct TerminalModes {
    pub mouse_mode: MouseMode,
    pub mouse_encoding: MouseEncoding,
    /// Pasted text goes between `ESC [200~` and `ESC [201~` (see
    /// [`TerminalScreen::paste`]).
    pub bracketed_paste: bool,
    /// Arrow keys send `ESC O A` (see [`TerminalScreen::key`]).
    pub app_cursor: bool,
    /// The keypad sends application sequences (DECKPAM).
    pub app_keypad: bool,
    /// Alternate screen (vim, less, htop...).
    pub alternate_screen: bool,
    /// In the alternate screen, the wheel (and swipes) should send arrows.
    pub alternate_scroll: bool,
    /// The program wants focus in/out reports (`ESC [I`, `ESC [O`).
    pub focus_reporting: bool,
    pub cursor_visible: bool,
    pub cursor_blinking: bool,
}

/// Colours of a terminal, in ARGB (`0xAARRGGBB`).
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct TerminalColors {
    pub background: u32,
    pub foreground: u32,
    pub cursor: u32,
    /// Selection (and find matches) over the background; the apps may use
    /// it with some transparency.
    pub selection: u32,
    /// The 16 ANSI colours: normal (0–7) and bright (8–15). Missing ones
    /// keep the current palette's.
    pub ansi: Vec<u32>,
}

/// A colour theme of the shared list (the same ids on desktop, iOS and
/// Android: stored in settings and in `HostSettings::theme`).
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct TerminalThemeInfo {
    pub id: String,
    pub name: String,
    pub is_light: bool,
    pub colors: TerminalColors,
}

/// Every terminal colour theme, in the order the pickers show them (the
/// first one is the default).
#[uniffi::export]
pub fn terminal_themes() -> Vec<TerminalThemeInfo> {
    themes::THEMES.iter().map(theme_info).collect()
}

/// Theme id for a host's terminal: `value` is its effective
/// `HostSettings::theme` and `app_theme` the app's theme id. `dark` and
/// `light` (what the desktop's host editor saves) keep the app's theme when
/// it is of that kind and otherwise use Termoak's; a theme id uses it;
/// anything else (or nothing) follows the app.
#[uniffi::export]
pub fn terminal_theme_for_host(value: Option<String>, app_theme: String) -> String {
    themes::for_host(value.as_deref(), &app_theme).id.to_string()
}

fn theme_info(t: &themes::TerminalTheme) -> TerminalThemeInfo {
    TerminalThemeInfo {
        id: t.id.to_string(),
        name: t.name.to_string(),
        is_light: t.is_light(),
        colors: Palette::from_theme(t).colors(),
    }
}

/// How a search went.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct FindStatus {
    /// Matches in the screen and the scrollback (at most 5,000).
    pub count: u32,
    /// There were more than 5,000 ("5000+").
    pub capped: bool,
    /// Index of the current match, counted from the top of the scrollback.
    pub current: Option<u32>,
    /// Number to show for the current one: "1 of 12" is the newest (at the
    /// bottom), since a terminal is searched upwards.
    pub ordinal: Option<u32>,
    /// The current match (the view scrolls to show it).
    pub current_match: Option<ScreenRange>,
    /// The regular expression is not valid (nothing is found).
    pub invalid: bool,
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

/// The active search.
struct Find {
    regex: RegexSearch,
    matches: Vec<cf::Match>,
    capped: bool,
}

struct Inner {
    term: Term<Proxy>,
    processor: Processor,
    events: Proxy,
    size: Size,
    scrollback: usize,
    palette: Palette,
    /// `None`: no search, or an invalid pattern (`find_invalid`).
    find: Option<Find>,
    find_invalid: bool,
}

impl Inner {
    fn new(size: Size, scrollback: usize, palette: Palette) -> Self {
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
            palette,
            find: None,
            find_invalid: false,
        }
    }

    /// A grid point from the FFI, clamped to the grid.
    fn point(&self, p: ScreenPoint) -> Point {
        let top = -(self.term.grid().history_size() as i32);
        let bottom = self.size.lines as i32 - 1;
        Point::new(
            Line(p.line.clamp(top, bottom)),
            Column((p.col as usize).min(self.size.cols.saturating_sub(1))),
        )
    }

    /// Text between two points (inclusive), as a selection copies it:
    /// wrapped lines joined, trailing blanks dropped; `block` takes the same
    /// columns of every line.
    fn text_between(&mut self, start: Point, end: Point, block: bool) -> String {
        let (start, end) = if start <= end { (start, end) } else { (end, start) };
        let ty = if block {
            SelectionType::Block
        } else {
            SelectionType::Simple
        };
        let mut sel = Selection::new(ty, start, Side::Left);
        sel.update(end, Side::Right);
        let saved = self.term.selection.replace(sel);
        let text = self.term.selection_to_string().unwrap_or_default();
        self.term.selection = saved;
        text
    }

    fn range(&mut self, start: Point, end: Point) -> ScreenRange {
        ScreenRange {
            start: screen_point(start),
            end: screen_point(end),
            text: self.text_between(start, end, false),
        }
    }

    /// The current match: the selection the search left (it moves with the
    /// text as output scrolls it up).
    fn current_match(&self) -> Option<cf::Match> {
        let r = self.term.selection.as_ref()?.to_range(&self.term)?;
        Some(find_point(r.start)..=find_point(r.end))
    }

    /// Lists the matches again and finds the current one in the list.
    fn recount(&mut self) -> Option<usize> {
        let current = self.current_match();
        let Some(find) = self.find.as_mut() else {
            return None;
        };
        let start = Point::new(self.term.topmost_line(), Column(0));
        let end = Point::new(
            self.term.bottommost_line(),
            Column(self.size.cols.saturating_sub(1)),
        );
        let mut all: Vec<cf::Match> =
            RegexIter::new(start, end, Direction::Right, &self.term, &mut find.regex)
                .take(cf::MAX_MATCHES + 1)
                .map(|m| find_point(*m.start())..=find_point(*m.end()))
                .collect();
        find.capped = all.len() > cf::MAX_MATCHES;
        all.truncate(cf::MAX_MATCHES);
        find.matches = all;
        current.and_then(|c| cf::position(&find.matches, &c))
    }

    /// Selects match `index` and scrolls it into view.
    fn select(&mut self, index: Option<usize>) {
        let found = index.and_then(|i| self.find.as_ref()?.matches.get(i).cloned());
        match found {
            Some(m) => {
                let (start, end) = (alac_point(*m.start()), alac_point(*m.end()));
                let mut sel = Selection::new(SelectionType::Simple, start, Side::Left);
                sel.update(end, Side::Right);
                self.term.selection = Some(sel);
                self.term.scroll_to_point(start);
            }
            None => self.term.selection = None,
        }
    }

    /// The bottom of what is on screen (where a search starts).
    fn view_bottom(&self) -> cf::Point {
        let offset = self.term.grid().display_offset() as i32;
        cf::Point::new(
            self.size.lines as i32 - 1 - offset,
            self.size.cols.saturating_sub(1),
        )
    }

    fn status(&mut self, current: Option<usize>) -> FindStatus {
        let Some(find) = self.find.as_ref() else {
            return FindStatus {
                count: 0,
                capped: false,
                current: None,
                ordinal: None,
                current_match: None,
                invalid: self.find_invalid,
            };
        };
        let (len, capped) = (find.matches.len(), find.capped);
        let current_match = current
            .and_then(|i| find.matches.get(i).cloned())
            .map(|m| (alac_point(*m.start()), alac_point(*m.end())));
        FindStatus {
            count: len as u32,
            capped,
            current: current.map(|i| i as u32),
            ordinal: current.map(|i| cf::ordinal(len, i) as u32),
            current_match: current_match.map(|(a, b)| self.range(a, b)),
            invalid: false,
        }
    }

    /// Find highlights of what is on screen (matches that start or end on
    /// wrapped lines just outside it included).
    fn highlights(&mut self) -> Vec<ScreenHighlight> {
        let current = self.current_match();
        let offset = self.term.grid().display_offset();
        let (lines, cols) = (self.size.lines, self.size.cols);
        let start = self
            .term
            .line_search_left(Point::new(Line(-(offset as i32)), Column(0)));
        let end = self.term.line_search_right(Point::new(
            Line(lines as i32 - 1 - offset as i32),
            Column(cols.saturating_sub(1)),
        ));
        let Some(find) = self.find.as_mut() else {
            return Vec::new();
        };
        let mut out = Vec::new();
        for m in RegexIter::new(start, end, Direction::Right, &self.term, &mut find.regex)
            .take(cf::MAX_MATCHES)
        {
            let m = find_point(*m.start())..=find_point(*m.end());
            let is_current = current.as_ref() == Some(&m);
            out.extend(
                cf::highlights(&m, offset, lines, cols, is_current)
                    .into_iter()
                    .map(|h| ScreenHighlight {
                        row: h.row as u32,
                        col: h.col as u32,
                        cells: h.cells as u32,
                        current: h.current,
                    }),
            );
        }
        out
    }
}

fn find_point(p: Point) -> cf::Point {
    cf::Point::new(p.line.0, p.column.0)
}

fn alac_point(p: cf::Point) -> Point {
    Point::new(Line(p.line), Column(p.column))
}

fn screen_point(p: Point) -> ScreenPoint {
    ScreenPoint {
        line: p.line.0,
        col: p.column.0 as u32,
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
            inner: Mutex::new(Inner::new(
                Size::new(cols, rows),
                scrollback as usize,
                Palette::default(),
            )),
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
        let palette = inner.palette;
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
                        256 => resolve(
                            Color::Named(NamedColor::Foreground),
                            &colors,
                            &palette,
                            true,
                        ),
                        257 => resolve(
                            Color::Named(NamedColor::Background),
                            &colors,
                            &palette,
                            false,
                        ),
                        258 => palette.cursor,
                        i if i < 256 => {
                            resolve(Color::Indexed(i as u8), &colors, &palette, true)
                        }
                        _ => palette.foreground,
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
        let (size, scrollback, palette) = (inner.size, inner.scrollback, inner.palette);
        *inner = Inner::new(size, scrollback, palette);
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
        let mut inner = self.inner.lock();
        let highlights = if inner.find.is_some() {
            inner.highlights()
        } else {
            Vec::new()
        };
        let palette = inner.palette;
        let blinking = inner.term.cursor_style().blinking;
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
                blinking,
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
            let mut fg = resolve(cell.fg, colors, &palette, true);
            let mut bg = (cell.bg != Color::Named(NamedColor::Background))
                .then(|| resolve(cell.bg, colors, &palette, false));
            if cell.flags.contains(Flags::INVERSE) {
                let back = bg.unwrap_or(palette.background);
                bg = Some(fg);
                fg = back;
            }
            if cell.flags.contains(Flags::DIM) {
                fg = dim(fg);
            }
            if cell.flags.contains(Flags::HIDDEN) {
                fg = bg.unwrap_or(palette.background);
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
            background: palette.background,
            foreground: palette.foreground,
            cursor_color: palette.cursor,
            highlights,
        }
    }

    // ----- Colours -----

    /// Uses a theme of [`terminal_themes`] (by id). `false` (and nothing
    /// changes) for an unknown id. Colours the program set (OSC 4/10/11)
    /// still win until it resets them.
    pub fn set_theme(&self, id: String) -> bool {
        match themes::by_id(&id) {
            Some(t) => {
                self.inner.lock().palette = Palette::from_theme(t);
                true
            }
            None => false,
        }
    }

    /// Uses these colours (ARGB). Missing ANSI colours keep the current
    /// ones; `selection` is only kept to be read back.
    pub fn set_colors(&self, colors: TerminalColors) {
        let mut inner = self.inner.lock();
        let mut p = inner.palette;
        p.background = opaque(colors.background);
        p.foreground = opaque(colors.foreground);
        p.cursor = opaque(colors.cursor);
        p.selection = colors.selection;
        for (slot, c) in p.ansi.iter_mut().zip(colors.ansi) {
            *slot = opaque(c);
        }
        inner.palette = p;
    }

    /// The colours in use.
    pub fn colors(&self) -> TerminalColors {
        self.inner.lock().palette.colors()
    }

    // ----- Modes -----

    /// What the remote program has turned on: mouse reporting and its
    /// encoding, bracketed paste, application cursor and keypad...
    pub fn modes(&self) -> TerminalModes {
        let inner = self.inner.lock();
        let mode = *inner.term.mode();
        let mouse_mode = if mode.contains(TermMode::MOUSE_MOTION) {
            MouseMode::Motion
        } else if mode.contains(TermMode::MOUSE_DRAG) {
            MouseMode::Drag
        } else if mode.contains(TermMode::MOUSE_REPORT_CLICK) {
            MouseMode::Click
        } else {
            MouseMode::Off
        };
        let mouse_encoding = if mode.contains(TermMode::SGR_MOUSE) {
            MouseEncoding::Sgr
        } else if mode.contains(TermMode::UTF8_MOUSE) {
            MouseEncoding::Utf8
        } else {
            MouseEncoding::Default
        };
        TerminalModes {
            mouse_mode,
            mouse_encoding,
            bracketed_paste: mode.contains(TermMode::BRACKETED_PASTE),
            app_cursor: mode.contains(TermMode::APP_CURSOR),
            app_keypad: mode.contains(TermMode::APP_KEYPAD),
            alternate_screen: mode.contains(TermMode::ALT_SCREEN),
            alternate_scroll: mode.contains(TermMode::ALTERNATE_SCROLL),
            focus_reporting: mode.contains(TermMode::FOCUS_IN_OUT),
            cursor_visible: mode.contains(TermMode::SHOW_CURSOR),
            cursor_blinking: inner.term.cursor_style().blinking,
        }
    }

    // ----- Text of the grid (selection beyond the screen) -----

    /// Lines of scrollback above the screen (`ScreenPoint::line` goes down
    /// to minus this).
    pub fn history_size(&self) -> u32 {
        self.inner.lock().term.grid().history_size() as u32
    }

    /// The grid point under viewport `row`, `col` (with the current scroll).
    pub fn point_at(&self, row: u32, col: u32) -> ScreenPoint {
        let inner = self.inner.lock();
        let offset = inner.term.grid().display_offset() as i32;
        let row = (row as usize).min(inner.size.lines.saturating_sub(1)) as i32;
        let col = (col as usize).min(inner.size.cols.saturating_sub(1)) as u32;
        ScreenPoint {
            line: row - offset,
            col,
        }
    }

    /// Text from `start` to `end` (inclusive, in either order), anywhere in
    /// the screen or the scrollback: wrapped lines are joined, trailing
    /// blanks dropped. `block`: the same columns of every line (a
    /// rectangle).
    #[uniffi::method(default(block = false))]
    pub fn text_range(&self, start: ScreenPoint, end: ScreenPoint, block: bool) -> String {
        let mut inner = self.inner.lock();
        let (a, b) = (inner.point(start), inner.point(end));
        inner.text_between(a, b, block)
    }

    /// The word at a point (double tap): letters, digits and the
    /// characters around them that are not separators (spaces, quotes,
    /// brackets, `|`, `:`...); across wrapped lines. `None` on a blank.
    pub fn word_at(&self, point: ScreenPoint) -> Option<ScreenRange> {
        let mut inner = self.inner.lock();
        let p = inner.point(point);
        let c = inner.term.grid()[p].c;
        if c == ' ' || c == '\0' || c == '\t' || inner.term.semantic_escape_chars().contains(c) {
            return None;
        }
        let start = inner.term.semantic_search_left(p);
        let end = inner.term.semantic_search_right(p);
        Some(inner.range(start, end))
    }

    /// The whole line at a point (triple tap), across wrapped lines.
    pub fn line_at(&self, point: ScreenPoint) -> ScreenRange {
        let mut inner = self.inner.lock();
        let p = inner.point(point);
        let start = inner.term.line_search_left(p);
        let end = inner.term.line_search_right(p);
        inner.range(start, end)
    }

    /// Scrolls the view so `line` is on screen (e.g. a selection handle
    /// dragged past the top).
    pub fn scroll_to_line(&self, line: i32) {
        let mut inner = self.inner.lock();
        let p = inner.point(ScreenPoint { line, col: 0 });
        inner.term.scroll_to_point(p);
    }

    // ----- Find -----

    /// Searches the screen and the scrollback for `query` (literal text, or
    /// a regular expression with `regex`; `case_sensitive` or not) and goes
    /// to the newest match at or above the bottom of the view (scrolling to
    /// it). The snapshot then highlights the matches on screen. An empty
    /// query clears the search.
    #[uniffi::method(default(case_sensitive = false, regex = false))]
    pub fn find(&self, query: String, case_sensitive: bool, regex: bool) -> FindStatus {
        let mut inner = self.inner.lock();
        let options = FindOptions {
            case_sensitive,
            regex,
        };
        inner.term.selection = None;
        let pattern = cf::pattern(&query, options);
        let regex = pattern.as_deref().and_then(|p| RegexSearch::new(p).ok());
        inner.find_invalid = pattern.is_some() && regex.is_none();
        inner.find = regex.map(|regex| Find {
            regex,
            matches: Vec::new(),
            capped: false,
        });
        inner.recount();
        let anchor = inner.view_bottom();
        let current = inner
            .find
            .as_ref()
            .and_then(|f| cf::nearest(&f.matches, anchor));
        inner.select(current);
        inner.status(current)
    }

    /// Goes to the next match: `older` upwards (Enter), otherwise downwards
    /// (Shift+Enter); both wrap around. Lists the matches again first (new
    /// output may have added some).
    pub fn find_step(&self, older: bool) -> FindStatus {
        let mut inner = self.inner.lock();
        let current = inner.recount();
        let len = inner.find.as_ref().map_or(0, |f| f.matches.len());
        let next = match current {
            Some(i) => cf::step(len, Some(i), older),
            None => {
                let anchor = inner.view_bottom();
                inner
                    .find
                    .as_ref()
                    .and_then(|f| cf::nearest(&f.matches, anchor))
            }
        };
        inner.select(next);
        inner.status(next)
    }

    /// The search as it is now (counted again: call it after new output to
    /// refresh "3 of 12", at most a few times a second).
    pub fn find_status(&self) -> FindStatus {
        let mut inner = self.inner.lock();
        let current = inner.recount();
        inner.status(current)
    }

    /// Ends the search (no more highlights).
    pub fn clear_find(&self) {
        let mut inner = self.inner.lock();
        inner.find = None;
        inner.find_invalid = false;
        inner.term.selection = None;
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

// ----- Colors -----

/// Default palette (the desktop's dark one), until a theme or colours are
/// set.
const FOREGROUND: u32 = 0xFFD6DBE4;
const BACKGROUND: u32 = 0xFF12151D;
const CURSOR: u32 = 0xFF6A90FF;
const SELECTION: u32 = 0x614F7CFF;
const ANSI: [u32; 16] = [
    0xFF1C2029, 0xFFF07178, 0xFF8BD49C, 0xFFFFCB6B, 0xFF5B9DFF, 0xFFC792EA, 0xFF5FD7D7, 0xFFC8CCD4,
    0xFF5C6370, 0xFFFF8A8A, 0xFFA8E6A3, 0xFFFFE08A, 0xFF82B1FF, 0xFFE0A8FF, 0xFF89DDFF, 0xFFFFFFFF,
];

/// Colours of a screen, in ARGB.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Palette {
    foreground: u32,
    background: u32,
    cursor: u32,
    selection: u32,
    ansi: [u32; 16],
}

impl Default for Palette {
    fn default() -> Self {
        Self {
            foreground: FOREGROUND,
            background: BACKGROUND,
            cursor: CURSOR,
            selection: SELECTION,
            ansi: ANSI,
        }
    }
}

impl Palette {
    fn from_theme(t: &themes::TerminalTheme) -> Self {
        Self {
            foreground: opaque(t.foreground),
            background: opaque(t.background),
            cursor: opaque(t.cursor),
            selection: opaque(t.selection()),
            ansi: t.ansi.map(opaque),
        }
    }

    fn colors(&self) -> TerminalColors {
        TerminalColors {
            background: self.background,
            foreground: self.foreground,
            cursor: self.cursor,
            selection: self.selection,
            ansi: self.ansi.to_vec(),
        }
    }
}

/// `0xRRGGBB` (or ARGB) as an opaque ARGB colour.
fn opaque(c: u32) -> u32 {
    0xFF00_0000 | (c & 0x00FF_FFFF)
}

fn rgb(r: u8, g: u8, b: u8) -> u32 {
    0xFF00_0000 | (r as u32) << 16 | (g as u32) << 8 | b as u32
}

/// Color `idx` of xterm's 256-color palette.
fn indexed(idx: u8, palette: &Palette) -> u32 {
    match idx {
        0..=15 => palette.ansi[idx as usize],
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
fn resolve(color: Color, colors: &Colors, palette: &Palette, is_fg: bool) -> u32 {
    let ansi = &palette.ansi;
    match color {
        Color::Spec(c) => rgb(c.r, c.g, c.b),
        Color::Indexed(i) => colors[i as usize]
            .map_or_else(|| indexed(i, palette), |c| rgb(c.r, c.g, c.b)),
        Color::Named(named) => {
            let idx = named as usize;
            if let Some(c) = colors[idx] {
                return rgb(c.r, c.g, c.b);
            }
            match named {
                NamedColor::Foreground | NamedColor::BrightForeground => palette.foreground,
                NamedColor::Background => palette.background,
                NamedColor::Cursor => palette.cursor,
                NamedColor::DimForeground => dim(palette.foreground),
                NamedColor::DimBlack => dim(ansi[0]),
                NamedColor::DimRed => dim(ansi[1]),
                NamedColor::DimGreen => dim(ansi[2]),
                NamedColor::DimYellow => dim(ansi[3]),
                NamedColor::DimBlue => dim(ansi[4]),
                NamedColor::DimMagenta => dim(ansi[5]),
                NamedColor::DimCyan => dim(ansi[6]),
                NamedColor::DimWhite => dim(ansi[7]),
                _ if idx < 16 => ansi[idx],
                _ if is_fg => palette.foreground,
                _ => palette.background,
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

    #[test]
    fn themes_and_colors() {
        let s = TerminalScreen::new(20, 3, 100);
        s.feed(b"\x1b[31mred\x1b[0m plain".to_vec());
        assert_eq!(s.snapshot().background, BACKGROUND);
        assert!(s.set_theme("dracula".into()));
        assert!(!s.set_theme("nope".into()));
        let snap = s.snapshot();
        assert_eq!(snap.background, 0xFF282A36);
        assert_eq!(snap.foreground, 0xFFF8F8F2);
        let red = snap.lines[0].runs.iter().find(|r| r.text == "red").unwrap();
        assert_eq!(red.fg, 0xFFFF5555);
        // The program asks for the background (OSC 11): the theme's.
        let events = s.feed(b"\x1b]11;?\x07".to_vec());
        let ScreenEvent::Write { data } = &events[0] else {
            panic!("{events:?}")
        };
        assert!(String::from_utf8_lossy(data).contains("rgb:2828/2a2a/3636"));

        let mut c = s.colors();
        c.background = 0x000000;
        c.ansi = vec![0x111111, 0x222222];
        s.set_colors(c);
        let c = s.colors();
        assert_eq!(c.background, 0xFF000000);
        assert_eq!(c.ansi[1], 0xFF222222);
        assert_eq!(c.ansi[2], 0xFF50FA7B, "the rest are kept");
        // A reset keeps the colours.
        s.reset();
        assert_eq!(s.snapshot().background, 0xFF000000);

        let all = terminal_themes();
        assert_eq!(all.len(), 15);
        assert_eq!(all[0].id, "termoak");
        assert!(all.iter().any(|t| t.id == "claro" && t.is_light));
        assert_eq!(all[2].colors.ansi.len(), 16);
        assert_eq!(terminal_theme_for_host(Some("light".into()), "nord".into()), "claro");
        assert_eq!(terminal_theme_for_host(None, "nord".into()), "nord");
    }

    #[test]
    fn find_in_the_scrollback() {
        let s = TerminalScreen::new(20, 3, 100);
        for i in 0..10 {
            s.feed(format!("line {i} error\r\n").into_bytes());
        }
        s.feed(b"$ ".to_vec());
        // Newest first: "1 of 10" is the last one, on screen.
        let st = s.find("ERROR".into(), false, false);
        assert_eq!((st.count, st.capped, st.invalid), (10, false, false));
        assert_eq!(st.current, Some(9));
        assert_eq!(st.ordinal, Some(1));
        let m = st.current_match.unwrap();
        assert_eq!(m.text, "error");
        assert_eq!((m.start.col, m.end.col), (7, 11));
        let snap = s.snapshot();
        assert_eq!(snap.display_offset, 0);
        let current: Vec<_> = snap.highlights.iter().filter(|h| h.current).collect();
        assert_eq!(current.len(), 1);
        assert_eq!((current[0].row, current[0].col, current[0].cells), (1, 7, 5));
        assert_eq!(snap.highlights.len(), 2);

        // Older ones scroll the view up.
        let st = s.find_step(true);
        assert_eq!((st.current, st.ordinal), (Some(8), Some(2)));
        for _ in 0..7 {
            s.find_step(true);
        }
        let st = s.find_step(true);
        assert_eq!(st.current, Some(0));
        assert!(s.snapshot().display_offset > 0);
        assert!(s.screen_text().contains("line 0 error"));
        // And wrap around.
        assert_eq!(s.find_step(true).current, Some(9));
        assert_eq!(s.find_step(false).current, Some(0));

        // Case-sensitive, regex, invalid, cleared.
        assert_eq!(s.find("ERROR".into(), true, false).count, 0);
        assert_eq!(s.find("line [2-4]".into(), false, true).count, 3);
        assert_eq!(s.find("line [2-4]".into(), false, false).count, 0);
        let bad = s.find("(".into(), false, true);
        assert!(bad.invalid && bad.count == 0);
        s.find("line".into(), false, false);
        s.clear_find();
        assert!(s.snapshot().highlights.is_empty());
        assert_eq!(s.find_status().count, 0);
        // New output is counted again.
        s.find("error".into(), false, false);
        s.feed(b"another error\r\n".to_vec());
        assert_eq!(s.find_status().count, 11);
    }

    #[test]
    fn text_beyond_the_screen() {
        let s = TerminalScreen::new(10, 2, 100);
        s.feed(b"first line\r\nhello wonderful world\r\nlast".to_vec());
        assert!(s.history_size() >= 2);
        // `hello wonderful world` wraps over three rows (10 columns).
        let top = -(s.history_size() as i32);
        let p = |line: i32, col: u32| ScreenPoint { line, col };
        assert_eq!(s.text_range(p(top, 0), p(top, 4), false), "first");
        let all = s.text_range(p(top, 0), p(1, 9), false);
        assert_eq!(all, "first line\nhello wonderful world\nlast");
        // In either order.
        assert_eq!(s.text_range(p(top, 4), p(top, 0), false), "first");
        let word = s.word_at(p(top + 1, 8)).unwrap();
        assert_eq!(word.text, "wonderful");
        assert_eq!((word.start.line, word.start.col), (top + 1, 6));
        assert_eq!((word.end.line, word.end.col), (top + 2, 4));
        assert!(s.word_at(p(top + 1, 5)).is_none(), "a blank");
        let line = s.line_at(p(top + 2, 0));
        assert_eq!(line.text, "hello wonderful world");
        assert_eq!(line.start.line, top + 1);
        // Out of range points are clamped.
        assert_eq!(s.text_range(p(-500, 0), p(top, 4), false), "first");
        // A rectangle.
        assert_eq!(s.text_range(p(top, 0), p(top + 1, 1), true), "fi\nhe");
        // Viewport rows and scrolling to a line.
        assert_eq!(s.point_at(1, 2), p(1, 2));
        s.scroll_to_line(top);
        assert_eq!(s.snapshot().display_offset, s.history_size());
        assert_eq!(s.point_at(0, 0), p(top, 0));
    }

    #[test]
    fn modes_and_blinking() {
        let s = TerminalScreen::new(20, 5, 100);
        let m = s.modes();
        assert_eq!(m.mouse_mode, MouseMode::Off);
        assert_eq!(m.mouse_encoding, MouseEncoding::Default);
        assert!(!m.bracketed_paste && !m.app_cursor && !m.app_keypad);
        assert!(m.cursor_visible && !m.cursor_blinking);
        s.feed(b"\x1b[?1002h\x1b[?1006h\x1b[?2004h\x1b[?1h\x1b=\x1b[?1004h".to_vec());
        let m = s.modes();
        assert_eq!(m.mouse_mode, MouseMode::Drag);
        assert_eq!(m.mouse_encoding, MouseEncoding::Sgr);
        assert!(m.bracketed_paste && m.app_cursor && m.app_keypad && m.focus_reporting);
        s.feed(b"\x1b[?1003h\x1b[?1006l\x1b[?1005h".to_vec());
        let m = s.modes();
        assert_eq!(m.mouse_mode, MouseMode::Motion);
        assert_eq!(m.mouse_encoding, MouseEncoding::Utf8);
        // DECSCUSR 5: blinking bar.
        s.feed(b"\x1b[5 q".to_vec());
        assert!(s.modes().cursor_blinking);
        let cursor = s.snapshot().cursor.unwrap();
        assert!(cursor.blinking);
        assert_eq!(cursor.shape, ScreenCursorShape::Beam);
        s.feed(b"\x1b[2 q\x1b[?25l".to_vec());
        let m = s.modes();
        assert!(!m.cursor_blinking && !m.cursor_visible);
    }
}
