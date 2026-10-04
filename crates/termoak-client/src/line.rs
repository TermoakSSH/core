//! Tracks the line being typed in a terminal, for the command history and
//! autocompletion (desktop and mobile apps).
//!
//! What is really on the shell's line is unknown (there is no shell
//! integration), so it is inferred from what has been typed since the last
//! Enter: text, deletions, cursor moves... Anything the shell may change on
//! its own (history with the arrows, Tab completion, Alt or Escape shortcuts)
//! leaves the line **unknown** until the next Enter, Ctrl+C or Ctrl+U.
//! Callers should also trust the line only if what is on screen before the
//! cursor matches it ([`screen_matches`]): that way nothing is suggested or
//! saved at prompts without echo, such as passwords.

/// The line being typed.
#[derive(Debug, Clone)]
pub struct LineTracker {
    chars: Vec<char>,
    /// Cursor position (in characters).
    cursor: usize,
    /// `false` if the shell may have changed the line without us knowing.
    known: bool,
}

impl Default for LineTracker {
    fn default() -> Self {
        Self {
            chars: Vec::new(),
            cursor: 0,
            known: true,
        }
    }
}

/// Bracketed paste delimiters.
const PASTE_START: &[u8] = b"\x1b[200~";
const PASTE_END: &[u8] = b"\x1b[201~";

impl LineTracker {
    /// The line's text, if known.
    pub fn current(&self) -> Option<String> {
        self.known.then(|| self.chars.iter().collect())
    }

    /// Is the line known and the cursor at the end?
    pub fn at_end(&self) -> bool {
        self.known && self.cursor == self.chars.len()
    }

    /// New, empty line (after Enter, Ctrl+C...).
    pub fn reset(&mut self) {
        self.chars.clear();
        self.cursor = 0;
        self.known = true;
    }

    /// The line becomes unknown until the next reset.
    pub fn forget(&mut self) {
        self.chars.clear();
        self.cursor = 0;
        self.known = false;
    }

    fn insert(&mut self, text: &str) {
        if !self.known {
            return;
        }
        for c in text.chars() {
            self.chars.insert(self.cursor, c);
            self.cursor += 1;
        }
    }

    fn backspace(&mut self) {
        if self.known && self.cursor > 0 {
            self.cursor -= 1;
            self.chars.remove(self.cursor);
        }
    }

    fn delete(&mut self) {
        if self.known && self.cursor < self.chars.len() {
            self.chars.remove(self.cursor);
        }
    }

    fn left(&mut self) {
        self.cursor = self.cursor.saturating_sub(1);
    }

    fn right(&mut self) {
        self.cursor = (self.cursor + 1).min(self.chars.len());
    }

    /// Ctrl+W: deletes the previous word (like readline: the spaces, then up
    /// to the previous space).
    fn delete_word(&mut self) {
        if !self.known {
            return;
        }
        let mut start = self.cursor;
        while start > 0 && self.chars[start - 1].is_whitespace() {
            start -= 1;
        }
        while start > 0 && !self.chars[start - 1].is_whitespace() {
            start -= 1;
        }
        self.chars.drain(start..self.cursor);
        self.cursor = start;
    }

    /// Applies what is sent to the terminal from the keyboard (or a paste).
    /// Returns the line submitted with Enter, if it was known and not
    /// empty.
    pub fn feed(&mut self, bytes: &[u8]) -> Option<String> {
        // Bracketed paste: a single line is added as text.
        if let Some(rest) = bytes.strip_prefix(PASTE_START) {
            let inner = rest.strip_suffix(PASTE_END).unwrap_or(rest);
            match std::str::from_utf8(inner) {
                Ok(text) if !text.chars().any(char::is_control) => self.insert(text),
                _ => self.forget(),
            }
            return None;
        }
        let mut submitted = None;
        let mut i = 0;
        while i < bytes.len() {
            let b = bytes[i];
            match b {
                0x1b => {
                    i = self.escape(bytes, i);
                    continue;
                }
                b'\r' | b'\n' => {
                    let line: String = self.chars.iter().collect();
                    if self.known && !line.trim().is_empty() {
                        submitted = Some(line);
                    }
                    self.reset();
                }
                0x03 => self.reset(),                   // Ctrl+C
                0x15 => self.reset(),                   // Ctrl+U
                0x7f | 0x08 => self.backspace(),        // Backspace
                0x01 => self.cursor = 0,                // Ctrl+A
                0x05 => self.cursor = self.chars.len(), // Ctrl+E
                0x02 => self.left(),                    // Ctrl+B
                0x06 => self.right(),                   // Ctrl+F
                0x0b => {
                    // Ctrl+K: delete to the end.
                    let cursor = self.cursor;
                    self.chars.truncate(cursor);
                }
                0x17 => self.delete_word(), // Ctrl+W
                0x0c => {}                  // Ctrl+L: only clears the screen
                0x04 => self.delete(),      // Ctrl+D (with text: delete)
                // Tab (the shell completes it) and the other control codes.
                b if b < 0x20 => self.forget(),
                _ => {
                    // Text: up to the next control character.
                    let end = bytes[i..]
                        .iter()
                        .position(|b| *b < 0x20 || *b == 0x7f)
                        .map_or(bytes.len(), |p| i + p);
                    match std::str::from_utf8(&bytes[i..end]) {
                        Ok(text) => self.insert(text),
                        Err(_) => self.forget(),
                    }
                    i = end;
                    continue;
                }
            }
            i += 1;
        }
        submitted
    }

    /// Escape sequence starting at `i`; returns where parsing continues.
    fn escape(&mut self, bytes: &[u8], i: usize) -> usize {
        match bytes.get(i + 1) {
            Some(b'[') => {
                // CSI: parameters and final letter.
                let mut j = i + 2;
                while j < bytes.len() && !(0x40..=0x7e).contains(&bytes[j]) {
                    j += 1;
                }
                let Some(&last) = bytes.get(j) else {
                    self.forget();
                    return bytes.len();
                };
                let params = &bytes[i + 2..j];
                match (last, params) {
                    (b'C', b"") => self.right(),
                    (b'D', b"") => self.left(),
                    (b'H', b"") | (b'~', b"1") | (b'~', b"7") => self.cursor = 0,
                    (b'F', b"") | (b'~', b"4") | (b'~', b"8") => self.cursor = self.chars.len(),
                    (b'~', b"3") => self.delete(),
                    // Up/down arrows (history), with modifiers (word
                    // jumps), function keys...: unknown line.
                    _ => self.forget(),
                }
                j + 1
            }
            Some(b'O') => {
                match bytes.get(i + 2) {
                    Some(b'C') => self.right(),
                    Some(b'D') => self.left(),
                    Some(b'H') => self.cursor = 0,
                    Some(b'F') => self.cursor = self.chars.len(),
                    _ => self.forget(),
                }
                (i + 3).min(bytes.len())
            }
            // Lone Escape or Alt+key: the shell may do anything.
            Some(_) => {
                self.forget();
                i + 2
            }
            None => {
                self.forget();
                i + 1
            }
        }
    }
}

/// Does what is on screen match the typed line? `before` is the screen text
/// before the cursor (with wrapped rows joined) and `after_blank` whether
/// nothing is written to the right of the cursor.
pub fn screen_matches(line: &str, before: &str, after_blank: bool) -> bool {
    after_blank && !line.is_empty() && before.ends_with(line)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn typed(t: &mut LineTracker, s: &str) -> Option<String> {
        t.feed(s.as_bytes())
    }

    #[test]
    fn text_and_backspace() {
        let mut t = LineTracker::default();
        typed(&mut t, "git sta");
        assert_eq!(t.current().as_deref(), Some("git sta"));
        t.feed(b"\x7f\x7f");
        assert_eq!(t.current().as_deref(), Some("git s"));
        assert!(t.at_end());
        typed(&mut t, "ñá日");
        assert_eq!(t.current().as_deref(), Some("git sñá日"));
        t.feed(b"\x7f");
        assert_eq!(t.current().as_deref(), Some("git sñá"));
    }

    #[test]
    fn enter_submits_and_resets() {
        let mut t = LineTracker::default();
        typed(&mut t, "ls -la");
        assert_eq!(t.feed(b"\r"), Some("ls -la".to_string()));
        assert_eq!(t.current().as_deref(), Some(""));
        // Empty line or only spaces: nothing to save.
        typed(&mut t, "   ");
        assert_eq!(t.feed(b"\r"), None);
    }

    #[test]
    fn ctrl_c_and_ctrl_u_reset() {
        let mut t = LineTracker::default();
        typed(&mut t, "rm -rf");
        t.feed(&[0x03]);
        assert_eq!(t.current().as_deref(), Some(""));
        typed(&mut t, "abc");
        t.feed(&[0x15]);
        assert_eq!(t.current().as_deref(), Some(""));
        // They also bring back a known line.
        t.feed(b"\x1b[A");
        assert_eq!(t.current(), None);
        t.feed(&[0x15]);
        assert_eq!(t.current().as_deref(), Some(""));
    }

    #[test]
    fn history_arrows_and_tab_make_the_line_unknown() {
        let mut t = LineTracker::default();
        typed(&mut t, "cd /v");
        t.feed(b"\t");
        assert_eq!(t.current(), None);
        // What is typed afterwards does not count...
        typed(&mut t, "ar/log");
        assert_eq!(t.current(), None);
        // ...and is not saved on Enter.
        assert_eq!(t.feed(b"\r"), None);
        assert_eq!(t.current().as_deref(), Some(""));
        for seq in [
            &b"\x1b[A"[..],
            b"\x1b[B",
            b"\x1bOA",
            b"\x1bOB",
            b"\x1bb",
            b"\x1b",
        ] {
            let mut t = LineTracker::default();
            typed(&mut t, "x");
            t.feed(seq);
            assert_eq!(t.current(), None, "{seq:?}");
        }
    }

    #[test]
    fn cursor_movement() {
        let mut t = LineTracker::default();
        typed(&mut t, "ech test");
        t.feed(b"\x1b[D\x1b[D\x1b[D\x1b[D\x1b[D");
        assert!(!t.at_end());
        typed(&mut t, "o");
        assert_eq!(t.current().as_deref(), Some("echo test"));
        t.feed(b"\x1bOF");
        assert!(t.at_end());
        t.feed(&[0x01]);
        t.feed(b"\x1b[3~");
        assert_eq!(t.current().as_deref(), Some("cho test"));
        t.feed(&[0x05]);
        assert!(t.at_end());
        // Right arrow at the end does nothing.
        t.feed(b"\x1b[C");
        assert!(t.at_end());
        // With modifiers (word jumps): unknown.
        t.feed(b"\x1b[1;5D");
        assert_eq!(t.current(), None);
    }

    #[test]
    fn readline_kills() {
        let mut t = LineTracker::default();
        typed(&mut t, "tail -f /var/log/syslog  ");
        t.feed(&[0x17]);
        assert_eq!(t.current().as_deref(), Some("tail -f "));
        t.feed(&[0x01, 0x06, 0x06, 0x0b]);
        assert_eq!(t.current().as_deref(), Some("ta"));
        t.feed(&[0x0c]);
        assert_eq!(t.current().as_deref(), Some("ta"));
    }

    #[test]
    fn paste() {
        let mut t = LineTracker::default();
        typed(&mut t, "echo ");
        t.feed(b"\x1b[200~hello world\x1b[201~");
        assert_eq!(t.current().as_deref(), Some("echo hello world"));
        // Several lines: the shell may run something; unknown.
        t.feed(b"\x1b[200~a\rb\x1b[201~");
        assert_eq!(t.current(), None);
        // Without brackets, pasted lines are submitted with Enter.
        let mut t = LineTracker::default();
        assert_eq!(t.feed(b"uptime\rdf"), Some("uptime".to_string()));
        assert_eq!(t.current().as_deref(), Some("df"));
    }

    #[test]
    fn screen_must_agree() {
        assert!(screen_matches("ls -l", "ana@srv:~$ ls -l", true));
        // No echo (password) or something right of the cursor: no.
        assert!(!screen_matches("secret", "[sudo] password for ana: ", true));
        assert!(!screen_matches("ls", "ana@srv:~$ ls", false));
        assert!(!screen_matches("", "ana@srv:~$ ", true));
    }
}
