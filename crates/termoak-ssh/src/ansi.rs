//! ANSI sequence stripping so the AI (or a search) can read terminal output as
//! plain text.

/// Removes escape sequences and roughly resolves `\r` and backspaces.
pub fn strip(input: &str) -> String {
    #[derive(PartialEq)]
    enum State {
        Text,
        Esc,
        Csi,
        Osc,
        OscEsc,
        /// Two-byte sequence (`ESC ( B`, etc.).
        Charset,
    }
    let mut out = String::with_capacity(input.len());
    let mut line_start = 0usize;
    let mut state = State::Text;
    for c in input.chars() {
        match state {
            State::Text => match c {
                '\u{1b}' => state = State::Esc,
                '\r' => {}
                '\n' => {
                    out.push('\n');
                    line_start = out.len();
                }
                '\u{8}' => {
                    if out.len() > line_start {
                        out.pop();
                    }
                }
                '\u{7}' => {}
                c if c.is_control() && c != '\t' => {}
                c => out.push(c),
            },
            State::Esc => {
                state = match c {
                    '[' => State::Csi,
                    ']' => State::Osc,
                    '(' | ')' | '*' | '+' | '#' | '%' => State::Charset,
                    _ => State::Text,
                }
            }
            State::Csi => {
                if ('\u{40}'..='\u{7e}').contains(&c) {
                    state = State::Text;
                }
            }
            State::Osc => match c {
                '\u{7}' => state = State::Text,
                '\u{1b}' => state = State::OscEsc,
                _ => {}
            },
            State::OscEsc => state = State::Text,
            State::Charset => state = State::Text,
        }
    }
    out
}

/// Last `max_chars` characters (respecting character boundaries).
pub fn tail(text: &str, max_chars: usize) -> &str {
    let count = text.chars().count();
    if count <= max_chars {
        return text;
    }
    let skip = count - max_chars;
    let idx = text.char_indices().nth(skip).map(|(i, _)| i).unwrap_or(0);
    &text[idx..]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strips_colors_and_titles() {
        let s =
            "\u{1b}]0;user@host: ~\u{7}\u{1b}[01;32muser@host\u{1b}[00m:~$ ls\r\nfile\u{1b}[K\r\n";
        assert_eq!(strip(s), "user@host:~$ ls\nfile\n");
    }

    #[test]
    fn backspace() {
        assert_eq!(strip("lss\u{8} -la"), "ls -la");
    }

    #[test]
    fn tail_chars() {
        assert_eq!(tail("ñandú", 3), "ndú");
        assert_eq!(tail("ab", 5), "ab");
    }
}
