//! QR codes (to set up two-factor authentication from the phone's
//! authenticator app).

pub use termoak_core::qr::{matrix, svg};

/// QR for the terminal, drawn with half blocks (two rows per line) and a margin.
/// It reads well on dark or light backgrounds because it paints the light modules.
pub fn terminal(text: &str) -> Option<String> {
    let m = matrix(text)?;
    let n = m.len();
    let quiet = 2;
    let size = n + quiet * 2;
    let dark = |y: usize, x: usize| -> bool {
        y >= quiet && x >= quiet && y < n + quiet && x < n + quiet && m[y - quiet][x - quiet]
    };
    let mut out = String::new();
    let mut y = 0;
    while y < size {
        for x in 0..size {
            let top = !dark(y, x);
            let bottom = y + 1 < size && !dark(y + 1, x);
            out.push(match (top, bottom) {
                (true, true) => '█',
                (true, false) => '▀',
                (false, true) => '▄',
                (false, false) => ' ',
            });
        }
        out.push('\n');
        y += 2;
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    #[test]
    fn qr_is_square() {
        let m = super::matrix("otpauth://totp/Termoak:ana?secret=GEZDGNBV").unwrap();
        assert!(m.len() >= 21);
        assert!(m.iter().all(|r| r.len() == m.len()));
        assert!(super::terminal("hello").unwrap().lines().count() > 10);
    }
}
