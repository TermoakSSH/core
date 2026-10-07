//! Optional automatic login: answers the host's first `login:` and
//! `Password:` prompts with the username and password of the host.
//!
//! A heuristic (Telnet has no login protocol): the output is watched only
//! during the first moments of the connection, each prompt is answered at
//! most once, and only when it is the last thing on the screen (case and
//! colors do not matter). The password is never logged and is wiped from
//! memory once used or when the watch ends.

use std::time::{Duration, Instant};

use zeroize::Zeroizing;

/// How long after connecting prompts are answered.
pub(crate) const WINDOW: Duration = Duration::from_secs(30);

/// Raw output kept to look for a prompt at its end.
const TAIL: usize = 256;

const USER_PROMPTS: &[&str] = &["login:", "username:", "user name:", "user:"];
const PASSWORD_PROMPTS: &[&str] = &["password:", "passcode:", "contraseña:"];

pub(crate) struct AutoLogin {
    user: Option<Zeroizing<String>>,
    password: Option<Zeroizing<String>>,
    tail: Vec<u8>,
    until: Instant,
}

impl AutoLogin {
    /// `None` if there is nothing to type.
    pub fn new(user: &str, password: Option<&str>) -> Option<Self> {
        let user = Some(user.trim())
            .filter(|u| !u.is_empty())
            .map(|u| Zeroizing::new(u.to_string()));
        let password = password
            .filter(|p| !p.is_empty())
            .map(|p| Zeroizing::new(p.to_string()));
        (user.is_some() || password.is_some()).then(|| Self {
            user,
            password,
            tail: Vec::with_capacity(TAIL),
            until: Instant::now() + WINDOW,
        })
    }

    /// Whether it still has something to do.
    pub fn active(&self) -> bool {
        (self.user.is_some() || self.password.is_some()) && Instant::now() < self.until
    }

    /// Looks at new output; the answer to type (with its Enter) if it ends
    /// in a prompt.
    pub fn feed(&mut self, output: &[u8]) -> Option<Zeroizing<Vec<u8>>> {
        if !self.active() {
            self.user = None;
            self.password = None;
            return None;
        }
        self.tail.extend_from_slice(output);
        if self.tail.len() > TAIL {
            self.tail.drain(..self.tail.len() - TAIL);
        }
        let text = crate::ansi::strip(&String::from_utf8_lossy(&self.tail)).to_lowercase();
        let end = text.trim_end();
        let answer = (if PASSWORD_PROMPTS.iter().any(|p| end.ends_with(p)) {
            // The password ends the login: the username is not typed later.
            self.user = None;
            self.password.take()
        } else if USER_PROMPTS.iter().any(|p| end.ends_with(p)) {
            self.user.take()
        } else {
            None
        })?;
        self.tail.clear();
        let mut line = Zeroizing::new(Vec::with_capacity(answer.len() + 1));
        line.extend_from_slice(answer.as_bytes());
        line.push(b'\r');
        Some(line)
    }

    #[cfg(test)]
    pub fn expire(&mut self) {
        self.until = Instant::now();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn feed(a: &mut AutoLogin, s: &str) -> Option<String> {
        a.feed(s.as_bytes())
            .map(|v| String::from_utf8(v.to_vec()).unwrap())
    }

    #[test]
    fn answers_each_prompt_once() {
        let mut a = AutoLogin::new("admin", Some("s3cret")).unwrap();
        assert_eq!(feed(&mut a, "Welcome\r\n"), None);
        assert_eq!(feed(&mut a, "router1 lo"), None);
        assert_eq!(feed(&mut a, "gin: ").as_deref(), Some("admin\r"));
        // The echo of the answer and the next prompt (colored, any case).
        assert_eq!(
            feed(&mut a, "admin\r\n\x1b[1mPASSWORD:\x1b[0m ").as_deref(),
            Some("s3cret\r")
        );
        assert!(!a.active());
        // Wrong password: the next prompts are left to the user.
        assert_eq!(feed(&mut a, "\r\nLogin incorrect\r\nlogin: "), None);
        assert_eq!(feed(&mut a, "Password: "), None);
    }

    #[test]
    fn only_what_is_set_and_only_at_the_end() {
        assert!(AutoLogin::new("  ", None).is_none());
        let mut a = AutoLogin::new("", Some("line")).unwrap();
        assert_eq!(feed(&mut a, "Username: "), None);
        // A prompt that is not the last thing on screen is not one.
        assert_eq!(feed(&mut a, "Password: set it later\r\n"), None);
        assert_eq!(feed(&mut a, "Password:").as_deref(), Some("line\r"));

        let mut a = AutoLogin::new("pi", None).unwrap();
        assert_eq!(feed(&mut a, "Password: "), None);
        assert!(
            !a.active(),
            "after a password prompt the username is not typed"
        );
    }

    #[test]
    fn stops_after_the_window() {
        let mut a = AutoLogin::new("admin", Some("pw")).unwrap();
        a.expire();
        assert_eq!(feed(&mut a, "login: "), None);
        assert!(!a.active());
    }
}
