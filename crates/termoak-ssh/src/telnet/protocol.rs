//! Telnet protocol (RFC 854) without I/O: option negotiation, `IAC`
//! escaping and the NVT end-of-line rules.
//!
//! Options this side takes part in:
//! - the host's `ECHO` (RFC 857) and `SUPPRESS-GO-AHEAD` (RFC 858), and
//!   `BINARY` (RFC 856) both ways if the host asks for it;
//! - our `TERMINAL-TYPE` (RFC 1091) and `NAWS` (window size, RFC 1073),
//!   sent again on every resize;
//! - `TIMING-MARK` (RFC 860): what [`Telnet::timing_mark`] asks for to
//!   measure the round trip, and answered when the host asks.
//!
//! Every other option is refused. The negotiation follows RFC 1143 (the
//! "Q method", without the queue), so it never loops.

/// Telnet commands.
pub(crate) mod cmd {
    pub const SE: u8 = 240;
    pub const NOP: u8 = 241;
    pub const DM: u8 = 242;
    pub const GA: u8 = 249;
    pub const SB: u8 = 250;
    pub const WILL: u8 = 251;
    pub const WONT: u8 = 252;
    pub const DO: u8 = 253;
    pub const DONT: u8 = 254;
    pub const IAC: u8 = 255;
}

/// Telnet options.
pub(crate) mod opt {
    pub const BINARY: u8 = 0;
    pub const ECHO: u8 = 1;
    pub const SGA: u8 = 3;
    pub const TIMING_MARK: u8 = 6;
    pub const TERMINAL_TYPE: u8 = 24;
    pub const NAWS: u8 = 31;
}

use cmd::*;

/// `TERMINAL-TYPE` subcommands.
const TTYPE_IS: u8 = 0;
const TTYPE_SEND: u8 = 1;

/// Longest subnegotiation kept (the rest is dropped).
const MAX_SB: usize = 1024;

/// State of an option on one side (RFC 1143).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Q {
    No,
    Yes,
    /// We asked to turn it off (this side never does: kept for RFC 1143).
    #[allow(dead_code)]
    WantNo,
    WantYes,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum State {
    Data,
    Iac,
    /// After `IAC WILL|WONT|DO|DONT`, waiting for the option.
    Verb(u8),
    Sb,
    SbIac,
}

/// What came out of a chunk from the host.
#[derive(Debug, Default)]
pub(crate) struct Received {
    /// Terminal output.
    pub data: Vec<u8>,
    /// Bytes to send back (negotiation).
    pub reply: Vec<u8>,
    /// Answers to our `DO TIMING-MARK`.
    pub timing_marks: usize,
}

/// Telnet state of one connection.
pub(crate) struct Telnet {
    term: String,
    cols: u16,
    rows: u16,
    /// Options on this side (we WILL).
    us: [Q; 256],
    /// Options on the host's side (it WILL).
    him: [Q; 256],
    state: State,
    sb: Vec<u8>,
    /// The last output byte was a CR (a NUL right after it is dropped).
    cr_in: bool,
    /// The last input byte was a CR, sent as CR LF (a LF right after it is
    /// dropped).
    cr_out: bool,
    /// The host has sent a Telnet command (it is a Telnet server, not a raw
    /// TCP service).
    spoke: bool,
}

impl Telnet {
    pub fn new(term: &str, cols: u16, rows: u16) -> Self {
        // Terminal types are ASCII (RFC 1091); anything else is left out.
        let term: String = term
            .chars()
            .filter(|c| c.is_ascii_graphic())
            .take(40)
            .collect();
        Self {
            term: if term.is_empty() {
                "xterm-256color".into()
            } else {
                term
            },
            cols,
            rows,
            us: [Q::No; 256],
            him: [Q::No; 256],
            state: State::Data,
            sb: Vec::new(),
            cr_in: false,
            cr_out: false,
            spoke: false,
        }
    }

    /// What we offer and ask for right after connecting (as PuTTY does):
    /// our terminal type and window size, the host's echo, and no go-aheads
    /// either way.
    pub fn start(&mut self) -> Vec<u8> {
        let mut out = Vec::new();
        for o in [opt::TERMINAL_TYPE, opt::NAWS, opt::SGA] {
            self.us[o as usize] = Q::WantYes;
            out.extend_from_slice(&[IAC, WILL, o]);
        }
        for o in [opt::ECHO, opt::SGA] {
            self.him[o as usize] = Q::WantYes;
            out.extend_from_slice(&[IAC, DO, o]);
        }
        out
    }

    /// Whether the host has sent any Telnet command yet.
    pub fn spoke_telnet(&self) -> bool {
        self.spoke
    }

    /// The host echoes what we type.
    #[cfg(test)]
    pub fn remote_echo(&self) -> bool {
        self.him[opt::ECHO as usize] == Q::Yes
    }

    /// Asks for a timing mark (the host answers `WILL` or `WONT`).
    pub fn timing_mark() -> [u8; 3] {
        [IAC, DO, opt::TIMING_MARK]
    }

    /// New window size: the `NAWS` message to send, if the option is on.
    pub fn resize(&mut self, cols: u16, rows: u16) -> Option<Vec<u8>> {
        self.cols = cols;
        self.rows = rows;
        (self.us[opt::NAWS as usize] == Q::Yes).then(|| self.naws())
    }

    /// Input typed by the user, ready for the wire: `IAC` doubled and, out of
    /// binary mode, CR sent as the NVT newline CR LF.
    pub fn encode_input(&mut self, input: &[u8], out: &mut Vec<u8>) {
        let binary = self.us[opt::BINARY as usize] == Q::Yes;
        out.reserve(input.len() + 4);
        for &b in input {
            if binary {
                out.push(b);
                if b == IAC {
                    out.push(IAC);
                }
                continue;
            }
            let after_cr = std::mem::replace(&mut self.cr_out, b == b'\r');
            match b {
                b'\r' => out.extend_from_slice(b"\r\n"),
                // Already sent with the CR.
                b'\n' if after_cr => {}
                IAC => out.extend_from_slice(&[IAC, IAC]),
                _ => out.push(b),
            }
        }
    }

    /// Takes a chunk from the host.
    pub fn receive(&mut self, input: &[u8]) -> Received {
        let mut r = Received {
            data: Vec::with_capacity(input.len()),
            ..Default::default()
        };
        for &b in input {
            match self.state {
                State::Data => {
                    if b == IAC {
                        self.state = State::Iac;
                    } else {
                        self.data_byte(b, &mut r.data);
                    }
                }
                State::Iac => self.command(b, &mut r),
                State::Verb(verb) => {
                    self.state = State::Data;
                    self.negotiate(verb, b, &mut r);
                }
                State::Sb => {
                    if b == IAC {
                        self.state = State::SbIac;
                    } else if self.sb.len() < MAX_SB {
                        self.sb.push(b);
                    }
                }
                State::SbIac => match b {
                    IAC => {
                        if self.sb.len() < MAX_SB {
                            self.sb.push(IAC);
                        }
                        self.state = State::Sb;
                    }
                    SE => {
                        self.state = State::Data;
                        self.subnegotiation(&mut r);
                    }
                    // A command without the SE: the subnegotiation ends
                    // here and the command counts.
                    _ => {
                        self.subnegotiation(&mut r);
                        self.command(b, &mut r);
                    }
                },
            }
        }
        r
    }

    fn data_byte(&mut self, b: u8, data: &mut Vec<u8>) {
        if self.him[opt::BINARY as usize] == Q::Yes {
            data.push(b);
            return;
        }
        // NVT: CR NUL is a bare CR.
        let after_cr = std::mem::replace(&mut self.cr_in, b == b'\r');
        if !(after_cr && b == 0) {
            data.push(b);
        }
    }

    /// The byte after an `IAC`.
    fn command(&mut self, b: u8, r: &mut Received) {
        self.spoke = true;
        self.state = State::Data;
        match b {
            IAC => self.data_byte(IAC, &mut r.data),
            WILL | WONT | DO | DONT => self.state = State::Verb(b),
            SB => {
                self.sb.clear();
                self.state = State::Sb;
            }
            // GA, NOP, DM, BRK, IP, AO, AYT, EC, EL and stray SE: nothing to
            // do for a terminal (without SUPPRESS-GO-AHEAD the host may send
            // a GA after each prompt).
            GA | NOP | DM => {}
            _ => {}
        }
    }

    fn negotiate(&mut self, verb: u8, o: u8, r: &mut Received) {
        if o == opt::TIMING_MARK {
            match verb {
                // The answer to a mark we asked for, either way.
                WILL | WONT => r.timing_marks += 1,
                // The host's mark: everything before it was processed.
                DO => r.reply.extend_from_slice(&[IAC, WILL, opt::TIMING_MARK]),
                _ => {}
            }
            return;
        }
        let i = o as usize;
        match verb {
            WILL => match self.him[i] {
                Q::No => {
                    if accept_him(o) {
                        self.him[i] = Q::Yes;
                        r.reply.extend_from_slice(&[IAC, DO, o]);
                    } else {
                        r.reply.extend_from_slice(&[IAC, DONT, o]);
                    }
                }
                Q::Yes => {}
                // We said DONT and it answers WILL: an error, it stays off.
                Q::WantNo => self.him[i] = Q::No,
                Q::WantYes => self.him[i] = Q::Yes,
            },
            WONT => match self.him[i] {
                Q::No => {}
                Q::Yes => {
                    self.him[i] = Q::No;
                    r.reply.extend_from_slice(&[IAC, DONT, o]);
                }
                Q::WantNo | Q::WantYes => self.him[i] = Q::No,
            },
            DO => match self.us[i] {
                Q::No => {
                    if accept_us(o) {
                        self.us[i] = Q::Yes;
                        r.reply.extend_from_slice(&[IAC, WILL, o]);
                        self.enabled_us(o, r);
                    } else {
                        r.reply.extend_from_slice(&[IAC, WONT, o]);
                    }
                }
                Q::Yes => {}
                Q::WantNo => self.us[i] = Q::No,
                Q::WantYes => {
                    self.us[i] = Q::Yes;
                    self.enabled_us(o, r);
                }
            },
            DONT => match self.us[i] {
                Q::No => {}
                Q::Yes => {
                    self.us[i] = Q::No;
                    r.reply.extend_from_slice(&[IAC, WONT, o]);
                }
                Q::WantNo | Q::WantYes => self.us[i] = Q::No,
            },
            _ => {}
        }
    }

    /// One of our options was just turned on.
    fn enabled_us(&mut self, o: u8, r: &mut Received) {
        if o == opt::NAWS {
            r.reply.extend_from_slice(&self.naws());
        }
    }

    fn subnegotiation(&mut self, r: &mut Received) {
        let sb = std::mem::take(&mut self.sb);
        if sb.len() >= 2
            && sb[0] == opt::TERMINAL_TYPE
            && sb[1] == TTYPE_SEND
            && self.us[opt::TERMINAL_TYPE as usize] == Q::Yes
        {
            r.reply
                .extend_from_slice(&[IAC, SB, opt::TERMINAL_TYPE, TTYPE_IS]);
            r.reply.extend_from_slice(self.term.as_bytes());
            r.reply.extend_from_slice(&[IAC, SE]);
        }
    }

    /// `IAC SB NAWS <cols> <rows> IAC SE`, with any 255 byte doubled.
    fn naws(&self) -> Vec<u8> {
        let mut out = vec![IAC, SB, opt::NAWS];
        for b in self
            .cols
            .to_be_bytes()
            .into_iter()
            .chain(self.rows.to_be_bytes())
        {
            out.push(b);
            if b == IAC {
                out.push(IAC);
            }
        }
        out.extend_from_slice(&[IAC, SE]);
        out
    }
}

/// Options we let the host turn on on its side.
fn accept_him(o: u8) -> bool {
    matches!(o, opt::BINARY | opt::ECHO | opt::SGA)
}

/// Options we turn on on our side when asked.
fn accept_us(o: u8) -> bool {
    matches!(o, opt::BINARY | opt::SGA | opt::TERMINAL_TYPE | opt::NAWS)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn data(t: &mut Telnet, input: &[u8]) -> Vec<u8> {
        t.receive(input).data
    }

    #[test]
    fn start_offers_and_asks() {
        let mut t = Telnet::new("xterm-256color", 80, 24);
        let s = t.start();
        assert_eq!(
            s,
            [
                IAC, WILL, 24, IAC, WILL, 31, IAC, WILL, 3, IAC, DO, 1, IAC, DO, 3
            ]
        );
        // The answers to our own requests are not answered again.
        let r = t.receive(&[IAC, WILL, opt::ECHO, IAC, WILL, opt::SGA]);
        assert!(r.reply.is_empty());
        assert!(t.remote_echo());
        // DO NAWS answers our WILL: the size goes right away, no WILL again.
        let r = t.receive(&[IAC, DO, opt::NAWS]);
        assert_eq!(r.reply, [IAC, SB, 31, 0, 80, 0, 24, IAC, SE]);
        // Asking again changes nothing (no loops).
        let r = t.receive(&[IAC, DO, opt::NAWS, IAC, WILL, opt::ECHO]);
        assert!(r.reply.is_empty());
    }

    #[test]
    fn refuses_unknown_options() {
        let mut t = Telnet::new("xterm", 80, 24);
        // DO LINEMODE (34), WILL STATUS (5), DO NEW-ENVIRON (39).
        let r = t.receive(&[IAC, DO, 34, IAC, WILL, 5, IAC, DO, 39]);
        assert_eq!(r.reply, [IAC, WONT, 34, IAC, DONT, 5, IAC, WONT, 39]);
        // Their WONT/DONT after that need no answer.
        let r = t.receive(&[IAC, WONT, 5, IAC, DONT, 34]);
        assert!(r.reply.is_empty());
    }

    #[test]
    fn host_turning_echo_off_is_acknowledged() {
        let mut t = Telnet::new("xterm", 80, 24);
        t.receive(&[IAC, WILL, opt::ECHO]);
        assert!(t.remote_echo());
        let r = t.receive(&[IAC, WONT, opt::ECHO]);
        assert_eq!(r.reply, [IAC, DONT, opt::ECHO]);
        assert!(!t.remote_echo());
    }

    #[test]
    fn terminal_type_is_sent_when_asked() {
        let mut t = Telnet::new("xterm-256color", 80, 24);
        let r = t.receive(&[IAC, DO, 24, IAC, SB, 24, TTYPE_SEND, IAC, SE]);
        let mut want = vec![IAC, WILL, 24, IAC, SB, 24, TTYPE_IS];
        want.extend_from_slice(b"xterm-256color");
        want.extend_from_slice(&[IAC, SE]);
        assert_eq!(r.reply, want);
    }

    #[test]
    fn naws_on_resize_escapes_255() {
        let mut t = Telnet::new("xterm", 80, 24);
        assert!(t.resize(100, 30).is_none(), "not negotiated yet");
        let r = t.receive(&[IAC, DO, opt::NAWS]);
        assert_eq!(
            r.reply,
            [IAC, WILL, 31, IAC, SB, 31, 0, 100, 0, 30, IAC, SE]
        );
        assert_eq!(
            t.resize(255, 300).unwrap(),
            [IAC, SB, 31, 0, 255, 255, 1, 44, IAC, SE]
        );
        // Turned off: no more sizes.
        t.receive(&[IAC, DONT, opt::NAWS]);
        assert!(t.resize(80, 24).is_none());
    }

    #[test]
    fn iac_escaping_both_ways() {
        let mut t = Telnet::new("xterm", 80, 24);
        assert_eq!(data(&mut t, &[b'a', IAC, IAC, b'b']), [b'a', 255, b'b']);
        // Split across chunks.
        assert_eq!(data(&mut t, &[b'x', IAC]), b"x");
        assert_eq!(data(&mut t, &[IAC, b'y']), [255, b'y']);
        let mut out = Vec::new();
        t.encode_input(&[b'q', 255, b'z'], &mut out);
        assert_eq!(out, [b'q', IAC, IAC, b'z']);
    }

    #[test]
    fn end_of_line_rules() {
        let mut t = Telnet::new("xterm", 80, 24);
        // CR NUL is a CR, CR LF stays, even split.
        assert_eq!(data(&mut t, b"a\r\0b\r\nc\r"), b"a\rb\r\nc\r");
        assert_eq!(data(&mut t, b"\0d"), b"d");
        // Enter is sent as CR LF; a CR LF already there is not doubled.
        let mut out = Vec::new();
        t.encode_input(b"ls\r", &mut out);
        t.encode_input(b"\n", &mut out);
        t.encode_input(b"a\r\nb\n", &mut out);
        assert_eq!(out, b"ls\r\na\r\nb\n");
        // In binary mode bytes go as they are (IAC still doubled).
        t.receive(&[IAC, DO, opt::BINARY, IAC, WILL, opt::BINARY]);
        let mut out = Vec::new();
        t.encode_input(&[b'\r', 255], &mut out);
        assert_eq!(out, [b'\r', IAC, IAC]);
        assert_eq!(data(&mut t, b"\r\0"), b"\r\0");
    }

    #[test]
    fn commands_and_subnegotiations_are_not_output() {
        let mut t = Telnet::new("xterm", 80, 24);
        let r = t.receive(&[
            b'>', IAC, GA, IAC, NOP, IAC, SB, 5, 1, 2, IAC, IAC, IAC, SE, b'<',
        ]);
        assert_eq!(r.data, b"><");
        assert!(t.spoke_telnet());
        // A subnegotiation cut by another command ends there.
        let r = t.receive(&[IAC, SB, 24, 1, IAC, WILL, 1, b'!']);
        assert_eq!(r.data, b"!");
        assert_eq!(r.reply, [IAC, DO, 1]);
    }

    #[test]
    fn timing_marks() {
        let mut t = Telnet::new("xterm", 80, 24);
        let r = t.receive(&[
            IAC,
            WILL,
            opt::TIMING_MARK,
            b'x',
            IAC,
            WONT,
            opt::TIMING_MARK,
        ]);
        assert_eq!(r.timing_marks, 2);
        assert!(r.reply.is_empty());
        assert_eq!(r.data, b"x");
        let r = t.receive(&[IAC, DO, opt::TIMING_MARK]);
        assert_eq!(r.reply, [IAC, WILL, opt::TIMING_MARK]);
    }
}
