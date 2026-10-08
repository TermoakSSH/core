//! The AI inside the terminal, without UI (the desktop's rules, from
//! `termoak_client::ai_assist` and `termoak_client::command_watch`):
//!
//! - [`CommandWatcher`]: when a command starts and ends (shell integration
//!   with OSC 133/633 marks, or a heuristic), its exit status and what it
//!   printed. For the "Explain / Fix with AI" chip and the long-command
//!   notifications.
//! - [`command_failure`]: when a command counts as failed for the chip.
//! - [`nl_request`]: the `# <request>` line typed at the prompt.
//! - [`typeable_command`]: a command the AI proposes, safe to type.
//! - [`ContextChip`] and [`copilot_context_block`]: the terminal context the
//!   copilot gets, as removable chips.
//!
//! Redaction: the text that goes to an AI passes through [`redact_for_ai`]
//! (chips of the last command and of the selection). See its docs.

use std::sync::Arc;
use std::time::Instant;

use parking_lot::Mutex;
use termoak_client::ai_assist as aa;

use crate::screen::TerminalScreen;

/// Hides obvious secrets in text that goes to an AI.
///
/// The secret redaction of the AI engine (`termoak_ai::redact`) is not in
/// the mobile library yet (parity item C1, being added separately as
/// `redactSecrets`): until it lands this function leaves the text as it
/// is, as the apps do today, and the server redacts what reaches its AI.
/// When C1 is merged this is the one place that switches to it.
fn redact_for_ai(text: &str) -> String {
    text.to_string()
}

/// How a command failed, for the chip.
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum CommandFailure {
    /// The shell gave this exit status (shell integration).
    Exit { code: i32 },
    /// No exit status, but its output ends like an error.
    Likely,
}

impl From<aa::Failure> for CommandFailure {
    fn from(f: aa::Failure) -> Self {
        match f {
            aa::Failure::Exit(code) => CommandFailure::Exit { code },
            aa::Failure::Likely => CommandFailure::Likely,
        }
    }
}

impl From<CommandFailure> for aa::Failure {
    fn from(f: CommandFailure) -> Self {
        match f {
            CommandFailure::Exit { code } => aa::Failure::Exit(code),
            CommandFailure::Likely => aa::Failure::Likely,
        }
    }
}

/// The last command that ended in a terminal (not a full-screen program).
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct LastCommandInfo {
    /// The command line, when known (typed and seen on screen, or sent by
    /// the shell).
    pub command: Option<String>,
    /// Exit status (only with shell integration).
    pub exit_code: Option<i32>,
    /// The end of what it printed, cleaned (at most 60 lines and 4,000
    /// characters; not redacted).
    pub output: String,
    /// Whether it failed, by the chip's rules. The app also checks its own
    /// setting and that an AI can be asked.
    pub failure: Option<CommandFailure>,
}

impl From<aa::LastCommand> for LastCommandInfo {
    fn from(l: aa::LastCommand) -> Self {
        LastCommandInfo {
            command: l.command,
            exit_code: l.exit,
            output: l.output,
            failure: l.failure.map(Into::into),
        }
    }
}

impl From<LastCommandInfo> for aa::LastCommand {
    fn from(l: LastCommandInfo) -> Self {
        aa::LastCommand {
            command: l.command,
            exit: l.exit_code,
            output: l.output,
            failure: l.failure.map(Into::into),
        }
    }
}

/// A command that ended.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct CommandEnded {
    pub command: Option<String>,
    /// From its start to its end (to the prompt, without shell
    /// integration). Notify when it is long and the terminal is not in
    /// view.
    pub duration_ms: u64,
    pub exit_code: Option<i32>,
    /// It used the alternate screen (vim, less, top...): not notified,
    /// no chip.
    pub interactive: bool,
    /// `None` for interactive programs.
    pub last: Option<LastCommandInfo>,
}

impl From<aa::CommandEnded> for CommandEnded {
    fn from(e: aa::CommandEnded) -> Self {
        CommandEnded {
            command: e.finished.command,
            duration_ms: u64::try_from(e.finished.duration.as_millis()).unwrap_or(u64::MAX),
            exit_code: e.finished.exit,
            interactive: e.finished.interactive,
            last: e.last.map(Into::into),
        }
    }
}

/// What a piece of output did.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct CommandOutputEvent {
    /// A command started (shell integration): hide the chip of the previous
    /// one.
    pub started: bool,
    pub ended: Option<CommandEnded>,
}

/// Follows the commands of one terminal, like [`crate::LineTracker`]
/// follows its line. Feed it every piece of output with
/// [`Self::output`] (after the emulator, to know whether the alternate
/// screen is on), call [`Self::enter`] when the user presses Enter at a
/// shell line (not in a full-screen program, not a bracketed paste) and,
/// while [`Self::waiting_for_prompt`], [`Self::idle`] every half second.
///
/// With shell integration (OSC 133 from the shell's scripts, or OSC 633
/// from VS Code's) start, end and exit status are exact; without it a
/// command ends when the output goes quiet for a second with a prompt at
/// the cursor.
#[derive(uniffi::Object)]
pub struct CommandWatcher {
    tracker: Mutex<aa::CommandTracker>,
    /// Android: the emulator, to read the screen when a command ends whose
    /// start was not seen.
    screen: Option<Arc<TerminalScreen>>,
}

#[uniffi::export]
impl CommandWatcher {
    /// `screen`: the terminal's [`TerminalScreen`] (Android); without it
    /// (iOS) a command whose start was not seen ends with no output.
    #[uniffi::constructor(default(screen = None))]
    pub fn new(screen: Option<Arc<TerminalScreen>>) -> Arc<Self> {
        Arc::new(Self {
            tracker: Mutex::new(aa::CommandTracker::default()),
            screen,
        })
    }

    /// A piece of terminal output; `alternate_screen`: the screen in use
    /// after it.
    pub fn output(&self, data: Vec<u8>, alternate_screen: bool) -> CommandOutputEvent {
        let screen = || self.screen_text();
        let ev = self
            .tracker
            .lock()
            .output(Instant::now(), &data, alternate_screen, &screen);
        CommandOutputEvent {
            started: ev.started,
            ended: ev.ended.map(Into::into),
        }
    }

    /// Enter was pressed at a shell line: `command` is the line typed (the
    /// `LineTracker`'s, if it is trusted) and `prompt` what is in front of
    /// it on screen. Whether a command started (without shell
    /// integration; then start calling [`Self::idle`]).
    #[uniffi::method(default(command = None, prompt = None))]
    pub fn enter(&self, command: Option<String>, prompt: Option<String>) -> bool {
        self.tracker.lock().enter(Instant::now(), command, prompt)
    }

    /// Without shell integration, a command is waiting for its prompt:
    /// call [`Self::idle`] every half second meanwhile.
    pub fn waiting_for_prompt(&self) -> bool {
        self.tracker.lock().waiting_for_prompt()
    }

    /// The shell marks its prompts and commands (OSC 133/633).
    pub fn integrated(&self) -> bool {
        self.tracker.lock().integrated()
    }

    /// The periodic check without shell integration: `before_cursor` is the
    /// text in front of the cursor on its line and `after_blank` whether the
    /// rest of the line is empty.
    pub fn idle(
        &self,
        alternate_screen: bool,
        before_cursor: String,
        after_blank: bool,
    ) -> Option<CommandEnded> {
        let screen = || self.screen_text();
        self.tracker
            .lock()
            .idle(
                Instant::now(),
                alternate_screen,
                &before_cursor,
                after_blank,
                &screen,
            )
            .map(Into::into)
    }

    /// The last command that ended (for the copilot's context chip).
    pub fn last_command(&self) -> Option<LastCommandInfo> {
        self.tracker.lock().last().cloned().map(Into::into)
    }

    /// Forgets everything (a new connection).
    pub fn reset(&self) {
        self.tracker.lock().reset();
    }
}

impl CommandWatcher {
    fn screen_text(&self) -> String {
        self.screen
            .as_ref()
            .map(|s| s.screen_text())
            .unwrap_or_default()
    }
}

/// When a command counts as failed for the "Fix with AI" chip: with an
/// exit status, non-zero but not Ctrl+C, SIGTERM, Ctrl+Z or a closed pipe
/// (130, 143, 148, 141); without one, when the last lines of its output
/// look like an error. Never for full-screen programs, a command line that
/// is a comment (`# request` run by mistake) or an unknown command.
#[uniffi::export(default(exit_code = None, interactive = false))]
pub fn command_failure(
    command: Option<String>,
    exit_code: Option<i32>,
    interactive: bool,
    output: String,
) -> Option<CommandFailure> {
    aa::failure(&aa::ChipInput {
        enabled: true,
        ai_ready: true,
        command: command.as_deref(),
        exit: exit_code,
        interactive,
        output: &output,
    })
    .map(Into::into)
}

/// A `# <request>` line typed at the prompt: the request in the user's
/// words (to turn into a command with the AI, Ctrl/⌘+Enter). `None` for a
/// shebang (`#!`), a command with a comment after it, or a bare `#`.
#[uniffi::export]
pub fn nl_request(line: String) -> Option<String> {
    aa::nl_request(&line).map(str::to_string)
}

/// A command the AI proposes, safe to type without running it: one line
/// (several become `a; b`; `\`, `&&`, `|` and `;` continuations are
/// joined) and no control characters (a carriage return or an escape
/// sequence would run it or do something else).
#[uniffi::export]
pub fn typeable_command(command: String) -> String {
    aa::typeable_command(&command)
}

/// Text of raw terminal output: escape sequences removed, carriage returns
/// and backspaces applied as on screen (a progress bar leaves its last
/// state).
#[uniffi::export]
pub fn clean_terminal_output(data: Vec<u8>) -> String {
    aa::clean_output(&data)
}

/// The end of a text: its last `max_lines` lines and at most `max_chars`
/// characters (cut at a line start when possible).
#[uniffi::export]
pub fn text_tail(text: String, max_lines: u32, max_chars: u32) -> String {
    aa::tail_lines(&text, max_lines as usize, max_chars as usize)
}

/// At most `max` characters: the start (`…` after) or, with `from_end`,
/// the end (`…` before). For chip labels.
#[uniffi::export(default(from_end = false))]
pub fn shorten_text(text: String, max: u32, from_end: bool) -> String {
    aa::short(&text, (max as usize).max(1), from_end)
}

/// What a piece of copilot context is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum ContextChipKind {
    Host,
    Directory,
    LastCommand,
    Selection,
}

/// A piece of terminal context the copilot sends with the next message,
/// shown as a chip the user can remove before sending.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct ContextChip {
    pub kind: ContextChipKind,
    /// Short text of the chip.
    pub label: String,
    /// What the AI gets.
    pub text: String,
}

impl From<aa::ContextChip> for ContextChip {
    fn from(c: aa::ContextChip) -> Self {
        ContextChip {
            kind: match c.kind {
                aa::ChipKind::Host => ContextChipKind::Host,
                aa::ChipKind::Directory => ContextChipKind::Directory,
                aa::ChipKind::LastCommand => ContextChipKind::LastCommand,
                aa::ChipKind::Selection => ContextChipKind::Selection,
            },
            label: c.label,
            text: c.text,
        }
    }
}

impl From<ContextChip> for aa::ContextChip {
    fn from(c: ContextChip) -> Self {
        aa::ContextChip {
            kind: match c.kind {
                ContextChipKind::Host => aa::ChipKind::Host,
                ContextChipKind::Directory => aa::ChipKind::Directory,
                ContextChipKind::LastCommand => aa::ChipKind::LastCommand,
                ContextChipKind::Selection => aa::ChipKind::Selection,
            },
            label: c.label,
            text: c.text,
        }
    }
}

/// Chip of the host ("web-1 · Ubuntu 24.04").
#[uniffi::export(default(os = None))]
pub fn context_chip_host(name: String, os: Option<String>) -> ContextChip {
    aa::ContextChip::host(&name, os.as_deref()).into()
}

/// Chip of the working directory (the label keeps its end).
#[uniffi::export]
pub fn context_chip_directory(cwd: String) -> ContextChip {
    aa::ContextChip::directory(&cwd).into()
}

/// Chip of the last command and the end of its output; `label` is how the
/// chip reads ("make · exit 2", translated by the app).
#[uniffi::export]
pub fn context_chip_last_command(last: LastCommandInfo, label: String) -> ContextChip {
    aa::ContextChip::last_command(&last.into(), label, &redact_for_ai).into()
}

/// Chip of the selected text (its last 200 lines); `label` is how the chip
/// reads ("Selection · 4 lines", translated by the app).
#[uniffi::export]
pub fn context_chip_selection(text: String, label: String) -> ContextChip {
    aa::ContextChip::selection(&text, label, &redact_for_ai).into()
}

/// The `<context>` block to put in front of the user's message with the
/// chips still there (empty without chips); `label` names the terminal
/// (the host).
#[uniffi::export]
pub fn copilot_context_block(label: String, chips: Vec<ContextChip>) -> String {
    let chips: Vec<aa::ContextChip> = chips.into_iter().map(Into::into).collect();
    aa::context_block(&label, &chips)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn watcher_follows_marked_commands() {
        let w = CommandWatcher::new(None);
        assert!(!w.integrated());
        w.output(b"\x1b]133;A\x07$ ".to_vec(), false);
        assert!(w.integrated());
        assert!(!w.enter(Some("ls nope".into()), Some("$ ".into())));
        let ev = w.output(
            b"\r\n\x1b]133;C\x07ls: nope: No such file or directory\r\n\x1b]133;D;2\x07".to_vec(),
            false,
        );
        assert!(ev.started);
        let ended = ev.ended.unwrap();
        assert_eq!(ended.exit_code, Some(2));
        assert!(!ended.interactive);
        let last = ended.last.unwrap();
        assert_eq!(last.failure, Some(CommandFailure::Exit { code: 2 }));
        assert_eq!(last.output, "ls: nope: No such file or directory");
        assert_eq!(w.last_command(), Some(last.clone()));

        let chip = context_chip_last_command(last, "ls · exit 2".into());
        assert_eq!(chip.kind, ContextChipKind::LastCommand);
        assert!(chip.text.contains("$ ls nope\nls: nope"));
        assert!(chip.text.contains("(exit status 2)"));
        let block = copilot_context_block(
            "web-1".into(),
            vec![
                context_chip_host("web-1".into(), Some("Ubuntu".into())),
                chip,
            ],
        );
        assert!(block.starts_with("<context>\nFrom the user's terminal (web-1):\nHost: web-1\n"));
        assert!(block.ends_with("</context>\n\n"));
        assert_eq!(copilot_context_block("x".into(), vec![]), "");
        w.reset();
        assert!(w.last_command().is_none());
    }

    #[test]
    fn watcher_without_marks_reads_the_screen() {
        let screen = TerminalScreen::new(40, 4, 100);
        screen.feed(b"some old output\r\n$ ".to_vec());
        let w = CommandWatcher::new(Some(screen));
        // Output of a command whose start was not seen, then its prompt.
        assert!(w.enter(Some("sleep 1".into()), Some("$ ".into())));
        assert!(w.waiting_for_prompt());
        assert!(w.idle(false, "$ ".into(), true).is_none(), "not quiet yet");
        w.reset();
        assert!(!w.waiting_for_prompt());
    }

    #[test]
    fn helpers() {
        assert_eq!(
            nl_request("# list big files".into()).as_deref(),
            Some("list big files")
        );
        assert_eq!(nl_request("#!/bin/sh".into()), None);
        assert_eq!(typeable_command("cd /tmp\nls".into()), "cd /tmp; ls");
        assert_eq!(
            command_failure(Some("gti".into()), Some(127), false, String::new()),
            Some(CommandFailure::Exit { code: 127 })
        );
        assert_eq!(
            command_failure(Some("x".into()), Some(130), false, String::new()),
            None
        );
        assert_eq!(
            command_failure(
                Some("cat x".into()),
                None,
                false,
                "cat: x: No such file or directory".into()
            ),
            Some(CommandFailure::Likely)
        );
        assert_eq!(
            clean_terminal_output(b"a\x1b[31mb\x1b[0m\r\n".to_vec()),
            "ab\n"
        );
        assert_eq!(text_tail("a\nb\nc".into(), 2, 100), "b\nc");
        assert_eq!(shorten_text("abcdef".into(), 4, false), "abc…");
        assert_eq!(shorten_text("abcdef".into(), 4, true), "…def");
        let dir = context_chip_directory("/srv/app".into());
        assert_eq!(
            (dir.kind, dir.label.as_str()),
            (ContextChipKind::Directory, "/srv/app")
        );
        let sel = context_chip_selection("line 1\nline 2".into(), "Selection · 2 lines".into());
        assert!(sel.text.contains("line 1\nline 2"));
    }
}
