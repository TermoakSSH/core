//! "Save as runbook": a finished task's executed commands as a snippet.
//!
//! The engine records every command it ran for a task, in order
//! ([`ExecutedStep`]: approved or allowed, with the user's edit if there
//! was one). [`build`] turns them into a multi-line snippet: each command
//! with a comment from the model's explanation, the host-specific parts
//! replaced with `{{host}}` (the host's label or address as a whole word) and
//! files it wrote as `cat > path <<'EOF'` blocks. Tasks run before steps
//! were recorded (or by an older server) are rebuilt from the transcript.

use serde::{Deserialize, Serialize};

use crate::message::{Message, Part};

/// Largest file content kept in a step (bytes).
pub const MAX_STEP_CONTENT: usize = 8 * 1024;

fn is_false(b: &bool) -> bool {
    !*b
}

/// A command (or file write) a task ran.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct ExecutedStep {
    pub call_id: String,
    /// `run_command`, `send_to_terminal` or `write_file`.
    pub tool: String,
    /// Host as the model named it, or the terminal session id.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host: Option<String>,
    /// What ran (the user's edit, if they edited it).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub command: Option<String>,
    /// File written.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    /// Content written (when at most [`MAX_STEP_CONTENT`]).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub content: Option<String>,
    pub ok: bool,
    /// The user edited it before approving.
    #[serde(default, skip_serializing_if = "is_false")]
    pub edited: bool,
    /// The model's `reason` for it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub explanation: Option<String>,
    pub at: i64,
}

/// A host whose label and address become `{{host}}`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct HostNames {
    pub label: String,
    pub address: String,
}

/// A snippet built from a task.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Runbook {
    pub name: String,
    pub description: String,
    pub script: String,
    /// `{{variables}}` of the script.
    pub variables: Vec<String>,
    /// Commands (and file writes) in it.
    pub steps: usize,
}

/// Builds the runbook of a task (see the module docs). `steps` are the
/// recorded ones (empty: rebuilt from `messages`); only the successful
/// ones are kept.
pub fn build(
    title: &str,
    messages: &[Message],
    steps: &[ExecutedStep],
    hosts: &[HostNames],
) -> Runbook {
    let derived;
    let steps = if steps.is_empty() {
        derived = steps_from_messages(messages);
        &derived
    } else {
        steps
    };
    let notes = explanations(messages);
    let mut script = format!("# {}\n", one_line(title, 120));
    let mut count = 0;
    let mut uses_host = false;
    for step in steps.iter().filter(|s| s.ok) {
        let comment = step
            .explanation
            .clone()
            .filter(|e| !e.trim().is_empty())
            .or_else(|| notes.get(&step.call_id).cloned());
        script.push('\n');
        if let Some(c) = comment {
            script.push_str(&format!("# {}\n", one_line(&c, 160)));
        }
        match step.tool.as_str() {
            "write_file" => {
                let Some(path) = &step.path else { continue };
                let path = parameterize(path, hosts, &mut uses_host);
                match &step.content {
                    Some(content) => {
                        let content = parameterize(content, hosts, &mut uses_host);
                        let mut marker = "TERMOAK_EOF".to_string();
                        while content.contains(&marker) {
                            marker.push('_');
                        }
                        script.push_str(&format!("cat > {} <<'{marker}'\n", shell_word(&path)));
                        script.push_str(&content);
                        if !content.ends_with('\n') {
                            script.push('\n');
                        }
                        script.push_str(&format!("{marker}\n"));
                    }
                    None => script
                        .push_str(&format!("# (the task wrote {path}: too long to include)\n")),
                }
            }
            _ => {
                let Some(command) = &step.command else {
                    continue;
                };
                script.push_str(&parameterize(command.trim_end(), hosts, &mut uses_host));
                script.push('\n');
            }
        }
        count += 1;
    }
    let mut variables = Vec::new();
    if uses_host {
        variables.push("host".to_string());
    }
    let first_line = messages
        .iter()
        .find_map(|m| match m {
            Message::User { content } => content.iter().find_map(|p| match p {
                Part::Text { text } => Some(strip_context(text)),
                _ => None,
            }),
            _ => None,
        })
        .unwrap_or_default();
    Runbook {
        name: one_line(title, 80),
        description: one_line(&first_line, 300),
        script,
        variables,
        steps: count,
    }
}

/// The request without the `<context>` blocks.
fn strip_context(text: &str) -> String {
    let mut rest = text.trim_start();
    while rest.starts_with("<context>")
        && let Some(end) = rest.find("</context>")
    {
        rest = rest[end + "</context>".len()..].trim_start();
    }
    rest.to_string()
}

fn one_line(s: &str, max: usize) -> String {
    let line = s
        .lines()
        .map(str::trim)
        .find(|l| !l.is_empty())
        .unwrap_or("");
    let mut out: String = line.chars().take(max).collect();
    if line.chars().count() > max {
        out.push('…');
    }
    out
}

fn shell_word(s: &str) -> String {
    if s.chars()
        .all(|c| c.is_ascii_alphanumeric() || "/._-{}+:@".contains(c))
    {
        s.to_string()
    } else {
        format!("'{}'", s.replace('\'', "'\\''"))
    }
}

/// The one host a task ran its commands on (its label and address become
/// `{{host}}`): the hosts the successful steps name (by id, label or
/// address) among `known`, or else the task's only host (`scope`). `None`
/// when it used several (nothing is parameterised then).
pub fn single_host<'a>(
    steps: &[ExecutedStep],
    scope: Option<&[uuid::Uuid]>,
    known: &'a [(uuid::Uuid, HostNames)],
) -> Option<HostNames> {
    let mut used: Vec<&'a (uuid::Uuid, HostNames)> = Vec::new();
    for step in steps
        .iter()
        .filter(|s| s.ok && s.tool != "send_to_terminal")
    {
        let Some(r) = step.host.as_deref().map(str::trim) else {
            continue;
        };
        let found = known.iter().find(|(id, h)| {
            id.to_string() == r
                || h.label.eq_ignore_ascii_case(r)
                || h.address.eq_ignore_ascii_case(r)
        });
        if let Some(f) = found
            && !used.iter().any(|u| u.0 == f.0)
        {
            used.push(f);
        }
    }
    if used.is_empty()
        && let Some([only]) = scope
    {
        used.extend(known.iter().filter(|(id, _)| id == only));
    }
    match used.as_slice() {
        [one] => Some(one.1.clone()),
        _ => None,
    }
}

/// Replaces the hosts' labels and addresses (whole words, at least 3
/// characters) with `{{host}}`.
pub fn parameterize(text: &str, hosts: &[HostNames], used: &mut bool) -> String {
    let mut names: Vec<&str> = hosts
        .iter()
        .flat_map(|h| [h.label.as_str(), h.address.as_str()])
        .map(str::trim)
        .filter(|n| n.len() >= 3)
        .collect();
    // Longest first (`web1.example.com` before `web1`).
    names.sort_by_key(|n| std::cmp::Reverse(n.len()));
    names.dedup();
    let mut out = text.to_string();
    for name in names {
        let mut result = String::with_capacity(out.len());
        let mut rest = out.as_str();
        let mut prev: Option<char> = None;
        while let Some(i) = rest.find(name) {
            let before = rest[..i].chars().next_back().or(prev);
            let after = rest[i + name.len()..].chars().next();
            let word = |c: Option<char>| {
                c.is_some_and(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
            };
            // `web1.example.com` ends a word at a dot only if it is not a longer name.
            let dot_after = after == Some('.')
                && rest[i + name.len() + 1..]
                    .chars()
                    .next()
                    .is_some_and(|c| c.is_ascii_alphanumeric());
            if word(before) || word(after) || dot_after || before == Some('.') {
                result.push_str(&rest[..i + name.len()]);
            } else {
                result.push_str(&rest[..i]);
                result.push_str("{{host}}");
                *used = true;
            }
            prev = rest[..i + name.len()].chars().next_back();
            rest = &rest[i + name.len()..];
        }
        result.push_str(rest);
        out = result;
    }
    out
}

/// The text the model wrote right before each tool call (its explanation),
/// by call id.
fn explanations(messages: &[Message]) -> std::collections::HashMap<String, String> {
    let mut out = std::collections::HashMap::new();
    for m in messages {
        if let Message::Assistant { content, .. } = m {
            let mut last_text = String::new();
            for p in content {
                match p {
                    Part::Text { text } if !text.trim().is_empty() => last_text = text.clone(),
                    Part::ToolCall { id, input, .. } => {
                        let note = input["reason"]
                            .as_str()
                            .filter(|r| !r.trim().is_empty())
                            .map(str::to_string)
                            .unwrap_or_else(|| last_sentence(&last_text));
                        if !note.is_empty() {
                            out.insert(id.clone(), note);
                        }
                    }
                    _ => {}
                }
            }
        }
    }
    out
}

/// Last non-empty line of a text (what usually introduces the next call).
fn last_sentence(text: &str) -> String {
    text.lines()
        .map(str::trim)
        .rfind(|l| !l.is_empty())
        .unwrap_or("")
        .trim_start_matches(['-', '*', '#', ' '])
        .to_string()
}

/// Results that mean the call did not run.
fn not_run(content: &str) -> bool {
    content.starts_with("Denied:")
        || content.starts_with("The user did NOT approve")
        || content.starts_with("The response was cut off")
        || content.starts_with("Not run:")
        || content.starts_with("Stopped by the user")
}

/// Steps rebuilt from the transcript (older tasks).
pub fn steps_from_messages(messages: &[Message]) -> Vec<ExecutedStep> {
    let mut results = std::collections::HashMap::new();
    for m in messages {
        if let Message::User { content } = m {
            for p in content {
                if let Part::ToolResult {
                    id,
                    content,
                    is_error,
                } = p
                {
                    results.insert(id.clone(), (content.clone(), *is_error));
                }
            }
        }
    }
    let mut out = Vec::new();
    for m in messages {
        let Message::Assistant { content, .. } = m else {
            continue;
        };
        for p in content {
            let Part::ToolCall { id, name, input } = p else {
                continue;
            };
            if !matches!(
                name.as_str(),
                "run_command" | "send_to_terminal" | "write_file"
            ) {
                continue;
            }
            let Some((result, is_error)) = results.get(id) else {
                continue;
            };
            if not_run(result) {
                continue;
            }
            let content_in = input["content"]
                .as_str()
                .filter(|c| c.len() <= MAX_STEP_CONTENT);
            out.push(ExecutedStep {
                call_id: id.clone(),
                tool: name.clone(),
                host: input["host"]
                    .as_str()
                    .or(input["session_id"].as_str())
                    .map(str::to_string),
                command: input["command"]
                    .as_str()
                    .or(input["input"].as_str())
                    .map(str::to_string),
                path: input["path"].as_str().map(str::to_string),
                content: content_in.map(str::to_string),
                ok: !is_error,
                edited: false,
                explanation: input["reason"].as_str().map(str::to_string),
                at: 0,
            });
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    fn call(id: &str, name: &str, input: serde_json::Value) -> Part {
        Part::ToolCall {
            id: id.into(),
            name: name.into(),
            input,
        }
    }

    fn result(id: &str, content: &str, is_error: bool) -> Part {
        Part::ToolResult {
            id: id.into(),
            content: content.into(),
            is_error,
        }
    }

    #[test]
    fn host_names_become_a_variable() {
        let hosts = [HostNames {
            label: "web1".into(),
            address: "10.0.0.5".into(),
        }];
        let mut used = false;
        assert_eq!(
            parameterize(
                "ping -c1 10.0.0.5 && ssh web1 uptime # web10 web1.example.com",
                &hosts,
                &mut used
            ),
            "ping -c1 {{host}} && ssh {{host}} uptime # web10 web1.example.com"
        );
        assert!(used);
        let mut used = false;
        assert_eq!(parameterize("df -h", &hosts, &mut used), "df -h");
        assert!(!used);
        // Too short to be safe.
        let mut used = false;
        let short = [HostNames {
            label: "db".into(),
            address: String::new(),
        }];
        assert_eq!(parameterize("du -sh db", &short, &mut used), "du -sh db");
    }

    #[test]
    fn the_single_host_is_found() {
        let (a, b) = (uuid::Uuid::new_v4(), uuid::Uuid::new_v4());
        let names = |l: &str| HostNames {
            label: l.into(),
            address: format!("{l}.example.com"),
        };
        let known = [(a, names("web1")), (b, names("web2"))];
        let step = |host: &str| ExecutedStep {
            tool: "run_command".into(),
            host: Some(host.into()),
            command: Some("x".into()),
            ok: true,
            ..Default::default()
        };
        assert_eq!(
            single_host(&[step("WEB1")], None, &known),
            Some(names("web1"))
        );
        assert_eq!(
            single_host(
                &[step("web1.example.com"), step(&a.to_string())],
                None,
                &known
            ),
            Some(names("web1"))
        );
        assert_eq!(
            single_host(&[step("web1"), step("web2")], None, &known),
            None
        );
        assert_eq!(single_host(&[], Some(&[b]), &known), Some(names("web2")));
        assert_eq!(single_host(&[], Some(&[a, b]), &known), None);
    }

    #[test]
    fn from_recorded_steps() {
        let messages = vec![
            Message::user_text("<context>\nx\n</context>\n\nFix nginx on web1"),
            Message::Assistant {
                content: vec![
                    Part::Text {
                        text: "First I check the configuration.".into(),
                    },
                    call(
                        "c1",
                        "run_command",
                        json!({"host": "web1", "command": "nginx -t"}),
                    ),
                ],
                native: None,
                provider: None,
            },
        ];
        let steps = vec![
            ExecutedStep {
                call_id: "c1".into(),
                tool: "run_command".into(),
                host: Some("web1".into()),
                command: Some("nginx -t".into()),
                ok: true,
                ..Default::default()
            },
            ExecutedStep {
                call_id: "c2".into(),
                tool: "run_command".into(),
                command: Some("systemctl reload nginx # on web1".into()),
                ok: true,
                edited: true,
                explanation: Some("Reload it".into()),
                ..Default::default()
            },
            ExecutedStep {
                call_id: "c3".into(),
                tool: "run_command".into(),
                command: Some("false".into()),
                ok: false,
                ..Default::default()
            },
            ExecutedStep {
                call_id: "c4".into(),
                tool: "write_file".into(),
                path: Some("/etc/motd".into()),
                content: Some("Welcome to web1\n".into()),
                ok: true,
                ..Default::default()
            },
        ];
        let hosts = [HostNames {
            label: "web1".into(),
            address: "web1.example.com".into(),
        }];
        let rb = build("Fix nginx", &messages, &steps, &hosts);
        assert_eq!(rb.name, "Fix nginx");
        assert_eq!(rb.description, "Fix nginx on web1");
        assert_eq!(rb.steps, 3);
        assert_eq!(rb.variables, ["host"]);
        assert_eq!(
            rb.script,
            "# Fix nginx\n\n# First I check the configuration.\nnginx -t\n\n# Reload it\nsystemctl reload nginx # on {{host}}\n\ncat > /etc/motd <<'TERMOAK_EOF'\nWelcome to {{host}}\nTERMOAK_EOF\n"
        );
    }

    #[test]
    fn from_the_transcript_of_older_tasks() {
        let messages = vec![
            Message::user_text("Clean up"),
            Message::Assistant {
                content: vec![
                    call(
                        "a",
                        "run_command",
                        json!({"host": "h", "command": "rm -rf /tmp/x", "reason": "Remove the old build"}),
                    ),
                    call(
                        "b",
                        "run_command",
                        json!({"host": "h", "command": "rm -rf /"}),
                    ),
                    call("c", "list_hosts", json!({})),
                ],
                native: None,
                provider: None,
            },
            Message::User {
                content: vec![
                    result("a", "host: h | exit code: 0", false),
                    result("b", "The user did NOT approve this action.", true),
                    result("c", "[]", false),
                ],
            },
        ];
        let rb = build("Clean up", &messages, &[], &[]);
        assert_eq!(rb.steps, 1);
        assert_eq!(
            rb.script,
            "# Clean up\n\n# Remove the old build\nrm -rf /tmp/x\n"
        );
        assert!(rb.variables.is_empty());
    }
}
