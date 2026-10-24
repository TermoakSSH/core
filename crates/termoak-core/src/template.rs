//! Snippet templates: `{{variables}}` in snippets (docs/SSH-PRO.md §7).
//!
//! One engine for every app, the server's multi-host runs and startup
//! snippets:
//!
//! - `{{name}}`: a built-in ([`BUILTINS`]) or, for any other name, a prompt
//!   labelled `name` (the pre-0.7 behaviour). Names: letters, digits, `_`
//!   and `-`.
//! - `{{prompt:Label}}`, `{{prompt:Label|default}}`: free text.
//! - `{{select:Label|a|b|c}}`: one of the options (the first is the default).
//! - `{{secret:Label}}`: masked; never remembered, stored or logged.
//! - `\{{` before something that is a tag: a literal `{{`.
//!
//! Anything between `{{` and `}}` that is not a tag stays literal, so a
//! snippet without tags renders byte for byte as written. Malformed typed
//! tags (`{{select:Env}}` without options...) are [`Issue`]s: they render
//! literally, and editors refuse to save them ([`Template::check`]).

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::error::{CoreError, Result};

/// Built-in variables, filled per host (docs/SSH-PRO.md §7.1).
pub const BUILTINS: &[&str] = &[
    "host",
    "label",
    "user",
    "port",
    "group",
    "date",
    "time",
    "datetime",
    "timestamp",
];

/// Built-ins that need a host (the others are the clock).
const HOST_BUILTINS: &[&str] = &["host", "label", "user", "port", "group"];

/// Longest label of a typed tag (characters).
pub const MAX_LABEL: usize = 64;

/// Most variables a snippet may have.
pub const MAX_VARIABLES: usize = 50;

/// Kind of variable.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum VarKind {
    /// Filled from the host or the clock (see [`BUILTINS`]).
    Builtin,
    /// Free text (`{{prompt:…}}`, or a plain `{{name}}` that is not a built-in).
    Prompt,
    /// One of `options` (`{{select:…}}`).
    Select,
    /// Masked text (`{{secret:…}}`).
    Secret,
}

/// A variable of a template (several tags with the same label are one
/// variable).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct Variable {
    /// What values are keyed by: the label (typed tags) or the name.
    pub key: String,
    pub kind: VarKind,
    /// Text to show (the same as `key`).
    pub label: String,
    /// Prefilled value: a prompt's default or a select's first option.
    #[serde(default)]
    pub default: Option<String>,
    /// Options of a select.
    #[serde(default)]
    pub options: Vec<String>,
}

impl Variable {
    /// A built-in that needs a host (`host`, `label`, `user`, `port`, `group`).
    pub fn needs_host(&self) -> bool {
        self.kind == VarKind::Builtin && HOST_BUILTINS.contains(&self.key.as_str())
    }

    /// Whether its value may be remembered (not a secret).
    pub fn rememberable(&self) -> bool {
        matches!(self.kind, VarKind::Prompt | VarKind::Select)
    }
}

/// A malformed typed tag (character offsets into the script).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct Issue {
    /// Offset of the tag's `{{`, in characters (Unicode scalar values).
    pub start: usize,
    /// Offset just after the tag's `}}`, in characters.
    pub end: usize,
    /// The tag as written.
    pub tag: String,
    /// What is wrong (English).
    pub message: String,
}

/// Values a built-in takes from where the snippet runs.
#[derive(Debug, Clone, Default)]
pub struct TemplateContext {
    /// The host's address. `None`: no host (the host built-ins are asked).
    pub host: Option<String>,
    pub label: Option<String>,
    pub user: Option<String>,
    pub port: Option<u16>,
    pub group: Option<String>,
    /// The clock for `date`, `time`... (default: local time now).
    pub now: Option<chrono::DateTime<chrono::FixedOffset>>,
}

impl TemplateContext {
    /// Whether the host built-ins are known.
    pub fn has_host(&self) -> bool {
        self.host.is_some()
    }

    fn now(&self) -> chrono::DateTime<chrono::FixedOffset> {
        self.now
            .unwrap_or_else(|| chrono::Local::now().fixed_offset())
    }

    /// Value of a built-in, if known here.
    pub fn builtin(&self, name: &str) -> Option<String> {
        let host = self.has_host();
        Some(match name {
            "host" => self.host.clone()?,
            "label" if host => self.label.clone().unwrap_or_default(),
            "user" if host => self.user.clone().unwrap_or_default(),
            "port" if host => self.port.map(|p| p.to_string()).unwrap_or_default(),
            "group" if host => self.group.clone().unwrap_or_default(),
            "date" => self.now().format("%Y-%m-%d").to_string(),
            "time" => self.now().format("%H:%M:%S").to_string(),
            "datetime" => self.now().format("%Y-%m-%dT%H:%M:%S").to_string(),
            "timestamp" => self.now().timestamp().to_string(),
            _ => return None,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Segment {
    Text(String),
    /// A tag: the variable it refers to and the tag as written.
    Var {
        var: usize,
        raw: String,
    },
}

/// A parsed snippet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Template {
    segments: Vec<Segment>,
    /// Variables in order of first appearance.
    pub variables: Vec<Variable>,
    /// Malformed typed tags.
    pub issues: Vec<Issue>,
}

/// What a tag's inside is.
enum Tag {
    /// Not a tag: literal.
    None,
    /// A variable definition.
    Var(Variable),
    /// A malformed typed tag (the message).
    Bad(String),
}

fn is_name(s: &str) -> bool {
    !s.is_empty()
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
}

fn classify(inner: &str) -> Tag {
    let inner = inner.trim();
    // (Spaces and line breaks around the inside are trimmed, as before 0.7.)
    if inner.contains('\n') || inner.contains('\r') {
        return Tag::None;
    }
    if is_name(inner) {
        let kind = if BUILTINS.contains(&inner) {
            VarKind::Builtin
        } else {
            VarKind::Prompt
        };
        return Tag::Var(Variable {
            key: inner.to_string(),
            kind,
            label: inner.to_string(),
            default: None,
            options: Vec::new(),
        });
    }
    let Some((prefix, rest)) = inner.split_once(':') else {
        return Tag::None;
    };
    let kind = match prefix.trim_end() {
        "prompt" => VarKind::Prompt,
        "select" => VarKind::Select,
        "secret" => VarKind::Secret,
        _ => return Tag::None,
    };
    let mut parts = rest.splitn(2, '|');
    let label = parts.next().unwrap_or_default().trim().to_string();
    let tail = parts.next();
    if label.is_empty() {
        return Tag::Bad("the variable has no label".into());
    }
    if label.chars().count() > MAX_LABEL {
        return Tag::Bad(format!("the label is longer than {MAX_LABEL} characters"));
    }
    let mut var = Variable {
        key: label.clone(),
        kind,
        label,
        default: None,
        options: Vec::new(),
    };
    match kind {
        VarKind::Prompt => var.default = tail.map(|d| d.trim().to_string()),
        VarKind::Select => {
            for o in tail.unwrap_or_default().split('|') {
                let o = o.trim();
                if !o.is_empty() && !var.options.iter().any(|x| x == o) {
                    var.options.push(o.to_string());
                }
            }
            if var.options.is_empty() {
                return Tag::Bad("a select needs at least one option (select:Label|a|b)".into());
            }
            var.default = var.options.first().cloned();
        }
        VarKind::Secret => {
            if tail.is_some() {
                return Tag::Bad("a secret cannot have a default value".into());
            }
        }
        VarKind::Builtin => unreachable!("typed tags are never built-ins"),
    }
    Tag::Var(var)
}

/// Parses a script. Never fails: what is not a tag stays literal.
pub fn parse(script: &str) -> Template {
    let mut t = Template {
        segments: Vec::new(),
        variables: Vec::new(),
        issues: Vec::new(),
    };
    let mut text = String::new();
    let mut i = 0usize;
    let char_at = |byte: usize| script[..byte].chars().count();
    while i < script.len() {
        let rest = &script[i..];
        let escaped = rest.starts_with("\\{{");
        if escaped || rest.starts_with("{{") {
            let open = if escaped { i + 1 } else { i };
            let after = &script[open + 2..];
            if let Some(end) = after.find("}}") {
                let inner = &after[..end];
                let close = open + 2 + end + 2;
                let raw = &script[open..close];
                match classify(inner) {
                    Tag::None => {}
                    _ if escaped => {
                        // `\{{tag}}`: the tag as literal text.
                        text.push_str(raw);
                        i = close;
                        continue;
                    }
                    Tag::Var(var) => {
                        if !text.is_empty() {
                            t.segments.push(Segment::Text(std::mem::take(&mut text)));
                        }
                        let idx = t.define(var, raw, char_at(open), char_at(close));
                        t.segments.push(Segment::Var {
                            var: idx,
                            raw: raw.to_string(),
                        });
                        i = close;
                        continue;
                    }
                    Tag::Bad(message) => {
                        t.issues.push(Issue {
                            start: char_at(open),
                            end: char_at(close),
                            tag: raw.to_string(),
                            message,
                        });
                    }
                }
            }
            // Not a tag (or malformed): the `{{` is literal; keep scanning
            // right after it (and after the backslash, kept as written).
            let upto = open + 2;
            text.push_str(&script[i..upto]);
            i = upto;
            continue;
        }
        // Copy up to the next `{{` or `\{{` candidate.
        let first = rest.chars().next().map(char::len_utf8).unwrap_or(1);
        let next = rest[first..]
            .find(['{', '\\'])
            .map(|p| i + first + p)
            .unwrap_or(script.len());
        text.push_str(&script[i..next]);
        i = next;
    }
    if !text.is_empty() {
        t.segments.push(Segment::Text(text));
    }
    if t.variables.len() > MAX_VARIABLES {
        t.issues.push(Issue {
            start: 0,
            end: 0,
            tag: String::new(),
            message: format!("a snippet can have at most {MAX_VARIABLES} variables"),
        });
    }
    t
}

impl Template {
    /// Adds (or merges) a variable; returns its index.
    fn define(&mut self, var: Variable, raw: &str, start: usize, end: usize) -> usize {
        if let Some(idx) = self.variables.iter().position(|v| v.key == var.key) {
            let existing = &mut self.variables[idx];
            if existing.kind != var.kind {
                self.issues.push(Issue {
                    start,
                    end,
                    tag: raw.to_string(),
                    message: format!(
                        "\"{}\" is already a {} variable",
                        existing.key,
                        kind_name(existing.kind)
                    ),
                });
            } else if existing.kind == VarKind::Prompt && existing.default.is_none() {
                existing.default = var.default;
            }
            return idx;
        }
        self.variables.push(var);
        self.variables.len() - 1
    }

    /// Whether the script has any tag.
    pub fn has_variables(&self) -> bool {
        !self.variables.is_empty()
    }

    /// Fails with the issues (editors and the REST API refuse to save them).
    pub fn check(&self) -> Result<()> {
        if self.issues.is_empty() {
            return Ok(());
        }
        let list: Vec<String> = self
            .issues
            .iter()
            .map(|i| {
                if i.tag.is_empty() {
                    i.message.clone()
                } else {
                    format!("{}: {}", i.tag, i.message)
                }
            })
            .collect();
        Err(CoreError::vault_detail(
            crate::error::codes::INVALID_SNIPPET,
            format!("invalid snippet: {}", list.join("; ")),
            serde_json::json!({ "issues": self.issues }),
        ))
    }

    /// The variables to ask the user for here: prompts, selects, secrets
    /// and, without a host, the host built-ins.
    pub fn prompts(&self, ctx: &TemplateContext) -> Vec<&Variable> {
        self.variables
            .iter()
            .filter(|v| v.kind != VarKind::Builtin || (v.needs_host() && !ctx.has_host()))
            .collect()
    }

    /// Value of each variable (by index).
    fn values(
        &self,
        values: &BTreeMap<String, String>,
        ctx: &TemplateContext,
    ) -> Result<Vec<String>> {
        self.variables
            .iter()
            .map(|v| {
                if let Some(value) = values.get(&v.key) {
                    if v.kind == VarKind::Select && !v.options.iter().any(|o| o == value) {
                        return Err(CoreError::Invalid(format!(
                            "\"{}\" must be one of: {}",
                            v.label,
                            v.options.join(", ")
                        )));
                    }
                    return Ok(value.clone());
                }
                let found = match v.kind {
                    VarKind::Builtin => ctx.builtin(&v.key),
                    VarKind::Prompt | VarKind::Select => v.default.clone(),
                    VarKind::Secret => None,
                };
                found.ok_or_else(|| CoreError::Invalid(format!("missing variable \"{}\"", v.key)))
            })
            .collect()
    }

    /// Renders the script. `values` are keyed by [`Variable::key`]; a value
    /// given for a built-in wins over the context. Fails if a variable has
    /// no value (a prompt without default, a secret, a host built-in without
    /// a host) or a select value is not one of its options.
    pub fn render(
        &self,
        values: &BTreeMap<String, String>,
        ctx: &TemplateContext,
    ) -> Result<String> {
        let vals = self.values(values, ctx)?;
        let mut out = String::new();
        for s in &self.segments {
            match s {
                Segment::Text(t) => out.push_str(t),
                Segment::Var { var, .. } => out.push_str(&vals[*var]),
            }
        }
        Ok(out)
    }

    /// Renders for several hosts at once (broadcast, multi-run): the same
    /// prompted `values`, each host's own built-ins.
    pub fn render_for_hosts(
        &self,
        values: &BTreeMap<String, String>,
        contexts: &[TemplateContext],
    ) -> Result<Vec<String>> {
        contexts.iter().map(|c| self.render(values, c)).collect()
    }

    /// Renders what can be filled without asking: built-ins known here,
    /// prompt defaults and the first option of selects. Any other tag stays
    /// as written (startup snippets cannot ask).
    pub fn render_known(&self, ctx: &TemplateContext) -> String {
        let mut out = String::new();
        for s in &self.segments {
            match s {
                Segment::Text(t) => out.push_str(t),
                Segment::Var { var, raw } => {
                    let v = &self.variables[*var];
                    let value = match v.kind {
                        VarKind::Builtin => ctx.builtin(&v.key),
                        VarKind::Prompt | VarKind::Select => v.default.clone(),
                        VarKind::Secret => None,
                    };
                    out.push_str(value.as_deref().unwrap_or(raw));
                }
            }
        }
        out
    }
}

fn kind_name(k: VarKind) -> &'static str {
    match k {
        VarKind::Builtin => "built-in",
        VarKind::Prompt => "prompt",
        VarKind::Select => "select",
        VarKind::Secret => "secret",
    }
}

/// Startup snippets: [`Template::render_known`] of `script`.
pub fn render_startup(script: &str, ctx: &TemplateContext) -> String {
    parse(script).render_known(ctx)
}

/// Escapes text so it renders literally (`{{` → `\{{` where it would be a
/// tag). Used for commands recorded by the AI (runbooks).
pub fn escape(text: &str) -> String {
    let t = parse(text);
    if t.variables.is_empty() && t.issues.is_empty() {
        return text.to_string();
    }
    let mut out = String::with_capacity(text.len() + 8);
    for s in &t.segments {
        match s {
            Segment::Text(x) => out.push_str(x),
            Segment::Var { raw, .. } => {
                out.push('\\');
                out.push_str(raw);
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn vals(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    }

    fn host_ctx() -> TemplateContext {
        TemplateContext {
            host: Some("10.0.0.5".into()),
            label: Some("web1".into()),
            user: Some("deploy".into()),
            port: Some(2222),
            group: Some("Prod".into()),
            now: Some(chrono::DateTime::parse_from_rfc3339("2026-10-24T09:08:07+02:00").unwrap()),
        }
    }

    #[test]
    fn plain_text_is_untouched() {
        for s in [
            "",
            "ls -la",
            "echo {{",
            "echo }} {{",
            "docker inspect -f '{{.State.Running}}' x",
            "helm {{ .Values.image }}",
            "{{#each items}}{{/each}}",
            "a {{foo:bar}} b",
            "{{a b}}",
            "grep '\\{{' file",
            "\\{{ not a tag }}",
            "ünïcödé {{ ✓ }}",
        ] {
            let t = parse(s);
            assert!(t.variables.is_empty(), "{s}");
            assert!(t.issues.is_empty(), "{s}");
            assert_eq!(
                t.render(&BTreeMap::new(), &TemplateContext::default())
                    .unwrap(),
                s
            );
            assert_eq!(escape(s), s);
        }
    }

    #[test]
    fn legacy_names_are_prompts() {
        let t = parse("journalctl -u {{service}} -n {{ lines }} | grep {{service}}");
        let keys: Vec<_> = t.variables.iter().map(|v| v.key.as_str()).collect();
        assert_eq!(keys, ["service", "lines"]);
        assert!(t.variables.iter().all(|v| v.kind == VarKind::Prompt));
        let ctx = TemplateContext::default();
        assert!(t.render(&vals(&[("service", "nginx")]), &ctx).is_err());
        assert_eq!(
            t.render(&vals(&[("service", "nginx"), ("lines", "50")]), &ctx)
                .unwrap(),
            "journalctl -u nginx -n 50 | grep nginx"
        );
    }

    #[test]
    fn builtins_per_host() {
        let t = parse(
            "ssh {{user}}@{{host}} -p {{port}} # {{label}} {{group}} {{date}} {{time}} {{datetime}} {{timestamp}}",
        );
        assert!(t.variables.iter().all(|v| v.kind == VarKind::Builtin));
        let ctx = host_ctx();
        assert!(t.prompts(&ctx).is_empty());
        assert_eq!(
            t.render(&BTreeMap::new(), &ctx).unwrap(),
            format!(
                "ssh deploy@10.0.0.5 -p 2222 # web1 Prod 2026-10-24 09:08:07 2026-10-24T09:08:07 {}",
                ctx.now.unwrap().timestamp()
            )
        );
        // Without a host: the host built-ins are asked, the clock is not.
        let none = TemplateContext::default();
        let asked: Vec<_> = t.prompts(&none).iter().map(|v| v.key.as_str()).collect();
        assert_eq!(asked, ["user", "host", "port", "label", "group"]);
        assert!(t.render(&BTreeMap::new(), &none).is_err());
        // A value given for a built-in wins (older clients ask for it).
        let out = parse("ping {{host}}")
            .render(&vals(&[("host", "other")]), &ctx)
            .unwrap();
        assert_eq!(out, "ping other");
    }

    #[test]
    fn typed_tags() {
        let s = "git checkout {{prompt:Branch|main}} && deploy --env {{select:Env| prod |staging|prod||dev}} --token {{secret:Token}} # {{ prompt: Branch }}";
        let t = parse(s);
        assert!(t.issues.is_empty(), "{:?}", t.issues);
        assert_eq!(t.variables.len(), 3);
        let b = &t.variables[0];
        assert_eq!(
            (b.kind, b.key.as_str(), b.default.as_deref()),
            (VarKind::Prompt, "Branch", Some("main"))
        );
        let e = &t.variables[1];
        assert_eq!(e.kind, VarKind::Select);
        assert_eq!(e.options, ["prod", "staging", "dev"]);
        assert_eq!(e.default.as_deref(), Some("prod"));
        assert_eq!(t.variables[2].kind, VarKind::Secret);
        assert!(!t.variables[2].rememberable());
        let ctx = TemplateContext::default();
        // The secret has no default.
        assert!(t.render(&BTreeMap::new(), &ctx).is_err());
        assert_eq!(
            t.render(&vals(&[("Token", "s3cr3t")]), &ctx).unwrap(),
            "git checkout main && deploy --env prod --token s3cr3t # main"
        );
        assert_eq!(
            t.render(
                &vals(&[("Token", "x"), ("Env", "dev"), ("Branch", "fix")]),
                &ctx
            )
            .unwrap(),
            "git checkout fix && deploy --env dev --token x # fix"
        );
        // A select value must be an option.
        assert!(
            t.render(&vals(&[("Token", "x"), ("Env", "qa")]), &ctx)
                .is_err()
        );
        // Pipes in a prompt default after the first one are kept.
        let p = parse("{{prompt:Cmd|ps aux | grep x}}");
        assert_eq!(p.variables[0].default.as_deref(), Some("ps aux | grep x"));
        // An empty default is a default.
        let p = parse("x{{prompt:Suffix|}}y");
        assert_eq!(p.render(&BTreeMap::new(), &ctx).unwrap(), "xy");
    }

    #[test]
    fn same_label_is_one_variable() {
        let t = parse("{{env}} {{prompt:env|dev}} {{env}}");
        assert_eq!(t.variables.len(), 1);
        assert_eq!(t.variables[0].default.as_deref(), Some("dev"));
        assert_eq!(
            t.render(&BTreeMap::new(), &TemplateContext::default())
                .unwrap(),
            "dev dev dev"
        );
        let t = parse("{{select:X|a|b}} {{prompt:X}}");
        assert_eq!(t.issues.len(), 1);
        assert!(t.issues[0].message.contains("select"));
    }

    #[test]
    fn malformed_typed_tags_are_issues_and_literal() {
        for (s, msg) in [
            ("a {{prompt:}} b", "no label"),
            ("a {{prompt: |x}} b", "no label"),
            ("a {{select:Env}} b", "at least one option"),
            ("a {{select:Env| | }} b", "at least one option"),
            ("a {{secret:Pass|x}} b", "default"),
        ] {
            let t = parse(s);
            assert_eq!(t.issues.len(), 1, "{s}");
            assert!(
                t.issues[0].message.contains(msg),
                "{s}: {}",
                t.issues[0].message
            );
            assert_eq!(
                t.render(&BTreeMap::new(), &TemplateContext::default())
                    .unwrap(),
                s
            );
            assert!(t.check().is_err());
            assert_eq!(t.issues[0].start, 2);
        }
        let long = format!("{{{{prompt:{}}}}}", "x".repeat(MAX_LABEL + 1));
        assert_eq!(parse(&long).issues.len(), 1);
        let ok = format!("{{{{prompt:{}}}}}", "é".repeat(MAX_LABEL));
        assert!(parse(&ok).issues.is_empty());
        let many: String = (0..=MAX_VARIABLES)
            .map(|i| format!("{{{{v{i}}}}}"))
            .collect();
        assert_eq!(parse(&many).issues.len(), 1);
        // Offsets are in characters.
        let t = parse("ñ {{select:E}}");
        assert_eq!((t.issues[0].start, t.issues[0].end), (2, 14));
    }

    #[test]
    fn escaping() {
        let t = parse("echo \\{{host}} {{host}}");
        assert_eq!(t.variables.len(), 1);
        assert_eq!(
            t.render(&BTreeMap::new(), &host_ctx()).unwrap(),
            "echo {{host}} 10.0.0.5"
        );
        // A backslash before something that is not a tag stays.
        assert_eq!(
            parse("a \\{{ x y }} \\{{")
                .render(&BTreeMap::new(), &TemplateContext::default())
                .unwrap(),
            "a \\{{ x y }} \\{{"
        );
        // escape() makes a text render as written.
        for s in ["cat {{host}} | x", "{{prompt:A|b}} {{ .x }}"] {
            let e = escape(s);
            assert_eq!(
                parse(&e)
                    .render(&BTreeMap::new(), &TemplateContext::default())
                    .unwrap(),
                s
            );
        }
    }

    #[test]
    fn nested_and_unterminated() {
        // The first `{{` is literal and the inner tag still counts (as before).
        let t = parse("{{ {{name}}");
        assert_eq!(t.variables.len(), 1);
        assert_eq!(
            t.render(&vals(&[("name", "x")]), &TemplateContext::default())
                .unwrap(),
            "{{ x"
        );
        let t = parse("{{{{host}}}}");
        assert_eq!(
            t.render(&BTreeMap::new(), &host_ctx()).unwrap(),
            "{{10.0.0.5}}"
        );
        let t = parse("echo {{host");
        assert!(t.variables.is_empty());
    }

    #[test]
    fn render_known_for_startup() {
        let s = "cd /srv/{{label}} && export E={{select:Env|prod|dev}} B={{prompt:B|main}} T={{secret:T}} X={{x}} D={{date}}";
        assert_eq!(
            render_startup(s, &host_ctx()),
            "cd /srv/web1 && export E=prod B=main T={{secret:T}} X={{x}} D=2026-10-24"
        );
        assert_eq!(
            render_startup("plain {{ .x }}", &host_ctx()),
            "plain {{ .x }}"
        );
    }

    #[test]
    fn many_hosts() {
        let t = parse("echo {{label}} {{prompt:Msg}}");
        let mut a = host_ctx();
        let mut b = host_ctx();
        a.label = Some("a".into());
        b.label = Some("b".into());
        assert_eq!(
            t.render_for_hosts(&vals(&[("Msg", "hi")]), &[a, b])
                .unwrap(),
            ["echo a hi", "echo b hi"]
        );
    }

    /// The shared vectors (also for the web's implementation).
    #[test]
    fn vectors() {
        #[derive(Deserialize)]
        struct Case {
            script: String,
            #[serde(default)]
            values: BTreeMap<String, String>,
            #[serde(default)]
            host: bool,
            #[serde(default)]
            variables: Vec<String>,
            #[serde(default)]
            prompts: Option<Vec<String>>,
            #[serde(default)]
            issues: usize,
            #[serde(default)]
            output: Option<String>,
            #[serde(default)]
            error: bool,
        }
        #[derive(Deserialize)]
        struct Vectors {
            cases: Vec<Case>,
        }
        let cases = serde_json::from_str::<Vectors>(include_str!("../tests/template_vectors.json"))
            .unwrap()
            .cases;
        assert!(cases.len() > 20);
        for c in cases {
            let t = parse(&c.script);
            let ctx = if c.host {
                host_ctx()
            } else {
                TemplateContext::default()
            };
            let keys: Vec<String> = t.variables.iter().map(|v| v.key.clone()).collect();
            assert_eq!(keys, c.variables, "{}", c.script);
            assert_eq!(t.issues.len(), c.issues, "{}", c.script);
            if let Some(p) = c.prompts {
                let asked: Vec<String> = t.prompts(&ctx).iter().map(|v| v.key.clone()).collect();
                assert_eq!(asked, p, "{}", c.script);
            }
            match t.render(&c.values, &ctx) {
                Ok(out) => {
                    assert!(!c.error, "{} rendered {out:?}", c.script);
                    assert_eq!(Some(out), c.output, "{}", c.script);
                }
                Err(e) => assert!(c.error, "{}: {e}", c.script),
            }
        }
    }
}
