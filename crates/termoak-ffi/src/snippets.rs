//! Snippets with variables (docs/SSH-PRO.md §7): the template engine of
//! the core for the apps' editors, run dialogs and broadcasts.

use std::collections::{BTreeMap, HashMap};

use termoak_core::template::{self, TemplateContext, VarKind};

use crate::error::{Result, TermoakError};
use crate::models::{parse_id, parse_opt_id};
use crate::runtime::block_on;
use crate::vault::TermoakCore;

/// Kind of snippet variable.
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum SnippetVariableKind {
    /// Filled from the host or the clock (`{{host}}`, `{{date}}`...).
    Builtin,
    /// Free text (`{{prompt:…}}` or a plain `{{name}}`).
    Prompt,
    /// One of `options` (`{{select:…}}`): a picker.
    Select,
    /// Masked text (`{{secret:…}}`): never remember, store or log it.
    Secret,
}

impl From<VarKind> for SnippetVariableKind {
    fn from(k: VarKind) -> Self {
        match k {
            VarKind::Builtin => SnippetVariableKind::Builtin,
            VarKind::Prompt => SnippetVariableKind::Prompt,
            VarKind::Select => SnippetVariableKind::Select,
            VarKind::Secret => SnippetVariableKind::Secret,
        }
    }
}

/// A variable of a snippet.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct SnippetVariable {
    /// What values are keyed by.
    pub key: String,
    pub kind: SnippetVariableKind,
    pub label: String,
    /// Prefilled value (a prompt's default, a select's first option).
    pub default_value: Option<String>,
    pub options: Vec<String>,
    /// A built-in that needs a host (`host`, `label`, `user`, `port`,
    /// `group`): asked only when there is no host.
    pub needs_host: bool,
}

impl From<&template::Variable> for SnippetVariable {
    fn from(v: &template::Variable) -> Self {
        Self {
            key: v.key.clone(),
            kind: v.kind.into(),
            label: v.label.clone(),
            default_value: v.default.clone(),
            options: v.options.clone(),
            needs_host: v.needs_host(),
        }
    }
}

/// A malformed tag (offsets in characters, Unicode scalar values).
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct SnippetIssue {
    pub start: u32,
    pub end: u32,
    pub tag: String,
    pub message: String,
}

/// A parsed snippet.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct SnippetTemplate {
    pub variables: Vec<SnippetVariable>,
    /// Malformed typed tags: show them in the editor; saving fails with
    /// `Invalid` (`apiError.code` `invalid_snippet`) while there are any.
    pub issues: Vec<SnippetIssue>,
}

/// Where a snippet runs: the host's built-ins (`None` fields: no host).
#[derive(Debug, Clone, Default, PartialEq, Eq, uniffi::Record)]
pub struct SnippetContext {
    /// The host's address (`{{host}}`); `None`: no host.
    #[uniffi(default)]
    pub host: Option<String>,
    #[uniffi(default)]
    pub label: Option<String>,
    #[uniffi(default)]
    pub user: Option<String>,
    #[uniffi(default)]
    pub port: Option<u16>,
    #[uniffi(default)]
    pub group: Option<String>,
}

impl From<SnippetContext> for TemplateContext {
    fn from(c: SnippetContext) -> Self {
        TemplateContext {
            host: c.host,
            label: c.label,
            user: c.user,
            port: c.port,
            group: c.group,
            now: None,
        }
    }
}

impl From<TemplateContext> for SnippetContext {
    fn from(c: TemplateContext) -> Self {
        Self {
            host: c.host,
            label: c.label,
            user: c.user,
            port: c.port,
            group: c.group,
        }
    }
}

fn values_of(values: HashMap<String, String>) -> BTreeMap<String, String> {
    values.into_iter().collect()
}

/// Parses a snippet: its variables and issues.
#[uniffi::export]
pub fn parse_snippet(script: String) -> SnippetTemplate {
    let t = template::parse(&script);
    SnippetTemplate {
        variables: t.variables.iter().map(Into::into).collect(),
        issues: t
            .issues
            .iter()
            .map(|i| SnippetIssue {
                start: i.start as u32,
                end: i.end as u32,
                tag: i.tag.clone(),
                message: i.message.clone(),
            })
            .collect(),
    }
}

/// The variables to ask for before running `script` in `context` (no
/// context: also the host built-ins).
#[uniffi::export(default(context = None))]
pub fn snippet_prompts(script: String, context: Option<SnippetContext>) -> Vec<SnippetVariable> {
    let ctx: TemplateContext = context.unwrap_or_default().into();
    template::parse(&script)
        .prompts(&ctx)
        .into_iter()
        .map(Into::into)
        .collect()
}

/// Renders `script` with the asked `values` and the built-ins of
/// `context`. Fails with `Invalid` if a value is missing or a select value
/// is not an option.
#[uniffi::export(default(context = None))]
pub fn render_snippet_with(
    script: String,
    values: HashMap<String, String>,
    context: Option<SnippetContext>,
) -> Result<String> {
    Ok(template::parse(&script).render(&values_of(values), &context.unwrap_or_default().into())?)
}

/// Renders `script` for several hosts at once (broadcast): the same asked
/// `values`, each context's own built-ins; one result per context, in order.
#[uniffi::export]
pub fn render_snippet_for_hosts(
    script: String,
    values: HashMap<String, String>,
    contexts: Vec<SnippetContext>,
) -> Result<Vec<String>> {
    let ctxs: Vec<TemplateContext> = contexts.into_iter().map(Into::into).collect();
    Ok(template::parse(&script).render_for_hosts(&values_of(values), &ctxs)?)
}

#[uniffi::export]
impl TermoakCore {
    /// The built-ins of a host (`{{host}}`, `{{user}}`...) for snippets.
    /// No credentials are fetched (also for Use-only hosts).
    #[uniffi::method(default(account_id))]
    pub fn snippet_context(
        &self,
        host_id: String,
        account_id: Option<String>,
    ) -> Result<SnippetContext> {
        let item = self.item_of(parse_id(&host_id)?, &account_id)?;
        Ok(block_on(self.ws.snippet_context_item(item))?.into())
    }

    /// Values remembered on this device for `snippet_id` on `host_id` (or
    /// for runs without a host).
    #[uniffi::method(default(host_id = None))]
    pub fn snippet_values(
        &self,
        snippet_id: String,
        host_id: Option<String>,
    ) -> Result<HashMap<String, String>> {
        let host = parse_opt_id(&host_id)?;
        Ok(
            block_on(self.ws.snippet_values(parse_id(&snippet_id)?, host))?
                .into_iter()
                .collect(),
        )
    }

    /// Remembers the values of a run on this device (never synced). Secrets
    /// and built-ins are dropped. `script` is the snippet's script.
    #[uniffi::method(default(host_id = None))]
    pub fn remember_snippet_values(
        &self,
        snippet_id: String,
        host_id: Option<String>,
        script: String,
        values: HashMap<String, String>,
    ) -> Result<()> {
        let host = parse_opt_id(&host_id)?;
        let id = parse_id(&snippet_id)?;
        block_on(
            self.ws
                .remember_snippet_values(id, host, &script, &values_of(values)),
        )
        .map_err(TermoakError::from)
    }
}
