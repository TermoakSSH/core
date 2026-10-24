//! Snippet runs on this device (docs/SSH-PRO.md §7.4): the built-ins of a
//! host and the values remembered per snippet and host (never secrets,
//! never synced: the device store's `meta` table).

use std::collections::BTreeMap;

use termoak_core::Id;
use termoak_core::template::{self, TemplateContext};

use crate::LOCAL_OWNER;
use crate::error::Result;
use crate::items::{ItemRef, Scope};
use crate::workspace::Workspace;

/// Most remembered values kept per snippet and host (and their length).
const MAX_VALUES: usize = 50;
const MAX_VALUE_LEN: usize = 4096;

/// `meta` key of the values of `snippet` on `host` (`*`: runs without a host).
pub fn values_key(snippet: Id, host: Option<Id>) -> String {
    match host {
        Some(h) => format!("snippet_values:{snippet}:{h}"),
        None => format!("snippet_values:{snippet}:*"),
    }
}

/// The values of `values` that may be remembered for `script`: prompts and
/// selects only (no secrets, no built-ins), not too many or too long.
pub fn rememberable(script: &str, values: &BTreeMap<String, String>) -> BTreeMap<String, String> {
    let t = template::parse(script);
    t.variables
        .iter()
        .filter(|v| v.rememberable())
        .filter_map(|v| values.get(&v.key).map(|x| (v.key.clone(), x.clone())))
        .filter(|(_, x)| x.len() <= MAX_VALUE_LEN)
        .take(MAX_VALUES)
        .collect()
}

impl Workspace {
    /// The built-ins of a host for snippets (`{{host}}`, `{{user}}`...).
    pub async fn snippet_context(&self, host_id: Id) -> Result<TemplateContext> {
        let item = self.locate(host_id).await?;
        self.snippet_context_item(item).await
    }

    /// [`snippet_context`](Self::snippet_context) of a host of a scope. It
    /// resolves locally only (no just-in-time credentials for Use-only
    /// hosts: built-ins need no secret).
    pub async fn snippet_context_item(&self, item: ItemRef) -> Result<TemplateContext> {
        let resolved = match item.scope {
            Scope::Device => self.store.resolve_host(LOCAL_OWNER, item.id).await,
            Scope::Account(a) => {
                let acc = self.require_account(a)?;
                match acc.store.locate_local(item.id).await? {
                    Some((_, vault)) => {
                        acc.store
                            .resolve_local(vault, item.id, Some((&self.store, LOCAL_OWNER)))
                            .await
                    }
                    None => Err(termoak_core::CoreError::NotFound(format!(
                        "host {}",
                        item.id
                    ))),
                }
            }
        };
        match resolved {
            Ok(mut r) => {
                let ctx = r.template_context();
                r.zeroize_secrets();
                Ok(ctx)
            }
            // A host without a username yet: what the host itself says.
            Err(termoak_core::CoreError::Invalid(_)) => {
                let host = self
                    .get_item::<termoak_core::model::Host>(item)
                    .await?
                    .record
                    .data;
                Ok(TemplateContext {
                    port: Some(host.settings.port.unwrap_or(host.protocol.default_port())),
                    label: Some(host.label),
                    host: Some(host.address),
                    user: Some(String::new()),
                    group: None,
                    now: None,
                })
            }
            Err(e) => Err(e.into()),
        }
    }

    /// The values remembered for `snippet` on `host` (empty if none).
    pub async fn snippet_values(
        &self,
        snippet: Id,
        host: Option<Id>,
    ) -> Result<BTreeMap<String, String>> {
        Ok(self
            .store
            .meta_get(&values_key(snippet, host))
            .await?
            .and_then(|s| serde_json::from_str(&s).ok())
            .unwrap_or_default())
    }

    /// Remembers the values of a run of `script` (secrets and built-ins are
    /// dropped; see [`rememberable`]).
    pub async fn remember_snippet_values(
        &self,
        snippet: Id,
        host: Option<Id>,
        script: &str,
        values: &BTreeMap<String, String>,
    ) -> Result<()> {
        let keep = rememberable(script, values);
        let json = serde_json::to_string(&keep).unwrap_or_else(|_| "{}".into());
        self.store
            .meta_set(&values_key(snippet, host), &json)
            .await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn secrets_and_builtins_are_never_remembered() {
        let script =
            "deploy {{host}} {{prompt:Branch|main}} {{select:Env|a|b}} {{secret:Token}} {{x}}";
        let values: BTreeMap<String, String> = [
            ("host", "h"),
            ("Branch", "dev"),
            ("Env", "b"),
            ("Token", "s3cr3t"),
            ("x", "1"),
            ("unknown", "y"),
        ]
        .into_iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect();
        let keep = rememberable(script, &values);
        assert_eq!(
            keep.keys().map(String::as_str).collect::<Vec<_>>(),
            ["Branch", "Env", "x"]
        );
        let id = termoak_core::new_id();
        assert!(values_key(id, None).ends_with(":*"));
    }
}
