//! The audit log of an account (0.7 phase 5a, docs-next/E2EE-SSO-AUDIT.md
//! §4): search with filters, export (CSV, JSON, NDJSON), team retention and
//! SIEM sinks (signed webhooks, syslog over TCP/TLS).

use serde_json::{Value, json};
use termoak_core::Id;
use termoak_core::model::AuditEntry;
use termoak_core::store::audit::{
    AuditFilter, AuditSettings, AuditSink, AuditSinkConfig, AuditSinkKind,
};

use crate::accounts::Account;
use crate::error::Result;

/// Whose log.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuditOf {
    /// Your own account.
    Me,
    /// A vault you manage.
    Vault(Id),
    /// A team you own or administer.
    Team(Id),
    /// The whole server (administrators).
    Server,
}

impl AuditOf {
    fn base(self) -> String {
        match self {
            AuditOf::Me => "/api/v1/audit".into(),
            AuditOf::Vault(v) => format!("/api/v1/vaults/{v}/audit"),
            AuditOf::Team(t) => format!("/api/v1/teams/{t}/audit"),
            AuditOf::Server => "/api/v1/admin/audit".into(),
        }
    }

    fn sinks(self) -> Option<String> {
        match self {
            AuditOf::Team(t) => Some(format!("/api/v1/teams/{t}/audit/sinks")),
            AuditOf::Server => Some("/api/v1/admin/audit/sinks".into()),
            _ => None,
        }
    }
}

/// The query string of a filter.
pub fn filter_query(f: &AuditFilter) -> String {
    let mut q = url::form_urlencoded::Serializer::new(String::new());
    let mut add = |k: &str, v: String| {
        q.append_pair(k, &v);
    };
    if let Some(v) = &f.action {
        add("action", v.clone());
    }
    if let Some(v) = &f.actor {
        add("actor", v.clone());
    }
    if let Some(v) = f.vault_id {
        add("vault_id", v.to_string());
    }
    if let Some(v) = &f.target {
        add("target", v.clone());
    }
    if let Some(v) = f.since {
        add("since", v.to_string());
    }
    if let Some(v) = f.until {
        add("until", v.to_string());
    }
    if let Some(v) = &f.q {
        add("q", v.clone());
    }
    if let Some(v) = f.before {
        add("before", v.to_string());
    }
    if let Some(v) = f.after {
        add("after", v.to_string());
    }
    if let Some(v) = f.limit {
        add("limit", v.to_string());
    }
    q.finish()
}

fn not_here() -> crate::error::ClientError {
    crate::error::ClientError::Invalid("sinks belong to a team or to the server".into())
}

impl Account {
    /// Entries matching `filter`, newest first (oldest first with `after`).
    pub async fn audit_search(&self, of: AuditOf, filter: &AuditFilter) -> Result<Vec<AuditEntry>> {
        self.api
            .get(&format!("{}?{}", of.base(), filter_query(filter)))
            .await
    }

    /// Downloads the matching entries to `dest` as `csv`, `json` or
    /// `ndjson` (at most the server's export limit). Returns the bytes.
    pub async fn audit_export(
        &self,
        of: AuditOf,
        filter: &AuditFilter,
        format: &str,
        dest: &std::path::Path,
    ) -> Result<u64> {
        let path = format!(
            "{}/export?format={format}&{}",
            of.base(),
            filter_query(filter)
        );
        self.api.download_to(&path, dest, |_, _| {}).await
    }

    pub async fn audit_settings(&self, team: Id) -> Result<AuditSettings> {
        self.api
            .get(&format!("/api/v1/teams/{team}/audit/settings"))
            .await
    }

    pub async fn set_audit_settings(
        &self,
        team: Id,
        settings: &AuditSettings,
    ) -> Result<AuditSettings> {
        self.api
            .put(
                &format!("/api/v1/teams/{team}/audit/settings"),
                &serde_json::to_value(settings).unwrap_or_default(),
            )
            .await
    }

    pub async fn audit_sinks(&self, of: AuditOf) -> Result<Vec<AuditSink>> {
        self.api.get(&of.sinks().ok_or_else(not_here)?).await
    }

    /// Creates a sink. Webhooks answer with their signing secret once
    /// (`secret`), never again.
    pub async fn create_audit_sink(
        &self,
        of: AuditOf,
        kind: AuditSinkKind,
        name: &str,
        config: &AuditSinkConfig,
        actions: &[String],
    ) -> Result<Value> {
        self.api
            .post(
                &of.sinks().ok_or_else(not_here)?,
                &json!({"kind": kind, "name": name, "config": config, "actions": actions}),
            )
            .await
    }

    pub async fn update_audit_sink(&self, of: AuditOf, id: Id, patch: &Value) -> Result<AuditSink> {
        self.api
            .patch(&format!("{}/{id}", of.sinks().ok_or_else(not_here)?), patch)
            .await
    }

    pub async fn delete_audit_sink(&self, of: AuditOf, id: Id) -> Result<()> {
        self.api
            .delete(&format!("{}/{id}", of.sinks().ok_or_else(not_here)?))
            .await?;
        Ok(())
    }

    /// Sends a test event to a sink now; the answer says whether it arrived.
    pub async fn test_audit_sink(&self, of: AuditOf, id: Id) -> Result<Value> {
        self.api
            .post(
                &format!("{}/{id}/test", of.sinks().ok_or_else(not_here)?),
                &json!({}),
            )
            .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn query_strings() {
        let f = AuditFilter {
            action: Some("access.*,cert.issue".into()),
            q: Some("prod db".into()),
            limit: Some(50),
            ..Default::default()
        };
        assert_eq!(
            filter_query(&f),
            "action=access.*%2Ccert.issue&q=prod+db&limit=50"
        );
        assert_eq!(
            AuditOf::Team(Id::nil()).base(),
            format!("/api/v1/teams/{}/audit", Id::nil())
        );
    }
}
