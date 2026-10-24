//! Push notification payloads and per-device preferences, shared by the
//! server (which builds them) and the apps (which read them through the
//! FFI): docs-next/PUSH.md.
//!
//! A payload is small and says little: what happened (`type`), the ids the
//! app needs to fetch the details over the API, a short title and body that
//! never carry secrets or commands (unless the server runs with `[push]
//! detailed = true`), and a collapse key so a repeated event replaces the
//! previous notification. `type: "resolved"` withdraws the notification
//! with that collapse key (the request was answered elsewhere, or expired).
//!
//! The same JSON travels inside a Web Push message (UnifiedPush, encrypted
//! for the device), under the `termoak` key of an APNs payload, and as the
//! `data` strings of an FCM message.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::error::{CoreError, Result};

/// Version of the payload format.
pub const VERSION: u32 = 1;

/// The kinds of notification a device can choose (`PushPreferences`).
/// `test` and `resolved` are always delivered.
pub const KINDS: &[&str] = &[
    "ai_approval",
    "ai_finished",
    "session_shared",
    "session_prompt",
    "join_request",
    "control_request",
    "team_added",
    "security_key_request",
    "access_request",
    // 0.7 phase 4b: your access request was approved, denied, revoked or
    // expired (info).
    "access_decided",
];

/// Kinds that are always delivered whatever the preferences say.
pub const ALWAYS: &[&str] = &["test", "resolved"];

/// Kinds that ask the user to decide something (Approve / Deny): the apps
/// show those actions, which open the app's own confirmation.
pub const APPROVALS: &[&str] = &[
    "ai_approval",
    "join_request",
    "control_request",
    "access_request",
];

/// Largest title and body (characters).
pub const MAX_TITLE: usize = 80;
pub const MAX_BODY: usize = 240;

/// What the app should offer for a notification.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Category {
    /// Approve / Deny (each opens the app's confirmation).
    Approval,
    /// Open the app to use a security key (it answers over the events
    /// socket while the request waits).
    SecurityKey,
    /// Just open the right screen.
    Info,
    /// Withdraw the notification with the same collapse key.
    Resolved,
}

impl Category {
    pub fn of(kind: &str) -> Self {
        match kind {
            "resolved" => Self::Resolved,
            "security_key_request" => Self::SecurityKey,
            k if APPROVALS.contains(&k) => Self::Approval,
            _ => Self::Info,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Approval => "approval",
            Self::SecurityKey => "security_key",
            Self::Info => "info",
            Self::Resolved => "resolved",
        }
    }
}

/// A notification as it travels to the device.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Payload {
    /// Format version ([`VERSION`]).
    pub v: u32,
    /// What happened: one of [`KINDS`], `test` or `resolved`.
    #[serde(rename = "type")]
    pub kind: String,
    /// Short texts in the recipient's language (empty for `resolved`).
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub title: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub body: String,
    /// The same key replaces (or, with `resolved`, withdraws) a
    /// notification.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub collapse: Option<String>,
    /// Ids for the app (`task_id`, `approval_id`, `session_id`,
    /// `participant`, `prompt_id`, `team_id`, `request_id`...). Never
    /// secrets.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub data: BTreeMap<String, String>,
    /// The server's `instance_id` (`/info`): which account it is for when a
    /// device has accounts on several servers.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub server: Option<String>,
    /// The account (user id) it is for.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user: Option<String>,
    /// When it was sent and, for requests that wait, when they expire
    /// (Unix milliseconds).
    #[serde(default)]
    pub sent_at: i64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<i64>,
}

fn cut(s: &str, max: usize) -> String {
    let s = s.trim();
    if s.chars().count() <= max {
        return s.to_string();
    }
    let mut out: String = s.chars().take(max.saturating_sub(1)).collect();
    out.push('…');
    out
}

impl Payload {
    pub fn new(kind: &str, title: &str, body: &str) -> Self {
        Self {
            v: VERSION,
            kind: kind.to_string(),
            title: cut(title, MAX_TITLE),
            body: cut(body, MAX_BODY),
            collapse: None,
            data: BTreeMap::new(),
            server: None,
            user: None,
            sent_at: crate::time::now_ms(),
            expires_at: None,
        }
    }

    /// Withdraws the notification with `collapse`.
    pub fn resolved(collapse: &str) -> Self {
        let mut p = Self::new("resolved", "", "");
        p.collapse = Some(collapse.to_string());
        p
    }

    pub fn with(mut self, key: &str, value: impl ToString) -> Self {
        self.data.insert(key.to_string(), value.to_string());
        self
    }

    pub fn category(&self) -> Category {
        Category::of(&self.kind)
    }

    /// Compact JSON (what a Web Push message carries).
    pub fn to_json(&self) -> String {
        serde_json::to_string(self).expect("payload serializes")
    }

    /// The payload as FCM `data` (strings only): the data ids at the top
    /// level, as before, plus `v`, `title`, `body`, `collapse`, `category`,
    /// `server`, `user`, `sent_at` and `expires_at`.
    pub fn to_flat(&self) -> BTreeMap<String, String> {
        let mut m = self.data.clone();
        m.insert("v".into(), self.v.to_string());
        m.insert("type".into(), self.kind.clone());
        m.insert("category".into(), self.category().as_str().into());
        if !self.title.is_empty() {
            m.insert("title".into(), self.title.clone());
        }
        if !self.body.is_empty() {
            m.insert("body".into(), self.body.clone());
        }
        if let Some(c) = &self.collapse {
            m.insert("collapse".into(), c.clone());
        }
        if let Some(s) = &self.server {
            m.insert("server".into(), s.clone());
        }
        if let Some(u) = &self.user {
            m.insert("user".into(), u.clone());
        }
        m.insert("sent_at".into(), self.sent_at.to_string());
        if let Some(e) = self.expires_at {
            m.insert("expires_at".into(), e.to_string());
        }
        m
    }

    /// Reads a payload in any of the forms it travels in: the JSON of a Web
    /// Push message, a whole APNs payload (`{"aps": …, "termoak": {…}}`),
    /// the `termoak` dictionary alone, or FCM's flat `data`.
    pub fn parse(text: &str) -> Result<Self> {
        let v: Value = serde_json::from_str(text.trim())
            .map_err(|e| CoreError::Invalid(format!("not a push payload: {e}")))?;
        Self::from_value(&v)
    }

    pub fn from_value(v: &Value) -> Result<Self> {
        let bad = || CoreError::Invalid("not a Termoak push payload".into());
        let obj = v.as_object().ok_or_else(bad)?;
        // APNs: the payload under `termoak`, the texts in `aps.alert`.
        if let Some(inner) = obj.get("termoak").and_then(Value::as_object) {
            let mut p = Self::from_value(&Value::Object(inner.clone()))?;
            if p.title.is_empty() && p.body.is_empty() {
                let alert = &v["aps"]["alert"];
                p.title = alert["title"].as_str().unwrap_or_default().to_string();
                p.body = alert["body"]
                    .as_str()
                    .or_else(|| alert.as_str())
                    .unwrap_or_default()
                    .to_string();
            }
            return Ok(p);
        }
        let kind = obj.get("type").and_then(Value::as_str).ok_or_else(bad)?;
        let s = |k: &str| match obj.get(k) {
            Some(Value::String(s)) => Some(s.clone()),
            Some(Value::Number(n)) => Some(n.to_string()),
            _ => None,
        };
        let int = |k: &str| s(k).and_then(|x| x.parse::<i64>().ok());
        // The structured form has `data`; the flat one has the ids beside
        // the known fields.
        const KNOWN: &[&str] = &[
            "v",
            "type",
            "title",
            "body",
            "collapse",
            "data",
            "server",
            "user",
            "sent_at",
            "expires_at",
            "category",
            "aps",
        ];
        let mut data = BTreeMap::new();
        match obj.get("data") {
            Some(Value::Object(d)) => {
                for (k, v) in d {
                    match v {
                        Value::String(s) => {
                            data.insert(k.clone(), s.clone());
                        }
                        Value::Number(n) => {
                            data.insert(k.clone(), n.to_string());
                        }
                        Value::Bool(b) => {
                            data.insert(k.clone(), b.to_string());
                        }
                        _ => {}
                    }
                }
            }
            _ => {
                for (k, v) in obj {
                    if KNOWN.contains(&k.as_str()) {
                        continue;
                    }
                    if let Value::String(s) = v {
                        data.insert(k.clone(), s.clone());
                    }
                }
            }
        }
        Ok(Self {
            v: int("v").map(|x| x as u32).unwrap_or(VERSION),
            kind: kind.to_string(),
            title: cut(&s("title").unwrap_or_default(), MAX_TITLE),
            body: cut(&s("body").unwrap_or_default(), MAX_BODY),
            collapse: s("collapse").filter(|c| !c.is_empty()),
            data,
            server: s("server").filter(|c| !c.is_empty()),
            user: s("user").filter(|c| !c.is_empty()),
            sent_at: int("sent_at").unwrap_or(0),
            expires_at: int("expires_at"),
        })
    }

    /// Whether a request that waits has already expired at `now_ms`.
    pub fn is_expired(&self, now_ms: i64) -> bool {
        self.expires_at.is_some_and(|e| e <= now_ms)
    }
}

/// Which notifications a device wants.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Preferences {
    /// Per kind (one of [`KINDS`]); a kind not listed is on.
    #[serde(default)]
    pub kinds: BTreeMap<String, bool>,
    /// Also notify while this device has the events socket open (by default
    /// it is quiet then: the app already shows the event).
    #[serde(default)]
    pub when_online: bool,
}

impl Default for Preferences {
    fn default() -> Self {
        Self {
            kinds: KINDS.iter().map(|k| (k.to_string(), true)).collect(),
            when_online: false,
        }
    }
}

impl Preferences {
    /// Reads stored preferences (anything unreadable is the default).
    pub fn from_json(text: Option<&str>) -> Self {
        text.and_then(|t| serde_json::from_str::<Self>(t).ok())
            .map(Self::normalized)
            .unwrap_or_default()
    }

    /// Every known kind present; unknown ones dropped.
    pub fn normalized(mut self) -> Self {
        self.kinds.retain(|k, _| KINDS.contains(&k.as_str()));
        for k in KINDS {
            self.kinds.entry(k.to_string()).or_insert(true);
        }
        self
    }

    /// Checks a change sent by a client: unknown kinds are an error (a typo
    /// would otherwise switch nothing off).
    pub fn validate(&self) -> Result<()> {
        if let Some(k) = self.kinds.keys().find(|k| !KINDS.contains(&k.as_str())) {
            return Err(CoreError::Invalid(format!(
                "unknown notification kind \"{k}\" (known: {})",
                KINDS.join(", ")
            )));
        }
        Ok(())
    }

    /// Whether the device wants `kind`.
    pub fn allows(&self, kind: &str) -> bool {
        ALWAYS.contains(&kind) || self.kinds.get(kind).copied().unwrap_or(true)
    }

    pub fn to_json(&self) -> String {
        serde_json::to_string(self).expect("preferences serialize")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_in_every_form() {
        let mut p = Payload::new("ai_approval", "Approval pending", "An AI task waits")
            .with("task_id", "t1")
            .with("approval_id", "a1");
        p.collapse = Some("approval-a1".into());
        p.server = Some("srv".into());
        p.user = Some("u1".into());
        p.expires_at = Some(p.sent_at + 60_000);
        assert_eq!(p.category(), Category::Approval);
        // Web Push JSON.
        assert_eq!(Payload::parse(&p.to_json()).unwrap(), p);
        // FCM's flat strings.
        let flat = serde_json::to_string(&p.to_flat()).unwrap();
        assert_eq!(Payload::parse(&flat).unwrap(), p);
        // APNs, with and without the texts inside.
        let apns = serde_json::json!({
            "aps": {"alert": {"title": p.title, "body": p.body}},
            "termoak": p.to_flat(),
        });
        assert_eq!(Payload::from_value(&apns).unwrap(), p);
        let mut flat_no_text = p.to_flat();
        flat_no_text.remove("title");
        flat_no_text.remove("body");
        let apns = serde_json::json!({
            "aps": {"alert": {"title": p.title, "body": p.body}},
            "termoak": flat_no_text,
        });
        assert_eq!(Payload::from_value(&apns).unwrap(), p);
        // An old server's APNs payload (no version, flat ids).
        let old = serde_json::json!({
            "aps": {"alert": {"title": "New team", "body": "You have been added to a team."}},
            "termoak": {"type": "team_added", "team_id": "x"},
        });
        let o = Payload::from_value(&old).unwrap();
        assert_eq!(
            (o.kind.as_str(), o.data["team_id"].as_str()),
            ("team_added", "x")
        );
        assert_eq!(o.body, "You have been added to a team.");
        assert!(Payload::parse("{}").is_err());
        assert!(Payload::parse("nope").is_err());
    }

    #[test]
    fn texts_are_short_and_resolved_is_empty() {
        let p = Payload::new("test", &"t".repeat(200), &"b".repeat(500));
        assert_eq!(p.title.chars().count(), MAX_TITLE);
        assert_eq!(p.body.chars().count(), MAX_BODY);
        let r = Payload::resolved("sk-1");
        assert_eq!(r.category(), Category::Resolved);
        let json = r.to_json();
        assert!(!json.contains("title"));
        assert_eq!(
            Payload::parse(&json).unwrap().collapse.as_deref(),
            Some("sk-1")
        );
        assert_eq!(Category::of("security_key_request"), Category::SecurityKey);
        assert_eq!(Category::of("access_request"), Category::Approval);
        assert_eq!(Category::of("ai_finished"), Category::Info);
    }

    #[test]
    fn preferences() {
        let d = Preferences::default();
        assert!(KINDS.iter().all(|k| d.allows(k)));
        assert!(!d.when_online);
        let mut p = Preferences::from_json(Some(r#"{"kinds":{"ai_finished":false,"bogus":true}}"#));
        assert!(!p.allows("ai_finished"));
        assert!(p.allows("ai_approval"));
        assert!(p.allows("test") && p.allows("resolved"));
        assert!(!p.kinds.contains_key("bogus"));
        assert_eq!(p.kinds.len(), KINDS.len());
        p.kinds.insert("bogus".into(), false);
        assert!(p.validate().is_err());
        assert_eq!(Preferences::from_json(Some("garbage")), d);
        assert_eq!(Preferences::from_json(None), d);
    }
}
