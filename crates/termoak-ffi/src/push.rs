//! Push notifications without Firebase (docs-next/PUSH.md): the shared
//! logic the apps need around the system's push service.
//!
//! - Registration: `TermoakCore::register_web_push` (a UnifiedPush endpoint
//!   with its Web Push keys, Android) or `register_push_token` (APNs, iOS);
//!   `push_status` and `set_push_preferences` per account.
//! - Payloads: [`parse_push_payload`] turns what arrived (the decrypted Web
//!   Push message, an APNs `userInfo` as JSON, FCM's data) into a
//!   [`PushEvent`] with what to show: category (Approve/Deny, security key,
//!   just open), channel, a stable notification id and tag, whether it
//!   already expired, and `resolved` to withdraw one.
//! - Web Push keys for receivers that do not decrypt with their own library
//!   ([`webpush_generate_keys`], [`webpush_decrypt`]).

use std::collections::HashMap;

use serde_json::{Value, json};
use termoak_core::push as cp;
use termoak_core::webpush;

use crate::error::{Result, TermoakError};

/// What a notification asks for.
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum PushCategory {
    /// Approve / Deny: each action opens the app's own confirmation (never
    /// decide from the notification itself, and never while the app lock is
    /// on).
    Approval,
    /// Open the app so it connects the events socket and answers the
    /// waiting security key request (`request_id`) before `expires_at`.
    SecurityKey,
    /// Open the right screen.
    Info,
    /// Remove the notification with this `tag` (answered elsewhere or
    /// expired). Show nothing.
    Resolved,
}

impl From<cp::Category> for PushCategory {
    fn from(c: cp::Category) -> Self {
        match c {
            cp::Category::Approval => Self::Approval,
            cp::Category::SecurityKey => Self::SecurityKey,
            cp::Category::Info => Self::Info,
            cp::Category::Resolved => Self::Resolved,
        }
    }
}

/// A received notification, ready to show.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct PushEvent {
    /// `ai_approval`, `ai_finished`, `session_shared`, `session_prompt`,
    /// `join_request`, `control_request`, `team_added`,
    /// `security_key_request`, `access_request`, `test` or `resolved`.
    pub kind: String,
    pub category: PushCategory,
    /// Texts in the account's language (empty for `resolved`).
    pub title: String,
    pub body: String,
    /// Ids for the app: `task_id`, `approval_id`, `session_id`,
    /// `participant`, `prompt_id`, `team_id`, `request_id`...
    pub data: HashMap<String, String>,
    /// The server's `instance_id` and the account's user id it is for (when
    /// the server sent them).
    pub server: Option<String>,
    pub user: Option<String>,
    pub sent_at: i64,
    pub expires_at: Option<i64>,
    /// The request it announces already expired: do not show it.
    pub expired: bool,
    /// Replaces (or, `Resolved`, removes) the notification with the same
    /// tag: the collapse key, else `<kind>-<sent_at>`.
    pub tag: String,
    /// A stable positive number from `tag` (Android's notification id).
    pub notification_id: i32,
    /// Suggested notification channel / thread: `approvals`, `sessions`,
    /// `security_keys`, `ai` or `general`.
    pub channel: String,
}

fn channel_of(kind: &str) -> &'static str {
    match kind {
        "ai_approval" | "access_request" => "approvals",
        "join_request" | "control_request" | "session_prompt" | "session_shared" => "sessions",
        "security_key_request" => "security_keys",
        "ai_finished" => "ai",
        _ => "general",
    }
}

/// FNV-1a, 31 bits: the same tag always gives the same id.
fn stable_id(tag: &str) -> i32 {
    let mut h: u32 = 0x811c_9dc5;
    for b in tag.as_bytes() {
        h ^= *b as u32;
        h = h.wrapping_mul(0x0100_0193);
    }
    (h & 0x7fff_ffff) as i32
}

fn event_from(p: cp::Payload) -> PushEvent {
    let tag = p
        .collapse
        .clone()
        .unwrap_or_else(|| format!("{}-{}", p.kind, p.sent_at));
    PushEvent {
        category: p.category().into(),
        expired: p.is_expired(termoak_core::time::now_ms()),
        notification_id: stable_id(&tag),
        channel: channel_of(&p.kind).to_string(),
        tag,
        kind: p.kind,
        title: p.title,
        body: p.body,
        data: p.data.into_iter().collect(),
        server: p.server,
        user: p.user,
        sent_at: p.sent_at,
        expires_at: p.expires_at,
    }
}

/// Reads a push notification's content: the decrypted Web Push message
/// (UnifiedPush), an APNs `userInfo` serialized as JSON (`{"aps": …,
/// "termoak": {…}}`), the `termoak` dictionary alone or FCM's data map.
#[uniffi::export]
pub fn parse_push_payload(text: String) -> Result<PushEvent> {
    let p = cp::Payload::parse(&text).map_err(|e| TermoakError::Invalid(e.to_string()))?;
    Ok(event_from(p))
}

/// The kinds of notification a device can turn on and off.
#[uniffi::export]
pub fn push_kinds() -> Vec<String> {
    cp::KINDS.iter().map(|k| k.to_string()).collect()
}

/// Which notifications this device wants from an account's server.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct PushPreferences {
    /// Per kind ([`push_kinds`]); a kind not listed is on.
    pub kinds: HashMap<String, bool>,
    /// Also notify while the app has the events socket open (by default the
    /// server is quiet then: the app already shows the event).
    pub when_online: bool,
}

impl Default for PushPreferences {
    fn default() -> Self {
        cp::Preferences::default().into()
    }
}

impl From<cp::Preferences> for PushPreferences {
    fn from(p: cp::Preferences) -> Self {
        Self {
            kinds: p.kinds.into_iter().collect(),
            when_online: p.when_online,
        }
    }
}

impl From<PushPreferences> for cp::Preferences {
    fn from(p: PushPreferences) -> Self {
        Self {
            kinds: p.kinds.into_iter().collect(),
            when_online: p.when_online,
        }
    }
}

/// This device's notifications on one account's server.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct PushStatus {
    /// This device is registered (`platform`: `webpush`, `apns` or `fcm`).
    pub registered: bool,
    pub platform: Option<String>,
    /// The registered UnifiedPush endpoint (APNs/FCM tokens are not shown).
    pub endpoint: Option<String>,
    pub preferences: PushPreferences,
    /// What the server can send: Web Push (UnifiedPush), APNs, FCM.
    pub server_webpush: bool,
    pub server_apns: bool,
    pub server_fcm: bool,
    /// The server's VAPID public key (base64url): some UnifiedPush
    /// distributors ask for it when registering.
    pub vapid_public_key: Option<String>,
    pub kinds: Vec<String>,
}

pub(crate) fn status_from(v: &Value) -> PushStatus {
    let prefs = cp::Preferences::from_json(Some(&v["preferences"].to_string()));
    let platform = v["platform"].as_str().map(str::to_string);
    PushStatus {
        registered: v["registered"].as_bool().unwrap_or(platform.is_some()),
        platform,
        endpoint: v["endpoint"].as_str().map(str::to_string),
        preferences: prefs.into(),
        server_webpush: v["server"]["webpush"].as_bool().unwrap_or(false),
        server_apns: v["server"]["apns"].as_bool().unwrap_or(false),
        server_fcm: v["server"]["fcm"].as_bool().unwrap_or(false),
        vapid_public_key: v["server"]["vapid_public_key"].as_str().map(str::to_string),
        kinds: v["kinds"]
            .as_array()
            .map(|a| {
                a.iter()
                    .filter_map(|k| k.as_str().map(str::to_string))
                    .collect()
            })
            .unwrap_or_else(push_kinds),
    }
}

pub(crate) fn web_push_body(endpoint: &str, p256dh: &str, auth: &str) -> Result<Value> {
    let endpoint = endpoint.trim();
    if !(endpoint.starts_with("https://") || endpoint.starts_with("http://")) {
        return Err(TermoakError::Invalid(
            "the push endpoint must be an http(s) URL".into(),
        ));
    }
    webpush::validate_keys(p256dh, auth).map_err(|e| TermoakError::Invalid(e.to_string()))?;
    Ok(json!({
        "platform": "webpush",
        "endpoint": endpoint,
        "keys": {"p256dh": p256dh.trim(), "auth": auth.trim()},
    }))
}

pub(crate) fn prefs_body(p: PushPreferences) -> Result<Value> {
    let p: cp::Preferences = p.into();
    p.validate()
        .map_err(|e| TermoakError::Invalid(e.to_string()))?;
    Ok(serde_json::to_value(&p).expect("preferences serialize"))
}

/// A receiver's Web Push keys: keep `private_key` on the device; give the
/// server `p256dh` and `auth` with the endpoint.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct WebPushKeys {
    pub private_key: String,
    pub p256dh: String,
    pub auth: String,
}

/// New Web Push keys (for receivers that do not have their own; the
/// UnifiedPush connector library makes and uses its own).
#[uniffi::export]
pub fn webpush_generate_keys() -> WebPushKeys {
    let k = webpush::ReceiverKeys::generate();
    WebPushKeys {
        private_key: k.private_key().to_string(),
        p256dh: k.p256dh(),
        auth: k.auth(),
    }
}

/// Decrypts a Web Push message (`aes128gcm`) with keys from
/// [`webpush_generate_keys`].
#[uniffi::export]
pub fn webpush_decrypt(keys: WebPushKeys, body: Vec<u8>) -> Result<Vec<u8>> {
    let k = webpush::ReceiverKeys::from_parts(&keys.private_key, &keys.auth)
        .map_err(|e| TermoakError::Invalid(e.to_string()))?;
    k.decrypt(&body)
        .map_err(|e| TermoakError::Invalid(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn events_from_every_form() {
        let mut p = cp::Payload::new("ai_approval", "Approval pending", "Waiting")
            .with("task_id", "t")
            .with("approval_id", "a");
        p.collapse = Some("approval-a".into());
        let e = parse_push_payload(p.to_json()).unwrap();
        assert_eq!(e.category, PushCategory::Approval);
        assert_eq!(e.channel, "approvals");
        assert_eq!(e.tag, "approval-a");
        assert!(e.notification_id > 0);
        assert_eq!(e.notification_id, stable_id("approval-a"));
        assert!(!e.expired);
        assert_eq!(e.data["approval_id"], "a");
        // The resolution of the same request has the same id.
        let r = parse_push_payload(cp::Payload::resolved("approval-a").to_json()).unwrap();
        assert_eq!(r.category, PushCategory::Resolved);
        assert_eq!(r.notification_id, e.notification_id);
        // APNs userInfo; an expired security key request.
        let mut sk = cp::Payload::new("security_key_request", "Security key", "Open Termoak")
            .with("request_id", "r1");
        sk.collapse = Some("sk-r1".into());
        sk.expires_at = Some(1);
        let apns = json!({"aps": {"alert": {"title": "x", "body": "y"}}, "termoak": sk.to_flat()});
        let e = parse_push_payload(apns.to_string()).unwrap();
        assert_eq!(e.category, PushCategory::SecurityKey);
        assert_eq!(e.channel, "security_keys");
        assert!(e.expired);
        assert!(parse_push_payload("{}".into()).is_err());
    }

    #[test]
    fn keys_bodies_and_status() {
        let k = webpush_generate_keys();
        let body = webpush::encrypt(&k.p256dh, &k.auth, b"hello").unwrap();
        assert_eq!(webpush_decrypt(k.clone(), body).unwrap(), b"hello");
        let v = web_push_body(" https://ntfy.sh/upX?up=1 ", &k.p256dh, &k.auth).unwrap();
        assert_eq!(v["platform"], "webpush");
        assert_eq!(v["endpoint"], "https://ntfy.sh/upX?up=1");
        assert!(web_push_body("ntfy.sh/x", &k.p256dh, &k.auth).is_err());
        assert!(web_push_body("https://x/y", &k.auth, &k.auth).is_err());
        let mut p = PushPreferences::default();
        assert_eq!(p.kinds.len(), push_kinds().len());
        p.kinds.insert("nope".into(), false);
        assert!(prefs_body(p).is_err());
        let s = status_from(&json!({
            "registered": true, "platform": "webpush", "endpoint": "https://x/y",
            "preferences": {"kinds": {"ai_finished": false}, "when_online": true},
            "server": {"webpush": true, "apns": false, "fcm": false, "vapid_public_key": "BK"},
            "kinds": ["ai_approval"],
        }));
        assert!(s.registered && s.server_webpush && !s.server_apns);
        assert!(!s.preferences.kinds["ai_finished"]);
        assert!(s.preferences.when_online);
        assert_eq!(s.vapid_public_key.as_deref(), Some("BK"));
    }
}
