//! Server account: two-factor authentication, teams, invitations and user
//! administration.
//!
//! Anything without a typed helper here can be called with the generic API
//! (`api_get`, `api_post`...).

use serde_json::{Value, json};
use termoak_core::model as cm;

use crate::accounts::AccountHandle;
use crate::error::{Result, TermoakError};
use crate::models::parse_id;
use crate::remote::ShareInvite;
use crate::server::str_of;
use crate::vault::TermoakCore;

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/// The account's two-factor authentication status.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct TwoFactorStatus {
    pub enabled: bool,
    /// Unused recovery codes.
    pub recovery_codes_left: u32,
}

/// Data to set up the authenticator app (Google Authenticator, 1Password,
/// Aegis...). Show the QR code of `otpauth_url` (see
/// [`qr_code`](crate::qr_code)) or the secret to type it in, then confirm
/// with `enable_two_factor` and a code.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct TwoFactorSetup {
    /// Secret in base32.
    pub secret: String,
    /// URL `otpauth://totp/...`.
    pub otpauth_url: String,
}

/// Role within a team.
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum TeamRole {
    /// Sees the sessions shared with the team.
    Member,
    /// Also adds and removes members.
    Admin,
    /// Also renames or deletes the team and appoints admins.
    Owner,
}

impl From<cm::TeamRole> for TeamRole {
    fn from(r: cm::TeamRole) -> Self {
        match r {
            cm::TeamRole::Member => Self::Member,
            cm::TeamRole::Admin => Self::Admin,
            cm::TeamRole::Owner => Self::Owner,
        }
    }
}

impl From<TeamRole> for cm::TeamRole {
    fn from(r: TeamRole) -> Self {
        match r {
            TeamRole::Member => Self::Member,
            TeamRole::Admin => Self::Admin,
            TeamRole::Owner => Self::Owner,
        }
    }
}

/// A team you belong to.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct Team {
    pub id: String,
    pub name: String,
    /// Your role (`None` if you are a server admin but not a member).
    pub role: Option<TeamRole>,
    pub member_count: u32,
    pub created_at: i64,
}

impl From<cm::Team> for Team {
    fn from(t: cm::Team) -> Self {
        Team {
            id: t.id.to_string(),
            name: t.name,
            role: t.role.map(Into::into),
            member_count: u32::try_from(t.member_count).unwrap_or(0),
            created_at: t.created_at,
        }
    }
}

/// A team member.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct TeamMember {
    pub user_id: String,
    pub email: String,
    pub name: String,
    pub role: TeamRole,
    pub added_at: i64,
}

impl From<cm::TeamMember> for TeamMember {
    fn from(m: cm::TeamMember) -> Self {
        TeamMember {
            user_id: m.user_id.to_string(),
            email: m.email,
            name: m.name,
            role: m.role.into(),
            added_at: m.added_at,
        }
    }
}

/// Who a server session is shared with.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Enum)]
pub enum ShareTarget {
    /// A user of this server, by email.
    User { email: String },
    /// All members of a team you belong to.
    Team { team_id: String },
    /// A link: anyone who has it can join without an account.
    Link,
}

/// Options of a new invitation to a session.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct ShareOptions {
    /// Can ask for (and receive) the keyboard; otherwise only watches.
    pub control: bool,
    /// No expiry if not given.
    pub expires_in_minutes: Option<i64>,
    /// Whoever joins waits until you let them in. `None`: the server's
    /// default (yes for links, no for users and teams).
    pub require_approval: Option<bool>,
    /// Requests for the keyboard are granted without asking you.
    pub auto_grant: bool,
    /// With `auto_grant`: each automatic grant lasts at most this many
    /// minutes (1-240); `None`: no limit.
    #[uniffi(default)]
    pub control_minutes: Option<u32>,
}

/// Changes to an invitation (`None` leaves the field as it is).
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct ShareChanges {
    /// `Some(false)` goes down to view only (the keyboard is taken away).
    pub control: Option<bool>,
    /// New expiry, in minutes from now.
    pub expires_in_minutes: Option<i64>,
    /// Remove the expiry.
    pub no_expiry: bool,
    pub require_approval: Option<bool>,
    pub auto_grant: Option<bool>,
    /// New time limit of automatic grants (1-240 minutes).
    #[uniffi(default)]
    pub control_minutes: Option<u32>,
    /// Remove the time limit of automatic grants.
    #[uniffi(default)]
    pub no_control_limit: bool,
}

/// Who an invitation is for.
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum ShareKind {
    User,
    Team,
    Link,
}

/// An invitation to one of your sessions.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct SessionShareInfo {
    pub id: String,
    pub session_id: String,
    pub kind: ShareKind,
    /// Can ask for the keyboard (otherwise view only).
    pub control: bool,
    pub user_id: Option<String>,
    pub user_email: Option<String>,
    pub user_name: Option<String>,
    pub team_id: Option<String>,
    pub team_name: Option<String>,
    pub expires_at: Option<i64>,
    pub revoked: bool,
    /// Not revoked and not expired.
    pub active: bool,
    pub require_approval: bool,
    pub auto_grant: bool,
    pub created_at: i64,
    /// People in the session with it now.
    pub participants: u32,
    /// Time limit of automatic grants (minutes), if any.
    #[uniffi(default)]
    pub control_minutes: Option<u32>,
}

impl SessionShareInfo {
    pub(crate) fn from_json(v: &Value) -> Self {
        let opt = |k: &str| v[k].as_str().map(str::to_string);
        SessionShareInfo {
            id: str_of(&v["id"]),
            session_id: str_of(&v["session_id"]),
            kind: if v["is_link"].as_bool().unwrap_or(false) {
                ShareKind::Link
            } else if v["team_id"].is_string() {
                ShareKind::Team
            } else {
                ShareKind::User
            },
            control: v["permission"] == "control",
            user_id: opt("user_id"),
            user_email: opt("user_email"),
            user_name: opt("user_name"),
            team_id: opt("team_id"),
            team_name: opt("team_name"),
            expires_at: v["expires_at"].as_i64(),
            revoked: v["revoked"].as_bool().unwrap_or(false),
            active: v["active"]
                .as_bool()
                .unwrap_or(!v["revoked"].as_bool().unwrap_or(false)),
            require_approval: v["require_approval"].as_bool().unwrap_or(false),
            auto_grant: v["auto_grant"].as_bool().unwrap_or(false),
            created_at: v["created_at"].as_i64().unwrap_or(0),
            participants: v["participants"].as_u64().unwrap_or(0) as u32,
            control_minutes: v["control_minutes"].as_u64().map(|m| m as u32),
        }
    }
}

/// `GET /sessions/{id}/shares`.
pub(crate) async fn list_shares(
    api: &termoak_client::ApiClient,
    session: termoak_core::Id,
) -> Result<Vec<SessionShareInfo>> {
    let v: Value = api
        .get(&format!("/api/v1/sessions/{session}/shares"))
        .await?;
    Ok(v.as_array()
        .map(|a| a.iter().map(SessionShareInfo::from_json).collect())
        .unwrap_or_default())
}

/// `PATCH /sessions/{id}/shares/{share_id}`.
pub(crate) async fn update_share(
    api: &termoak_client::ApiClient,
    session: termoak_core::Id,
    share: termoak_core::Id,
    changes: &ShareChanges,
) -> Result<SessionShareInfo> {
    let mut body = json!({"no_expiry": changes.no_expiry});
    if let Some(c) = changes.control {
        body["permission"] = json!(permission(c));
    }
    if let Some(m) = changes.expires_in_minutes {
        body["expires_in_minutes"] = json!(m);
    }
    if let Some(r) = changes.require_approval {
        body["require_approval"] = json!(r);
    }
    if let Some(a) = changes.auto_grant {
        body["auto_grant"] = json!(a);
    }
    if changes.no_control_limit {
        body["no_control_limit"] = json!(true);
    } else if let Some(m) = changes.control_minutes {
        crate::remote::check_minutes(Some(m))?;
        body["control_minutes"] = json!(m);
    }
    let v: Value = api
        .patch(&format!("/api/v1/sessions/{session}/shares/{share}"), &body)
        .await?;
    Ok(SessionShareInfo::from_json(&v))
}

/// Invitation to create an account on the server.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct AccountInvite {
    pub id: String,
    /// Only this email can use it.
    pub email: Option<String>,
    /// The new account will be an admin.
    pub is_admin: bool,
    /// Team joined on sign-up.
    pub team_id: Option<String>,
    pub created_at: i64,
    pub expires_at: Option<i64>,
    pub used_at: Option<i64>,
    pub revoked: bool,
    /// Role in `team_id` on sign-up (`None`: member).
    #[uniffi(default)]
    pub team_role: Option<TeamRole>,
}

impl From<cm::Invite> for AccountInvite {
    fn from(i: cm::Invite) -> Self {
        AccountInvite {
            id: i.id.to_string(),
            email: i.email,
            is_admin: i.is_admin,
            team_id: i.team_id.map(|t| t.to_string()),
            created_at: i.created_at,
            expires_at: i.expires_at,
            used_at: i.used_at,
            revoked: i.revoked,
            team_role: i.team_role.map(Into::into),
        }
    }
}

/// Newly created invitation: the code can only be seen now.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct CreatedAccountInvite {
    pub invite: AccountInvite,
    /// Code for `register(..., invite: code)`.
    pub token: String,
    /// Server URL.
    pub server: String,
    /// Link to open the app directly (`termoak://invite?...`).
    pub app_link: String,
}

/// What is shown before signing up with an invitation.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct InviteInfo {
    /// If tied to an email, only that one can use it.
    pub email: Option<String>,
    /// Team you will join.
    pub team: Option<String>,
    pub expires_at: Option<i64>,
}

/// A server user (admin view).
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct ServerUser {
    pub id: String,
    pub email: String,
    pub name: String,
    pub is_admin: bool,
    pub disabled: bool,
    pub two_factor: bool,
    pub created_at: i64,
    /// Preferred language (BCP 47: `en`, `es`...). The server uses it for
    /// emails; change your own with `set_locale`.
    pub locale: String,
}

impl From<cm::User> for ServerUser {
    fn from(u: cm::User) -> Self {
        ServerUser {
            id: u.id.to_string(),
            email: u.email,
            name: u.name,
            is_admin: u.is_admin,
            disabled: u.disabled,
            two_factor: u.totp_enabled,
            created_at: u.created_at,
            locale: u.locale,
        }
    }
}

/// An audit log entry.
#[derive(Debug, Clone, PartialEq, uniffi::Record)]
pub struct AuditEvent {
    pub id: i64,
    /// User the entry belongs to.
    pub owner_id: String,
    /// Who: `user:<id>`, `ai:<task>`, `guest:<id>`...
    pub actor: String,
    pub action: String,
    pub target: Option<String>,
    /// Details as JSON.
    pub detail_json: String,
    pub created_at: i64,
}

impl From<cm::AuditEntry> for AuditEvent {
    fn from(e: cm::AuditEntry) -> Self {
        AuditEvent {
            id: e.id,
            owner_id: e.owner_id.to_string(),
            actor: e.actor,
            action: e.action,
            target: e.target,
            detail_json: e.detail.to_string(),
            created_at: e.created_at,
        }
    }
}

/// Result of inviting someone to a team by email.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct TeamInviteResult {
    /// They already had an account and are in the team now (`members` is
    /// the updated list).
    pub added: bool,
    pub members: Vec<TeamMember>,
    /// Without an account: the invitation to sign up that adds them to the
    /// team (emailed when the server can send email: `emailed`).
    pub invite: Option<CreatedAccountInvite>,
    pub emailed: bool,
}

/// System push notification service.
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum PushPlatform {
    /// Apple Push Notification service (iOS).
    Apns,
    /// Firebase Cloud Messaging (Android).
    Fcm,
}

fn from_value<T: serde::de::DeserializeOwned>(v: Value) -> Result<T> {
    serde_json::from_value(v)
        .map_err(|e| TermoakError::Server(format!("unexpected server response: {e}")))
}

fn permission(control: bool) -> &'static str {
    if control { "control" } else { "view" }
}

/// Body of `POST /sessions/{id}/shares` for a target.
pub(crate) fn share_body(
    target: &ShareTarget,
    control: bool,
    expires_in_minutes: Option<i64>,
) -> Result<Value> {
    share_body_with(
        target,
        &ShareOptions {
            control,
            expires_in_minutes,
            require_approval: None,
            auto_grant: false,
            control_minutes: None,
        },
    )
}

/// Body of `POST /sessions/{id}/shares` with every option.
pub(crate) fn share_body_with(target: &ShareTarget, opts: &ShareOptions) -> Result<Value> {
    let mut body = json!({
        "permission": permission(opts.control),
        "expires_in_minutes": opts.expires_in_minutes,
        "auto_grant": opts.auto_grant,
    });
    if let Some(r) = opts.require_approval {
        body["require_approval"] = json!(r);
    }
    if let Some(m) = opts.control_minutes {
        crate::remote::check_minutes(Some(m))?;
        body["control_minutes"] = json!(m);
    }
    match target {
        ShareTarget::User { email } => body["email"] = json!(email.trim()),
        ShareTarget::Team { team_id } => body["team_id"] = json!(parse_id(team_id)?),
        ShareTarget::Link => body["link"] = json!(true),
    }
    Ok(body)
}

/// Public data of an invitation (no sign-in needed), to show "you have been
/// invited to…" before signing up.
#[uniffi::export]
pub async fn invite_info(url: String, token: String) -> Result<InviteInfo> {
    crate::vault::install_crypto_provider();
    crate::runtime::run(async move {
        let api = termoak_client::ApiClient::new(&url)?;
        let v = api.invite_info(&token).await?;
        Ok(InviteInfo {
            email: v["email"].as_str().map(str::to_string),
            team: v["team"].as_str().map(str::to_string),
            expires_at: v["expires_at"].as_i64(),
        })
    })
    .await
}

/// A language the server has for emails and notifications.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct ServerLocale {
    /// BCP 47 code (`en`, `es`, `pt-BR`...).
    pub code: String,
    /// Name of the language in that language (`English`, `Español`).
    pub name: String,
}

/// Languages the server at `url` has (no sign-in needed). The apps can offer
/// these, or just send their own language to `set_locale`.
#[uniffi::export]
pub async fn server_locales(url: String) -> Result<Vec<ServerLocale>> {
    crate::vault::install_crypto_provider();
    crate::runtime::run(async move {
        let api = termoak_client::ApiClient::new(&url)?;
        let list = api.locales().await?;
        Ok(list
            .locales
            .into_iter()
            .map(|l| ServerLocale {
                code: l.code,
                name: l.name,
            })
            .collect())
    })
    .await
}

#[uniffi::export]
impl TermoakCore {
    // ----- Account -----

    /// The signed-in user, including their preferred language (`locale`).
    pub async fn current_user(&self) -> Result<ServerUser> {
        self.with_api(|api| async move { Ok(api.me().await?.into()) })
            .await
    }

    /// Saves the preferred language (BCP 47: `en`, `es`...) in the account,
    /// so the server sends emails in it. Call it when the user picks a
    /// language in the app (and after signing in, with the app's language).
    /// Fails if the server does not have that language (see
    /// [`server_locales`](crate::server_locales)). Returns the updated user.
    pub async fn set_locale(&self, locale: String) -> Result<ServerUser> {
        self.with_api(move |api| async move { Ok(api.set_locale(&locale).await?.into()) })
            .await
    }

    // ----- Two-factor authentication -----

    /// Two-factor authentication status.
    pub async fn two_factor_status(&self) -> Result<TwoFactorStatus> {
        self.with_api(|api| async move {
            let v: Value = api.get("/api/v1/me/2fa").await?;
            Ok(TwoFactorStatus {
                enabled: v["enabled"].as_bool().unwrap_or(false),
                recovery_codes_left: v["recovery_codes_left"]
                    .as_u64()
                    .and_then(|n| u32::try_from(n).ok())
                    .unwrap_or(0),
            })
        })
        .await
    }

    /// Starts setting up two-factor authentication (generates a new secret; it
    /// is not enabled until `enable_two_factor`).
    pub async fn setup_two_factor(&self) -> Result<TwoFactorSetup> {
        self.with_api(|api| async move {
            let v: Value = api.post("/api/v1/me/2fa/setup", &json!({})).await?;
            Ok(TwoFactorSetup {
                secret: str_of(&v["secret"]),
                otpauth_url: str_of(&v["otpauth_url"]),
            })
        })
        .await
    }

    /// Enables two-factor authentication with a code from the authenticator
    /// app. Returns the (single-use) recovery codes: show them once so the
    /// user can save them.
    pub async fn enable_two_factor(&self, code: String) -> Result<Vec<String>> {
        self.with_api(move |api| async move {
            let v: Value = api
                .post("/api/v1/me/2fa/enable", &json!({"code": code.trim()}))
                .await?;
            Ok(v["recovery_codes"]
                .as_array()
                .map(|a| {
                    a.iter()
                        .filter_map(|c| c.as_str().map(str::to_string))
                        .collect()
                })
                .unwrap_or_default())
        })
        .await
    }

    /// Disables two-factor authentication (requires the password and a current
    /// or recovery code).
    pub async fn disable_two_factor(&self, password: String, code: String) -> Result<()> {
        self.with_api(move |api| async move {
            let _: Value = api
                .post(
                    "/api/v1/me/2fa/disable",
                    &json!({"password": password, "code": code.trim()}),
                )
                .await?;
            Ok(())
        })
        .await
    }

    // ----- Push notifications -----

    /// Enables notifications on this device with the token the system gives
    /// (on iOS, the `deviceToken` in hex; on Android, the Firebase token).
    /// `sandbox` = iOS app built for development. Returns whether the server
    /// has that service configured. Call it every time the system gives a new
    /// token.
    pub async fn register_push_token(
        &self,
        platform: PushPlatform,
        token: String,
        sandbox: bool,
    ) -> Result<bool> {
        let platform = match platform {
            PushPlatform::Apns => "apns",
            PushPlatform::Fcm => "fcm",
        };
        self.with_api(move |api| async move {
            let v: Value = api
                .post(
                    "/api/v1/push/register",
                    &json!({"platform": platform, "token": token.trim(), "sandbox": sandbox}),
                )
                .await?;
            Ok(v["server_enabled"].as_bool().unwrap_or(false))
        })
        .await
    }

    /// Stops receiving notifications on this device.
    pub async fn unregister_push_token(&self) -> Result<()> {
        self.with_api(|api| async move {
            api.delete("/api/v1/push/register").await?;
            Ok(())
        })
        .await
    }

    /// Sends a test notification to this device.
    pub async fn send_test_push(&self) -> Result<()> {
        self.with_api(|api| async move {
            let _: Value = api.post("/api/v1/push/test", &json!({})).await?;
            Ok(())
        })
        .await
    }

    // ----- Teams -----

    /// Teams you belong to (all of them, if you are an admin).
    pub async fn list_teams(&self) -> Result<Vec<Team>> {
        self.with_api(|api| async move {
            let list: Vec<cm::Team> = from_value(api.get("/api/v1/teams").await?)?;
            Ok(list.into_iter().map(Into::into).collect())
        })
        .await
    }

    /// Creates a team (you will be its owner).
    pub async fn create_team(&self, name: String) -> Result<Team> {
        self.with_api(move |api| async move {
            let t: cm::Team = from_value(
                api.post("/api/v1/teams", &json!({"name": name.trim()}))
                    .await?,
            )?;
            Ok(t.into())
        })
        .await
    }

    /// Renames a team (team owners and admins).
    pub async fn rename_team(&self, team_id: String, name: String) -> Result<Team> {
        let id = parse_id(&team_id)?;
        self.with_api(move |api| async move {
            let t: cm::Team = from_value(
                api.patch(
                    &format!("/api/v1/teams/{id}"),
                    &json!({"name": name.trim()}),
                )
                .await?,
            )?;
            Ok(t.into())
        })
        .await
    }

    /// Deletes a team (owners). Sessions shared with it are revoked.
    pub async fn delete_team(&self, team_id: String) -> Result<()> {
        let id = parse_id(&team_id)?;
        self.with_api(move |api| async move {
            api.delete(&format!("/api/v1/teams/{id}")).await?;
            Ok(())
        })
        .await
    }

    /// Members of a team.
    pub async fn list_team_members(&self, team_id: String) -> Result<Vec<TeamMember>> {
        let id = parse_id(&team_id)?;
        self.with_api(move |api| async move {
            let list: Vec<cm::TeamMember> =
                from_value(api.get(&format!("/api/v1/teams/{id}/members")).await?)?;
            Ok(list.into_iter().map(Into::into).collect())
        })
        .await
    }

    /// Adds a server user by email (team admins; only the owner can appoint
    /// admins). Returns the updated members.
    pub async fn add_team_member(
        &self,
        team_id: String,
        email: String,
        role: TeamRole,
    ) -> Result<Vec<TeamMember>> {
        let id = parse_id(&team_id)?;
        let role = cm::TeamRole::from(role).as_str();
        self.with_api(move |api| async move {
            let list: Vec<cm::TeamMember> = from_value(
                api.post(
                    &format!("/api/v1/teams/{id}/members"),
                    &json!({"email": email.trim(), "role": role}),
                )
                .await?,
            )?;
            Ok(list.into_iter().map(Into::into).collect())
        })
        .await
    }

    /// Changes a member's role. Returns the updated members.
    pub async fn set_team_member_role(
        &self,
        team_id: String,
        user_id: String,
        role: TeamRole,
    ) -> Result<Vec<TeamMember>> {
        let (id, user) = (parse_id(&team_id)?, parse_id(&user_id)?);
        let role = cm::TeamRole::from(role).as_str();
        self.with_api(move |api| async move {
            let list: Vec<cm::TeamMember> = from_value(
                api.patch(
                    &format!("/api/v1/teams/{id}/members/{user}"),
                    &json!({"role": role}),
                )
                .await?,
            )?;
            Ok(list.into_iter().map(Into::into).collect())
        })
        .await
    }

    /// Removes a member (they immediately lose access to the sessions shared
    /// with the team).
    pub async fn remove_team_member(&self, team_id: String, user_id: String) -> Result<()> {
        let (id, user) = (parse_id(&team_id)?, parse_id(&user_id)?);
        self.with_api(move |api| async move {
            api.delete(&format!("/api/v1/teams/{id}/members/{user}"))
                .await?;
            Ok(())
        })
        .await
    }

    /// Leaves a team (the last owner cannot leave: appoint another owner or
    /// delete the team first).
    pub async fn leave_team(&self, team_id: String) -> Result<()> {
        let id = parse_id(&team_id)?;
        self.with_api(move |api| async move {
            let me: Value = api.get("/api/v1/me").await?;
            let user = str_of(&me["user"]["id"]);
            api.delete(&format!("/api/v1/teams/{id}/members/{user}"))
                .await?;
            Ok(())
        })
        .await
    }

    /// Pending invitations of a team (team admins).
    pub async fn list_team_invites(&self, team_id: String) -> Result<Vec<AccountInvite>> {
        let id = parse_id(&team_id)?;
        self.with_api(move |api| async move {
            let list: Vec<cm::Invite> =
                from_value(api.get(&format!("/api/v1/teams/{id}/invites")).await?)?;
            Ok(list.into_iter().map(Into::into).collect())
        })
        .await
    }

    /// Invites someone to a team by email (team admins; only owners appoint
    /// owners): with an account they join at once; otherwise they get an
    /// invitation to sign up (when the server's registration is open or you
    /// are a server admin).
    pub async fn invite_to_team(
        &self,
        team_id: String,
        email: String,
        role: TeamRole,
    ) -> Result<TeamInviteResult> {
        let id = parse_id(&team_id)?;
        let role = cm::TeamRole::from(role).as_str();
        self.with_api(move |api| async move {
            let v: Value = api
                .post(
                    &format!("/api/v1/teams/{id}/invites"),
                    &json!({"email": email.trim(), "role": role}),
                )
                .await?;
            let members: Vec<cm::TeamMember> = match &v["members"] {
                Value::Array(_) => from_value(v["members"].clone())?,
                _ => Vec::new(),
            };
            let invite = if v["invite"].is_object() {
                let invite: cm::Invite = from_value(v["invite"].clone())?;
                Some(CreatedAccountInvite {
                    invite: invite.into(),
                    token: str_of(&v["token"]),
                    server: str_of(&v["server"]),
                    app_link: str_of(&v["url"]),
                })
            } else {
                None
            };
            Ok(TeamInviteResult {
                added: v["added"].as_bool().unwrap_or(false),
                members: members.into_iter().map(Into::into).collect(),
                invite,
                emailed: v["emailed"].as_bool().unwrap_or(false),
            })
        })
        .await
    }

    /// Revokes a pending team invitation.
    pub async fn revoke_team_invite(&self, team_id: String, invite_id: String) -> Result<()> {
        let (id, invite) = (parse_id(&team_id)?, parse_id(&invite_id)?);
        self.with_api(move |api| async move {
            api.delete(&format!("/api/v1/teams/{id}/invites/{invite}"))
                .await?;
            Ok(())
        })
        .await
    }

    /// Shares a persistent server session with a user, a team or through a
    /// link (`control` = can ask for the keyboard; links wait for your
    /// approval).
    pub async fn share_server_session(
        &self,
        session_id: String,
        target: ShareTarget,
        control: bool,
        expires_in_minutes: Option<i64>,
    ) -> Result<ShareInvite> {
        let id = parse_id(&session_id)?;
        let body = share_body(&target, control, expires_in_minutes)?;
        self.with_api(move |api| async move {
            let v: Value = api
                .post(&format!("/api/v1/sessions/{id}/shares"), &body)
                .await?;
            Ok(ShareInvite::from_json(&v))
        })
        .await
    }

    /// Shares a session with every option (waiting room, automatic
    /// keyboard...).
    pub async fn share_server_session_with(
        &self,
        session_id: String,
        target: ShareTarget,
        options: ShareOptions,
    ) -> Result<ShareInvite> {
        let id = parse_id(&session_id)?;
        let body = share_body_with(&target, &options)?;
        self.with_api(move |api| async move {
            let v: Value = api
                .post(&format!("/api/v1/sessions/{id}/shares"), &body)
                .await?;
            Ok(ShareInvite::from_json(&v))
        })
        .await
    }

    /// The invitations of one of your sessions (also revoked and expired ones).
    pub async fn list_server_session_shares(
        &self,
        session_id: String,
    ) -> Result<Vec<SessionShareInfo>> {
        let id = parse_id(&session_id)?;
        self.with_api(move |api| async move { list_shares(&api, id).await })
            .await
    }

    /// Changes an invitation live: whoever uses it gets the new permission
    /// at once (going down to view only takes the keyboard away).
    pub async fn update_server_session_share(
        &self,
        session_id: String,
        share_id: String,
        changes: ShareChanges,
    ) -> Result<SessionShareInfo> {
        let (id, share) = (parse_id(&session_id)?, parse_id(&share_id)?);
        self.with_api(move |api| async move { update_share(&api, id, share, &changes).await })
            .await
    }

    /// Stops sharing a session: every invitation is revoked and everyone but
    /// you leaves. Returns how many invitations were active.
    pub async fn stop_sharing_server_session(&self, session_id: String) -> Result<u32> {
        let id = parse_id(&session_id)?;
        self.with_api(move |api| async move {
            let v: Value = api.delete(&format!("/api/v1/sessions/{id}/shares")).await?;
            Ok(v["revoked"].as_u64().unwrap_or(0) as u32)
        })
        .await
    }

    /// Revokes an invitation to a persistent session (whoever used it and
    /// has no other one leaves).
    pub async fn revoke_server_session_share(
        &self,
        session_id: String,
        share_id: String,
    ) -> Result<()> {
        let (id, share) = (parse_id(&session_id)?, parse_id(&share_id)?);
        self.with_api(move |api| async move {
            api.delete(&format!("/api/v1/sessions/{id}/shares/{share}"))
                .await?;
            Ok(())
        })
        .await
    }

    // ----- Administration (server admins only) -----

    /// The server's users.
    pub async fn admin_list_users(&self) -> Result<Vec<ServerUser>> {
        self.with_api(|api| async move {
            let list: Vec<cm::User> = from_value(api.get("/api/v1/admin/users").await?)?;
            Ok(list.into_iter().map(Into::into).collect())
        })
        .await
    }

    /// Creates a user directly (without an invitation).
    pub async fn admin_create_user(
        &self,
        email: String,
        name: String,
        password: String,
        is_admin: bool,
    ) -> Result<ServerUser> {
        self.with_api(move |api| async move {
            let u: cm::User = from_value(
                api.post(
                    "/api/v1/admin/users",
                    &json!({"email": email.trim(), "name": name.trim(), "password": password, "is_admin": is_admin}),
                )
                .await?,
            )?;
            Ok(u.into())
        })
        .await
    }

    /// Changes the name, the admin role or whether the account is disabled
    /// (`None` = unchanged). Disabling signs the user out everywhere.
    pub async fn admin_update_user(
        &self,
        user_id: String,
        name: Option<String>,
        is_admin: Option<bool>,
        disabled: Option<bool>,
    ) -> Result<ServerUser> {
        let id = parse_id(&user_id)?;
        self.with_api(move |api| async move {
            let u: cm::User = from_value(
                api.patch(
                    &format!("/api/v1/admin/users/{id}"),
                    &json!({"name": name, "is_admin": is_admin, "disabled": disabled}),
                )
                .await?,
            )?;
            Ok(u.into())
        })
        .await
    }

    /// Sets a new password for a user and signs them out everywhere.
    pub async fn admin_reset_password(&self, user_id: String, password: String) -> Result<()> {
        let id = parse_id(&user_id)?;
        self.with_api(move |api| async move {
            let _: Value = api
                .post(
                    &format!("/api/v1/admin/users/{id}/password"),
                    &json!({"password": password}),
                )
                .await?;
            Ok(())
        })
        .await
    }

    /// Removes a user's two-factor authentication (they lost their phone and
    /// recovery codes).
    pub async fn admin_reset_two_factor(&self, user_id: String) -> Result<()> {
        let id = parse_id(&user_id)?;
        self.with_api(move |api| async move {
            let _: Value = api
                .post(&format!("/api/v1/admin/users/{id}/2fa/reset"), &json!({}))
                .await?;
            Ok(())
        })
        .await
    }

    /// Created invitations.
    pub async fn admin_list_invites(&self) -> Result<Vec<AccountInvite>> {
        self.with_api(|api| async move {
            let list: Vec<cm::Invite> = from_value(api.get("/api/v1/admin/invites").await?)?;
            Ok(list.into_iter().map(Into::into).collect())
        })
        .await
    }

    /// Creates an invitation to sign up even when registration is closed.
    /// `expires_in_hours`: 7 days if `None`, no expiry if 0.
    pub async fn admin_create_invite(
        &self,
        email: Option<String>,
        team_id: Option<String>,
        is_admin: bool,
        expires_in_hours: Option<i64>,
    ) -> Result<CreatedAccountInvite> {
        let team = crate::models::parse_opt_id(&team_id)?;
        let email = email
            .map(|e| e.trim().to_string())
            .filter(|e| !e.is_empty());
        self.with_api(move |api| async move {
            let v: Value = api
                .post(
                    "/api/v1/admin/invites",
                    &json!({"email": email, "team_id": team, "is_admin": is_admin, "expires_in_hours": expires_in_hours}),
                )
                .await?;
            let invite: cm::Invite = from_value(v["invite"].clone())?;
            Ok(CreatedAccountInvite {
                invite: invite.into(),
                token: str_of(&v["token"]),
                server: str_of(&v["server"]),
                app_link: str_of(&v["url"]),
            })
        })
        .await
    }

    /// Revokes an unused invitation.
    pub async fn admin_revoke_invite(&self, invite_id: String) -> Result<()> {
        let id = parse_id(&invite_id)?;
        self.with_api(move |api| async move {
            api.delete(&format!("/api/v1/admin/invites/{id}")).await?;
            Ok(())
        })
        .await
    }

    /// Audit log of the whole server, newest first (`before` = id to
    /// paginate).
    pub async fn admin_audit(&self, before: Option<i64>, limit: u32) -> Result<Vec<AuditEvent>> {
        let limit = limit.clamp(1, 500);
        let path = match before {
            Some(b) => format!("/api/v1/admin/audit?limit={limit}&before={b}"),
            None => format!("/api/v1/admin/audit?limit={limit}"),
        };
        self.with_api(move |api| async move {
            let list: Vec<cm::AuditEntry> = from_value(api.get(&path).await?)?;
            Ok(list.into_iter().map(Into::into).collect())
        })
        .await
    }
}

// ---------------------------------------------------------------------------
// The same, per account
// ---------------------------------------------------------------------------

/// The account calls of [`TermoakCore`] for one account (they work on the
/// current account there): its user and language, two-factor
/// authentication, push notifications (register the token on every signed-in
/// account) and teams.
#[uniffi::export]
impl AccountHandle {
    /// This account's user, including its language (`locale`).
    pub async fn current_user(&self) -> Result<ServerUser> {
        self.core().current_user().await
    }

    /// Saves this account's preferred language (BCP 47) on its server.
    pub async fn set_locale(&self, locale: String) -> Result<ServerUser> {
        self.core().set_locale(locale).await
    }

    pub async fn two_factor_status(&self) -> Result<TwoFactorStatus> {
        self.core().two_factor_status().await
    }

    pub async fn setup_two_factor(&self) -> Result<TwoFactorSetup> {
        self.core().setup_two_factor().await
    }

    pub async fn enable_two_factor(&self, code: String) -> Result<Vec<String>> {
        self.core().enable_two_factor(code).await
    }

    pub async fn disable_two_factor(&self, password: String, code: String) -> Result<()> {
        self.core().disable_two_factor(password, code).await
    }

    /// Enables notifications of this account on this device (call it for
    /// every signed-in account, with the same system token).
    pub async fn register_push_token(
        &self,
        platform: PushPlatform,
        token: String,
        sandbox: bool,
    ) -> Result<bool> {
        self.core()
            .register_push_token(platform, token, sandbox)
            .await
    }

    pub async fn unregister_push_token(&self) -> Result<()> {
        self.core().unregister_push_token().await
    }

    pub async fn send_test_push(&self) -> Result<()> {
        self.core().send_test_push().await
    }

    pub async fn list_teams(&self) -> Result<Vec<Team>> {
        self.core().list_teams().await
    }

    pub async fn create_team(&self, name: String) -> Result<Team> {
        self.core().create_team(name).await
    }

    pub async fn rename_team(&self, team_id: String, name: String) -> Result<Team> {
        self.core().rename_team(team_id, name).await
    }

    pub async fn delete_team(&self, team_id: String) -> Result<()> {
        self.core().delete_team(team_id).await
    }

    pub async fn list_team_members(&self, team_id: String) -> Result<Vec<TeamMember>> {
        self.core().list_team_members(team_id).await
    }

    pub async fn add_team_member(
        &self,
        team_id: String,
        email: String,
        role: TeamRole,
    ) -> Result<Vec<TeamMember>> {
        self.core().add_team_member(team_id, email, role).await
    }

    pub async fn set_team_member_role(
        &self,
        team_id: String,
        user_id: String,
        role: TeamRole,
    ) -> Result<Vec<TeamMember>> {
        self.core()
            .set_team_member_role(team_id, user_id, role)
            .await
    }

    pub async fn remove_team_member(&self, team_id: String, user_id: String) -> Result<()> {
        self.core().remove_team_member(team_id, user_id).await
    }

    pub async fn leave_team(&self, team_id: String) -> Result<()> {
        self.core().leave_team(team_id).await
    }

    pub async fn list_team_invites(&self, team_id: String) -> Result<Vec<AccountInvite>> {
        self.core().list_team_invites(team_id).await
    }

    pub async fn invite_to_team(
        &self,
        team_id: String,
        email: String,
        role: TeamRole,
    ) -> Result<TeamInviteResult> {
        self.core().invite_to_team(team_id, email, role).await
    }

    pub async fn revoke_team_invite(&self, team_id: String, invite_id: String) -> Result<()> {
        self.core().revoke_team_invite(team_id, invite_id).await
    }

    /// Shares one of this account's server sessions with every option.
    pub async fn share_server_session_with(
        &self,
        session_id: String,
        target: ShareTarget,
        options: ShareOptions,
    ) -> Result<ShareInvite> {
        self.core()
            .share_server_session_with(session_id, target, options)
            .await
    }

    pub async fn list_server_session_shares(
        &self,
        session_id: String,
    ) -> Result<Vec<SessionShareInfo>> {
        self.core().list_server_session_shares(session_id).await
    }

    pub async fn update_server_session_share(
        &self,
        session_id: String,
        share_id: String,
        changes: ShareChanges,
    ) -> Result<SessionShareInfo> {
        self.core()
            .update_server_session_share(session_id, share_id, changes)
            .await
    }

    pub async fn stop_sharing_server_session(&self, session_id: String) -> Result<u32> {
        self.core().stop_sharing_server_session(session_id).await
    }

    pub async fn revoke_server_session_share(
        &self,
        session_id: String,
        share_id: String,
    ) -> Result<()> {
        self.core()
            .revoke_server_session_share(session_id, share_id)
            .await
    }
}
