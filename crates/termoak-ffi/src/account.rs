//! Server account: two-factor authentication, teams, invitations and user
//! administration.
//!
//! Anything without a typed helper here can be called with the generic API
//! (`api_get`, `api_post`...).

use serde_json::{Value, json};
use termoak_core::model as cm;

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
    let mut body = json!({
        "permission": permission(control),
        "expires_in_minutes": expires_in_minutes,
    });
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

    /// Shares a persistent server session with a user, a team or through a
    /// link (`control` = can type).
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

    /// Revokes an invitation to a persistent session (kicks out whoever is
    /// using it).
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
