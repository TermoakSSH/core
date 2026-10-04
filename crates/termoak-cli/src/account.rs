//! Account, server administration and teams from the terminal.

use anyhow::{Context, Result, bail};
use clap::Subcommand;
use serde_json::{Value, json};
use termoak_client::{ApiClient, Workspace};

use crate::data::need_server;
use crate::{out, prompt};

#[derive(Subcommand)]
pub enum TwoFaCmd {
    /// Two-factor authentication status.
    Status,
    /// Enables two-factor authentication (shows a QR code for your phone).
    Enable,
    /// Disables two-factor authentication.
    Disable,
}

#[derive(Subcommand)]
pub enum AdminCmd {
    /// Lists the server's users.
    Users,
    /// Creates an invitation to sign up (even if registration is closed).
    Invite {
        /// Only this email can use it.
        #[arg(long)]
        email: Option<String>,
        /// The account will be an administrator.
        #[arg(long)]
        admin: bool,
        /// Team the account joins on sign-up (name or id).
        #[arg(long)]
        team: Option<String>,
        /// Expiry in hours (0 = never).
        #[arg(long, default_value_t = 168)]
        hours: i64,
    },
    /// Lists the invitations.
    Invites,
    /// Revokes an invitation.
    RevokeInvite { id: String },
    /// Disables an account (signs it out everywhere).
    Disable { email: String },
    /// Re-enables an account.
    Enable { email: String },
    /// Grants the administrator role.
    MakeAdmin { email: String },
    /// Removes the administrator role.
    RemoveAdmin { email: String },
    /// Sets a new password (signs the account out everywhere).
    ResetPassword { email: String },
    /// Removes two-factor authentication (lost phone).
    #[command(name = "reset-2fa")]
    Reset2fa { email: String },
    /// A user's signed-in devices.
    Devices { email: String },
    /// Changes an account's plan (catalog id: free, pro...).
    Plan { email: String, plan: String },
    /// Changes a team's plan.
    TeamPlan { team: String, plan: String },
    /// Marks an account's email as verified.
    VerifyEmail { email: String },
    /// Audit log of the whole server.
    Audit {
        #[arg(long, default_value_t = 50)]
        limit: i64,
    },
}

#[derive(Subcommand)]
pub enum TeamsCmd {
    /// Your teams.
    List,
    /// Creates a team (you become its owner).
    Create { name: String },
    /// A team's members.
    Show { team: String },
    /// Adds a server user (member, admin or owner).
    Add {
        team: String,
        email: String,
        #[arg(long, default_value = "member")]
        role: String,
    },
    /// Changes a member's role.
    Role {
        team: String,
        email: String,
        role: String,
    },
    /// Removes a member.
    Remove { team: String, email: String },
    /// Invites by email: with an account they join directly; otherwise they
    /// get an invitation to sign up (member, admin or owner).
    Invite {
        team: String,
        email: String,
        #[arg(long, default_value = "member")]
        role: String,
    },
    /// Leaves a team.
    Leave { team: String },
    /// Deletes a team.
    Delete { team: String },
}

#[derive(Subcommand)]
pub enum AccountCmd {
    /// Your plan, its limits and your usage.
    Plan,
    /// Resends the email to confirm your address.
    VerifyEmail,
    /// Changes your account's email (confirmed from the new address).
    ChangeEmail { email: String },
    /// Requests a link to set a new password (without signing in).
    ForgotPassword { server: String, email: String },
    /// Deletes your account and all its data from the server.
    Delete,
}

fn s<'a>(v: &'a Value, k: &str) -> &'a str {
    v[k].as_str().unwrap_or("")
}

/// Finds one of your teams by name or id.
pub async fn find_team(api: &ApiClient, team: &str) -> Result<Value> {
    let teams: Value = api.get("/api/v1/teams").await?;
    let list = teams.as_array().cloned().unwrap_or_default();
    let found: Vec<Value> = list
        .into_iter()
        .filter(|t| s(t, "id") == team || s(t, "name").eq_ignore_ascii_case(team))
        .collect();
    match found.len() {
        1 => Ok(found.into_iter().next().unwrap_or_default()),
        0 => bail!("you are not a member of any team \"{team}\""),
        _ => bail!("there are several teams \"{team}\": use its id"),
    }
}

async fn member_id(api: &ApiClient, team_id: &str, email: &str) -> Result<String> {
    let members: Value = api.get(&format!("/api/v1/teams/{team_id}/members")).await?;
    members
        .as_array()
        .into_iter()
        .flatten()
        .find(|m| s(m, "email").eq_ignore_ascii_case(email))
        .map(|m| s(m, "user_id").to_string())
        .with_context(|| format!("{email} is not a member of the team"))
}

async fn user_by_email(api: &ApiClient, email: &str) -> Result<Value> {
    let users: Value = api.get("/api/v1/admin/users").await?;
    users
        .as_array()
        .into_iter()
        .flatten()
        .find(|u| s(u, "email").eq_ignore_ascii_case(email))
        .cloned()
        .with_context(|| format!("no user {email}"))
}

fn date(ms: i64) -> String {
    chrono::DateTime::from_timestamp_millis(ms)
        .map(|d| {
            d.with_timezone(&chrono::Local)
                .format("%Y-%m-%d %H:%M")
                .to_string()
        })
        .unwrap_or_default()
}

pub async fn two_fa(ws: &Workspace, cmd: TwoFaCmd, json: bool) -> Result<()> {
    let api = need_server(ws).await?;
    match cmd {
        TwoFaCmd::Status => {
            let v: Value = api.get("/api/v1/me/2fa").await?;
            out(json, &v, || {
                if v["enabled"] == true {
                    println!(
                        "Two-factor authentication enabled ({} unused recovery codes).",
                        v["recovery_codes_left"]
                    );
                } else {
                    println!(
                        "Two-factor authentication disabled. Enable it with `termoak 2fa enable`."
                    );
                }
            });
        }
        TwoFaCmd::Enable => {
            let setup: Value = api.post("/api/v1/me/2fa/setup", &json!({})).await?;
            let url = s(&setup, "otpauth_url");
            println!(
                "Scan this code with your authenticator app (Aegis, Google Authenticator, 1Password…):\n"
            );
            if let Some(qr) = termoak_client::qr::terminal(url) {
                println!("{qr}");
            }
            println!("Or enter the secret by hand: {}\n", s(&setup, "secret"));
            let code = prompt::ask_line("Code shown by the app: ")?;
            let v: Value = api
                .post("/api/v1/me/2fa/enable", &json!({"code": code.trim()}))
                .await?;
            println!("\nTwo-factor authentication enabled.");
            println!("Keep these recovery codes somewhere safe (each one works once):\n");
            for c in v["recovery_codes"].as_array().into_iter().flatten() {
                println!("  {}", c.as_str().unwrap_or(""));
            }
        }
        TwoFaCmd::Disable => {
            let password = prompt::password_from_env_or("Password: ")?;
            let code = prompt::ask_line("App code or recovery code: ")?;
            api.post::<Value>(
                "/api/v1/me/2fa/disable",
                &json!({"password": password, "code": code.trim()}),
            )
            .await?;
            println!("Two-factor authentication disabled.");
        }
    }
    Ok(())
}

pub async fn admin(ws: &Workspace, cmd: AdminCmd, json: bool) -> Result<()> {
    let api = need_server(ws).await?;
    match cmd {
        AdminCmd::Users => {
            let v: Value = api.get("/api/v1/admin/users").await?;
            out(json, &v, || {
                for u in v.as_array().into_iter().flatten() {
                    let mut flags = Vec::new();
                    if u["is_admin"] == true {
                        flags.push("admin");
                    }
                    if u["totp_enabled"] == true {
                        flags.push("2FA");
                    }
                    if u["disabled"] == true {
                        flags.push("disabled");
                    }
                    if u["email_verified"] == false {
                        flags.push("unverified");
                    }
                    let plan = format!("plan {}", s(u, "plan"));
                    if !matches!(s(u, "plan"), "" | "free") {
                        flags.push(&plan);
                    }
                    println!(
                        "{:32} {:22} {}",
                        s(u, "email"),
                        s(u, "name"),
                        flags.join(", ")
                    );
                }
            });
        }
        AdminCmd::Invite {
            email,
            admin,
            team,
            hours,
        } => {
            let team_id = match team {
                Some(t) => Some(s(&find_team(&api, &t).await?, "id").to_string()),
                None => None,
            };
            let v: Value = api
                .post(
                    "/api/v1/admin/invites",
                    &json!({"email": email, "is_admin": admin, "team_id": team_id, "expires_in_hours": hours}),
                )
                .await?;
            out(json, &v, || {
                if v["emailed"] == true {
                    println!("Invitation created and emailed. You can also send them:\n");
                } else {
                    println!("Invitation created. Send the invitee these details:\n");
                }
                println!("  Server: {}", s(&v, "server"));
                println!("  Code:   {}", s(&v, "token"));
                if let Some(web) = v["web_url"].as_str() {
                    println!("  On the web: {web}");
                }
                println!();
                println!(
                    "With the CLI: termoak register {} --invite {}",
                    s(&v, "server"),
                    s(&v, "token")
                );
            });
        }
        AdminCmd::Invites => {
            let v: Value = api.get("/api/v1/admin/invites").await?;
            out(json, &v, || {
                for i in v.as_array().into_iter().flatten() {
                    let state = if i["revoked"] == true {
                        "revoked".to_string()
                    } else if !i["used_at"].is_null() {
                        format!("used {}", date(i["used_at"].as_i64().unwrap_or(0)))
                    } else if i["expires_at"]
                        .as_i64()
                        .is_some_and(|e| e < termoak_core::time::now_ms())
                    {
                        "expired".to_string()
                    } else {
                        "pending".to_string()
                    };
                    println!(
                        "{}  {:28} {:12} {}",
                        s(i, "id"),
                        i["email"].as_str().unwrap_or("(any email)"),
                        state,
                        if i["is_admin"] == true { "admin" } else { "" }
                    );
                }
            });
        }
        AdminCmd::RevokeInvite { id } => {
            api.delete(&format!("/api/v1/admin/invites/{id}")).await?;
            println!("Invitation revoked.");
        }
        AdminCmd::Disable { email } => {
            patch_user(&api, &email, json!({"disabled": true}), "Account disabled.").await?
        }
        AdminCmd::Enable { email } => {
            patch_user(
                &api,
                &email,
                json!({"disabled": false}),
                "Account re-enabled.",
            )
            .await?
        }
        AdminCmd::Plan { email, plan } => {
            patch_user(
                &api,
                &email,
                json!({"plan": plan}),
                &format!("Plan changed to \"{plan}\"."),
            )
            .await?
        }
        AdminCmd::TeamPlan { team, plan } => {
            let t = find_team(&api, &team).await?;
            api.post::<Value>(
                &format!("/api/v1/admin/teams/{}/plan", s(&t, "id")),
                &json!({"plan": plan}),
            )
            .await?;
            println!(
                "The team \"{}\" now has the \"{plan}\" plan.",
                s(&t, "name")
            );
        }
        AdminCmd::VerifyEmail { email } => {
            patch_user(
                &api,
                &email,
                json!({"email_verified": true}),
                "Email marked as verified.",
            )
            .await?
        }
        AdminCmd::MakeAdmin { email } => {
            patch_user(
                &api,
                &email,
                json!({"is_admin": true}),
                "They are now an administrator.",
            )
            .await?
        }
        AdminCmd::RemoveAdmin { email } => {
            patch_user(
                &api,
                &email,
                json!({"is_admin": false}),
                "They are no longer an administrator.",
            )
            .await?
        }
        AdminCmd::ResetPassword { email } => {
            let u = user_by_email(&api, &email).await?;
            let p = rpassword::prompt_password("New password (min. 10 characters): ")?;
            if p != rpassword::prompt_password("Repeat it: ")? {
                bail!("the passwords do not match");
            }
            let v: Value = api
                .post(
                    &format!("/api/v1/admin/users/{}/password", s(&u, "id")),
                    &json!({"password": p}),
                )
                .await?;
            println!(
                "Password changed; signed out of {} device(s).",
                v["devices_signed_out"]
            );
        }
        AdminCmd::Reset2fa { email } => {
            let u = user_by_email(&api, &email).await?;
            api.post::<Value>(
                &format!("/api/v1/admin/users/{}/2fa/reset", s(&u, "id")),
                &json!({}),
            )
            .await?;
            println!("Two-factor authentication removed for {email}.");
        }
        AdminCmd::Devices { email } => {
            let u = user_by_email(&api, &email).await?;
            let v: Value = api
                .get(&format!("/api/v1/admin/users/{}/devices", s(&u, "id")))
                .await?;
            out(json, &v, || {
                for d in v.as_array().into_iter().flatten() {
                    println!(
                        "{}  {:24} {:16} seen {}",
                        s(d, "id"),
                        s(d, "name"),
                        s(d, "platform"),
                        date(d["last_seen_at"].as_i64().unwrap_or(0))
                    );
                }
            });
        }
        AdminCmd::Audit { limit } => {
            let v: Value = api
                .get(&format!("/api/v1/admin/audit?limit={limit}"))
                .await?;
            out(json, &v, || {
                for e in v.as_array().into_iter().flatten() {
                    println!(
                        "{}  {:28} {}",
                        date(e["created_at"].as_i64().unwrap_or(0)),
                        s(e, "action"),
                        e["target"].as_str().unwrap_or("")
                    );
                }
            });
        }
    }
    Ok(())
}

async fn patch_user(api: &ApiClient, email: &str, body: Value, done: &str) -> Result<()> {
    let u = user_by_email(api, email).await?;
    api.patch::<Value>(&format!("/api/v1/admin/users/{}", s(&u, "id")), &body)
        .await?;
    println!("{done}");
    Ok(())
}

pub async fn teams(ws: &Workspace, cmd: TeamsCmd, json: bool) -> Result<()> {
    let api = need_server(ws).await?;
    match cmd {
        TeamsCmd::List => {
            let v: Value = api.get("/api/v1/teams").await?;
            out(json, &v, || {
                if v.as_array().is_none_or(|a| a.is_empty()) {
                    println!(
                        "You are not in any team. Create one with `termoak teams create <name>`."
                    );
                }
                for t in v.as_array().into_iter().flatten() {
                    println!(
                        "{}  {:24} {:6} {} member(s)",
                        s(t, "id"),
                        s(t, "name"),
                        s(t, "role"),
                        t["member_count"]
                    );
                }
            });
        }
        TeamsCmd::Create { name } => {
            let v: Value = api.post("/api/v1/teams", &json!({"name": name})).await?;
            out(json, &v, || println!("Team \"{}\" created.", s(&v, "name")));
        }
        TeamsCmd::Show { team } => {
            let t = find_team(&api, &team).await?;
            let v: Value = api
                .get(&format!("/api/v1/teams/{}/members", s(&t, "id")))
                .await?;
            out(json, &v, || {
                println!("{}", s(&t, "name"));
                for m in v.as_array().into_iter().flatten() {
                    println!(
                        "  {:32} {:22} {}",
                        s(m, "email"),
                        s(m, "name"),
                        s(m, "role")
                    );
                }
            });
        }
        TeamsCmd::Add { team, email, role } => {
            let t = find_team(&api, &team).await?;
            api.post::<Value>(
                &format!("/api/v1/teams/{}/members", s(&t, "id")),
                &json!({"email": email, "role": role}),
            )
            .await?;
            println!("{email} added to \"{}\".", s(&t, "name"));
        }
        TeamsCmd::Role { team, email, role } => {
            let t = find_team(&api, &team).await?;
            let uid = member_id(&api, s(&t, "id"), &email).await?;
            api.patch::<Value>(
                &format!("/api/v1/teams/{}/members/{uid}", s(&t, "id")),
                &json!({"role": role}),
            )
            .await?;
            println!("Role of {email} changed to {role}.");
        }
        TeamsCmd::Remove { team, email } => {
            let t = find_team(&api, &team).await?;
            let uid = member_id(&api, s(&t, "id"), &email).await?;
            api.delete(&format!("/api/v1/teams/{}/members/{uid}", s(&t, "id")))
                .await?;
            println!("{email} is no longer in \"{}\".", s(&t, "name"));
        }
        TeamsCmd::Invite { team, email, role } => {
            let t = find_team(&api, &team).await?;
            let v: Value = api
                .post(
                    &format!("/api/v1/teams/{}/invites", s(&t, "id")),
                    &json!({"email": email, "role": role}),
                )
                .await?;
            out(json, &v, || {
                if v["added"] == true {
                    println!(
                        "{email} already had an account: they are now in \"{}\".",
                        s(&t, "name")
                    );
                } else {
                    if v["emailed"] == true {
                        println!("Invitation emailed to {email}.");
                    } else {
                        println!("Invitation created for {email}. Send them this link:");
                    }
                    println!("  {}", v["web_url"].as_str().unwrap_or(s(&v, "url")));
                }
            });
        }
        TeamsCmd::Leave { team } => {
            let t = find_team(&api, &team).await?;
            let me: Value = api.get("/api/v1/me").await?;
            let uid = me["user"]["id"].as_str().unwrap_or("");
            api.delete(&format!("/api/v1/teams/{}/members/{uid}", s(&t, "id")))
                .await?;
            println!("You left \"{}\".", s(&t, "name"));
        }
        TeamsCmd::Delete { team } => {
            let t = find_team(&api, &team).await?;
            let answer = prompt::ask_line(&format!(
                "Delete the team \"{}\"? Its sessions will no longer be shared. [y/N] ",
                s(&t, "name")
            ))?;
            if !matches!(answer.trim().to_lowercase().as_str(), "y" | "yes") {
                bail!("cancelled");
            }
            api.delete(&format!("/api/v1/teams/{}", s(&t, "id")))
                .await?;
            println!("Team deleted.");
        }
    }
    Ok(())
}

/// Your account: plan, email, forgotten password and account deletion.
pub async fn account(ws: &Workspace, cmd: AccountCmd, json: bool) -> Result<()> {
    if let AccountCmd::ForgotPassword { server, email } = &cmd {
        let api = ApiClient::new(server)?;
        let v: Value = api
            .post_public("/api/v1/auth/forgot-password", &json!({"email": email}))
            .await?;
        out(json, &v, || {
            println!(
                "If there is an account for {email}, you will get a link to set a new password (it expires in 1 hour)."
            );
        });
        return Ok(());
    }
    let api = need_server(ws).await?;
    match cmd {
        AccountCmd::ForgotPassword { .. } => unreachable!(),
        AccountCmd::Plan => {
            let v: Value = api.get("/api/v1/me/plan").await?;
            out(json, &v, || {
                let p = &v["plan"];
                println!("Plan: {} ({})", s(p, "name"), s(p, "id"));
                if !s(p, "description").is_empty() {
                    println!("{}", s(p, "description"));
                }
                let usage = |used: &Value, k: &str| match p["limits"][k].as_u64() {
                    Some(max) => format!("{used} of {max}"),
                    None => format!("{used} (unlimited)"),
                };
                println!(
                    "Teams owned: {}",
                    usage(&v["usage"]["teams_owned"], "max_teams")
                );
                println!(
                    "Open sessions: {}",
                    usage(&v["usage"]["server_sessions"], "max_server_sessions")
                );
            });
        }
        AccountCmd::VerifyEmail => {
            let v: Value = api.post("/api/v1/me/verify-email", &json!({})).await?;
            out(json, &v, || {
                println!("We sent an email to {} to confirm it.", s(&v, "email"));
            });
        }
        AccountCmd::ChangeEmail { email } => {
            let password = rpassword::prompt_password("Current password: ")?;
            let v: Value = api
                .post(
                    "/api/v1/me/email",
                    &json!({"email": email, "password": password}),
                )
                .await?;
            out(json, &v, || {
                if v["pending"] == true {
                    println!("Check the inbox of {email} and open the link to confirm the change.");
                } else {
                    println!("Your email is now {email}.");
                }
            });
        }
        AccountCmd::Delete => {
            let me: Value = api.get("/api/v1/me").await?;
            let email = s(&me["user"], "email").to_string();
            println!(
                "You are about to delete the account {email} and all its data from the server (synced hosts, sessions, recordings, AI tasks). This cannot be undone."
            );
            let typed = prompt::ask_line("Type your email to confirm: ")?;
            if !typed.trim().eq_ignore_ascii_case(&email) {
                bail!("cancelled: the email does not match");
            }
            let password = rpassword::prompt_password("Password: ")?;
            let code = if me["user"]["totp_enabled"] == true {
                Some(prompt::ask_line("Two-factor code: ")?)
            } else {
                None
            };
            let _: Value = api
                .request(
                    reqwest::Method::DELETE,
                    "/api/v1/me",
                    Some(&json!({"password": password, "totp_code": code})),
                )
                .await?;
            // The session no longer exists on the server: forget it here too.
            let _ = ws.logout().await;
            println!("Account deleted. The data on this computer is kept.");
        }
    }
    Ok(())
}
