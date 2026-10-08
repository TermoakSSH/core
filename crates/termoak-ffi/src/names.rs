//! How your own accounts are named on screen (`termoak_client::account_names`):
//! aliases ("Work", "Personal") and "Hide email addresses".
//!
//! The aliases and the toggle are device-local preferences the app keeps
//! with its settings (not synced, not in the vault), as the desktop does;
//! these functions are the rules, so every app shows the same names. Use
//! them wherever one of your own accounts is shown: the account switcher,
//! Settings › Accounts, the sidebar, share dialogs. Emails of other people
//! (vault members, participants) are shown as they are.

use std::collections::{BTreeMap, HashMap};

use termoak_client::account_names as an;

use crate::models::parse_id;

/// Longest alias kept (characters).
pub const ACCOUNT_ALIAS_MAX: u32 = an::ALIAS_MAX as u32;

/// The names of your accounts on this device.
#[derive(Debug, Clone, Default, PartialEq, Eq, uniffi::Record)]
pub struct AccountNames {
    /// Alias by account id (`AccountInfo.id`).
    #[uniffi(default)]
    pub aliases: HashMap<String, String>,
    /// "Hide email addresses": emails of your accounts are masked.
    #[uniffi(default)]
    pub hide_emails: bool,
}

impl AccountNames {
    fn rules(&self) -> an::AccountNames {
        an::AccountNames {
            aliases: self
                .aliases
                .iter()
                .filter_map(|(id, alias)| Some((parse_id(id).ok()?, alias.clone())))
                .collect::<BTreeMap<_, _>>(),
            hide_emails: self.hide_emails,
        }
    }
}

fn id_or_nil(id: &str) -> termoak_core::Id {
    parse_id(id).unwrap_or_default()
}

/// An email with only its first letters: "oihalitz@termoak.com" →
/// "o•••@t•••.com" (the top-level domain stays).
#[uniffi::export]
pub fn mask_email(email: String) -> String {
    an::mask_email(&email)
}

/// An alias as it should be saved: trimmed and at most 40 characters.
/// `None`: blank (remove the alias; the email is shown again).
#[uniffi::export]
pub fn clean_account_alias(alias: String) -> Option<String> {
    an::clean_alias(&alias)
}

/// Name of one of your accounts: its alias, or its email (masked when
/// emails are hidden).
#[uniffi::export]
pub fn account_display_name(names: AccountNames, account_id: String, email: String) -> String {
    names.rules().name(id_or_nil(&account_id), &email)
}

/// An email of one of your accounts as shown (masked when emails are
/// hidden), e.g. while signing in, before there is an account id.
#[uniffi::export]
pub fn account_display_email(names: AccountNames, email: String) -> String {
    names.rules().email(&email)
}

/// "Work" or "ana@example.com", followed by " · <server>" when `server` is
/// given (accounts of a server that is not the official one).
#[uniffi::export(default(server = None))]
pub fn account_display_label(
    names: AccountNames,
    account_id: String,
    email: String,
    server: Option<String>,
) -> String {
    names
        .rules()
        .label(id_or_nil(&account_id), &email, server.as_deref())
}

/// Letter of an account's avatar: from its alias, or from the name the
/// server knows and the email.
#[uniffi::export]
pub fn account_initial(
    names: AccountNames,
    account_id: String,
    name: String,
    email: String,
) -> String {
    names.rules().initial(id_or_nil(&account_id), &name, &email)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_follow_the_rules() {
        let id = "0192f0c0-0000-7000-8000-000000000001".to_string();
        let mut names = AccountNames::default();
        assert_eq!(
            account_display_name(names.clone(), id.clone(), "ana@example.com".into()),
            "ana@example.com"
        );
        names.aliases.insert(id.clone(), " Work ".into());
        names.aliases.insert("not-an-id".into(), "ignored".into());
        assert_eq!(
            account_display_name(names.clone(), id.clone(), "ana@example.com".into()),
            "Work"
        );
        assert_eq!(
            account_display_label(
                names.clone(),
                id.clone(),
                "ana@example.com".into(),
                Some("ssh.example.com".into())
            ),
            "Work · ssh.example.com"
        );
        assert_eq!(
            account_initial(names.clone(), id.clone(), "Ana".into(), "a@b.c".into()),
            "W"
        );
        names.hide_emails = true;
        assert_eq!(
            account_display_email(names.clone(), "ana@example.com".into()),
            "a•••@e•••.com"
        );
        assert_eq!(
            account_display_name(names, "bad".into(), "bob@example.net".into()),
            "b•••@e•••.net"
        );
        assert_eq!(mask_email("oihalitz@termoak.com".into()), "o•••@t•••.com");
        assert_eq!(clean_account_alias("  ".into()), None);
        assert_eq!(clean_account_alias(" Home ".into()).as_deref(), Some("Home"));
        assert_eq!(ACCOUNT_ALIAS_MAX, 40);
    }
}
