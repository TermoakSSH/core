//! How your own accounts are named on screen, on one device: an alias per
//! account ("Work", "Personal") and "Hide email addresses" (screenshots,
//! screen sharing, demos). Only the accounts signed in on the device; the
//! emails of other people (vault members, share participants, users of the
//! admin) are shown as they are.
//!
//! - With an alias, the alias is shown instead of the email (and the
//!   avatar takes its letter).
//! - Without one, the email; masked ("o•••@t•••.com") when emails are
//!   hidden.
//!
//! The aliases and the toggle are device-local preferences that each app
//! keeps with its other settings (the desktop in its settings file, the
//! mobile apps in their preferences); they are not synced and not stored in
//! the vault. This module only has the rules, so every app shows the same
//! thing.

use std::collections::BTreeMap;

use termoak_core::Id;

/// Longest alias kept (characters).
pub const ALIAS_MAX: usize = 40;

/// The names of your accounts on this device.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AccountNames {
    pub aliases: BTreeMap<Id, String>,
    pub hide_emails: bool,
}

impl AccountNames {
    /// No aliases, emails shown.
    pub const EMPTY: Self = Self {
        aliases: BTreeMap::new(),
        hide_emails: false,
    };

    /// The alias of an account, if it has one that is not blank.
    pub fn alias(&self, id: Id) -> Option<&str> {
        self.aliases
            .get(&id)
            .map(|a| a.trim())
            .filter(|a| !a.is_empty())
    }

    /// An email of one of your accounts as shown: masked when emails are
    /// hidden.
    pub fn email(&self, email: &str) -> String {
        if self.hide_emails {
            mask_email(email)
        } else {
            email.trim().to_string()
        }
    }

    /// Name of an account: its alias, or its email as shown.
    pub fn name(&self, id: Id, email: &str) -> String {
        match self.alias(id) {
            Some(a) => a.to_string(),
            None => self.email(email),
        }
    }

    /// Letter of an account's avatar: from the alias, or from the name the
    /// server knows and the email.
    pub fn initial(&self, id: Id, name: &str, email: &str) -> String {
        match self.alias(id) {
            Some(a) => avatar_initial(a, ""),
            None => avatar_initial(name, email),
        }
    }

    /// "Work" or "ana@example.com", followed by " · <server>" for an
    /// account of a server that is not the official one.
    pub fn label(&self, id: Id, email: &str, server: Option<&str>) -> String {
        let title = self.name(id, email);
        match server.map(str::trim).filter(|s| !s.is_empty()) {
            Some(s) => format!("{title} · {s}"),
            None => title,
        }
    }
}

/// An alias as kept: trimmed, at most [`ALIAS_MAX`] characters (`None`:
/// blank, the email is shown again).
pub fn clean_alias(alias: &str) -> Option<String> {
    let a: String = alias.trim().chars().take(ALIAS_MAX).collect();
    let a = a.trim_end().to_string();
    (!a.is_empty()).then_some(a)
}

/// An email with only its first letters: "oihalitz@termoak.com" →
/// "o•••@t•••.com" (the top-level domain stays).
pub fn mask_email(email: &str) -> String {
    const DOTS: &str = "•••";
    fn first(s: &str) -> String {
        s.chars().next().map(String::from).unwrap_or_default()
    }
    let email = email.trim();
    if email.is_empty() {
        return String::new();
    }
    let Some((user, domain)) = email.rsplit_once('@') else {
        return format!("{}{DOTS}", first(email));
    };
    let domain = match domain.rsplit_once('.') {
        Some((name, tld)) if !name.is_empty() && !tld.is_empty() => {
            format!("{}{DOTS}.{tld}", first(name))
        }
        _ => format!("{}{DOTS}", first(domain)),
    };
    format!("{}{DOTS}@{domain}", first(user))
}

/// Letter of an account's avatar: the first letter or digit of the name,
/// or of the email; `?` without any.
pub fn avatar_initial(name: &str, email: &str) -> String {
    name.trim()
        .chars()
        .chain(email.trim().chars())
        .find(|c| c.is_alphanumeric())
        .map(|c| c.to_uppercase().collect())
        .unwrap_or_else(|| "?".into())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn id(n: u128) -> Id {
        Id::from_u128(n)
    }

    #[test]
    fn emails_are_masked_to_their_first_letters() {
        assert_eq!(mask_email("oihalitz@termoak.com"), "o•••@t•••.com");
        assert_eq!(mask_email(" Ana@Mail.Example.co.uk "), "A•••@M•••.uk");
        assert_eq!(mask_email("ñandú@ñ.es"), "ñ•••@ñ•••.es");
        assert_eq!(mask_email("root@localhost"), "r•••@l•••");
        assert_eq!(mask_email("@example.com"), "•••@e•••.com");
        assert_eq!(mask_email("ana@"), "a•••@•••");
        assert_eq!(mask_email("ana@.com"), "a•••@.•••");
        assert_eq!(mask_email("not-an-email"), "n•••");
        assert_eq!(mask_email("   "), "");
        // Nothing of the user or the domain name is left.
        let m = mask_email("ana.garcia@example.org");
        assert!(!m.contains("garcia") && !m.contains("example"));
    }

    #[test]
    fn aliases_are_trimmed_and_blank_ones_dropped() {
        assert_eq!(clean_alias("  Work "), Some("Work".into()));
        assert_eq!(clean_alias("   "), None);
        assert_eq!(clean_alias(""), None);
        let long = "x".repeat(ALIAS_MAX + 10);
        assert_eq!(clean_alias(&long).unwrap().chars().count(), ALIAS_MAX);
        // Cut at a space: no trailing blank.
        let spaced = format!("{} y", "x".repeat(ALIAS_MAX - 1));
        assert_eq!(clean_alias(&spaced), Some("x".repeat(ALIAS_MAX - 1)));
    }

    #[test]
    fn own_accounts_show_their_alias_or_their_email() {
        let (ana, work) = (id(1), id(2));
        let mut names = AccountNames::default();

        // Nothing set: the email, the letter of the name.
        assert_eq!(names.name(ana, "ana@example.com"), "ana@example.com");
        assert_eq!(names.initial(ana, "Ana García", "ana@example.com"), "A");
        assert_eq!(names.alias(ana), None);

        // An alias: shown instead of the email, its letter on the avatar.
        names.aliases.insert(ana, " Personal ".into());
        names.aliases.insert(work, "Work".into());
        assert_eq!(names.name(ana, "ana@example.com"), "Personal");
        assert_eq!(names.initial(ana, "Ana García", "ana@example.com"), "P");
        assert_eq!(
            names.label(work, "ana@work.com", Some("ssh.example.com")),
            "Work · ssh.example.com"
        );
        assert_eq!(names.initial(work, "", "ana@work.com"), "W");

        // A blank alias counts as none.
        names.aliases.insert(ana, "  ".into());
        assert_eq!(names.alias(ana), None);
        assert_eq!(names.name(ana, "ana@example.com"), "ana@example.com");

        // Hidden emails: the alias if there is one, otherwise masked.
        names.hide_emails = true;
        assert_eq!(names.name(ana, "ana@example.com"), "a•••@e•••.com");
        assert_eq!(names.name(work, "ana@work.com"), "Work");
        assert_eq!(names.email("ana@work.com"), "a•••@w•••.com");
        assert_eq!(names.label(ana, "ana@example.com", None), "a•••@e•••.com");
        // An account the names know nothing about.
        assert_eq!(names.name(id(99), "bob@example.net"), "b•••@e•••.net");
        assert_eq!(avatar_initial("", "  "), "?");
        assert_eq!(avatar_initial("", "ñandú@x.es"), "Ñ");
    }
}
