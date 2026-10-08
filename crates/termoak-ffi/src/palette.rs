//! Ranking of a command palette (`termoak_client::palette`, the desktop's
//! Cmd/Ctrl+K): fuzzy matching (fzy scores) of what is typed against each
//! entry's title, detail and keywords, recent entries first. For tablets
//! with a keyboard; the app builds the entries and draws the list.

use termoak_client::palette as pl;

/// Kind of entry (also the order of the groups with nothing typed).
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum PaletteKind {
    /// An open tab: switch to it.
    Tab,
    /// A saved host: connect.
    Host,
    /// A server session: attach.
    Session,
    /// A snippet: run it in the current terminal.
    Snippet,
    /// An action of the app.
    Command,
}

impl From<PaletteKind> for pl::Kind {
    fn from(k: PaletteKind) -> Self {
        match k {
            PaletteKind::Tab => pl::Kind::Tab,
            PaletteKind::Host => pl::Kind::Host,
            PaletteKind::Session => pl::Kind::Session,
            PaletteKind::Snippet => pl::Kind::Snippet,
            PaletteKind::Command => pl::Kind::Command,
        }
    }
}

/// An entry of the palette.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct PaletteEntry {
    /// Stable identity, to remember it among the recent ones (`host:<id>`,
    /// `cmd:<name>`...).
    pub key: String,
    pub kind: PaletteKind,
    pub title: String,
    /// Second line (address, command, menu...).
    #[uniffi(default)]
    pub detail: String,
    /// More words it is found by (tags, names in English...).
    #[uniffi(default)]
    pub keywords: Vec<String>,
}

/// An entry to show.
#[derive(Debug, Clone, PartialEq, uniffi::Record)]
pub struct PaletteMatch {
    /// Index in the entries given.
    pub index: u32,
    pub score: f64,
    /// Characters of the title that matched (positions in characters, not
    /// bytes), to highlight them.
    pub hits: Vec<u32>,
}

/// The entries to show for `query`, best first (every word must match
/// somewhere). With nothing typed: the recent ones first, then by kind.
/// `recent`: keys, the most recent first (see [`palette_remember`]).
#[uniffi::export(default(recent = []))]
pub fn palette_rank(
    query: String,
    entries: Vec<PaletteEntry>,
    recent: Vec<String>,
) -> Vec<PaletteMatch> {
    let entries: Vec<pl::Entry> = entries
        .into_iter()
        .map(|e| pl::Entry {
            key: e.key,
            kind: e.kind.into(),
            title: e.title,
            detail: e.detail,
            keywords: e.keywords,
        })
        .collect();
    pl::rank(&query, &entries, &recent)
        .into_iter()
        .map(|r| PaletteMatch {
            index: r.index as u32,
            score: r.score,
            hits: r.hits.into_iter().map(|h| h as u32).collect(),
        })
        .collect()
}

/// The recent keys with `key` first (at most 20): save them and pass them
/// to [`palette_rank`].
#[uniffi::export]
pub fn palette_remember(recent: Vec<String>, key: String) -> Vec<String> {
    let mut recent = recent;
    pl::remember(&mut recent, &key);
    recent
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(kind: PaletteKind, key: &str, title: &str, detail: &str) -> PaletteEntry {
        PaletteEntry {
            key: key.into(),
            kind,
            title: title.into(),
            detail: detail.into(),
            keywords: Vec::new(),
        }
    }

    #[test]
    fn ranks_and_remembers() {
        let entries = vec![
            entry(PaletteKind::Command, "cmd:settings", "Settings", ""),
            entry(PaletteKind::Host, "host:1", "web-server", "10.0.0.1"),
            entry(PaletteKind::Host, "host:2", "db-primary", "10.0.0.2"),
        ];
        let r = palette_rank("ws".into(), entries.clone(), vec![]);
        assert_eq!(r[0].index, 1);
        assert_eq!(r[0].hits, vec![0, 4]);
        // Nothing typed: recent first, then by kind (hosts before commands).
        let recent = palette_remember(vec![], "cmd:settings".into());
        let r = palette_rank(String::new(), entries, recent);
        let order: Vec<u32> = r.iter().map(|m| m.index).collect();
        assert_eq!(order, vec![0, 1, 2]);
    }
}
