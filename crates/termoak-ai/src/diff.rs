//! Unified diff of two texts (for the approval of `write_file`).
//!
//! Line based, with 3 lines of context, like `diff -u`. The common start and
//! end are skipped first; the rest is compared with a longest-common-
//! subsequence table when it is small enough (otherwise the changed middle
//! is shown as removed and added as a whole). The output is capped.

/// A unified diff.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct UnifiedDiff {
    /// `--- a/…`, `+++ b/…` and the hunks (`@@ -1,3 +1,4 @@`).
    pub text: String,
    /// Cut at the size limit.
    pub truncated: bool,
    pub added: usize,
    pub removed: usize,
}

/// Largest LCS table (cells) before falling back to a block replacement.
const MAX_CELLS: usize = 1_000_000;
const CONTEXT: usize = 3;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Op {
    Equal(usize, usize),
    Delete(usize),
    Insert(usize),
}

/// Diff of `old` → `new` named `path`, at most `max_bytes` long.
pub fn unified_diff(old: &str, new: &str, path: &str, max_bytes: usize) -> UnifiedDiff {
    let a: Vec<&str> = old.lines().collect();
    let b: Vec<&str> = new.lines().collect();
    let ops = diff_ops(&a, &b);
    let added = ops.iter().filter(|o| matches!(o, Op::Insert(_))).count();
    let removed = ops.iter().filter(|o| matches!(o, Op::Delete(_))).count();
    let mut out = UnifiedDiff {
        text: String::new(),
        truncated: false,
        added,
        removed,
    };
    if added == 0 && removed == 0 {
        return out;
    }
    let old_name = if old.is_empty() {
        "/dev/null".to_string()
    } else {
        format!("a{}", slash(path))
    };
    out.text = format!("--- {old_name}\n+++ b{}\n", slash(path));
    for hunk in hunks(&ops) {
        let ops = &ops[hunk.0..hunk.1];
        let (mut a_start, mut a_len, mut b_start, mut b_len) = (None, 0, None, 0);
        for op in ops {
            match *op {
                Op::Equal(i, j) => {
                    a_start.get_or_insert(i);
                    b_start.get_or_insert(j);
                    a_len += 1;
                    b_len += 1;
                }
                Op::Delete(i) => {
                    a_start.get_or_insert(i);
                    a_len += 1;
                }
                Op::Insert(j) => {
                    b_start.get_or_insert(j);
                    b_len += 1;
                }
            }
        }
        // Empty side: the line before it (0 at the start), as `diff -u`.
        let a_start = a_start
            .map(|s| s + 1)
            .unwrap_or_else(|| line_before(ops, true));
        let b_start = b_start
            .map(|s| s + 1)
            .unwrap_or_else(|| line_before(ops, false));
        let mut chunk = format!(
            "@@ -{} +{} @@\n",
            range(a_start, a_len),
            range(b_start, b_len)
        );
        for op in ops {
            let (sign, line) = match *op {
                Op::Equal(i, _) => (' ', a[i]),
                Op::Delete(i) => ('-', a[i]),
                Op::Insert(j) => ('+', b[j]),
            };
            chunk.push(sign);
            chunk.push_str(line);
            chunk.push('\n');
        }
        if out.text.len() + chunk.len() > max_bytes {
            // Whole lines that fit.
            let room = max_bytes.saturating_sub(out.text.len());
            let cut = chunk[..room.min(chunk.len())]
                .rfind('\n')
                .map(|p| p + 1)
                .unwrap_or(0);
            out.text.push_str(&chunk[..cut]);
            out.truncated = true;
            break;
        }
        out.text.push_str(&chunk);
    }
    out
}

fn slash(path: &str) -> String {
    if path.starts_with('/') {
        path.to_string()
    } else {
        format!("/{path}")
    }
}

fn range(start: usize, len: usize) -> String {
    if len == 1 {
        start.to_string()
    } else {
        format!("{start},{len}")
    }
}

/// Line number before an empty side of a hunk.
fn line_before(ops: &[Op], old: bool) -> usize {
    // The hunk has no line of this side: count the ones of that side before
    // it is not possible from the slice alone, so use the other side's
    // position (insertions and deletions at the same point).
    for op in ops {
        match (*op, old) {
            (Op::Insert(j), true) => return j,
            (Op::Delete(i), false) => return i,
            _ => {}
        }
    }
    0
}

/// Ranges of `ops` that make up each hunk (changes with their context).
fn hunks(ops: &[Op]) -> Vec<(usize, usize)> {
    let changes: Vec<usize> = ops
        .iter()
        .enumerate()
        .filter(|(_, o)| !matches!(o, Op::Equal(..)))
        .map(|(i, _)| i)
        .collect();
    let mut out: Vec<(usize, usize)> = Vec::new();
    for &c in &changes {
        let start = c.saturating_sub(CONTEXT);
        let end = (c + 1 + CONTEXT).min(ops.len());
        match out.last_mut() {
            Some(last) if start <= last.1 => last.1 = last.1.max(end),
            _ => out.push((start, end)),
        }
    }
    out
}

fn diff_ops(a: &[&str], b: &[&str]) -> Vec<Op> {
    let prefix = a.iter().zip(b).take_while(|(x, y)| x == y).count();
    let suffix = a[prefix..]
        .iter()
        .rev()
        .zip(b[prefix..].iter().rev())
        .take_while(|(x, y)| x == y)
        .count();
    let (am, bm) = (&a[prefix..a.len() - suffix], &b[prefix..b.len() - suffix]);
    let mut ops: Vec<Op> = (0..prefix).map(|i| Op::Equal(i, i)).collect();
    let (n, m) = (am.len(), bm.len());
    if n == 0 || m == 0 || (n + 1) * (m + 1) > MAX_CELLS {
        ops.extend((0..n).map(|i| Op::Delete(prefix + i)));
        ops.extend((0..m).map(|j| Op::Insert(prefix + j)));
    } else {
        // lcs[i][j]: LCS length of am[i..] and bm[j..].
        let w = m + 1;
        let mut lcs = vec![0u32; (n + 1) * w];
        for i in (0..n).rev() {
            for j in (0..m).rev() {
                lcs[i * w + j] = if am[i] == bm[j] {
                    lcs[(i + 1) * w + j + 1] + 1
                } else {
                    lcs[(i + 1) * w + j].max(lcs[i * w + j + 1])
                };
            }
        }
        let (mut i, mut j) = (0, 0);
        while i < n || j < m {
            if i < n && j < m && am[i] == bm[j] {
                ops.push(Op::Equal(prefix + i, prefix + j));
                i += 1;
                j += 1;
            } else if j < m && (i == n || lcs[i * w + j + 1] >= lcs[(i + 1) * w + j]) {
                ops.push(Op::Insert(prefix + j));
                j += 1;
            } else {
                ops.push(Op::Delete(prefix + i));
                i += 1;
            }
        }
        // Deletions before insertions within each change block.
        normalize(&mut ops);
    }
    let (ae, be) = (a.len() - suffix, b.len() - suffix);
    ops.extend((0..suffix).map(|k| Op::Equal(ae + k, be + k)));
    ops
}

/// Within each run of changes, deletions first (as `diff -u` prints them).
fn normalize(ops: &mut [Op]) {
    let mut start = 0;
    while start < ops.len() {
        if matches!(ops[start], Op::Equal(..)) {
            start += 1;
            continue;
        }
        let mut end = start;
        while end < ops.len() && !matches!(ops[end], Op::Equal(..)) {
            end += 1;
        }
        ops[start..end].sort_by_key(|o| match o {
            Op::Delete(i) => (0, *i),
            Op::Insert(j) => (1, *j),
            Op::Equal(..) => (2, 0),
        });
        start = end;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identical_texts_have_no_diff() {
        let d = unified_diff("a\nb\n", "a\nb\n", "/etc/x", 10_000);
        assert!(d.text.is_empty());
        assert_eq!((d.added, d.removed), (0, 0));
    }

    #[test]
    fn changed_line_with_context() {
        let old = "1\n2\n3\n4\n5\n6\n7\n8\n9\n";
        let new = "1\n2\n3\n4\nfive\n6\n7\n8\n9\n";
        let d = unified_diff(old, new, "/etc/app.conf", 10_000);
        assert_eq!(
            d.text,
            "--- a/etc/app.conf\n+++ b/etc/app.conf\n@@ -2,7 +2,7 @@\n 2\n 3\n 4\n-5\n+five\n 6\n 7\n 8\n"
        );
        assert_eq!((d.added, d.removed), (1, 1));
        assert!(!d.truncated);
    }

    #[test]
    fn new_file_and_insertions() {
        let d = unified_diff("", "a\nb\n", "/tmp/new", 10_000);
        assert_eq!(
            d.text,
            "--- /dev/null\n+++ b/tmp/new\n@@ -0,0 +1,2 @@\n+a\n+b\n"
        );
        let d = unified_diff("a\nc\n", "a\nb\nc\n", "f", 10_000);
        assert_eq!(d.text, "--- a/f\n+++ b/f\n@@ -1,2 +1,3 @@\n a\n+b\n c\n");
    }

    #[test]
    fn separate_hunks_and_lcs() {
        let old: String = (1..=30).map(|i| format!("line {i}\n")).collect();
        let new = old
            .replace("line 3\n", "line three\n")
            .replace("line 25\n", "")
            .replace("line 26\n", "line 26\nextra\n");
        let d = unified_diff(&old, &new, "/f", 10_000);
        assert_eq!(d.text.matches("@@ ").count(), 2, "{}", d.text);
        assert!(d.text.contains("-line 3\n+line three\n"));
        assert!(d.text.contains("-line 25\n"));
        assert!(d.text.contains("+extra\n"));
        assert_eq!((d.added, d.removed), (2, 2));
    }

    #[test]
    fn output_is_capped_at_whole_lines() {
        let new: String = (0..1000).map(|i| format!("row {i}\n")).collect();
        let d = unified_diff("", &new, "/f", 500);
        assert!(d.truncated);
        assert!(d.text.len() <= 500);
        assert!(d.text.ends_with('\n'));
        assert_eq!(d.added, 1000);
    }
}
