//! What an approval shows and how it is answered.
//!
//! Every approval request carries an [`ApprovalPreview`]: for `run_command`
//! the exact command, the host, the classifier's reasons and the risk level;
//! for `write_file` a unified diff of the current file against the new
//! content (size-capped), the host and the path; for a plan (tasks with
//! "plan before acting") the numbered plan. It is in the
//! `approval_requested` event and in the task's `pending_approvals`.
//!
//! The answer is an [`ApprovalDecision`]: approve or deny, `always` (approve
//! everything else in the task), the edited command or plan (what runs, and
//! what the model is told ran) and the reason of a denial (sent back to the
//! model).

use serde::{Deserialize, Serialize};

use crate::policy::{RiskLevel, RiskReason};

/// Largest diff shown in an approval (bytes).
pub const MAX_DIFF_BYTES: usize = 64 * 1024;
/// Largest current file read to build the diff (bytes).
pub const MAX_DIFF_SOURCE_BYTES: u64 = 512 * 1024;

fn is_false(b: &bool) -> bool {
    !*b
}

/// What an approval is about.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct ApprovalPreview {
    /// `command` (run_command), `terminal` (send_to_terminal), `file`
    /// (write_file), `plan` or `other`.
    pub kind: String,
    /// Host as the model named it (label, id or address) or, for a terminal,
    /// its title.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host: Option<String>,
    /// Exact command (or text typed into the terminal).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub command: Option<String>,
    /// File written.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    /// Unified diff of the file (`--- a/…`, `+++ b/…`, hunks).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub diff: Option<String>,
    /// The diff was cut at [`MAX_DIFF_BYTES`].
    #[serde(default, skip_serializing_if = "is_false")]
    pub diff_truncated: bool,
    /// Lines added and removed by the write.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub added: Option<usize>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub removed: Option<usize>,
    /// The file does not exist yet.
    #[serde(default, skip_serializing_if = "is_false")]
    pub new_file: bool,
    /// Why there is no diff (the file could not be read, it is binary or
    /// too large...).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub diff_error: Option<String>,
    #[serde(default)]
    pub risk: RiskLevel,
    /// The classifier's reasons (`pipe`, `rm -rf`, `writes to /etc`...).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub reasons: Vec<RiskReason>,
    /// Why the model wants to do it (its `reason`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub explanation: Option<String>,
    /// The plan to approve (`kind: plan`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub plan: Option<String>,
    /// It can be edited before approving (commands and plans).
    #[serde(default, skip_serializing_if = "is_false")]
    pub editable: bool,
}

/// The answer to an approval (`POST …/approvals/{id}`).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApprovalDecision {
    pub approve: bool,
    /// Approve this one and every later one in the task (switches the task
    /// to autonomous mode).
    #[serde(default)]
    pub always: bool,
    /// Approve with this command (`run_command`, `send_to_terminal`) or
    /// plan instead of the model's: it is what runs, and the model is told.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub edited: Option<String>,
    /// Why it was denied (or a note with the approval): sent to the model.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

impl ApprovalDecision {
    pub fn approve() -> Self {
        Self {
            approve: true,
            ..Default::default()
        }
    }

    pub fn deny(reason: Option<String>) -> Self {
        Self {
            approve: false,
            reason,
            ..Default::default()
        }
    }

    /// The edited text, trimmed, if it is not empty.
    pub fn edited_text(&self) -> Option<&str> {
        self.edited
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
    }

    /// The reason, trimmed and at most 2000 characters, if any.
    pub fn reason_text(&self) -> Option<String> {
        self.reason
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(|s| s.chars().take(2000).collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decision_serde_is_backward_compatible() {
        // What the apps send today.
        let d: ApprovalDecision = serde_json::from_str(r#"{"approve": true}"#).unwrap();
        assert_eq!(d, ApprovalDecision::approve());
        let d: ApprovalDecision =
            serde_json::from_str(r#"{"approve": false, "always": false, "reason": " no "}"#)
                .unwrap();
        assert_eq!(d.reason_text().as_deref(), Some("no"));
        let d = ApprovalDecision {
            edited: Some("  ".into()),
            ..ApprovalDecision::approve()
        };
        assert_eq!(d.edited_text(), None);
    }

    #[test]
    fn preview_skips_empty_fields() {
        let p = ApprovalPreview {
            kind: "command".into(),
            command: Some("ls".into()),
            ..Default::default()
        };
        let v = serde_json::to_value(&p).unwrap();
        assert_eq!(
            v,
            serde_json::json!({"kind": "command", "command": "ls", "risk": "medium"})
        );
        let back: ApprovalPreview = serde_json::from_value(v).unwrap();
        assert_eq!(back, p);
    }
}
