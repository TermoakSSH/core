//! Time helpers. All timestamps are stored as UTC milliseconds.

/// Milliseconds since the Unix epoch.
pub fn now_ms() -> i64 {
    chrono::Utc::now().timestamp_millis()
}
