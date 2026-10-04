//! Library logging forwarded to the app (Logcat, `os_log`...).

use std::fmt::Write as _;
use std::sync::Arc;

use tracing::field::{Field, Visit};
use tracing::{Event, Level, Subscriber};
use tracing_subscriber::Layer;
use tracing_subscriber::filter::{LevelFilter, Targets};
use tracing_subscriber::layer::{Context, SubscriberExt};
use tracing_subscriber::util::SubscriberInitExt;

/// Level of a log message.
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum LogLevel {
    Error,
    Warn,
    Info,
    Debug,
    Trace,
}

impl From<LogLevel> for LevelFilter {
    fn from(l: LogLevel) -> Self {
        match l {
            LogLevel::Error => LevelFilter::ERROR,
            LogLevel::Warn => LevelFilter::WARN,
            LogLevel::Info => LevelFilter::INFO,
            LogLevel::Debug => LevelFilter::DEBUG,
            LogLevel::Trace => LevelFilter::TRACE,
        }
    }
}

impl From<&Level> for LogLevel {
    fn from(l: &Level) -> Self {
        match *l {
            Level::ERROR => LogLevel::Error,
            Level::WARN => LogLevel::Warn,
            Level::INFO => LogLevel::Info,
            Level::DEBUG => LogLevel::Debug,
            Level::TRACE => LogLevel::Trace,
        }
    }
}

/// Implemented by the app to receive the library's log.
///
/// **Threads**: called from any thread, including the runtime; it must
/// return quickly (write to Logcat/`os_log` and nothing else).
#[uniffi::export(foreign)]
pub trait LogListener: Send + Sync {
    fn log(&self, level: LogLevel, target: String, message: String);
}

/// Enables logging. `level` applies to Termoak; dependencies (russh,
/// reqwest...) only log warnings and errors. Returns `false` if it was
/// already enabled.
#[uniffi::export]
pub fn init_logging(level: LogLevel, listener: Arc<dyn LogListener>) -> bool {
    let ours: LevelFilter = level.into();
    let filter = Targets::new()
        .with_default(ours.min(LevelFilter::WARN))
        .with_target("termoak_ffi", ours)
        .with_target("termoak_client", ours)
        .with_target("termoak_ssh", ours)
        .with_target("termoak_core", ours);
    tracing_subscriber::registry()
        .with(FfiLayer { listener }.with_filter(filter))
        .try_init()
        .is_ok()
}

struct FfiLayer {
    listener: Arc<dyn LogListener>,
}

impl<S: Subscriber> Layer<S> for FfiLayer {
    fn on_event(&self, event: &Event<'_>, _ctx: Context<'_, S>) {
        let meta = event.metadata();
        let mut visitor = MessageVisitor::default();
        event.record(&mut visitor);
        let message = if visitor.fields.is_empty() {
            visitor.message
        } else {
            format!("{}{}", visitor.message, visitor.fields)
        };
        self.listener
            .log(meta.level().into(), meta.target().to_string(), message);
    }
}

#[derive(Default)]
struct MessageVisitor {
    message: String,
    fields: String,
}

impl Visit for MessageVisitor {
    fn record_str(&mut self, field: &Field, value: &str) {
        if field.name() == "message" {
            self.message = value.to_string();
        } else {
            let _ = write!(self.fields, " {}={value}", field.name());
        }
    }

    fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
        if field.name() == "message" {
            self.message = format!("{value:?}");
        } else {
            let _ = write!(self.fields, " {}={value:?}", field.name());
        }
    }
}
