//! Cancelling file transfers from the app.
//!
//! Cancelling a Kotlin coroutine drops the Rust future (and aborts the
//! transfer), but the Swift bindings UniFFI generates (0.32) do not cancel
//! the Rust future when the Swift `Task` is cancelled: the transfer would go
//! on to the end. A [`TransferHandle`] passed to a transfer (`cancel`
//! parameter) stops it from any thread, on both platforms.

use std::future::Future;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use tokio::sync::Notify;

use crate::error::{Result, TermoakError};

/// Cancels the transfer it is passed to (`sftp_download`, `sftp_upload`,
/// `server_sftp_download`, `server_sftp_upload`, `download_recording`).
/// Create one per transfer and call `cancel()` from anywhere (a "Cancel"
/// button): the call then fails with `Cancelled` and leaves no partial file
/// under the final name. Cancelling before the transfer starts makes it fail
/// at once.
#[derive(uniffi::Object, Default)]
pub struct TransferHandle {
    cancelled: AtomicBool,
    notify: Notify,
}

#[uniffi::export]
impl TransferHandle {
    #[uniffi::constructor]
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    /// Stops the transfer (idempotent).
    pub fn cancel(&self) {
        self.cancelled.store(true, Ordering::SeqCst);
        self.notify.notify_waiters();
    }

    pub fn is_cancelled(&self) -> bool {
        self.cancelled.load(Ordering::SeqCst)
    }
}

impl TransferHandle {
    /// Resolves once `cancel` is called.
    async fn cancelled(&self) {
        loop {
            // Registered before checking the flag, so a `cancel` in between
            // is not missed (`notify_waiters` wakes futures created before).
            let notified = self.notify.notified();
            if self.is_cancelled() {
                return;
            }
            notified.await;
        }
    }
}

pub(crate) fn cancelled_error() -> TermoakError {
    TermoakError::Cancelled("the transfer was cancelled".into())
}

/// Runs `fut` until it ends or `handle` is cancelled (then `fut` is dropped,
/// which stops the transfer, and `on_cancel` cleans up).
pub(crate) async fn cancellable<T, F, C, CF>(
    handle: Option<Arc<TransferHandle>>,
    fut: F,
    on_cancel: C,
) -> Result<T>
where
    F: Future<Output = Result<T>>,
    C: FnOnce() -> CF,
    CF: Future<Output = ()>,
{
    let Some(handle) = handle else {
        return fut.await;
    };
    if handle.is_cancelled() {
        on_cancel().await;
        return Err(cancelled_error());
    }
    tokio::select! {
        r = fut => r,
        _ = handle.cancelled() => {
            on_cancel().await;
            Err(cancelled_error())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runtime::block_on;

    #[test]
    fn cancel_stops_a_pending_future() {
        let h = TransferHandle::new();
        let h2 = h.clone();
        std::thread::spawn(move || {
            std::thread::sleep(std::time::Duration::from_millis(50));
            h2.cancel();
        });
        let cleaned = Arc::new(AtomicBool::new(false));
        let c = cleaned.clone();
        let r: Result<()> = block_on(cancellable(
            Some(h.clone()),
            std::future::pending(),
            move || async move { c.store(true, Ordering::SeqCst) },
        ));
        assert!(matches!(r, Err(TermoakError::Cancelled(_))));
        assert!(cleaned.load(Ordering::SeqCst));
        assert!(h.is_cancelled());
        // Already cancelled: fails at once.
        let r: Result<()> = block_on(cancellable(Some(h), async { Ok(()) }, || async {}));
        assert!(matches!(r, Err(TermoakError::Cancelled(_))));
        // Without a handle, or not cancelled: the result.
        assert_eq!(
            block_on(cancellable(None, async { Ok(7) }, || async {})).unwrap(),
            7
        );
        assert_eq!(
            block_on(cancellable(
                Some(TransferHandle::new()),
                async { Ok(8) },
                || async {}
            ))
            .unwrap(),
            8
        );
    }
}
