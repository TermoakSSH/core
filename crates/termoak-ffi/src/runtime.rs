//! The library's own tokio runtime and helpers for crossing the FFI
//! boundary.
//!
//! - Exported synchronous functions use [`block_on`] (also safe when called
//!   from a callback running on a runtime thread).
//! - Exported `async` functions spawn the work on this runtime with [`run`]
//!   and await its `JoinHandle`, which works with any executor (Swift's or
//!   Kotlin coroutines). If the caller cancels, the task is aborted.

use std::future::Future;
use std::ops::Deref;
use std::sync::OnceLock;

use tokio::runtime::Runtime;
use tokio::task::AbortHandle;

use crate::error::TermoakError;

static RUNTIME: OnceLock<Runtime> = OnceLock::new();

/// Multi-threaded runtime shared by the whole library (created on first use).
pub(crate) fn runtime() -> &'static Runtime {
    RUNTIME.get_or_init(|| {
        let workers = std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(2)
            .clamp(2, 4);
        tokio::runtime::Builder::new_multi_thread()
            .worker_threads(workers)
            .thread_name("termoak-rt")
            .enable_all()
            .build()
            .expect("could not create the tokio runtime")
    })
}

/// Runs a future to completion from synchronous code.
pub(crate) fn block_on<F: Future>(fut: F) -> F::Output {
    let handle = runtime().handle();
    if tokio::runtime::Handle::try_current().is_ok() {
        // Called from a runtime thread (e.g. inside a callback).
        tokio::task::block_in_place(|| handle.block_on(fut))
    } else {
        handle.block_on(fut)
    }
}

/// Aborts the task if whoever awaits it goes away (cancellation in Swift/Kotlin).
struct AbortOnDrop(Option<AbortHandle>);

impl Drop for AbortOnDrop {
    fn drop(&mut self) {
        if let Some(h) = self.0.take() {
            h.abort();
        }
    }
}

/// Runs `fut` on the library's runtime and returns its result.
pub(crate) async fn run<F, T>(fut: F) -> Result<T, TermoakError>
where
    F: Future<Output = Result<T, TermoakError>> + Send + 'static,
    T: Send + 'static,
{
    let handle = runtime().spawn(fut);
    let mut guard = AbortOnDrop(Some(handle.abort_handle()));
    let res = handle.await;
    guard.0 = None;
    match res {
        Ok(r) => r,
        Err(e) if e.is_panic() => Err(TermoakError::Internal(
            "unexpected internal failure (a task panicked)".into(),
        )),
        Err(_) => Err(TermoakError::Internal("operation cancelled".into())),
    }
}

/// Container that drops its value inside the runtime context: some russh
/// `Drop` impls spawn tasks with `tokio::spawn`, and FFI objects are released
/// from Swift/Kotlin threads that do not belong to the runtime.
pub(crate) struct InRuntime<T>(Option<T>);

impl<T> InRuntime<T> {
    pub(crate) fn new(value: T) -> Self {
        Self(Some(value))
    }
}

impl<T> Deref for InRuntime<T> {
    type Target = T;
    fn deref(&self) -> &T {
        self.0.as_ref().expect("value present until Drop")
    }
}

impl<T> Drop for InRuntime<T> {
    fn drop(&mut self) {
        if let Some(value) = self.0.take() {
            let _guard = runtime().enter();
            drop(value);
        }
    }
}

/// Spawns a thread dedicated to delivering callbacks to the app. Each terminal
/// has its own: callbacks arrive in order, one at a time, and a slow callback
/// does not stall the runtime.
pub(crate) fn spawn_callback_thread<F>(name: &str, f: F)
where
    F: FnOnce(&tokio::runtime::Handle) + Send + 'static,
{
    let handle = runtime().handle().clone();
    let spawned = std::thread::Builder::new()
        .name(name.to_string())
        .spawn(move || {
            let _guard = handle.enter();
            f(&handle)
        });
    if let Err(e) = spawned {
        tracing::error!(error = %e, "could not create the callback thread");
    }
}
