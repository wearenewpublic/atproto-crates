//! Graceful shutdown coordination — `CancellationToken` + `TaskTracker`.
//!
//! The PDS holds long-lived background workers (sequencer,
//! notifier, blob GC, SWR refreshers) and open WebSocket subscribers
//! (`subscribeRepos`). Without coordinated shutdown, restarts drop firehose
//! events between commit and broadcast.
//!
//! `ShutdownController` is constructed at process startup and clones its
//! cancellation token into every spawned task. Tasks must select against the
//! token and exit cleanly when it fires. On signal (SIGTERM / SIGINT), the
//! controller cancels the token and joins all tracked tasks with a deadline.

use std::time::Duration;
use tokio::signal::unix::{SignalKind, signal};
use tokio_util::sync::CancellationToken;
use tokio_util::task::TaskTracker;

/// Default shutdown deadline if not configured.
pub const DEFAULT_SHUTDOWN_DEADLINE: Duration = Duration::from_secs(30);

/// Coordinator for graceful shutdown of all PDS background tasks.
///
/// Construction is one-shot per process; clone [`CancellationToken`] handles
/// out to spawned tasks via [`Self::token`].
pub struct ShutdownController {
    token: CancellationToken,
    tracker: TaskTracker,
    deadline: Duration,
}

impl ShutdownController {
    /// Construct a new controller with the default shutdown deadline.
    pub fn new() -> Self {
        Self::with_deadline(DEFAULT_SHUTDOWN_DEADLINE)
    }

    /// Construct with a specified shutdown deadline.
    pub fn with_deadline(deadline: Duration) -> Self {
        Self {
            token: CancellationToken::new(),
            tracker: TaskTracker::new(),
            deadline,
        }
    }

    /// Get a clone of the cancellation token to pass into spawned tasks.
    pub fn token(&self) -> CancellationToken {
        self.token.clone()
    }

    /// Get a clone of the task tracker for spawning trackable tasks.
    pub fn tracker(&self) -> TaskTracker {
        self.tracker.clone()
    }

    /// Trigger shutdown manually (e.g., for testing).
    pub fn shutdown(&self) {
        self.token.cancel();
    }

    /// Wait for SIGTERM or SIGINT, then trigger shutdown.
    ///
    /// Returns once both signals have been observed *and* the cancellation
    /// token has been fired. Use in conjunction with [`Self::wait_drain`] to
    /// also wait for tasks to finish.
    pub async fn wait_for_signal(&self) -> std::io::Result<()> {
        watch_for_signal(&self.token).await
    }

    /// Run `server` to completion, then cancel and drain the tracked tasks.
    ///
    /// This is the shutdown sequence, and its whole content is the order.
    ///
    /// It used to be a `select!` between the server future and the signal
    /// watcher. That reads as "stop on whichever happens first", which is the
    /// wrong shape for a graceful shutdown: `with_graceful_shutdown` does its
    /// work *while the server future is still being polled*, so returning from
    /// the select on the signal branch dropped that future mid-drain and
    /// aborted every in-flight request. The two `drop()` calls that followed
    /// dropped clones and did nothing, and [`Self::wait_drain`] -- the method
    /// with the deadline, written for exactly this -- had no caller at all.
    ///
    /// What that cost was one aborted request per redeploy at worst and a torn
    /// write at best: a SIGTERM landing between a durable commit and the
    /// `stream_event` append leaves a commit no firehose event will ever
    /// announce.
    ///
    /// So the signal watcher runs *alongside* rather than against. It cancels
    /// the token, the server observes that through its own hook and finishes
    /// what it is holding, and only then are the background workers stopped and
    /// waited for.
    ///
    /// The token is cancelled again after the server returns. The server can
    /// exit on its own -- a bind lost, an I/O error -- and the workers should
    /// stop in that case too rather than outliving the thing they support.
    ///
    /// # Errors
    ///
    /// Returns the server's own error. A drain that exceeds the deadline is
    /// logged rather than returned: the process is exiting either way, and the
    /// distinction the operator needs is in the log, not the exit code.
    pub async fn serve_and_drain<F, E>(self, server: F) -> Result<(), E>
    where
        F: std::future::IntoFuture<Output = Result<(), E>>,
    {
        // `IntoFuture` rather than `Future` because that is what axum's
        // `WithGracefulShutdown` is, and the conversion is the trap: `select!`
        // performs it implicitly, so the racing version this replaced compiled
        // and read as though it awaited the server.
        let server = server.into_future();
        let signal_token = self.token.clone();
        let watcher = tokio::spawn(async move {
            if let Err(error) = watch_for_signal(&signal_token).await {
                tracing::error!(error = ?error, "signal handler error");
            }
        });

        // `IntoFuture` rather than `Future` because that is what axum's
        // `WithGracefulShutdown` is, and the conversion is the trap: `select!`
        // performs it implicitly, so the racing version this replaced compiled
        // and read as though it awaited the server.
        let mut server = std::pin::pin!(server.into_future());

        // Nothing is bounded yet -- this is just serving.
        let exited_early = tokio::select! {
            result = &mut server => Some(result),
            () = self.token.cancelled() => None,
        };
        watcher.abort();

        // One budget for the whole shutdown, not one per stage. The deadline
        // is sized against the supervisor's grace period, and a supervisor
        // does not care which stage was slow.
        let expires_at = tokio::time::Instant::now() + self.deadline;

        let served = match exited_early {
            Some(result) => {
                // The server stopped on its own -- a lost bind, an accept
                // error. Stop the workers rather than let them outlive the
                // thing they exist to support.
                self.token.cancel();
                result
            }
            None => {
                tracing::info!("draining connections");
                // Bounded, because `axum::serve` waits for *every* connection
                // and an idle `subscribeRepos` socket never closes on its own.
                // Unbounded, a single attached firehose consumer would hold
                // the process open until the supervisor killed it -- turning a
                // graceful shutdown back into the abrupt one it replaced.
                match tokio::time::timeout_at(expires_at, &mut server).await {
                    Ok(result) => result,
                    Err(_) => {
                        tracing::warn!(
                            deadline_secs = self.deadline.as_secs(),
                            "connections still open at the shutdown deadline; \
                             abandoning them"
                        );
                        Ok(())
                    }
                }
            }
        };

        tracing::info!("draining tasks");
        let deadline = self.deadline;
        match self.wait_drain_until(expires_at).await {
            Ok(()) => tracing::info!("background tasks drained"),
            Err(_) => tracing::warn!(
                deadline_secs = deadline.as_secs(),
                "shutdown deadline elapsed before every task finished"
            ),
        }
        served
    }

    /// Wait for all tracked tasks to finish, with the configured deadline.
    ///
    /// Closes the tracker (no new tasks may be added), then waits until every
    /// tracked task exits or the deadline elapses. Returns `Ok(())` if drained
    /// cleanly, or `Err(timeout)` if the deadline was hit.
    pub async fn wait_drain(self) -> Result<(), tokio::time::error::Elapsed> {
        let expires_at = tokio::time::Instant::now() + self.deadline;
        self.wait_drain_until(expires_at).await
    }

    /// Wait for all tracked tasks to finish, but no later than `expires_at`.
    ///
    /// Takes an instant rather than a duration so a caller partway through a
    /// shutdown can pass on what is left of the budget instead of starting a
    /// fresh one.
    async fn wait_drain_until(
        self,
        expires_at: tokio::time::Instant,
    ) -> Result<(), tokio::time::error::Elapsed> {
        self.tracker.close();
        tokio::time::timeout_at(expires_at, self.tracker.wait()).await
    }
}

/// Wait for SIGTERM or SIGINT, then cancel `token`.
///
/// Free-standing so it can be spawned without borrowing the controller, which
/// [`ShutdownController::serve_and_drain`] needs in order to run the watcher
/// alongside the server rather than racing it.
///
/// # Errors
///
/// Returns the error from registering either signal handler.
async fn watch_for_signal(token: &CancellationToken) -> std::io::Result<()> {
    let mut sigterm = signal(SignalKind::terminate())?;
    let mut sigint = signal(SignalKind::interrupt())?;
    tokio::select! {
        _ = sigterm.recv() => tracing::info!("received SIGTERM"),
        _ = sigint.recv() => tracing::info!("received SIGINT"),
    }
    token.cancel();
    Ok(())
}

impl Default for ShutdownController {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};

    #[tokio::test]
    async fn token_clones_share_cancellation() {
        let ctrl = ShutdownController::new();
        let t1 = ctrl.token();
        let t2 = ctrl.token();
        assert!(!t1.is_cancelled());
        assert!(!t2.is_cancelled());
        ctrl.shutdown();
        assert!(t1.is_cancelled());
        assert!(t2.is_cancelled());
    }

    #[tokio::test]
    async fn drain_completes_when_no_tasks() {
        let ctrl = ShutdownController::with_deadline(Duration::from_secs(1));
        let result = ctrl.wait_drain().await;
        assert!(result.is_ok());
    }

    /// A stand-in for `axum::serve(..).with_graceful_shutdown(..)`: it notices
    /// the cancellation and *then* takes time finishing what it was holding,
    /// which is the part the racing version used to throw away.
    async fn server_that_drains(
        token: CancellationToken,
        finished: Arc<AtomicBool>,
    ) -> Result<(), std::io::Error> {
        token.cancelled().await;
        tokio::time::sleep(Duration::from_millis(50)).await;
        finished.store(true, Ordering::SeqCst);
        Ok(())
    }

    #[tokio::test]
    async fn in_flight_work_finishes_before_the_process_exits() {
        let ctrl = ShutdownController::with_deadline(Duration::from_secs(5));
        let token = ctrl.token();
        let tracker = ctrl.tracker();

        let request_finished = Arc::new(AtomicBool::new(false));
        let worker_finished = Arc::new(AtomicBool::new(false));

        let worker_token = token.clone();
        let worker_flag = worker_finished.clone();
        tracker.spawn(async move {
            worker_token.cancelled().await;
            // Stands in for a worker with something to flush after the stop
            // signal -- the notifier finishing its batch, say.
            tokio::time::sleep(Duration::from_millis(50)).await;
            worker_flag.store(true, Ordering::SeqCst);
        });

        let server = server_that_drains(token.clone(), request_finished.clone());

        let signal = token.clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(10)).await;
            signal.cancel();
        });

        ctrl.serve_and_drain(server).await.expect("clean exit");

        assert!(
            request_finished.load(Ordering::SeqCst),
            "the server future was dropped instead of awaited, so an in-flight \
             request was aborted mid-shutdown"
        );
        assert!(
            worker_finished.load(Ordering::SeqCst),
            "the drain returned before a tracked worker had finished"
        );
    }

    #[tokio::test]
    async fn a_connection_that_never_closes_does_not_hold_the_process_open() {
        let ctrl = ShutdownController::with_deadline(Duration::from_millis(50));
        let token = ctrl.token();

        // An attached `subscribeRepos` socket. `axum::serve` waits for every
        // connection before its graceful shutdown returns, and a firehose
        // consumer has no reason to close.
        let server = async {
            std::future::pending::<()>().await;
            Ok::<(), std::io::Error>(())
        };

        let signal = token.clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(10)).await;
            signal.cancel();
        });

        // A real timeout so a regression fails the test rather than hanging
        // the suite -- the failure mode here is "waits forever".
        let outcome =
            tokio::time::timeout(Duration::from_secs(5), ctrl.serve_and_drain(server)).await;

        assert!(
            outcome.is_ok(),
            "an idle connection held the shutdown open past the deadline"
        );
    }

    #[tokio::test]
    async fn a_server_error_still_drains_and_propagates() {
        let ctrl = ShutdownController::with_deadline(Duration::from_secs(5));
        let token = ctrl.token();
        let tracker = ctrl.tracker();

        let worker_finished = Arc::new(AtomicBool::new(false));
        let worker_token = token.clone();
        let worker_flag = worker_finished.clone();
        tracker.spawn(async move {
            worker_token.cancelled().await;
            worker_flag.store(true, Ordering::SeqCst);
        });

        // The server can fail on its own -- a lost bind, an accept error --
        // without any signal. The workers should stop rather than outlive it.
        let result = ctrl
            .serve_and_drain(async {
                Err::<(), std::io::Error>(std::io::Error::other("accept failed"))
            })
            .await;

        assert!(result.is_err(), "the server's error must reach the caller");
        assert!(
            worker_finished.load(Ordering::SeqCst),
            "workers were left running after the server exited"
        );
    }

    #[tokio::test]
    async fn a_task_that_ignores_the_deadline_does_not_block_exit() {
        let ctrl = ShutdownController::with_deadline(Duration::from_millis(50));
        ctrl.tracker().spawn(async {
            tokio::time::sleep(Duration::from_secs(30)).await;
        });

        let started = tokio::time::Instant::now();
        ctrl.serve_and_drain(async { Ok::<(), std::io::Error>(()) })
            .await
            .expect("clean exit");

        assert!(
            started.elapsed() < Duration::from_secs(5),
            "a task that ignores cancellation held the process open past the \
             deadline"
        );
    }

    #[tokio::test]
    async fn tracked_task_runs_to_completion_during_drain() {
        let ctrl = ShutdownController::with_deadline(Duration::from_secs(2));
        let token = ctrl.token();
        let tracker = ctrl.tracker();

        tracker.spawn(async move {
            tokio::select! {
                _ = token.cancelled() => "cancelled",
                _ = tokio::time::sleep(Duration::from_millis(50)) => "slept",
            }
        });

        // Cancel and drain
        ctrl.shutdown();
        let result = ctrl.wait_drain().await;
        assert!(result.is_ok());
    }
}
