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
        let mut sigterm = signal(SignalKind::terminate())?;
        let mut sigint = signal(SignalKind::interrupt())?;
        tokio::select! {
            _ = sigterm.recv() => tracing::info!("received SIGTERM"),
            _ = sigint.recv() => tracing::info!("received SIGINT"),
        }
        self.token.cancel();
        Ok(())
    }

    /// Wait for all tracked tasks to finish, with the configured deadline.
    ///
    /// Closes the tracker (no new tasks may be added), then waits until every
    /// tracked task exits or the deadline elapses. Returns `Ok(())` if drained
    /// cleanly, or `Err(timeout)` if the deadline was hit.
    pub async fn wait_drain(self) -> Result<(), tokio::time::error::Elapsed> {
        self.tracker.close();
        tokio::time::timeout(self.deadline, self.tracker.wait()).await
    }
}

impl Default for ShutdownController {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
