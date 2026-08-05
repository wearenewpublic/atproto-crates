//! Outbound email — SMTP-backed when the `smtp` Cargo feature is enabled,
//! a no-op (with INFO logging of the would-be confirmation URL) otherwise.
//!
//! this module backs:
//!
//! - `requestEmailUpdate` (§1.9) — confirmation token delivered to the new
//!   address.
//! - `requestAccountDelete` (§2.3) — confirmation token to the account's
//!   primary email.
//! - `admin.sendEmail` (§2.4) — operator-issued message to a user.
//!
//! Two backends:
//!
//! - [`EmailService::Disabled`] — dev/test default. `send` returns `Ok(())`
//!   after logging the recipient and subject. It does **not** log the body:
//!   bodies carry password-reset and account-deletion tokens, and a log is a
//!   lower-trust store than the one those tokens protect. Setting
//!   `PDS_EMAIL_LOG_BODIES` restores the body at DEBUG for local development,
//!   and warns loudly at startup that it has been asked for.
//! - [`EmailService::Smtp`] (gated on `feature = "smtp"`) — wraps a
//!   `lettre::AsyncSmtpTransport`. Reads the SMTP URL + sender address
//!   from `PDS_EMAIL_SMTP_URL` + `PDS_EMAIL_FROM_ADDRESS`. Falls back to
//!   `Disabled` when those are unset so a binary built with the feature
//!   enabled still works in dev.

use crate::errors::PdsResult;

/// Outbound email service. `Clone` so axum can pass it through `HttpState`.
#[derive(Clone)]
pub enum EmailService {
    /// No-op delivery. Used in dev/test, or whenever SMTP is unconfigured.
    Disabled {
        /// Whether to log the rendered body — dev-only, and off unless
        /// `PDS_EMAIL_LOG_BODIES` asked for it.
        log_bodies: bool,
    },
    /// Real SMTP delivery via `lettre`.
    #[cfg(feature = "smtp")]
    Smtp(Box<SmtpBackend>),
}

impl Default for EmailService {
    /// Disabled, and not logging bodies. Reaching the opt-in requires
    /// [`EmailService::disabled`], which reads the environment.
    fn default() -> Self {
        EmailService::Disabled { log_bodies: false }
    }
}

impl EmailService {
    /// A disabled service, reading the dev body-logging opt-in from the
    /// environment.
    #[must_use]
    pub fn disabled() -> Self {
        let log_bodies = std::env::var("PDS_EMAIL_LOG_BODIES")
            .map(|v| matches!(v.trim().to_ascii_lowercase().as_str(), "1" | "true" | "yes"))
            .unwrap_or(false);
        if log_bodies {
            tracing::warn!(
                "PDS_EMAIL_LOG_BODIES is set: rendered email bodies will be written to the log at \
                 DEBUG. Bodies carry password-reset and account-deletion tokens — anyone who can \
                 read the log can take over any account. Never set this outside development."
            );
        }
        EmailService::Disabled { log_bodies }
    }

    /// Construct an SMTP-backed service. Without the `smtp` feature this
    /// always returns [`EmailService::Disabled`].
    ///
    /// `smtp_url` is a `lettre`-style URL (e.g. `smtps://user:pw@smtp.example:465`).
    /// `from_address` is the `From:` header (e.g. `"PDS <noreply@pds.example>"`).
    pub fn from_env(smtp_url: Option<&str>, from_address: Option<&str>) -> PdsResult<Self> {
        match (smtp_url, from_address) {
            #[cfg(feature = "smtp")]
            (Some(url), Some(from)) => {
                let backend = SmtpBackend::new(url, from)?;
                Ok(EmailService::Smtp(Box::new(backend)))
            }
            #[cfg(not(feature = "smtp"))]
            (Some(_), Some(_)) => {
                tracing::warn!(
                    "PDS_EMAIL_SMTP_URL set but `smtp` Cargo feature is disabled; email delivery is a no-op"
                );
                Ok(EmailService::disabled())
            }
            _ => {
                // Not a note in passing: with no mailer, requestPasswordReset
                // and requestAccountDelete return success and deliver nothing,
                // so the flows are broken in a way the caller cannot see.
                tracing::warn!(
                    "email delivery is disabled — PDS_EMAIL_SMTP_URL and PDS_EMAIL_FROM_ADDRESS \
                     are not both set. Password reset, account deletion and email confirmation \
                     will report success without sending anything."
                );
                Ok(EmailService::disabled())
            }
        }
    }

    /// Send an email. Returns `Ok(())` on success.
    ///
    /// The disabled backend logs `to` and `subject` at INFO, and the body
    /// only when `PDS_EMAIL_LOG_BODIES` opted in — at DEBUG, never INFO. The
    /// SMTP backend dispatches via lettre; transport errors surface as
    /// `PdsError::Storage`.
    pub async fn send(&self, to: &str, subject: &str, body: &str) -> PdsResult<()> {
        match self {
            EmailService::Disabled { log_bodies } => {
                // Never the body. It carries the password-reset and
                // account-deletion tokens, and logs are routinely lower-trust
                // than the credential store — shipped to aggregators, mounted
                // into sidecars, swept up by crash reporters. Anyone who could
                // read one could complete a reset for any account.
                tracing::info!(
                    to = to,
                    subject = subject,
                    "email delivery is disabled; message not sent"
                );
                if *log_bodies {
                    tracing::debug!(
                        to = to,
                        body = body,
                        "PDS_EMAIL_LOG_BODIES: rendered body follows"
                    );
                }
                Ok(())
            }
            #[cfg(feature = "smtp")]
            EmailService::Smtp(backend) => backend.send(to, subject, body).await,
        }
    }
}

#[cfg(feature = "smtp")]
mod smtp {
    use crate::errors::{PdsError, PdsResult};
    use lettre::message::header::ContentType;
    use lettre::message::{Mailbox, Message};
    use lettre::transport::smtp::AsyncSmtpTransport;
    use lettre::{AsyncTransport, Tokio1Executor};

    /// SMTP transport + sender address. Configured once at startup via
    /// [`super::EmailService::from_env`] and held by reference throughout
    /// the process lifetime.
    #[derive(Clone)]
    pub struct SmtpBackend {
        transport: AsyncSmtpTransport<Tokio1Executor>,
        from: Mailbox,
    }

    impl SmtpBackend {
        /// Construct a transport from a `lettre`-style URL and a parsed
        /// `From:` address.
        pub fn new(smtp_url: &str, from_address: &str) -> PdsResult<Self> {
            let transport = AsyncSmtpTransport::<Tokio1Executor>::from_url(smtp_url)
                .map_err(|e| PdsError::Storage {
                    reason: format!("parse PDS_EMAIL_SMTP_URL: {e}"),
                })?
                .build();
            let from: Mailbox = from_address.parse().map_err(|e| PdsError::Storage {
                reason: format!("parse PDS_EMAIL_FROM_ADDRESS: {e}"),
            })?;
            Ok(SmtpBackend { transport, from })
        }

        /// Send a message. Surfaces transport errors as `PdsError::Storage`.
        pub async fn send(&self, to: &str, subject: &str, body: &str) -> PdsResult<()> {
            let to_mbox: Mailbox = to.parse().map_err(|e| PdsError::Storage {
                reason: format!("parse `to` address {to}: {e}"),
            })?;
            let msg = Message::builder()
                .from(self.from.clone())
                .to(to_mbox)
                .subject(subject)
                // Declared explicitly. lettre encodes the body as
                // quoted-printable regardless, and with no Content-Type a
                // client falls back to us-ascii -- so every non-ASCII
                // character in a message body, and there are several, arrives
                // as mojibake in the one place the account holder is being
                // asked to read carefully.
                .header(ContentType::TEXT_PLAIN)
                .body(body.to_string())
                .map_err(|e| PdsError::Storage {
                    reason: format!("build email message: {e}"),
                })?;
            let response = self.transport.send(msg).await.map_err(|e| {
                tracing::warn!(to = to, subject = subject, error = %e, "SMTP send failed");
                PdsError::Storage {
                    reason: format!("smtp send: {e}"),
                }
            })?;

            // Logged on success as well as failure.
            //
            // Nothing recorded a delivered message, so an operator whose mail
            // was not arriving had only silence to work with -- and silence
            // meant either "sent" or "the handler never ran", which are
            // different problems with different fixes. The relay's reply is
            // included because it usually carries the queue identifier, which
            // is what ties this line to a row in the provider's own log.
            //
            // Recipient and subject only. Never the body: it carries
            // password-reset and account-deletion codes, and logs are
            // routinely lower-trust than the credential store.
            tracing::info!(
                to = to,
                subject = subject,
                response = ?response.message().collect::<Vec<_>>(),
                "email accepted by the relay"
            );
            Ok(())
        }
    }
}

#[cfg(feature = "smtp")]
pub use smtp::SmtpBackend;

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};
    use tracing::field::{Field, Visit};
    use tracing_subscriber::Layer;
    use tracing_subscriber::layer::{Context, SubscriberExt};

    /// One captured `tracing` event: its level and the names of its fields.
    #[derive(Debug, Clone)]
    struct Captured {
        level: tracing::Level,
        fields: Vec<String>,
    }

    #[derive(Default)]
    struct FieldNames(Vec<String>);

    impl Visit for FieldNames {
        fn record_debug(&mut self, field: &Field, _value: &dyn std::fmt::Debug) {
            self.0.push(field.name().to_string());
        }
        fn record_str(&mut self, field: &Field, _value: &str) {
            self.0.push(field.name().to_string());
        }
    }

    /// Collects every event emitted while it is the active subscriber.
    #[derive(Clone, Default)]
    struct Collector(Arc<Mutex<Vec<Captured>>>);

    impl<S: tracing::Subscriber> Layer<S> for Collector {
        fn on_event(&self, event: &tracing::Event<'_>, _ctx: Context<'_, S>) {
            let mut names = FieldNames::default();
            event.record(&mut names);
            self.0.lock().unwrap().push(Captured {
                level: *event.metadata().level(),
                fields: names.0,
            });
        }
    }

    /// Run `f` with a capturing subscriber installed, returning what it emitted.
    async fn capture<F, Fut>(f: F) -> Vec<Captured>
    where
        F: FnOnce() -> Fut,
        Fut: std::future::Future<Output = ()>,
    {
        let collector = Collector::default();
        let subscriber = tracing_subscriber::registry().with(collector.clone());
        let guard = tracing::subscriber::set_default(subscriber);
        f().await;
        drop(guard);
        collector.0.lock().unwrap().clone()
    }

    /// The rendered body carries password-reset and account-deletion tokens.
    /// Whoever can read the log must not thereby be able to complete either
    /// flow, so the body is never a field of a log event by default.
    #[tokio::test]
    async fn a_disabled_send_never_logs_the_body() {
        let events = capture(|| async {
            let svc = EmailService::default();
            svc.send(
                "recipient@example.com",
                "Reset your password",
                "https://pds.example/reset?token=SECRET-RESET-TOKEN",
            )
            .await
            .unwrap();
        })
        .await;

        assert!(
            !events.is_empty(),
            "the disabled backend should say something"
        );
        for event in &events {
            assert!(
                !event.fields.iter().any(|f| f == "body"),
                "an email body reached the log: {event:?}"
            );
        }
        // It must still be visible that a send was attempted, and to whom.
        let send = events
            .iter()
            .find(|e| e.fields.iter().any(|f| f == "to"))
            .expect("the attempt should be logged with its recipient");
        assert!(send.fields.iter().any(|f| f == "subject"));
    }

    /// The dev affordance survives, but only when asked for and never at INFO.
    #[tokio::test]
    async fn the_body_is_logged_at_debug_when_explicitly_opted_in() {
        let events = capture(|| async {
            let svc = EmailService::Disabled { log_bodies: true };
            svc.send("recipient@example.com", "subject", "the body")
                .await
                .unwrap();
        })
        .await;

        let body_event = events
            .iter()
            .find(|e| e.fields.iter().any(|f| f == "body"))
            .expect("opting in should log the body");
        assert_eq!(
            body_event.level,
            tracing::Level::DEBUG,
            "a message body is never INFO-worthy"
        );
    }

    #[tokio::test]
    async fn disabled_backend_succeeds() {
        let svc = EmailService::default();
        svc.send("recipient@example.com", "subject", "body")
            .await
            .unwrap();
    }

    /// An unconfigured mailer is a broken password reset, so say so at WARN
    /// rather than burying it in INFO.
    #[tokio::test]
    async fn an_unconfigured_mailer_warns() {
        let events = capture(|| async {
            let svc = EmailService::from_env(None, None).unwrap();
            assert!(matches!(svc, EmailService::Disabled { .. }));
        })
        .await;

        assert!(
            events.iter().any(|e| e.level == tracing::Level::WARN),
            "email being disabled should be a warning: {events:?}"
        );
    }
}
