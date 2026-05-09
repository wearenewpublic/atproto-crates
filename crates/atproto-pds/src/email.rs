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
//!   after emitting an INFO log with the message body, so a developer
//!   running the PDS locally can see what would have gone out without
//!   needing an SMTP server.
//! - [`EmailService::Smtp`] (gated on `feature = "smtp"`) — wraps a
//!   `lettre::AsyncSmtpTransport`. Reads the SMTP URL + sender address
//!   from `PDS_EMAIL_SMTP_URL` + `PDS_EMAIL_FROM_ADDRESS`. Falls back to
//!   `Disabled` when those are unset so a binary built with the feature
//!   enabled still works in dev.

use crate::errors::PdsResult;

/// Outbound email service. `Clone` so axum can pass it through `HttpState`.
#[derive(Clone, Default)]
pub enum EmailService {
    /// No-op: logs the message body at INFO. Used in dev/test or when the
    /// `smtp` feature is off.
    #[default]
    Disabled,
    /// Real SMTP delivery via `lettre`.
    #[cfg(feature = "smtp")]
    Smtp(Box<SmtpBackend>),
}

impl EmailService {
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
                Ok(EmailService::Disabled)
            }
            _ => {
                tracing::info!(
                    "EmailService disabled (PDS_EMAIL_SMTP_URL or PDS_EMAIL_FROM_ADDRESS unset); messages will be logged only"
                );
                Ok(EmailService::Disabled)
            }
        }
    }

    /// Send an email. Returns `Ok(())` on success.
    ///
    /// The disabled backend logs `to`, `subject`, and `body` at INFO with a
    /// `dev-only:` prefix so a developer running the PDS locally can see
    /// the message body. The SMTP backend dispatches via lettre; transport
    /// errors surface as `PdsError::Storage`.
    pub async fn send(&self, to: &str, subject: &str, body: &str) -> PdsResult<()> {
        match self {
            EmailService::Disabled => {
                tracing::info!(
                    to = to,
                    subject = subject,
                    body = body,
                    "dev-only: email-disabled stub would have sent message"
                );
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
                .body(body.to_string())
                .map_err(|e| PdsError::Storage {
                    reason: format!("build email message: {e}"),
                })?;
            self.transport
                .send(msg)
                .await
                .map_err(|e| PdsError::Storage {
                    reason: format!("smtp send: {e}"),
                })?;
            Ok(())
        }
    }
}

#[cfg(feature = "smtp")]
pub use smtp::SmtpBackend;

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn disabled_backend_logs_and_succeeds() {
        let svc = EmailService::default();
        svc.send("recipient@example.com", "subject", "body")
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn from_env_without_config_returns_disabled() {
        let svc = EmailService::from_env(None, None).unwrap();
        assert!(matches!(svc, EmailService::Disabled));
    }
}
