//! Startup configuration validation.
//!
//!
//! the PDS collects every config issue and reports them all at once rather
//! than failing on the first. The dev-sentinel guard for JWT secret + admin
//! password is the most important check here: deployments accidentally
//! shipping with `dev-only-jwt-secret-32-bytes-min!` would have completely
//! forged-token authentication.

use crate::errors::PdsError;

/// The dev-sentinel JWT secret string baked into the `pds` CLI default. Must
/// be rejected when `production = true`.
pub const DEV_SENTINEL_JWT_SECRET: &str = "dev-only-jwt-secret-32-bytes-min!";

/// The dev-sentinel admin password. Must be rejected when `production = true`.
pub const DEV_SENTINEL_ADMIN_PASSWORD: &str = "admin-default-CHANGE-ME";

/// Minimum acceptable JWT-secret length (bytes). HMAC-SHA256 needs ≥ 32B for
/// security; we enforce this even outside production mode.
pub const MIN_JWT_SECRET_LEN: usize = 32;

/// Configuration values inspected at startup.
#[derive(Debug, Clone)]
pub struct StartupConfig {
    /// `true` when `PDS_PRODUCTION=true`; trips the dev-sentinel guards.
    pub production: bool,
    /// The HMAC secret for app-password sessions and OAuth tokens.
    pub jwt_secret: String,
    /// The Basic-auth password for admin endpoints.
    pub admin_password: String,
    /// The configured service DID.
    pub service_did: String,
}

/// Validate startup config; collect every issue + report all at once.
///
/// # Errors
///
/// Returns [`PdsError::Config`] with one line per validation failure when at
/// least one check fails.
pub fn validate_production_safety(config: &StartupConfig) -> Result<(), PdsError> {
    let mut issues: Vec<String> = Vec::new();

    if config.jwt_secret.len() < MIN_JWT_SECRET_LEN {
        issues.push(format!(
            "PDS_JWT_SECRET must be ≥ {MIN_JWT_SECRET_LEN} bytes (got {})",
            config.jwt_secret.len()
        ));
    }

    if config.production {
        if config.jwt_secret == DEV_SENTINEL_JWT_SECRET {
            issues.push("PDS_JWT_SECRET is the development sentinel value — refusing to boot in production. Set PDS_JWT_SECRET to a 32+ byte random string.".to_string());
        }
        if config.admin_password == DEV_SENTINEL_ADMIN_PASSWORD {
            issues.push("PDS_ADMIN_PASSWORD is the development sentinel value — refusing to boot in production. Set PDS_ADMIN_PASSWORD to a strong random string.".to_string());
        }
        if config.service_did == "did:web:localhost" {
            issues.push("PDS_SERVICE_DID is the development default did:web:localhost — refusing to boot in production. Set PDS_SERVICE_DID to your did:web hostname.".to_string());
        }
        if !config.service_did.starts_with("did:") {
            issues.push(format!(
                "PDS_SERVICE_DID must be a DID (got {})",
                config.service_did
            ));
        }
    }

    if issues.is_empty() {
        Ok(())
    } else {
        Err(PdsError::Config { issues })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn good_secret() -> String {
        "x".repeat(MIN_JWT_SECRET_LEN)
    }

    #[test]
    fn dev_secret_accepted_outside_production() {
        let cfg = StartupConfig {
            production: false,
            jwt_secret: DEV_SENTINEL_JWT_SECRET.to_string(),
            admin_password: DEV_SENTINEL_ADMIN_PASSWORD.to_string(),
            service_did: "did:web:localhost".to_string(),
        };
        validate_production_safety(&cfg).unwrap();
    }

    #[test]
    fn dev_secret_rejected_in_production() {
        let cfg = StartupConfig {
            production: true,
            jwt_secret: DEV_SENTINEL_JWT_SECRET.to_string(),
            admin_password: "real-admin-pw".to_string(),
            service_did: "did:web:pds.example.com".to_string(),
        };
        let err = validate_production_safety(&cfg).unwrap_err();
        let issues = match err {
            PdsError::Config { issues } => issues,
            other => panic!("expected Config, got {other:?}"),
        };
        assert!(
            issues.iter().any(|s| s.contains("PDS_JWT_SECRET")),
            "issues: {issues:?}"
        );
    }

    #[test]
    fn dev_admin_password_rejected_in_production() {
        let cfg = StartupConfig {
            production: true,
            jwt_secret: good_secret(),
            admin_password: DEV_SENTINEL_ADMIN_PASSWORD.to_string(),
            service_did: "did:web:pds.example.com".to_string(),
        };
        let err = validate_production_safety(&cfg).unwrap_err();
        let issues = match err {
            PdsError::Config { issues } => issues,
            other => panic!("expected Config, got {other:?}"),
        };
        assert!(issues.iter().any(|s| s.contains("PDS_ADMIN_PASSWORD")));
    }

    #[test]
    fn localhost_service_did_rejected_in_production() {
        let cfg = StartupConfig {
            production: true,
            jwt_secret: good_secret(),
            admin_password: "real-admin-pw".to_string(),
            service_did: "did:web:localhost".to_string(),
        };
        let err = validate_production_safety(&cfg).unwrap_err();
        let issues = match err {
            PdsError::Config { issues } => issues,
            other => panic!("expected Config, got {other:?}"),
        };
        assert!(issues.iter().any(|s| s.contains("PDS_SERVICE_DID")));
    }

    #[test]
    fn short_jwt_secret_always_rejected() {
        let cfg = StartupConfig {
            production: false,
            jwt_secret: "short".to_string(),
            admin_password: "any".to_string(),
            service_did: "did:web:localhost".to_string(),
        };
        let err = validate_production_safety(&cfg).unwrap_err();
        let issues = match err {
            PdsError::Config { issues } => issues,
            _ => unreachable!(),
        };
        assert!(issues.iter().any(|s| s.contains("≥ 32 bytes")));
    }

    #[test]
    fn all_issues_reported_at_once() {
        let cfg = StartupConfig {
            production: true,
            jwt_secret: "short".to_string(),
            admin_password: DEV_SENTINEL_ADMIN_PASSWORD.to_string(),
            service_did: "did:web:localhost".to_string(),
        };
        let err = validate_production_safety(&cfg).unwrap_err();
        let issues = match err {
            PdsError::Config { issues } => issues,
            _ => unreachable!(),
        };
        // Length, jwt_secret-not-needed-check-fires-because-len-fails-first?,
        // admin_password, service_did. We expect ≥3 reports.
        assert!(
            issues.len() >= 3,
            "expected multiple issues, got: {issues:?}"
        );
    }

    #[test]
    fn good_production_config_passes() {
        let cfg = StartupConfig {
            production: true,
            jwt_secret: good_secret(),
            admin_password: "real-admin-pw".to_string(),
            service_did: "did:web:pds.example.com".to_string(),
        };
        validate_production_safety(&cfg).unwrap();
    }
}
