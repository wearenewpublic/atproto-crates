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
    /// `true` when `PDS_ALLOW_DEV_DEFAULTS=true`, which is the only way to
    /// boot with the sentinel admin password.
    ///
    /// The sentinel used to be permitted whenever `production` was false —
    /// so an operator who never read the flag's help shipped a password that
    /// is written down in this repository. Requiring an explicit opt-in makes
    /// forgetting fail closed instead.
    pub allow_dev_defaults: bool,
    /// The HMAC secret for app-password sessions and OAuth tokens.
    pub jwt_secret: String,
    /// The Basic-auth password for admin endpoints.
    pub admin_password: String,
    /// The configured service DID.
    pub service_did: String,
    /// `PDS_DURABILITY_PROFILE` — `memory`, `sql`, or `valkey` when a Valkey
    /// URL is configured.
    pub durability_profile: String,
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

    // The sentinel admin password is refused everywhere, not only in
    // production. It is the single secret standing in front of every admin
    // verb, and its value is public — it is a constant in this crate.
    if config.admin_password == DEV_SENTINEL_ADMIN_PASSWORD && !config.allow_dev_defaults {
        issues.push(
            "PDS_ADMIN_PASSWORD is the development sentinel value, which is a constant in this \
             crate and therefore public. Set PDS_ADMIN_PASSWORD to a strong random string, or set \
             PDS_ALLOW_DEV_DEFAULTS=true to acknowledge that this deployment is not reachable by \
             anyone else."
                .to_string(),
        );
    }

    if config.production {
        if config.jwt_secret == DEV_SENTINEL_JWT_SECRET {
            issues.push("PDS_JWT_SECRET is the development sentinel value — refusing to boot in production. Set PDS_JWT_SECRET to a 32+ byte random string.".to_string());
        }
        if config.admin_password == DEV_SENTINEL_ADMIN_PASSWORD && config.allow_dev_defaults {
            issues.push(
                "PDS_ALLOW_DEV_DEFAULTS cannot be combined with PDS_PRODUCTION. Set \
                 PDS_ADMIN_PASSWORD to a strong random string."
                    .to_string(),
            );
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
        // The memory backend holds the JTI replay guard and every rate-limit
        // bucket in process. A restart clears both: single-use OAuth refresh
        // tokens become replayable, and an attacker mid-flood gets a fresh
        // budget. The crate's own module doc has always said so; nothing
        // checked it.
        if config.durability_profile == "memory" {
            issues.push(
                "PDS_DURABILITY_PROFILE=memory keeps the OAuth replay guard and every rate-limit \
                 bucket in process, so both are lost on restart — refusing to boot in production. \
                 Set PDS_DURABILITY_PROFILE=sql, or configure PDS_VALKEY_URL."
                    .to_string(),
            );
        }
    }

    if issues.is_empty() {
        Ok(())
    } else {
        Err(PdsError::Config { issues })
    }
}

/// Refuse to boot when an unsupported backend is configured.
///
/// See `crates/atproto-pds/README.md` § "Unsupported deployment modes".
/// PostgreSQL accounts storage and S3 blob storage both have complete,
/// tested implementations in this crate and no construction site in the
/// binary. Both environment variables used to parse and be ignored, so an
/// operator who configured either believed they had it and got neither.
///
/// A documented deployment mode that does not work is worse than an absent
/// one; one that fails at startup naming the reason is neither.
///
/// # Errors
///
/// [`PdsError::Config`] with one line per configured-but-unsupported
/// backend.
pub fn validate_supported_backends(
    postgres_url: Option<&str>,
    blob_store_url: Option<&str>,
    valkey_url: Option<&str>,
) -> Result<(), PdsError> {
    let set = |v: Option<&str>| v.is_some_and(|s| !s.trim().is_empty());
    let mut issues: Vec<String> = Vec::new();
    if set(postgres_url) {
        issues.push(
            "PDS_POSTGRES_URL is set, but PostgreSQL is not a supported accounts backend on this \
             build — thirteen production call sites take a SQLite-only pool accessor that would \
             panic. Unset it; the accounts DB is SQLite at PDS_DATA_DIRECTORY/accounts.sqlite."
                .to_string(),
        );
    }
    // `PDS_VALKEY_URL` on a build without the feature was worse than ignored.
    // It was read once, to decide what to tell the production-safety gate the
    // durability profile would be, and the runtime selection that would honour
    // it is `#[cfg(feature = "valkey")]` -- compiled out. So the gate was told
    // "valkey", passed, and the server then fell through to the in-memory
    // default: the exact configuration the gate exists to refuse, reached by
    // setting the variable that is supposed to avoid it.
    if set(valkey_url) && !cfg!(feature = "valkey") {
        issues.push(
            "PDS_VALKEY_URL is set, but this build has no `valkey` feature — the JTI replay guard              and rate limiters would silently fall back to in-process memory, which is the              configuration PDS_PRODUCTION refuses. Rebuild with `--features valkey`, or unset it              and set PDS_DURABILITY_PROFILE=sql."
                .to_string(),
        );
    }
    if set(blob_store_url) {
        issues.push(
            "PDS_BLOB_STORE_URL is set, but S3 blob storage is not wired into this binary — \
             HybridS3BlobStorage exists and nothing constructs it. Unset it; blobs are stored in \
             the per-actor store."
                .to_string(),
        );
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

    /// The sentinel *JWT secret* is still fine outside production.
    ///
    /// The admin password is deliberately not: it guards every admin verb from
    /// the network, where a forged token needs the JWT secret to be reachable
    /// in the first place. Hence a real admin password here — this test is
    /// about the JWT sentinel, and used to pass only because both sentinels
    /// were permitted together.
    #[test]
    fn dev_jwt_secret_accepted_outside_production() {
        let cfg = StartupConfig {
            production: false,
            allow_dev_defaults: false,
            jwt_secret: DEV_SENTINEL_JWT_SECRET.to_string(),
            admin_password: "a-real-admin-password".to_string(),
            service_did: "did:web:localhost".to_string(),
            durability_profile: "sql".to_string(),
        };
        validate_production_safety(&cfg).unwrap();
    }

    #[test]
    fn dev_secret_rejected_in_production() {
        let cfg = StartupConfig {
            production: true,
            allow_dev_defaults: false,
            jwt_secret: DEV_SENTINEL_JWT_SECRET.to_string(),
            admin_password: "real-admin-pw".to_string(),
            service_did: "did:web:pds.example.com".to_string(),
            durability_profile: "sql".to_string(),
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
            allow_dev_defaults: false,
            jwt_secret: good_secret(),
            admin_password: DEV_SENTINEL_ADMIN_PASSWORD.to_string(),
            service_did: "did:web:pds.example.com".to_string(),
            durability_profile: "sql".to_string(),
        };
        let err = validate_production_safety(&cfg).unwrap_err();
        let issues = match err {
            PdsError::Config { issues } => issues,
            other => panic!("expected Config, got {other:?}"),
        };
        assert!(issues.iter().any(|s| s.contains("PDS_ADMIN_PASSWORD")));
    }

    #[test]
    fn an_unset_backend_url_is_fine() {
        validate_supported_backends(None, None, None).unwrap();
        // Empty and whitespace-only count as unset: an operator who exports
        // the variable with no value has not configured anything.
        validate_supported_backends(Some(""), Some("   "), Some(" ")).unwrap();
    }

    #[test]
    fn a_configured_postgres_url_refuses_and_says_why() {
        let err =
            validate_supported_backends(Some("postgres://localhost/pds"), None, None).unwrap_err();
        let msg = format!("{err}");
        assert!(msg.contains("PDS_POSTGRES_URL"), "{msg}");
        assert!(
            msg.contains("not a supported accounts backend"),
            "the refusal must name the reason, not just refuse: {msg}"
        );
    }

    #[test]
    fn a_configured_blob_store_url_refuses_and_says_why() {
        let err = validate_supported_backends(None, Some("s3://bucket"), None).unwrap_err();
        let msg = format!("{err}");
        assert!(msg.contains("PDS_BLOB_STORE_URL"), "{msg}");
        assert!(msg.contains("not wired into this binary"), "{msg}");
    }

    /// A valkey URL on a build that cannot use it is refused.
    ///
    /// This one is not merely ignored when unsupported, which is what makes it
    /// worth its own test. The URL was read to decide what the production gate
    /// was told the durability profile would be, while the code that would
    /// honour it is compiled out — so setting it made the gate pass and the
    /// server run on in-process memory, which is the state the gate exists to
    /// refuse. Setting the variable meant to avoid that state was the way to
    /// reach it.
    #[cfg(not(feature = "valkey"))]
    #[test]
    fn a_valkey_url_without_the_feature_refuses_and_says_why() {
        let err =
            validate_supported_backends(None, None, Some("redis://localhost:6379")).unwrap_err();
        let msg = format!("{err}");
        assert!(msg.contains("PDS_VALKEY_URL"), "{msg}");
        assert!(
            msg.contains("no `valkey` feature"),
            "the refusal must name the reason: {msg}"
        );
        assert!(
            msg.contains("--features valkey"),
            "and what to do about it: {msg}"
        );
    }

    /// With the feature compiled in, the same URL is ordinary configuration.
    #[cfg(feature = "valkey")]
    #[test]
    fn a_valkey_url_with_the_feature_is_accepted() {
        validate_supported_backends(None, None, Some("redis://localhost:6379")).unwrap();
    }

    #[test]
    fn both_are_reported_together() {
        // Same rule as the production gate: an operator fixing config should
        // see every problem in one boot, not one per attempt.
        let err = validate_supported_backends(
            Some("postgres://localhost/pds"),
            Some("s3://bucket"),
            None,
        )
        .unwrap_err();
        let msg = format!("{err}");
        assert!(msg.contains("PDS_POSTGRES_URL"), "{msg}");
        assert!(msg.contains("PDS_BLOB_STORE_URL"), "{msg}");
    }

    #[test]
    fn memory_durability_rejected_in_production() {
        // The memory backend loses the OAuth replay guard and every rate-limit
        // bucket on restart. Single-use refresh tokens become replayable and
        // an attacker mid-flood gets a fresh budget.
        let cfg = StartupConfig {
            production: true,
            allow_dev_defaults: false,
            jwt_secret: "x".repeat(32),
            admin_password: "a-real-admin-password".to_string(),
            service_did: "did:web:pds.example.com".to_string(),
            durability_profile: "memory".to_string(),
        };
        let err = validate_production_safety(&cfg).unwrap_err();
        assert!(format!("{err}").contains("PDS_DURABILITY_PROFILE"), "{err}");
    }

    #[test]
    fn memory_durability_is_fine_outside_production() {
        // Refusing it everywhere would break every developer running the
        // binary with no flags, which is not what the risk warrants.
        let cfg = StartupConfig {
            production: false,
            allow_dev_defaults: false,
            jwt_secret: "x".repeat(32),
            admin_password: "a-real-admin-password".to_string(),
            service_did: "did:web:localhost".to_string(),
            durability_profile: "memory".to_string(),
        };
        validate_production_safety(&cfg).unwrap();
    }

    #[test]
    fn valkey_and_sql_both_satisfy_the_production_gate() {
        for profile in ["sql", "valkey"] {
            let cfg = StartupConfig {
                production: true,
                allow_dev_defaults: false,
                jwt_secret: "x".repeat(32),
                admin_password: "a-real-admin-password".to_string(),
                service_did: "did:web:pds.example.com".to_string(),
                durability_profile: profile.to_string(),
            };
            validate_production_safety(&cfg)
                .unwrap_or_else(|e| panic!("{profile} should be accepted: {e}"));
        }
    }

    #[test]
    fn localhost_service_did_rejected_in_production() {
        let cfg = StartupConfig {
            production: true,
            allow_dev_defaults: false,
            jwt_secret: good_secret(),
            admin_password: "real-admin-pw".to_string(),
            service_did: "did:web:localhost".to_string(),
            durability_profile: "sql".to_string(),
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
            allow_dev_defaults: false,
            jwt_secret: "short".to_string(),
            admin_password: "any".to_string(),
            service_did: "did:web:localhost".to_string(),
            durability_profile: "sql".to_string(),
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
            allow_dev_defaults: false,
            jwt_secret: "short".to_string(),
            admin_password: DEV_SENTINEL_ADMIN_PASSWORD.to_string(),
            service_did: "did:web:localhost".to_string(),
            durability_profile: "sql".to_string(),
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
            allow_dev_defaults: false,
            jwt_secret: good_secret(),
            admin_password: "real-admin-pw".to_string(),
            service_did: "did:web:pds.example.com".to_string(),
            durability_profile: "sql".to_string(),
        };
        validate_production_safety(&cfg).unwrap();
    }

    /// The sentinel is refused even outside production.
    ///
    /// It used to be accepted whenever `production` was false, so an operator
    /// who never set `PDS_PRODUCTION` shipped a password written down in this
    /// crate. Absence of a flag now fails closed.
    #[test]
    fn dev_admin_password_refused_without_an_explicit_opt_in() {
        let cfg = StartupConfig {
            production: false,
            allow_dev_defaults: false,
            jwt_secret: "x".repeat(MIN_JWT_SECRET_LEN),
            admin_password: DEV_SENTINEL_ADMIN_PASSWORD.to_string(),
            service_did: "did:web:localhost".to_string(),
            durability_profile: "sql".to_string(),
        };
        let err = validate_production_safety(&cfg).unwrap_err();
        assert!(
            format!("{err}").contains("PDS_ADMIN_PASSWORD"),
            "the sentinel must be refused without an opt-in: {err}"
        );
    }

    /// A developer who says so explicitly may still use it.
    #[test]
    fn dev_admin_password_allowed_with_an_explicit_opt_in() {
        let cfg = StartupConfig {
            production: false,
            allow_dev_defaults: true,
            jwt_secret: "x".repeat(MIN_JWT_SECRET_LEN),
            admin_password: DEV_SENTINEL_ADMIN_PASSWORD.to_string(),
            service_did: "did:web:localhost".to_string(),
            durability_profile: "sql".to_string(),
        };
        validate_production_safety(&cfg).unwrap();
    }

    /// The opt-in is not a production escape hatch.
    #[test]
    fn the_dev_opt_in_cannot_be_combined_with_production() {
        let cfg = StartupConfig {
            production: true,
            allow_dev_defaults: true,
            jwt_secret: "x".repeat(MIN_JWT_SECRET_LEN),
            admin_password: DEV_SENTINEL_ADMIN_PASSWORD.to_string(),
            service_did: "did:web:pds.example".to_string(),
            durability_profile: "sql".to_string(),
        };
        let err = validate_production_safety(&cfg).unwrap_err();
        assert!(format!("{err}").contains("PDS_ALLOW_DEV_DEFAULTS"), "{err}");
    }
}
