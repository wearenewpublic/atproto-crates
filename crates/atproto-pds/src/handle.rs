//! Handle normalization, validation and service-domain constraints.
//!
//! Every path that accepts a handle from a caller — `createAccount`,
//! `updateHandle`, `admin.updateAccountHandle` — runs the string through
//! [`normalize_and_validate`] before it reaches storage or a PLC operation.
//!
//! The syntax rules live in `atproto_identity::validation`, which the
//! workspace already ships and which the PDS previously did not call at
//! all. This module adds the two things that are policy rather than
//! syntax: the disallowed-TLD list, and the shape constraints that apply
//! only to handles issued under a domain this server operates.
//!
//! A handle that is *not* under a service domain is a claim about a domain
//! the caller says they control. Syntax cannot establish that, so the
//! caller must additionally prove it by resolution — see
//! `http::identity_handlers::prove_handle_ownership`.

use crate::errors::PdsError;

/// TLDs that may never appear in an AT Protocol handle.
///
/// Mirrors `DISALLOWED_TLDS` in `@atproto/syntax`. Four of these
/// (`.localhost`, `.internal`, `.arpa`, `.local`) are already rejected by
/// `atproto_identity::validation::is_valid_hostname` because they are
/// SSRF-relevant; the remaining four are handle policy and belong here.
///
/// `.test` is deliberately absent — upstream allows it for development,
/// and the acceptance tests in this crate depend on that.
pub const DISALLOWED_TLDS: [&str; 8] = [
    ".local",
    ".arpa",
    ".invalid",
    ".localhost",
    ".internal",
    ".example",
    ".alt",
    ".onion",
];

/// Names this server will not issue as the first label of a handle under
/// one of its own domains.
///
/// This is a deliberately smaller list than the reference's several
/// thousand entries: it covers the names that would let a holder
/// impersonate the operator, a protocol role, or a piece of mail or DNS
/// infrastructure. Operators wanting a broader policy should front the
/// service with their own allocation rules.
const RESERVED_SUBDOMAINS: [&str; 66] = [
    "abuse",
    "about",
    "account",
    "accounts",
    "admin",
    "administrator",
    "anonymous",
    "api",
    "appview",
    "assets",
    "at",
    "atproto",
    "auth",
    "billing",
    "blog",
    "bsky",
    "cdn",
    "dev",
    "did",
    "dns",
    "docs",
    "firehose",
    "ftp",
    "help",
    "hostmaster",
    "imap",
    "legal",
    "login",
    "mail",
    "mod",
    "moderation",
    "mx",
    "no-reply",
    "none",
    "noreply",
    "ns",
    "ns1",
    "ns2",
    "oauth",
    "official",
    "pds",
    "plc",
    "pop",
    "postmaster",
    "privacy",
    "prod",
    "production",
    "register",
    "relay",
    "root",
    "security",
    "service",
    "signup",
    "smtp",
    "staff",
    "staging",
    "static",
    "status",
    "support",
    "system",
    "team",
    "terms",
    "tos",
    "webmaster",
    "well-known",
    "www",
];

/// Shortest first label allowed under a service domain.
const MIN_SERVICE_LABEL: usize = 3;

/// Longest first label allowed under a service domain.
const MAX_SERVICE_LABEL: usize = 18;

/// Normalize a caller-supplied handle and reject it if it is not a valid
/// AT Protocol handle.
///
/// Strips an `at://` or `@` prefix, lowercases, and applies the hostname
/// and disallowed-TLD rules. Returns the normalized form — callers should
/// use the returned value rather than the input, because they differ.
///
/// # Errors
///
/// [`PdsError::InvalidHandle`] when the string is not a syntactically
/// valid handle or ends in a disallowed TLD.
pub fn normalize_and_validate(handle: &str) -> Result<String, PdsError> {
    let normalized = atproto_identity::validation::is_valid_handle(handle).ok_or_else(|| {
        PdsError::InvalidHandle {
            handle: handle.to_string(),
            reason: "not a syntactically valid handle".to_string(),
        }
    })?;
    if let Some(tld) = DISALLOWED_TLDS
        .iter()
        .find(|tld| normalized.ends_with(*tld))
    {
        return Err(PdsError::InvalidHandle {
            handle: normalized,
            reason: format!("{tld} is not an allowed handle TLD"),
        });
    }
    Ok(normalized)
}

/// Whether `handle` sits under one of the domains this server issues
/// handles for.
///
/// An empty `domains` list means the operator pinned no domains, in which
/// case nothing is a service domain and every handle must prove itself by
/// resolution.
#[must_use]
pub fn is_service_domain(handle: &str, domains: &[String]) -> bool {
    service_domain_suffix(handle, domains).is_some()
}

/// The matching service domain for `handle`, if any.
fn service_domain_suffix<'a>(handle: &str, domains: &'a [String]) -> Option<&'a String> {
    domains.iter().find(|domain| {
        let bare = domain.trim_start_matches('.').to_ascii_lowercase();
        handle.ends_with(&format!(".{bare}"))
    })
}

/// Apply the shape constraints for a handle issued under a service domain.
///
/// The portion in front of the service domain must be a single label of
/// 3–18 characters that is not reserved. `allow_reserved` lets an admin
/// hand out a name an ordinary caller could not claim.
///
/// # Errors
///
/// [`PdsError::InvalidHandle`] for a multi-label or out-of-range front,
/// [`PdsError::HandleNotAvailable`] for a reserved name.
pub fn ensure_service_constraints(
    handle: &str,
    domains: &[String],
    allow_reserved: bool,
) -> Result<(), PdsError> {
    let suffix = service_domain_suffix(handle, domains)
        .map(|d| d.trim_start_matches('.').to_ascii_lowercase())
        .unwrap_or_default();
    // `+ 1` for the dot that `service_domain_suffix` matched.
    let front = &handle[..handle.len().saturating_sub(suffix.len() + 1)];
    if front.contains('.') {
        return Err(PdsError::InvalidHandle {
            handle: handle.to_string(),
            reason: "handles under a service domain may not contain a subdomain".to_string(),
        });
    }
    if front.len() < MIN_SERVICE_LABEL {
        return Err(PdsError::InvalidHandle {
            handle: handle.to_string(),
            reason: format!("handle must be at least {MIN_SERVICE_LABEL} characters"),
        });
    }
    if front.len() > MAX_SERVICE_LABEL {
        return Err(PdsError::InvalidHandle {
            handle: handle.to_string(),
            reason: format!("handle must be at most {MAX_SERVICE_LABEL} characters"),
        });
    }
    if !allow_reserved && RESERVED_SUBDOMAINS.contains(&front) {
        return Err(PdsError::HandleNotAvailable {
            handle: handle.to_string(),
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn domains() -> Vec<String> {
        vec!["example.test".to_string()]
    }

    #[test]
    fn normalization_strips_prefixes_and_lowercases() {
        assert_eq!(
            normalize_and_validate("@Alice.Example.Test").unwrap(),
            "alice.example.test"
        );
        assert_eq!(
            normalize_and_validate("at://bob.example.test").unwrap(),
            "bob.example.test"
        );
    }

    #[test]
    fn syntactically_invalid_handles_are_refused() {
        for bad in [
            "localhost",        // no dot
            "192.168.1.1",      // address literal
            "double..dot.test", // empty label
            "-leading.hyphen.test",
            "trailing-.hyphen.test",
            "",
        ] {
            assert!(
                normalize_and_validate(bad).is_err(),
                "{bad} should not validate"
            );
        }
    }

    #[test]
    fn disallowed_tlds_are_refused_including_example() {
        // `.example` is the one that matters here: it reads as a perfectly
        // ordinary handle and upstream forbids it.
        for bad in [
            "alice.example",
            "alice.invalid",
            "alice.alt",
            "alice.onion",
            "alice.local",
            "alice.internal",
        ] {
            assert!(
                normalize_and_validate(bad).is_err(),
                "{bad} should not validate"
            );
        }
        // `.test` is explicitly permitted upstream for development.
        assert!(normalize_and_validate("alice.example.test").is_ok());
    }

    #[test]
    fn service_domain_membership() {
        assert!(is_service_domain("alice.example.test", &domains()));
        assert!(!is_service_domain("alice.elsewhere.test", &domains()));
        // The domain itself is not a handle under the domain.
        assert!(!is_service_domain("example.test", &domains()));
        // No pinned domains means nothing is a service domain.
        assert!(!is_service_domain("alice.example.test", &[]));
    }

    #[test]
    fn service_constraints_bound_the_front_label() {
        assert!(ensure_service_constraints("alice.example.test", &domains(), false).is_ok());
        // Too short.
        assert!(ensure_service_constraints("ab.example.test", &domains(), false).is_err());
        // Too long — 19 characters.
        assert!(
            ensure_service_constraints("abcdefghijklmnopqrs.example.test", &domains(), false)
                .is_err()
        );
        // Nested subdomain.
        assert!(ensure_service_constraints("a.b.example.test", &domains(), false).is_err());
    }

    #[test]
    fn reserved_names_are_refused_unless_allowed() {
        assert!(matches!(
            ensure_service_constraints("admin.example.test", &domains(), false),
            Err(PdsError::HandleNotAvailable { .. })
        ));
        assert!(ensure_service_constraints("admin.example.test", &domains(), true).is_ok());
    }
}
