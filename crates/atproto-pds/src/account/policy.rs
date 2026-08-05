//! Whether an account has accepted the operator's current policy documents.
//!
//! The acceptance lives in the account's own repository, as a
//! `com.atproto-crates.pds.policyAcceptance` record. That is deliberate --
//! it travels with the identity through a migration and can be shown to
//! anyone -- but it means the check here is a repository read rather than a
//! column lookup.
//!
//! # What "accepted" means
//!
//! A record whose `policy` equals the configured set identifier exactly.
//! Nothing else counts: the identifier names one immutable set of documents,
//! so an acceptance of last year's terms is not an acceptance of this year's,
//! and revising the documents means issuing a new identifier and asking again.
//!
//! # Where it is enforced
//!
//! At session creation, which is the narrowest place that still covers
//! everything. A holder who has not accepted cannot mint an app-password
//! session or complete an OAuth grant, so no client can act for them -- but
//! the portal deliberately still lets them *sign in*, because being unable to
//! reach the page that records the acceptance would be a deadlock rather than
//! a gate.

use crate::http::state::PolicyDocuments;
use crate::repo::RepoReader;

/// The record type an acceptance is written as.
pub const POLICY_ACCEPTANCE_NSID: &str = "com.atproto-crates.pds.policyAcceptance";

/// How many acceptance records to look through.
///
/// One per policy revision the holder has ever agreed to, so this is a
/// handful even for a long-lived account. A page of a hundred is far more
/// than a real repository holds and bounds the read regardless.
const SCAN_LIMIT: u32 = 100;

/// Whether `did` has accepted `policy`.
///
/// Fails **closed** on a read error: an account whose repository cannot be
/// read has not demonstrated acceptance, and letting a storage fault open the
/// gate would make the gate worthless exactly when something is wrong. The
/// caller logs; the holder sees the acceptance prompt and their existing
/// record makes the second attempt succeed.
pub async fn has_accepted(reader: &RepoReader, did: &str, policy: &PolicyDocuments) -> bool {
    let page = match reader
        .list_records(did, POLICY_ACCEPTANCE_NSID, SCAN_LIMIT, None, true)
        .await
    {
        Ok(p) => p,
        Err(e) => {
            tracing::warn!(
                did,
                error = ?e,
                "could not read policy acceptances; treating as not accepted"
            );
            return false;
        }
    };
    page.records.iter().any(|r| {
        r.value
            .get("policy")
            .and_then(|v| v.as_str())
            .is_some_and(|p| p == policy.set_id)
    })
}

/// Whether this account must accept before a session may be created.
///
/// `None` when the operator configured no policy, which is the common case
/// and costs no read at all.
pub async fn acceptance_required(
    reader: &RepoReader,
    did: &str,
    policy: Option<&PolicyDocuments>,
) -> bool {
    let Some(policy) = policy else {
        return false;
    };
    !has_accepted(reader, did, policy).await
}

#[cfg(test)]
mod tests {
    use crate::http::state::PolicyDocuments;

    fn policy() -> PolicyDocuments {
        PolicyDocuments {
            set_id: "2026-08-05-abc".to_string(),
            url: "https://example.invalid/p".to_string(),
        }
    }

    #[test]
    fn a_matching_identifier_is_what_counts() {
        // The rule is exact equality against the configured set, expressed
        // here over the shape `has_accepted` reads. An acceptance of another
        // set -- last year's terms -- is not an acceptance of this one, which
        // is the whole reason revising the documents means issuing a new
        // identifier.
        let p = policy();
        let accepted_this = serde_json::json!({"policy": "2026-08-05-abc"});
        let accepted_other = serde_json::json!({"policy": "2025-01-01-xyz"});
        let malformed = serde_json::json!({"policy": 42});
        let missing = serde_json::json!({});

        let matches = |v: &serde_json::Value| {
            v.get("policy")
                .and_then(|x| x.as_str())
                .is_some_and(|x| x == p.set_id)
        };
        assert!(matches(&accepted_this));
        assert!(!matches(&accepted_other));
        assert!(!matches(&malformed));
        assert!(!matches(&missing));
    }
}
