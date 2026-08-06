//! `community.lexicon.service.describe` — what this service is and serves.
//!
//! One unauthenticated query, no parameters. A caller learns what roles a
//! service plays and which XRPC methods it actually implements, without having
//! to try each one and read the failures.
//!
//! That last part is the reason to bother. A method this server does not route
//! answers `501 MethodNotImplemented`, which from outside is indistinguishable
//! from a method that is routed and broken — and a caller two hops away sees
//! neither. `com.atproto.sync.getRecord` was missing here for months and
//! surfaced only as `invalid_scope` in an authorization server's log, naming no
//! method and no host. A service that says what it serves turns that into a
//! question anyone can ask directly.
//!
//! # Keeping the answer true
//!
//! The list below is the answer, and a list maintained by hand drifts from the
//! router the first time someone adds a route and forgets. So the test reads
//! `router.rs` and requires the two to agree exactly: a new method that is not
//! declared here fails the build, and a declared method that is not routed
//! fails it too. An honest description is worth more than a flattering one.
//!
//! Proxied namespaces (`app.bsky.*`, `chat.bsky.*`, `tools.ozone.*`) are
//! deliberately absent. This server forwards those rather than implementing
//! them, and claiming them would describe the AppView's capabilities as its
//! own.

use axum::Json;
use serde::Serialize;

/// What this service is. Plain strings, per the proposal.
///
/// `pds` alone: the spaces methods are an extension of what a PDS does with
/// its own repositories rather than a second role, and `labeler` or `relay`
/// would name things this server is not.
const ROLES: [&str; 1] = ["pds"];

/// Every XRPC method this server routes.
///
/// Held to the router by `the_described_methods_match_the_router`. Add a route
/// without adding it here and the tests fail, which is the point.
const METHODS: [&str; 97] = [
    "app.bsky.actor.getPreferences",
    "app.bsky.actor.putPreferences",
    "com.atproto.admin.deleteAccount",
    "com.atproto.admin.disableAccountInvites",
    "com.atproto.admin.disableInviteCodes",
    "com.atproto.admin.enableAccountInvites",
    "com.atproto.admin.forceRepoSync",
    "com.atproto.admin.getAccountInfo",
    "com.atproto.admin.getAccountInfos",
    "com.atproto.admin.getInviteCodes",
    "com.atproto.admin.getSubjectStatus",
    "com.atproto.admin.revokeServiceAuth",
    "com.atproto.admin.searchAccounts",
    "com.atproto.admin.sendEmail",
    "com.atproto.admin.takedownSpaceRecord",
    "com.atproto.admin.updateAccountEmail",
    "com.atproto.admin.updateAccountHandle",
    "com.atproto.admin.updateAccountPassword",
    "com.atproto.admin.updateSubjectStatus",
    "com.atproto.identity.getRecommendedDidCredentials",
    "com.atproto.identity.refreshIdentity",
    "com.atproto.identity.requestPlcOperationSignature",
    "com.atproto.identity.resolveHandle",
    "com.atproto.identity.signPlcOperation",
    "com.atproto.identity.submitPlcOperation",
    "com.atproto.identity.updateHandle",
    "com.atproto.moderation.createReport",
    "com.atproto.repo.applyWrites",
    "com.atproto.repo.createRecord",
    "com.atproto.repo.deleteRecord",
    "com.atproto.repo.describeRepo",
    "com.atproto.repo.getRecord",
    "com.atproto.repo.importRepo",
    "com.atproto.repo.listMissingBlobs",
    "com.atproto.repo.listRecords",
    "com.atproto.repo.putRecord",
    "com.atproto.repo.uploadBlob",
    "com.atproto.server.activateAccount",
    "com.atproto.server.checkAccountStatus",
    "com.atproto.server.confirmEmail",
    "com.atproto.server.createAccount",
    "com.atproto.server.createAppPassword",
    "com.atproto.server.createInviteCode",
    "com.atproto.server.createSession",
    "com.atproto.server.deactivateAccount",
    "com.atproto.server.deleteAccount",
    "com.atproto.server.deleteSession",
    "com.atproto.server.describeServer",
    "com.atproto.server.getAccountInviteCodes",
    "com.atproto.server.getServiceAuth",
    "com.atproto.server.getSession",
    "com.atproto.server.listAppPasswords",
    "com.atproto.server.refreshSession",
    "com.atproto.server.requestAccountDelete",
    "com.atproto.server.requestEmailConfirmation",
    "com.atproto.server.requestEmailUpdate",
    "com.atproto.server.requestPasswordReset",
    "com.atproto.server.reserveSigningKey",
    "com.atproto.server.resetPassword",
    "com.atproto.server.revokeAppPassword",
    "com.atproto.server.updateEmail",
    "com.atproto.simplespace.addMember",
    "com.atproto.simplespace.createSpace",
    "com.atproto.simplespace.deleteSpace",
    "com.atproto.simplespace.listMembers",
    "com.atproto.simplespace.removeMember",
    "com.atproto.simplespace.updateSpace",
    "com.atproto.space.applyWrites",
    "com.atproto.space.createRecord",
    "com.atproto.space.deleteRecord",
    "com.atproto.space.getBlob",
    "com.atproto.space.getDelegationToken",
    "com.atproto.space.getLatestCommit",
    "com.atproto.space.getRecord",
    "com.atproto.space.getRepo",
    "com.atproto.space.getRepoState",
    "com.atproto.space.getSpace",
    "com.atproto.space.getSpaceCredential",
    "com.atproto.space.listRecords",
    "com.atproto.space.listRepoOps",
    "com.atproto.space.listRepos",
    "com.atproto.space.listSpaces",
    "com.atproto.space.notifySpaceDeleted",
    "com.atproto.space.notifyWrite",
    "com.atproto.space.putRecord",
    "com.atproto.space.registerNotify",
    "com.atproto.sync.getBlob",
    "com.atproto.sync.getBlocks",
    "com.atproto.sync.getLatestCommit",
    "com.atproto.sync.getRecord",
    "com.atproto.sync.getRepo",
    "com.atproto.sync.getRepoStatus",
    "com.atproto.sync.listBlobs",
    "com.atproto.sync.listRepos",
    "com.atproto.sync.requestCrawl",
    "com.atproto.sync.subscribeRepos",
    // This method itself: a description that omitted it would be the one
    // claim a caller could disprove from the response in hand.
    "community.lexicon.service.describe",
];

/// One entry in `methods`.
///
/// The proposal allows an NSID, an AT-URI, or a strongRef. Every method here is
/// standardised and resolvable by NSID, so that is the form used; an AT-URI or
/// strongRef would pin a schema record this server does not publish.
#[derive(Debug, Serialize)]
struct MethodRef {
    /// Discriminates the union member.
    #[serde(rename = "$type")]
    kind: &'static str,
    /// The NSID itself.
    value: &'static str,
}

/// Output of `community.lexicon.service.describe`.
#[derive(Debug, Serialize)]
pub struct ServiceDescription {
    /// Roles this service plays.
    roles: Vec<&'static str>,
    /// Methods it implements.
    methods: Vec<MethodRef>,
}

/// Handler for `GET /xrpc/community.lexicon.service.describe`.
///
/// Unauthenticated by design: a caller deciding whether it can talk to this
/// server at all has nothing to authenticate with yet.
pub async fn describe() -> Json<ServiceDescription> {
    Json(ServiceDescription {
        roles: ROLES.to_vec(),
        methods: METHODS
            .iter()
            .map(|nsid| MethodRef {
                kind: "community.lexicon.service.describe#nsid",
                value: nsid,
            })
            .collect(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    /// Every routed method is described, and every described method is routed.
    ///
    /// The whole value of this endpoint is that its answer is true. A hand-kept
    /// list drifts the first time a route is added without touching this file,
    /// and a service that misdescribes itself is worse than one that says
    /// nothing — a caller can handle silence.
    #[test]
    fn the_described_methods_match_the_router() {
        let router = include_str!("router.rs");

        let mut routed = BTreeSet::new();
        let mut rest = router;
        while let Some(i) = rest.find("\"/xrpc/") {
            rest = &rest[i + 7..];
            if let Some(end) = rest.find('"') {
                let nsid = &rest[..end];
                // `_health` is not a method, and `{*nsid}` is a proxy prefix
                // rather than something this server implements.
                if nsid.contains('.') && !nsid.contains('{') {
                    routed.insert(nsid.to_string());
                }
                rest = &rest[end..];
            }
        }

        let described: BTreeSet<String> = METHODS.iter().map(|s| (*s).to_string()).collect();

        let undeclared: Vec<_> = routed.difference(&described).collect();
        assert!(
            undeclared.is_empty(),
            "these methods are routed but not described, so the description \
             understates what this server serves: {undeclared:?}"
        );

        let unrouted: Vec<_> = described.difference(&routed).collect();
        assert!(
            unrouted.is_empty(),
            "these methods are described but not routed, so the description \
             claims what this server does not serve: {unrouted:?}"
        );
    }

    /// The union member is discriminated, or a client cannot tell which of the
    /// three reference forms it received.
    #[tokio::test(flavor = "multi_thread")]
    async fn entries_name_their_union_member() {
        let Json(described) = describe().await;
        let value = serde_json::to_value(&described).unwrap();

        assert_eq!(value["roles"][0], "pds");
        assert_eq!(
            value["methods"][0]["$type"],
            "community.lexicon.service.describe#nsid"
        );
        assert!(
            value["methods"][0]["value"].as_str().unwrap().contains('.'),
            "an NSID entry carries the NSID: {value}"
        );
    }

    /// The spaces methods are described. They are experimental and this server
    /// implements them, and a description that quietly omitted them would hide
    /// exactly the part a caller cannot guess at.
    #[test]
    fn the_experimental_space_methods_are_described() {
        assert!(METHODS.iter().any(|m| m.starts_with("com.atproto.space.")));
        assert!(
            METHODS
                .iter()
                .any(|m| m.starts_with("com.atproto.simplespace."))
        );
    }

    /// Proxied namespaces are not claimed as this server's own.
    #[test]
    fn proxied_namespaces_are_not_claimed() {
        for prefix in ["chat.bsky.", "tools.ozone."] {
            assert!(
                !METHODS.iter().any(|m| m.starts_with(prefix)),
                "{prefix} is forwarded, not implemented here"
            );
        }
    }
}
