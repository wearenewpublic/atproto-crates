//! axum router construction.

use crate::admin;
use crate::http::auth_handlers;
use crate::http::blob_handlers;
use crate::http::discovery_handlers;
use crate::http::handlers;
use crate::http::identity_handlers;
use crate::http::moderation_handlers;
use crate::http::portal;
use crate::http::preference_handlers;
use crate::http::proxy_handlers;
use crate::http::service_auth_handlers;
use crate::http::space_handlers;
use crate::http::state::HttpState;
use crate::http::write_handlers;
use crate::oauth;
use axum::Router;
use axum::routing::{any, get, post};

/// Build the full router (read-only + auth flows).
///
/// Routes:
/// - Health: `/_alive`, `/_ready`, `/xrpc/_health`.
/// - Repo reads: `getRecord`, `listRecords`, `describeRepo`.
/// - Sync reads: `getLatestCommit`, `getRepoStatus`.
/// - Server: `createAccount`, `createSession`, `getSession`,
///   `refreshSession`, `deleteSession`, `createAppPassword`,
///   `listAppPasswords`, `revokeAppPassword`, `createInviteCode`.
pub fn build_router(state: HttpState) -> Router {
    Router::new()
        .route("/", get(handlers::root))
        .route("/_alive", get(handlers::alive))
        .route("/_ready", get(handlers::ready))
        .route("/xrpc/_health", get(handlers::xrpc_health))
        // com.atproto.repo.*
        .route(
            "/xrpc/com.atproto.repo.getRecord",
            get(handlers::get_record),
        )
        .route(
            "/xrpc/com.atproto.repo.listRecords",
            get(handlers::list_records),
        )
        .route(
            "/xrpc/com.atproto.repo.describeRepo",
            get(handlers::describe_repo),
        )
        // com.atproto.repo.* — writes
        .route(
            "/xrpc/com.atproto.repo.createRecord",
            post(write_handlers::create_record),
        )
        .route(
            "/xrpc/com.atproto.repo.putRecord",
            post(write_handlers::put_record),
        )
        .route(
            "/xrpc/com.atproto.repo.deleteRecord",
            post(write_handlers::delete_record),
        )
        .route(
            "/xrpc/com.atproto.repo.applyWrites",
            post(write_handlers::apply_writes),
        )
        .route(
            "/xrpc/com.atproto.repo.listMissingBlobs",
            get(write_handlers::list_missing_blobs),
        )
        .route(
            "/xrpc/com.atproto.repo.uploadBlob",
            post(write_handlers::upload_blob),
        )
        .route(
            "/xrpc/com.atproto.repo.importRepo",
            post(write_handlers::import_repo),
        )
        // com.atproto.sync.*
        .route(
            "/xrpc/com.atproto.sync.listRepos",
            get(discovery_handlers::list_repos),
        )
        .route(
            "/xrpc/com.atproto.sync.getLatestCommit",
            get(handlers::get_latest_commit),
        )
        .route(
            "/xrpc/com.atproto.sync.getRepoStatus",
            get(handlers::get_repo_status),
        )
        .route("/xrpc/com.atproto.sync.getRepo", get(handlers::get_repo))
        .route(
            "/xrpc/com.atproto.sync.getBlocks",
            get(handlers::get_blocks),
        )
        .route(
            "/xrpc/com.atproto.sync.getBlob",
            get(blob_handlers::get_blob),
        )
        .route(
            "/xrpc/com.atproto.sync.listBlobs",
            get(blob_handlers::list_blobs),
        )
        .route(
            "/xrpc/com.atproto.sync.subscribeRepos",
            get(crate::http::subscribe_handlers::subscribe_repos),
        )
        // §11b — requestCrawl. Operators announce this PDS to the crawlers
        // listed in PDS_CRAWLERS so they start consuming the firehose.
        .route(
            "/xrpc/com.atproto.sync.requestCrawl",
            post(handlers::request_crawl),
        )
        // Private per-account state the PDS owns, not the AppView. Declared
        // before the `app.bsky.*` catch-all below, which would otherwise proxy
        // them to a service that implements neither — so every call failed and
        // preferences could not migrate in either direction.
        .route(
            "/xrpc/app.bsky.actor.getPreferences",
            get(preference_handlers::get_preferences),
        )
        .route(
            "/xrpc/app.bsky.actor.putPreferences",
            post(preference_handlers::put_preferences),
        )
        // Namespaces this server forwards rather than serves. The default
        // target is the configured AppView; a per-request
        // `Atproto-Proxy: <did>#<service-id>` names any other service, which
        // is what makes labelers, feed generators, chat and Ozone reachable.
        //
        // `com.atproto.label.` rather than `com.atproto.` — the rest of that
        // namespace is served locally and a broader prefix would shadow it.
        .route(
            "/xrpc/app.bsky.{*nsid}",
            any(proxy_handlers::proxy_app_bsky),
        )
        .route(
            "/xrpc/chat.bsky.{*nsid}",
            any(proxy_handlers::proxy_app_bsky),
        )
        .route(
            "/xrpc/tools.ozone.{*nsid}",
            any(proxy_handlers::proxy_app_bsky),
        )
        .route(
            "/xrpc/com.atproto.label.{*nsid}",
            any(proxy_handlers::proxy_app_bsky),
        )
        // com.atproto.server.*
        .route(
            "/xrpc/com.atproto.server.describeServer",
            get(discovery_handlers::describe_server),
        )
        .route(
            "/xrpc/com.atproto.server.createAccount",
            post(auth_handlers::create_account),
        )
        .route(
            "/xrpc/com.atproto.server.createSession",
            post(auth_handlers::create_session),
        )
        .route(
            "/xrpc/com.atproto.server.getSession",
            get(auth_handlers::get_session),
        )
        .route(
            "/xrpc/com.atproto.server.refreshSession",
            post(auth_handlers::refresh_session),
        )
        .route(
            "/xrpc/com.atproto.server.deleteSession",
            post(auth_handlers::delete_session),
        )
        .route(
            "/xrpc/com.atproto.server.createAppPassword",
            post(auth_handlers::create_app_password),
        )
        .route(
            "/xrpc/com.atproto.server.listAppPasswords",
            get(auth_handlers::list_app_passwords),
        )
        .route(
            "/xrpc/com.atproto.server.revokeAppPassword",
            post(auth_handlers::revoke_app_password),
        )
        .route(
            "/xrpc/com.atproto.server.createInviteCode",
            post(auth_handlers::create_invite_code),
        )
        .route(
            "/xrpc/com.atproto.server.getServiceAuth",
            get(service_auth_handlers::get_service_auth),
        )
        .route(
            "/xrpc/com.atproto.server.activateAccount",
            post(auth_handlers::activate_account),
        )
        .route(
            "/xrpc/com.atproto.server.deactivateAccount",
            post(auth_handlers::deactivate_account),
        )
        .route(
            "/xrpc/com.atproto.server.checkAccountStatus",
            get(auth_handlers::check_account_status),
        )
        .route(
            "/xrpc/com.atproto.server.reserveSigningKey",
            post(auth_handlers::reserve_signing_key),
        )
        .route(
            "/xrpc/com.atproto.server.requestEmailUpdate",
            post(auth_handlers::request_email_update),
        )
        .route(
            "/xrpc/com.atproto.server.updateEmail",
            post(auth_handlers::update_email),
        )
        .route(
            "/xrpc/com.atproto.server.requestAccountDelete",
            post(auth_handlers::request_account_delete),
        )
        .route(
            "/xrpc/com.atproto.server.deleteAccount",
            post(auth_handlers::delete_account_with_token),
        )
        .route(
            "/xrpc/com.atproto.server.getAccountInviteCodes",
            get(auth_handlers::get_account_invite_codes),
        )
        .route(
            "/xrpc/com.atproto.identity.signPlcOperation",
            post(auth_handlers::sign_plc_operation),
        )
        .route(
            "/xrpc/com.atproto.identity.submitPlcOperation",
            post(auth_handlers::submit_plc_operation),
        )
        .route(
            "/xrpc/com.atproto.identity.resolveHandle",
            get(identity_handlers::resolve_handle),
        )
        .route(
            "/xrpc/com.atproto.identity.updateHandle",
            post(identity_handlers::update_handle),
        )
        .route(
            "/xrpc/com.atproto.identity.requestPlcOperationSignature",
            post(identity_handlers::request_plc_operation_signature),
        )
        // §8.2
        .route(
            "/xrpc/com.atproto.identity.getRecommendedDidCredentials",
            get(identity_handlers::get_recommended_did_credentials),
        )
        // §8.3
        .route(
            "/xrpc/com.atproto.identity.refreshIdentity",
            post(identity_handlers::refresh_identity),
        )
        // §9.1 — initial-email confirmation flow.
        .route(
            "/xrpc/com.atproto.server.requestEmailConfirmation",
            post(auth_handlers::request_email_confirmation),
        )
        .route(
            "/xrpc/com.atproto.server.confirmEmail",
            post(auth_handlers::confirm_email),
        )
        // §9.2 — password-reset flow.
        .route(
            "/xrpc/com.atproto.server.requestPasswordReset",
            post(auth_handlers::request_password_reset),
        )
        .route(
            "/xrpc/com.atproto.server.resetPassword",
            post(auth_handlers::reset_password),
        )
        // §9.3 — moderation report forwarding.
        .route(
            "/xrpc/com.atproto.moderation.createReport",
            post(moderation_handlers::create_report),
        )
        // OAuth
        .route("/oauth/par", post(oauth::par_handler))
        .route("/oauth/authorize", get(oauth::consent_page))
        .route("/oauth/authorize", post(oauth::authorize_handler))
        .route("/oauth/token", post(oauth::token_handler))
        .route("/oauth/revoke", post(oauth::revoke_handler))
        .route("/oauth/jwks", get(oauth::jwks_handler))
        // Identity discovery. `atproto-did` resolves a handle hosted on this
        // server's own domain; `did.json` is this server's own did:web
        // document, synthesised rather than served from a file.
        .route(
            "/.well-known/atproto-did",
            get(discovery_handlers::well_known_atproto_did),
        )
        .route(
            "/.well-known/did.json",
            get(discovery_handlers::well_known_did_json),
        )
        .route(
            "/.well-known/oauth-authorization-server",
            get(oauth::oauth_authorization_server),
        )
        .route(
            "/.well-known/oauth-protected-resource",
            get(oauth::oauth_protected_resource),
        )
        // com.atproto.simplespace.* — host-internal space management
        .route(
            "/xrpc/com.atproto.simplespace.createSpace",
            post(space_handlers::create_space),
        )
        .route(
            "/xrpc/com.atproto.simplespace.updateSpace",
            post(space_handlers::update_space),
        )
        .route(
            "/xrpc/com.atproto.simplespace.deleteSpace",
            post(space_handlers::delete_space),
        )
        .route(
            "/xrpc/com.atproto.simplespace.addMember",
            post(space_handlers::add_member),
        )
        .route(
            "/xrpc/com.atproto.simplespace.removeMember",
            post(space_handlers::remove_member),
        )
        .route(
            "/xrpc/com.atproto.simplespace.listMembers",
            get(space_handlers::get_members),
        )
        // com.atproto.space.* — permissioned realm
        .route(
            "/xrpc/com.atproto.space.getSpace",
            get(space_handlers::get_space),
        )
        .route(
            "/xrpc/com.atproto.space.listSpaces",
            get(space_handlers::list_spaces),
        )
        .route(
            "/xrpc/com.atproto.space.applyWrites",
            post(space_handlers::apply_writes),
        )
        .route(
            "/xrpc/com.atproto.space.createRecord",
            post(space_handlers::create_record_write),
        )
        .route(
            "/xrpc/com.atproto.space.putRecord",
            post(space_handlers::put_record_write),
        )
        .route(
            "/xrpc/com.atproto.space.deleteRecord",
            post(space_handlers::delete_record_write),
        )
        .route(
            "/xrpc/com.atproto.space.getRecord",
            get(space_handlers::get_record),
        )
        .route(
            "/xrpc/com.atproto.space.listRecords",
            get(space_handlers::list_records),
        )
        .route(
            "/xrpc/com.atproto.space.getBlob",
            get(space_handlers::get_blob),
        )
        .route(
            "/xrpc/com.atproto.space.listRepos",
            get(space_handlers::list_repos),
        )
        // Full-state recovery: the whole repo as a CAR. The only path open to a
        // syncer past its oplog retention.
        .route(
            "/xrpc/com.atproto.space.getRepo",
            get(space_handlers::get_repo),
        )
        // `getLatestCommit` is the canonical name; `getRepoState` is the name
        // this server shipped before the draft settled and is kept as an alias
        // to the same handler, which is what HappyView does. A conformant client
        // was 404ing on the only name it knows.
        .route(
            "/xrpc/com.atproto.space.getLatestCommit",
            get(space_handlers::get_repo_state),
        )
        .route(
            "/xrpc/com.atproto.space.getRepoState",
            get(space_handlers::get_repo_state),
        )
        .route(
            "/xrpc/com.atproto.space.listRepoOps",
            get(space_handlers::list_repo_ops),
        )
        .route(
            "/xrpc/com.atproto.space.getDelegationToken",
            get(space_handlers::get_delegation_token),
        )
        .route(
            "/xrpc/com.atproto.space.getSpaceCredential",
            post(space_handlers::get_space_credential),
        )
        // Notify subscription (space-credential auth).
        .route(
            "/xrpc/com.atproto.space.registerNotify",
            post(space_handlers::register_notify),
        )
        // Inbound notifyWrite (service auth; contentless { space, repo, rev }).
        .route(
            "/xrpc/com.atproto.space.notifyWrite",
            post(space_handlers::notify_write),
        )
        // Space-deletion lifecycle (service auth).
        .route(
            "/xrpc/com.atproto.space.notifySpaceDeleted",
            post(space_handlers::notify_space_deleted),
        )
        // com.atproto.admin.*
        .route(
            "/xrpc/com.atproto.admin.getAccountInfo",
            get(admin::get_account_info),
        )
        .route(
            "/xrpc/com.atproto.admin.getAccountInfos",
            get(admin::get_account_infos),
        )
        .route(
            "/xrpc/com.atproto.admin.getSubjectStatus",
            get(admin::get_subject_status),
        )
        .route(
            "/xrpc/com.atproto.admin.updateSubjectStatus",
            post(admin::update_subject_status),
        )
        .route(
            "/xrpc/com.atproto.admin.deleteAccount",
            post(admin::delete_account),
        )
        .route(
            "/xrpc/com.atproto.admin.searchAccounts",
            get(admin::search_accounts),
        )
        .route(
            "/xrpc/com.atproto.admin.getInviteCodes",
            get(admin::get_invite_codes),
        )
        // §4.2
        .route("/xrpc/com.atproto.admin.sendEmail", post(admin::send_email))
        // §4.3
        .route(
            "/xrpc/com.atproto.admin.updateAccountEmail",
            post(admin::update_account_email),
        )
        .route(
            "/xrpc/com.atproto.admin.updateAccountHandle",
            post(admin::update_account_handle),
        )
        .route(
            "/xrpc/com.atproto.admin.updateAccountPassword",
            post(admin::update_account_password),
        )
        // §4.4
        .route(
            "/xrpc/com.atproto.admin.takedownSpaceRecord",
            post(admin::takedown_space_record),
        )
        // §4.5
        .route(
            "/xrpc/com.atproto.admin.revokeServiceAuth",
            post(admin::revoke_service_auth),
        )
        // §4.6
        .route(
            "/xrpc/com.atproto.admin.disableAccountInvites",
            post(admin::disable_account_invites),
        )
        .route(
            "/xrpc/com.atproto.admin.enableAccountInvites",
            post(admin::enable_account_invites),
        )
        .route(
            "/xrpc/com.atproto.admin.disableInviteCodes",
            post(admin::disable_invite_codes),
        )
        // §7.2
        .route(
            "/xrpc/com.atproto.admin.forceRepoSync",
            post(admin::force_repo_sync),
        )
        // Operator HTML dashboard (Basic-auth gated, same as JSON admin API).
        // The account portal. Not XRPC: these are HTML pages and form posts,
        // the only way to use this server with nothing but a browser.
        .route("/account", get(portal::dashboard))
        .route("/account/signin", get(portal::sign_in_page))
        .route("/account/signin", post(portal::sign_in))
        .route("/account/signout", post(portal::sign_out))
        .route("/account/signup", get(portal::sign_up_page))
        .route("/account/signup", post(portal::sign_up))
        .route("/account/email", post(portal::change_email))
        .route("/account/email/code", post(portal::email_code))
        .route("/account/password", post(portal::change_password))
        .route("/account/policy", post(portal::accept_policy))
        .route("/account/app-passwords", post(portal::create_app_password))
        .route(
            "/account/app-passwords/revoke",
            post(portal::revoke_app_password),
        )
        .route(
            "/account/signout-everywhere",
            post(portal::sign_out_everywhere),
        )
        .route("/admin", get(admin::dashboard_handler))
        .route("/admin/", get(admin::dashboard_handler))
        .fallback(unmatched)
        .layer(cors_layer())
        .with_state(state)
}

/// Answer a request that matched no route.
///
/// An XRPC path gets `MethodNotImplemented` (501) in a JSON error envelope;
/// everything else gets the bare 404 axum would have produced on its own.
///
/// # Why an unrouted XRPC method is 501 and not 404
///
/// XRPC requires every error response to carry `{"error", "message"}`, and a
/// client parses that body to decide what happened. A bodiless 404 is
/// indistinguishable from a misconfigured proxy or a wrong hostname, so a
/// client cannot tell "this server does not implement that method" from "this
/// is not a PDS". The reference server routes `/xrpc/:methodId` to a single
/// handler and raises `MethodNotImplementedError` when the method id is not in
/// its lexicon catalogue, and `ResponseType.MethodNotImplemented` is 501.
///
/// # Why this is scoped by path prefix rather than a `/xrpc/{*rest}` route
///
/// The XRPC envelope is a claim about which protocol a path speaks, and it is
/// only true under `/xrpc/`. A missing `/.well-known/oauth-protected-resource`,
/// `/oauth/callback` or `/metrics` is an ordinary HTTP 404 and answering it
/// with an XRPC error name would misdescribe it — an OAuth client reading a 501
/// there would conclude the authorization server is broken rather than absent.
/// Testing the prefix inside the fallback keeps the routing table untouched, so
/// no existing route can be shadowed by a new wildcard and the proxy prefixes
/// (`/xrpc/app.bsky.{*nsid}` and friends) keep matching first and forwarding
/// methods this server does not itself implement.
///
/// # Why only a single path segment counts as a method id
///
/// An NSID is one path segment: it has no `/` in it. The reference route is
/// `/xrpc/:methodId` and an express `:param` does not match across slashes, so
/// `/xrpc/`, `/xrpc/a/b/c` and `/xrpc//bar` reach no XRPC handler there and are
/// ordinary 404s. A path that cannot name a method has no method to report as
/// unimplemented, so requiring a non-empty segment containing no `/` keeps the
/// 501 to the paths that route actually reaches.
///
/// A trailing slash — `/xrpc/foo/` — is the one case where this is stricter
/// than the reference, whose router has `strict routing` off and so reads it as
/// `foo`. Matching that would mean normalizing trailing slashes, and this
/// server does not: `/xrpc/com.atproto.repo.createRecord/` matches no route
/// either, so treating the same path as a named method here would contradict
/// the routing table one line above. Trailing-slash normalization is a separate
/// decision for the whole surface, not something to smuggle in via the
/// fallback.
async fn unmatched(uri: axum::http::Uri) -> axum::response::Response {
    use crate::http::errors::XrpcError;
    use axum::http::StatusCode;
    use axum::response::IntoResponse;

    let nsid = uri
        .path()
        .strip_prefix("/xrpc/")
        .filter(|nsid| !nsid.is_empty() && !nsid.contains('/'));

    match nsid {
        Some(nsid) => {
            tracing::debug!(nsid = %nsid, "unrouted XRPC method");
            XrpcError::new(
                StatusCode::NOT_IMPLEMENTED,
                "MethodNotImplemented",
                "Method Not Implemented",
            )
            .into_response()
        }
        None => StatusCode::NOT_FOUND.into_response(),
    }
}

/// Cross-origin policy for the whole surface.
///
/// A browser OAuth client runs on some other origin. Without these headers the
/// browser refuses to hand it the response body, so discovery fails before the
/// authorization request is attempted — and every XRPC call afterwards fails
/// the same way.
///
/// # Why a wildcard origin is safe here, and why credentials are not allowed
///
/// AT Protocol authenticates with `Authorization` and `DPoP` request headers,
/// never with cookies. A browser attaches neither to a cross-origin request
/// unless the calling script sets them explicitly — and a script that can set
/// them already holds the token. So `Allow-Origin: *` grants a hostile page
/// nothing it could not get by calling this server from its own backend.
///
/// `Allow-Credentials: true` is what would change that: it is the switch that
/// makes a browser send *ambient* credentials — cookies, cached Basic-auth —
/// and hand the response to the page. Combined with a wildcard origin it is
/// also forbidden outright by the Fetch standard. It is deliberately absent,
/// and `preflight_is_answered_without_credentials` fails if it ever appears.
///
/// This covers the admin routes too. They are Basic-auth gated, and an
/// operator's browser will not attach cached Basic credentials to a
/// cross-origin request whose response it is not allowed to read.
fn cors_layer() -> tower_http::cors::CorsLayer {
    use axum::http::{HeaderName, Method, header};
    use tower_http::cors::{Any, CorsLayer};

    CorsLayer::new()
        .allow_origin(Any)
        .allow_methods([Method::GET, Method::POST, Method::OPTIONS])
        .allow_headers([
            header::CONTENT_TYPE,
            header::AUTHORIZATION,
            HeaderName::from_static("dpop"),
            HeaderName::from_static("atproto-proxy"),
            HeaderName::from_static("atproto-accept-labelers"),
        ])
        // A client cannot read a response header it was not told about, so a
        // DPoP nonce challenge or a `WWW-Authenticate` hint would be invisible
        // to the code that has to act on it.
        .expose_headers([
            HeaderName::from_static("dpop-nonce"),
            header::WWW_AUTHENTICATE,
            HeaderName::from_static("atproto-repo-rev"),
        ])
        .max_age(std::time::Duration::from_secs(86_400))
}

/// Mount the Prometheus `/metrics` route + request-counter middleware on
/// an existing router.
///
/// Mounted as a no-op stub when the `metrics` feature is off so the
/// boot sequence in `bin/pds.rs` doesn't need feature gates of its
/// own.
#[cfg(feature = "metrics")]
pub fn with_metrics(router: Router, metrics: crate::metrics::Metrics) -> Router {
    use axum::middleware::from_fn;
    router
        .route("/metrics", get(crate::metrics::metrics_handler))
        .layer(from_fn(crate::metrics::metrics_middleware))
        .layer(axum::Extension(metrics))
}

/// Off-feature stub — returns the router unchanged. Takes a unit-typed
/// metrics handle so callers don't need feature gates around the
/// invocation.
#[cfg(not(feature = "metrics"))]
pub fn with_metrics(router: Router, _metrics: ()) -> Router {
    router
}

/// Apply the per-IP rate-limit policy to every route.
///
/// Layered outside the router so it runs before routing: a scan of a hundred
/// nonexistent paths should cost the scanner its budget rather than costing
/// nothing because none of them matched.
///
/// Kept separate from `build_router` so tests can build an unlimited router —
/// and, more usefully, so a test that *is* about limiting opts in explicitly
/// rather than inheriting a policy it did not set.
pub fn with_rate_limit(router: Router, policy: crate::http::rate_limit::RateLimitPolicy) -> Router {
    use axum::middleware::from_fn;
    router
        .layer(from_fn(crate::http::rate_limit::rate_limit_middleware))
        .layer(axum::Extension(policy))
}
