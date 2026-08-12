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
use crate::http::repository;
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
    build_router_with_request_timeout(state, REQUEST_TIMEOUT)
}

/// [`build_router`] with both deadlines supplied.
///
/// `upload_timeout` covers `uploadBlob` and `importRepo`; `request_timeout`
/// covers everything else. See [`large_body_routes`].
pub fn build_router_with_timeouts(
    state: HttpState,
    request_timeout: std::time::Duration,
    upload_timeout: std::time::Duration,
) -> Router {
    build_router_inner(state, request_timeout, upload_timeout)
}

/// [`build_router`] with the request deadline supplied.
///
/// Exists so a test can assert what the deadline does *not* reach without
/// waiting out the real one — specifically that a `subscribeRepos` subscription
/// outlives it. That holds because the deadline bounds *producing a response*
/// and an upgraded connection is not a response being produced: the handler
/// answers 101 immediately and hyper hands the socket off, outside the future
/// this layer wraps. It is not obvious, it is not written down anywhere else,
/// and a later change — a body-level timeout, a connection-level one, a
/// different server — could take it away without touching this line.
pub fn build_router_with_request_timeout(
    state: HttpState,
    request_timeout: std::time::Duration,
) -> Router {
    build_router_inner(state, request_timeout, UPLOAD_TIMEOUT)
}

fn build_router_inner(
    state: HttpState,
    request_timeout: std::time::Duration,
    upload_timeout: std::time::Duration,
) -> Router {
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
        // What this service is and which methods it serves. Unauthenticated:
        // a caller deciding whether it can talk to this server at all has
        // nothing to authenticate with yet.
        .route(
            "/xrpc/community.lexicon.service.describe",
            get(crate::http::service_describe::describe),
        )
        // A proof of one record's presence or absence, and the only fetch an
        // authorization server makes when resolving a permission set.
        .route(
            "/xrpc/com.atproto.sync.getRecord",
            get(handlers::sync_get_record),
        )
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
        // §11b — requestCrawl. A relay's method, serving the mirror image
        // here: an operator announces this PDS to the crawlers listed in
        // PDS_CRAWLERS so they start consuming its firehose. Admin-gated,
        // because it is outbound traffic this server sends rather than a
        // request it answers.
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
        .route(
            "/xrpc/com.atproto.simplespace.getSpace",
            get(space_handlers::get_space),
        )
        // com.atproto.space.* — permissioned realm
        // Deprecated: getSpace moved to com.atproto.simplespace in PR #100.
        // Kept as an alias so callers can migrate without a flag day.
        .route(
            "/xrpc/com.atproto.space.getSpace",
            get(space_handlers::get_space_deprecated_alias),
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
            "/xrpc/com.atproto.space.listBlobs",
            get(space_handlers::list_blobs),
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
        .route(
            "/xrpc/com.atproto.space.unregisterNotify",
            post(space_handlers::unregister_notify),
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
        //
        // Four sections, each a page in its own right and all four in the nav
        // every page carries: Settings here, then Access, Repository and
        // Delegation below.
        .route("/account", get(portal::dashboard))
        .route("/account/signin", get(portal::sign_in_page))
        .route("/account/signin", post(portal::sign_in))
        .route("/account/signout", post(portal::sign_out))
        .route("/account/signup", get(portal::sign_up_page))
        .route("/account/signup", post(portal::sign_up))
        .route("/account/handle", post(portal::change_handle))
        .route("/account/sessions", get(portal::sessions))
        .route("/account/delegation", get(portal::delegation))
        // The Repository section: a browser over this account's records.
        // `{segment}` is a collection or a blob CID; `looks_like_cid` decides,
        // and nothing else needs to.
        //
        // Both spellings of the index. A section named in a nav is also a URL
        // people type, and axum matches paths literally -- `/account/repository`
        // and `/account/repository/` are two different routes, and mounting only
        // one makes the other a 404 for no reason a reader could guess.
        .route("/account/repository", get(repository::index))
        .route("/account/repository/", get(repository::index))
        .route(
            "/account/repository/public/",
            get(repository::public_collections).post(repository::public_create),
        )
        .route(
            "/account/repository/public/{segment}",
            get(repository::public_collection_or_blob),
        )
        .route(
            "/account/repository/public/{collection}/{rkey}",
            get(repository::public_record)
                .post(repository::public_record_post)
                .delete(repository::public_record_delete),
        )
        .route(
            "/account/repository/space/{host}/{space_type}/{space_key}",
            get(repository::space_collections),
        )
        .route(
            "/account/repository/space/{host}/{space_type}/{space_key}/{segment}",
            get(repository::space_collection_or_blob),
        )
        .route(
            "/account/repository/space/{host}/{space_type}/{space_key}/{collection}/{rkey}",
            get(repository::space_record)
                .post(repository::space_record_post)
                .delete(repository::space_record_delete),
        )
        .route("/account/email", post(portal::change_email))
        .route("/account/email/verify", post(portal::verify_email))
        .route(
            "/account/email/verify/send",
            post(portal::send_verification),
        )
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
        .layer(request_timeout_layer(request_timeout))
        // Merged after the deadline above is applied and before the shared
        // layers below, so these two routes carry their own deadline and
        // everything else -- panic capture, body limit, shedding, CORS --
        // still reaches them.
        .merge(large_body_routes(upload_timeout))
        .layer(catch_panic_layer())
        .layer(axum::extract::DefaultBodyLimit::max(
            DEFAULT_BODY_LIMIT_BYTES,
        ))
        // Refuse past the cap rather than queue behind it. A concurrency limit
        // on its own is a queue, and an unbounded queue is the same unbounded
        // growth wearing a different shape: arrivals past the limit wait rather
        // than being turned away, holding a connection and a partially-read
        // body while they do. Shedding turns the excess into an immediate 503,
        // which a client can retry and a load balancer can read.
        .layer(
            tower::ServiceBuilder::new()
                .layer(axum::error_handling::HandleErrorLayer::new(|_| async {
                    crate::http::errors::XrpcError::new(
                        axum::http::StatusCode::SERVICE_UNAVAILABLE,
                        "Overloaded",
                        "the server is at capacity; retry shortly",
                    )
                }))
                .load_shed()
                .concurrency_limit(MAX_CONCURRENT_REQUESTS),
        )
        .layer(cors_layer())
        // Outermost, so it reaches responses no handler produced: the 503 from
        // load shedding, the 408 from a request deadline, the 500 from a caught
        // panic. Those are served from this origin like any other page.
        .layer(axum::middleware::from_fn(
            crate::http::security_headers::security_headers_middleware,
        ))
        .with_state(state)
}

/// The two routes whose request body is the payload rather than a description
/// of one, on a deadline sized for transferring it.
///
/// [`REQUEST_TIMEOUT`] bounds producing a response, and for a handler that
/// reads its body to completion that includes receiving the upload. Thirty
/// seconds is a sensible ceiling for a request whose body is a few hundred
/// bytes of JSON and the wrong question entirely for one carrying up to a
/// gibibyte: meeting it on `importRepo` at the default `PDS_IMPORT_LIMIT`
/// would take a sustained 273 Mbit/s from the client, and `uploadBlob` at its
/// 16 MiB default still asks for 4.3 Mbit/s -- above what plenty of domestic
/// and mobile uplinks manage.
///
/// The size limits are the real bound on these two; the deadline only has to
/// be long enough not to pre-empt them, while still reclaiming a connection
/// that has genuinely stalled.
fn large_body_routes(timeout: std::time::Duration) -> Router<HttpState> {
    Router::new()
        .route(
            "/xrpc/com.atproto.repo.uploadBlob",
            post(write_handlers::upload_blob),
        )
        .route(
            "/xrpc/com.atproto.repo.importRepo",
            post(write_handlers::import_repo),
        )
        .layer(request_timeout_layer(timeout))
}

/// How many requests may be in flight at once before the rest are refused.
///
/// A deadline bounds how long one request holds its resources; it does not
/// bound how many hold them at the same time. With no cap, arrival rate alone
/// decides peak memory -- and the expensive endpoints here are unauthenticated
/// ones, since `getRepo` builds the whole CAR in memory before sending a byte.
///
/// The number is deliberately high. This is a backstop against a pile-up, not a
/// throughput control: per-IP rate limiting is what shapes ordinary traffic, and
/// a cap low enough to be felt in normal use would be an outage of its own the
/// first time an upstream got slow.
const MAX_CONCURRENT_REQUESTS: usize = 1024;

/// How long a request has to produce a response.
///
/// Hyper applies no deadline of its own, so before this a request had none at
/// any layer: a client could open a connection, send a `Content-Length` and
/// then a byte a minute, and the task, the socket and the partially-buffered
/// body were held for as long as it cared to keep going. At roughly 0.3 bytes
/// per second per connection, the cost of holding a server down is a laptop.
///
/// Thirty seconds is longer than any handler here should need and short enough
/// that a stalled one is reclaimed. It applies to every route including
/// `subscribeRepos`, which sounds wrong for a live tail and is not: what is
/// bounded is producing the response, and a subscription's response is the 101
/// it answers with immediately. The socket that follows is hyper's, not this
/// layer's. `a_subscription_is_not_subject_to_the_request_deadline` is what
/// keeps that true.
const REQUEST_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

/// How long `uploadBlob` and `importRepo` have to produce a response.
///
/// Ten minutes carries a 1 GiB `importRepo` at about 14 Mbit/s and a 16 MiB
/// `uploadBlob` at about 0.2 Mbit/s, which is slow enough to cover a bad
/// mobile connection without leaving a stalled transfer holding a slot
/// indefinitely.
///
/// It is deliberately not unbounded. These are the two endpoints where an
/// attacker gets the most out of a slow-body attack, since the server has
/// agreed in advance to wait for a large body.
const UPLOAD_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(600);

/// Ceiling on a request body buffered by an extractor.
///
/// Equal to the axum default this replaces, so nothing changes size — what
/// changes is that the number is stated here instead of inherited from a
/// dependency's constant. The two endpoints that take large bodies read them as
/// a stream and enforce their own ceilings (`PDS_BLOB_UPLOAD_LIMIT`,
/// `PDS_IMPORT_LIMIT`), which is why this can stay small.
const DEFAULT_BODY_LIMIT_BYTES: usize = 2 * 1024 * 1024;

fn request_timeout_layer(timeout: std::time::Duration) -> tower_http::timeout::TimeoutLayer {
    // 408 rather than the 500 an unhandled stall would eventually look like:
    // the request ran out of time, which is a thing the caller can act on.
    tower_http::timeout::TimeoutLayer::with_status_code(
        axum::http::StatusCode::REQUEST_TIMEOUT,
        timeout,
    )
}

/// Turn a panic in a handler into a 503 instead of a dropped connection.
///
/// Without this a panic unwinds out of the task hyper is running the
/// connection on and the client gets a reset — indistinguishable from a network
/// fault in its telemetry, absent from the access log, and invisible in any
/// metric counting responses by status. The first sign of a reachable panic is
/// then silence, which is the worst way to learn about one.
fn catch_panic_layer() -> tower_http::catch_panic::CatchPanicLayer<
    fn(Box<dyn std::any::Any + Send + 'static>) -> axum::response::Response,
> {
    fn on_panic(err: Box<dyn std::any::Any + Send + 'static>) -> axum::response::Response {
        // The payload is whatever `panic!` was given; a `&str` or `String` for
        // an ordinary panic. It is logged and not returned: a panic message
        // names internals and the caller has no use for it.
        let detail = err
            .downcast_ref::<&str>()
            .map(|s| (*s).to_string())
            .or_else(|| err.downcast_ref::<String>().cloned())
            .unwrap_or_else(|| "non-string panic payload".to_string());
        tracing::error!(panic = %detail, "a request handler panicked");

        use axum::response::IntoResponse as _;
        crate::http::errors::XrpcError::new(
            axum::http::StatusCode::INTERNAL_SERVER_ERROR,
            "InternalServerError",
            "internal error",
        )
        .into_response()
    }

    tower_http::catch_panic::CatchPanicLayer::custom(on_panic as fn(_) -> _)
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
        // Mirror whatever the client asks for rather than naming a fixed set.
        //
        // A PDS cannot know which request headers its callers will send. The
        // set is open-ended and grows without warning: an app can ship a build
        // that adds a vendor header — `x-bsky-topics` is a real example — and a
        // named allowlist rejects it at the preflight. The browser then refuses
        // to send the request at all, so the failure never reaches the server,
        // never appears in its logs, and surfaces to the user as a bare
        // "unable to connect" with a healthy-looking PDS behind it.
        //
        // Mirroring costs nothing here. A request header is only attached by a
        // script that chose to set it, and a script that can set headers can
        // already make the identical request from its own backend, where no
        // CORS policy applies. The allowlist was never a barrier to an attacker
        // — only to legitimate clients. What does the real work is the absence
        // of `Allow-Credentials` below: that is the switch that would let a page
        // spend a visitor's ambient credentials, and it stays off.
        .allow_headers(tower_http::cors::AllowHeaders::mirror_request())
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

/// Stamp the current `DPoP-Nonce` on every response.
///
/// A client learns the nonce from a response header, so a server that only
/// sent one when refusing would make the first request of every session a
/// wasted round trip. Sending it always means a client that keeps the latest
/// value it saw is never challenged after its first exchange.
///
/// Which nonce depends on the endpoint: RFC 9449 §8.1 keeps the authorization
/// server's nonces separate from the resource server's, and this process is
/// both.
pub fn with_dpop_nonce(router: Router, issuer: crate::oauth::nonce::NonceIssuer) -> Router {
    use crate::oauth::nonce::NonceSpace;
    use axum::middleware::from_fn_with_state;

    async fn stamp(
        axum::extract::State(issuer): axum::extract::State<crate::oauth::nonce::NonceIssuer>,
        request: axum::extract::Request,
        next: axum::middleware::Next,
    ) -> axum::response::Response {
        let space = if request.uri().path().starts_with("/oauth/") {
            NonceSpace::Authorization
        } else {
            NonceSpace::Resource
        };
        let mut response = next.run(request).await;
        // A refusal that already carries a challenge chose its own value;
        // overwriting it with the same-space current nonce is harmless, but
        // leaving it alone keeps the challenge and the header it names in
        // agreement whatever order the layers run in.
        if !response.headers().contains_key("dpop-nonce")
            && let Ok(value) = axum::http::HeaderValue::from_str(&issuer.current(space))
        {
            response
                .headers_mut()
                .insert(axum::http::HeaderName::from_static("dpop-nonce"), value);
        }
        response
    }

    router.layer(from_fn_with_state(issuer, stamp))
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
