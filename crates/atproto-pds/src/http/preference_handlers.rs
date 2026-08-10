//! `app.bsky.actor.getPreferences` / `putPreferences`.
//!
//! Private per-account state: muted words, feed preferences, content-label
//! settings. `getPreferences`'s own lexicon names the purpose —
//! *"synchronization between multiple devices, and import/export during account
//! migration"* — so these belong to the PDS, not to an AppView.
//!
//! They previously fell through the `app.bsky.*` catch-all and were proxied to
//! an AppView that implements neither, so every call failed and private state
//! could not migrate in either direction.
//!
//! # Why the payload is opaque
//!
//! `app.bsky.actor.defs#preferences` is an array of open-union objects. The PDS
//! has no reason to interpret a muted word or a feed choice, and parsing them
//! would mean tracking every preference type any AppView ever adds. The array is
//! stored as the JSON it arrived as and returned verbatim, so a preference type
//! this build has never heard of round-trips intact.

use crate::actor_store::sql::SqlActorStore;
use crate::http::auth::{request_htm_htu, require_authn_sub};
use crate::http::errors::XrpcError;
use crate::http::extract::XrpcJson as Json;
use crate::http::state::HttpState;
use axum::extract::State;
use axum::http::StatusCode;
use axum::http::request::Parts;
use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Output of `app.bsky.actor.getPreferences`.
#[derive(Debug, Serialize)]
pub struct GetPreferencesResponse {
    /// The stored preferences array. Required by the lexicon, so an account
    /// that has never stored any gets `[]` rather than an omitted field.
    pub preferences: Value,
}

/// Input for `app.bsky.actor.putPreferences`.
#[derive(Debug, Deserialize)]
pub struct PutPreferencesInput {
    /// The full preferences array to store.
    pub preferences: Value,
}

/// Handler for `GET /xrpc/app.bsky.actor.getPreferences`.
///
/// Requires auth, and answers only for the calling account: preferences are
/// private state, and there is no lexicon parameter naming another actor.
pub async fn get_preferences(
    State(state): State<HttpState>,
    parts: Parts,
) -> Result<Json<GetPreferencesResponse>, XrpcError> {
    let (htm, htu) = request_htm_htu(&parts);
    let did = require_authn_sub(&parts, &state, &htm, &htu).await?;
    let store = open_store(&state, &did).await?;

    let row: Option<(String,)> =
        sqlx::query_as("SELECT preferences_json FROM preference WHERE id = 1")
            .fetch_optional(store.pool())
            .await
            .map_err(|e| {
                XrpcError::new(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "InternalError",
                    format!("read preferences: {e}"),
                )
            })?;

    let preferences = match row {
        Some((json,)) => serde_json::from_str(&json).unwrap_or_else(|_| Value::Array(Vec::new())),
        None => Value::Array(Vec::new()),
    };
    Ok(Json(GetPreferencesResponse { preferences }))
}

/// Handler for `POST /xrpc/app.bsky.actor.putPreferences`.
///
/// Replaces the stored array wholesale.
///
/// The reference may instead merge by namespace, leaving entries outside
/// `app.bsky.*` untouched. That behaviour could not be verified from here, and a
/// merge rule that is subtly wrong silently discards user settings — so this
/// does the predictable thing and documents it, rather than half-implementing a
/// rule it cannot check. A client that reads, edits and writes back the whole
/// array — which is what the lexicon's shape invites — is unaffected either way.
pub async fn put_preferences(
    State(state): State<HttpState>,
    parts: Parts,
    Json(input): Json<PutPreferencesInput>,
) -> Result<StatusCode, XrpcError> {
    let (htm, htu) = request_htm_htu(&parts);
    let subject = crate::http::auth::require_authn(&parts, &state, &htm, &htu).await?;
    let did = subject.sub().to_string();

    // Preferences are account data, and any token at all could rewrite them.
    // The specification names them among what `transition:generic` grants, and
    // no granular preference scope is specified yet, so that is the grant to
    // ask for -- a bare `atproto` token should not be able to reach in here.
    if subject.is_oauth() && !subject.scopes().allows_legacy_generic() {
        return Err(XrpcError::new(
            StatusCode::FORBIDDEN,
            "InsufficientScope",
            "this token does not grant writing personal preferences",
        ));
    }

    if !input.preferences.is_array() {
        return Err(XrpcError::new(
            StatusCode::BAD_REQUEST,
            "InvalidRequest",
            "preferences must be an array",
        ));
    }

    let store = open_store(&state, &did).await?;
    let json = input.preferences.to_string();
    let now = chrono::Utc::now().to_rfc3339();

    sqlx::query(
        "INSERT INTO preference (id, preferences_json, updated_at) VALUES (1, ?, ?)
         ON CONFLICT (id) DO UPDATE SET
            preferences_json = excluded.preferences_json,
            updated_at = excluded.updated_at",
    )
    .bind(&json)
    .bind(&now)
    .execute(store.pool())
    .await
    .map_err(|e| {
        XrpcError::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            "InternalError",
            format!("write preferences: {e}"),
        )
    })?;

    Ok(StatusCode::OK)
}

/// Open the calling account's actor store.
async fn open_store(state: &HttpState, did: &str) -> Result<SqlActorStore, XrpcError> {
    let manager = state.account_manager.as_deref().ok_or_else(|| {
        XrpcError::new(
            StatusCode::SERVICE_UNAVAILABLE,
            "AccountManagementUnavailable",
            "account manager not configured",
        )
    })?;
    SqlActorStore::open(manager.data_dir(), did)
        .await
        .map_err(XrpcError::from)
}
