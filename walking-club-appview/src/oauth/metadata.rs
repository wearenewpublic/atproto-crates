//! OAuth `client-metadata.json` + `jwks.json` handlers.
//!
//! The client metadata advertises the confidential client and points at a
//! separate `jwks_uri` (so the space host can fetch the public keys by URL when
//! verifying client attestations).

use axum::Json;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Response};
use serde_json::{Value, json};

use crate::state::WebContext;

fn json_cors(value: Value) -> Response {
    let mut headers = HeaderMap::new();
    headers.insert(header::CONTENT_TYPE, "application/json".parse().unwrap());
    headers.insert(header::ACCESS_CONTROL_ALLOW_ORIGIN, "*".parse().unwrap());
    (StatusCode::OK, headers, Json(value)).into_response()
}

/// `GET /client-metadata.json` — the OAuth client document.
pub async fn client_metadata(State(ctx): State<WebContext>) -> Response {
    let config = &ctx.config;
    // Scope = base grants + the `space:` grants for the configured space. Query
    // grammar: the positional segment right after `space:` is the space TYPE
    // NSID; `action`/`collection` are query params (never positional). `manage`
    // is omitted (pure member/consumer client). The `space:` grants are emitted
    // only once SPACE_URI is configured (i.e. after the space is created).
    let mut scope = String::from("atproto transition:generic");
    if let Some(space_uri) = &config.space_uri {
        let stype = space_uri.space_type.as_str();
        scope.push_str(&format!(" space:{stype}?action=read"));
        for coll in &config.tracked_collections {
            scope.push_str(&format!(" space:{stype}?action=create&collection={coll}"));
        }
    }
    let doc = json!({
        "client_id": config.oauth_client_id(),
        "client_name": "Walking Club",
        "client_uri": config.external_base_url(),
        "redirect_uris": [config.oauth_redirect_uri()],
        "jwks_uri": config.jwks_uri(),
        "scope": scope,
        "grant_types": ["authorization_code", "refresh_token"],
        "response_types": ["code"],
        "application_type": "web",
        "token_endpoint_auth_method": "private_key_jwt",
        "token_endpoint_auth_signing_alg": "ES256",
        "dpop_bound_access_tokens": true,
        "subject_type": "public",
    });
    json_cors(doc)
}

/// `GET /jwks.json` — public keys for client-assertion + attestation verify.
pub async fn jwks(State(ctx): State<WebContext>) -> Response {
    // Publish the PUBLIC half of every configured signing key. The first key is
    // the current signer for both `private_key_jwt` and the client attestation;
    // the rest are historical (kept for rotation). Each JWK carries a stable
    // `kid` (the public key's `did:key`) so the space host can select by `kid`.
    let keys: Vec<Value> = ctx
        .config
        .oauth_public_keys()
        .iter()
        .filter_map(|public_key| {
            let wrapped = atproto_oauth::jwk::generate(public_key).ok()?;
            serde_json::to_value(&wrapped).ok()
        })
        .collect();
    json_cors(json!({ "keys": keys }))
}
