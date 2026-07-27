//! `GET /.well-known/did.json` — the AppView's did:web document.
//!
//! Advertises the AppView as both a service consumer and a personal-data-server
//! style endpoint so the owner PDS can resolve the notify `aud`.

use axum::Json;
use axum::extract::State;
use axum::response::{IntoResponse, Response};
use serde_json::json;

use crate::state::WebContext;

/// `GET /.well-known/did.json` — serve the did:web document.
pub async fn did_json(State(ctx): State<WebContext>) -> Response {
    let did = ctx.config.appview_did();
    let base = ctx.config.external_base_url();
    // The `AtprotoPersonalDataServer` service entry is load-bearing: the owner's
    // notify-recipient resolution follows /.well-known/atproto-did -> this doc ->
    // this service to derive the AppView DID it signs the HOP-2 `aud` with
    // (plan §3.2 / §3.6). Without it the inbound `aud == appview_did` check
    // rejects every fan-out.
    let doc = json!({
        "@context": [
            "https://www.w3.org/ns/did/v1",
            "https://w3id.org/security/multikey/v1",
        ],
        "id": did,
        "alsoKnownAs": [],
        "service": [
            {
                "id": "#atproto_pds",
                "type": "AtprotoPersonalDataServer",
                "serviceEndpoint": base,
            },
            {
                "id": "#walking_club_appview",
                "type": "WalkingClubAppViewService",
                "serviceEndpoint": base,
            }
        ],
    });
    Json(doc).into_response()
}
