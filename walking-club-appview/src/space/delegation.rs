//! Delegation token acquisition.
//!
//! The AppView, acting as the member's agent, obtains a delegation token from
//! the member's PDS (`getDelegationToken`) to then exchange for a space
//! credential.

use atproto_client::client::DPoPAuth;
use atproto_space::types::SpaceUri;

use crate::error::AppResult;
use crate::xrpc;

/// Obtain a delegation token for `space` via the member's PDS/space host.
///
/// `GET com.atproto.space.getDelegationToken?space=<ats>` against the member's
/// own PDS with their OAuth+DPoP session. The returned token is signed by the
/// member's `#atproto` key (60s TTL, never cached).
pub async fn obtain_delegation_token(
    http: &reqwest::Client,
    auth: &DPoPAuth,
    host: &str,
    space: &SpaceUri,
) -> AppResult<String> {
    xrpc::get_delegation_token(http, auth, host, space).await
}
