//! Space management and enumeration.
//!
//! These are OAuth-session calls against one host, so they present a bound
//! token and need none of the credential chain in [`crate::credential`].
//!
//! Note which lexicon each belongs to. `listSpaces` is `com.atproto.space`;
//! creating, deleting, describing and enumerating members are
//! `com.atproto.simplespace`, one implementation's space-management surface
//! rather than the 0016 data plane. A host that serves spaces and does not
//! offer them is conformant -- it just does not let this client create them.

use atproto_client::client::DpopPresentation;
use atproto_identity::key::KeyData;
use atproto_space::SpaceUri;
use reqwest::Method;
use serde::{Deserialize, Serialize};

use crate::errors::SpaceClientError;

/// A host and the session that speaks to it.
///
/// Every call in this module takes the same four things, and bundling them
/// keeps the filters and the inputs distinguishable from the plumbing at a
/// call site.
#[derive(Clone, Copy)]
pub struct SpaceSession<'a> {
    /// The HTTP client to issue requests with.
    pub http: &'a reqwest::Client,
    /// The host, as a URL or a bare hostname.
    pub host: &'a str,
    /// The key the session's access token is bound to.
    pub dpop_key: &'a KeyData,
    /// The OAuth access token.
    pub access_token: &'a str,
}
use crate::methods;
use crate::transport::{Call, method_url};

/// One space, as `listSpaces` describes it.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct SpaceSummary {
    /// Full space URI.
    pub uri: String,
    /// Whether the viewer is the space's authority.
    #[serde(rename = "isOwner", default)]
    pub is_owner: bool,
    /// Whether the viewer is a member.
    #[serde(rename = "isMember", default)]
    pub is_member: bool,
    /// When the space was created.
    #[serde(rename = "createdAt", default)]
    pub created_at: Option<String>,
}

/// A page of `listSpaces`.
#[derive(Debug, Clone, Deserialize)]
struct ListSpacesResponse {
    spaces: Vec<SpaceSummary>,
    #[serde(default)]
    cursor: Option<String>,
}

/// What to narrow `listSpaces` to.
#[derive(Debug, Clone, Copy, Default)]
pub struct ListSpaces<'a> {
    /// Only spaces of this type (an NSID).
    pub space_type: Option<&'a str>,
    /// Only spaces under this authority DID.
    pub authority: Option<&'a str>,
    /// Continue from a previous page.
    pub cursor: Option<&'a str>,
    /// Page size.
    pub limit: Option<u32>,
}

/// A page of spaces and the cursor that follows it.
#[derive(Debug, Clone)]
pub struct SpacePage {
    /// This page.
    pub spaces: Vec<SpaceSummary>,
    /// Cursor for the next page; absent on the last.
    pub cursor: Option<String>,
}

/// Every space the session can see, a page at a time.
///
/// # Errors
///
/// Returns [`SpaceClientError::Refused`] when the host refuses.
pub async fn list_spaces(
    session: SpaceSession<'_>,
    filter: &ListSpaces<'_>,
) -> Result<SpacePage, SpaceClientError> {
    let limit = filter.limit.map(|limit| limit.to_string());
    let mut params: Vec<(&str, &str)> = Vec::new();
    if let Some(space_type) = filter.space_type {
        params.push(("type", space_type));
    }
    if let Some(authority) = filter.authority {
        params.push(("did", authority));
    }
    if let Some(cursor) = filter.cursor {
        params.push(("cursor", cursor));
    }
    if let Some(limit) = limit.as_deref() {
        params.push(("limit", limit));
    }

    let page: ListSpacesResponse = Call {
        host: session.host,
        method: methods::LIST_SPACES,
        key: session.dpop_key,
        presentation: DpopPresentation::Bound(session.access_token),
        http_method: Method::GET,
        url: method_url(session.host, methods::LIST_SPACES, &params)?,
        body: None,
    }
    .send_json(session.http)
    .await?;

    Ok(SpacePage {
        spaces: page.spaces,
        cursor: page.cursor,
    })
}

/// One member of a space.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct Member {
    /// The member's DID.
    pub did: String,
    /// The revision at which they were added, when the host reports one.
    #[serde(rename = "memberRev", default)]
    pub member_rev: Option<String>,
    /// When they were added, when the host reports it.
    #[serde(rename = "addedAt", default)]
    pub added_at: Option<String>,
}

/// A page of members.
#[derive(Debug, Clone, Deserialize)]
pub struct MemberPage {
    /// This page.
    pub members: Vec<Member>,
    /// Cursor for the next page; absent on the last.
    #[serde(default)]
    pub cursor: Option<String>,
}

/// Who is in a space, a page at a time.
///
/// # Errors
///
/// Returns [`SpaceClientError::Refused`] when the host refuses -- which it
/// does for a caller holding a covering scope but no membership. Holding a
/// scope is the user's consent to an application, not evidence that the user
/// is in the space.
pub async fn list_members(
    session: SpaceSession<'_>,
    space: &SpaceUri,
    cursor: Option<&str>,
    limit: Option<u32>,
) -> Result<MemberPage, SpaceClientError> {
    let space_uri = space.to_string();
    let limit = limit.map(|limit| limit.to_string());
    let mut params: Vec<(&str, &str)> = vec![("space", &space_uri)];
    if let Some(cursor) = cursor {
        params.push(("cursor", cursor));
    }
    if let Some(limit) = limit.as_deref() {
        params.push(("limit", limit));
    }

    Call {
        host: session.host,
        method: methods::LIST_MEMBERS,
        key: session.dpop_key,
        presentation: DpopPresentation::Bound(session.access_token),
        http_method: Method::GET,
        url: method_url(session.host, methods::LIST_MEMBERS, &params)?,
        body: None,
    }
    .send_json(session.http)
    .await
}

/// What a space is created with.
///
/// `policy` and `app_access` are both required, which is not this client being
/// strict: the lexicon marks both required, and a host that accepted their
/// absence and applied its documented defaults gave a caller a `200` and a
/// silently defaulted space. Making them mandatory here is what stops that
/// from being reachable by omission.
#[derive(Debug, Clone, Serialize)]
pub struct CreateSpace<'a> {
    /// The authority DID. `None` means the calling account.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub did: Option<&'a str>,
    /// The space type, an NSID.
    #[serde(rename = "type")]
    pub space_type: &'a str,
    /// The space key. `None` asks the host to generate a TID.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub skey: Option<&'a str>,
    /// User-authorization policy, as the lexicon's open union.
    pub policy: serde_json::Value,
    /// App-authorization policy, as the lexicon's open union.
    #[serde(rename = "appAccess")]
    pub app_access: serde_json::Value,
}

/// Output of `createSpace`.
#[derive(Debug, Deserialize)]
struct CreateSpaceResponse {
    uri: String,
}

/// Create a space.
///
/// **Idempotent when `skey` is given.** A space URI is `did + type + skey`, so
/// a caller sending an explicit key is naming a particular space; sending the
/// same one twice answers the same URI both times rather than erroring, and a
/// double-submitted create dialog converges on its own. The replay changes
/// nothing -- the space keeps its original `createdAt` and its stored policy
/// is left as it is -- so a caller cannot use it to reconfigure.
///
/// # Errors
///
/// Returns [`SpaceClientError::Refused`] when the host refuses.
pub async fn create_space(
    session: SpaceSession<'_>,
    input: &CreateSpace<'_>,
) -> Result<SpaceUri, SpaceClientError> {
    let body = serde_json::to_value(input).map_err(|error| SpaceClientError::InvalidRequest {
        reason: error.to_string(),
    })?;

    let created: CreateSpaceResponse = Call {
        host: session.host,
        method: methods::CREATE_SPACE,
        key: session.dpop_key,
        presentation: DpopPresentation::Bound(session.access_token),
        http_method: Method::POST,
        url: method_url(session.host, methods::CREATE_SPACE, &[])?,
        body: Some(body),
    }
    .send_json(session.http)
    .await?;

    SpaceUri::parse(&created.uri).map_err(|error| SpaceClientError::InvalidSpaceUri {
        uri: created.uri.clone(),
        reason: error.to_string(),
    })
}

/// Tombstone a space.
///
/// # Errors
///
/// Returns [`SpaceClientError::Refused`] when the host refuses.
pub async fn delete_space(
    session: SpaceSession<'_>,
    space: &SpaceUri,
) -> Result<(), SpaceClientError> {
    Call {
        host: session.host,
        method: methods::DELETE_SPACE,
        key: session.dpop_key,
        presentation: DpopPresentation::Bound(session.access_token),
        http_method: Method::POST,
        url: method_url(session.host, methods::DELETE_SPACE, &[])?,
        body: Some(serde_json::json!({ "space": space.to_string() })),
    }
    .send(session.http)
    .await
    .map(|_| ())
}

/// A space's configuration, as `getSpace` reports it.
#[derive(Debug, Clone, Deserialize)]
pub struct SpaceConfig {
    /// The space URI.
    pub uri: String,
    /// User-authorization policy, as an open union.
    ///
    /// Kept as a `Value` rather than a typed enum: the lexicon declares it
    /// **open**, so a variant this build does not know is a server ahead of
    /// it rather than a malformed answer, and decoding into a closed enum
    /// would turn the first into the second.
    #[serde(default)]
    pub policy: serde_json::Value,
    /// App-authorization policy, as an open union.
    #[serde(rename = "appAccess", default)]
    pub app_access: serde_json::Value,
}

/// Describe a space and its configuration.
///
/// # Errors
///
/// Returns [`SpaceClientError::Refused`] when the host refuses.
pub async fn get_space(
    session: SpaceSession<'_>,
    space: &SpaceUri,
) -> Result<SpaceConfig, SpaceClientError> {
    let space_uri = space.to_string();
    Call {
        host: session.host,
        method: methods::GET_SPACE,
        key: session.dpop_key,
        presentation: DpopPresentation::Bound(session.access_token),
        http_method: Method::GET,
        url: method_url(session.host, methods::GET_SPACE, &[("space", &space_uri)])?,
        body: None,
    }
    .send_json(session.http)
    .await
}
