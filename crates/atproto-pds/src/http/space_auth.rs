//! HTTP-layer auth helpers for `com.atproto.space.*`.
//!
//! Three token shapes flow through Spaces endpoints:
//! 1. **OAuth bearer** — same DPoP-bound HS256 token used for the public
//!    realm. Verified by [`crate::oauth::token::verify_oauth_jwt`]. Used for
//!    own-PDS reads and writes.
//! 2. **Delegation token** (`typ=atproto-space-delegation+jwt`) — presented in
//!    the `Authorization: Bearer` header to `getSpaceCredential`. Signed by the
//!    member's atproto signing key (header `kid="#atproto"`).
//! 3. **SpaceCredential JWT** (`typ=atproto-space-credential+jwt`) — passed to
//!    `getRecord`/`listRecords`/`getRepoState`/etc. by remote consumers.
//!    Signed by the space authority's `#atproto_space` signing key.
//!
//! Delegation-token verification at the authority's PDS requires resolving the
//! member's DID document to obtain their `#atproto` signing key. The
//! **same-PDS** case (the member is also a locally-managed account on this PDS)
//! looks up the signing key directly via the `AccountManager` + `KeyStore`.
//! Cross-PDS resolution through `atproto-identity` is wired — the resolver
//! picks the path automatically based on whether the DID is locally managed.

use crate::account::AccountManager;
use crate::http::errors::XrpcError;
use atproto_identity::key::{KeyData, to_public};
use atproto_space::credential::{
    DelegationToken, TYP_DELEGATION_TOKEN, TYP_SPACE_CREDENTIAL, verify_delegation_token,
};
use atproto_space::types::SpaceUri;
use axum::http::StatusCode;
use base64::{Engine as _, engine::general_purpose};
use serde::Deserialize;
use std::sync::Arc;

/// JWT typ discriminator inspection.
#[derive(Debug, Deserialize)]
struct JwtTypHeader {
    typ: String,
}

/// Identify which kind of token this is by parsing the JWT header `typ`.
/// Returns the literal `typ` value or `None` if the token is malformed /
/// missing a `typ` claim.
pub fn classify_token_typ(token: &str) -> Option<String> {
    let header_b64 = token.split('.').next()?;
    let header_bytes = general_purpose::URL_SAFE_NO_PAD
        .decode(header_b64.as_bytes())
        .ok()?;
    let header: JwtTypHeader = serde_json::from_slice(&header_bytes).ok()?;
    Some(header.typ)
}

/// Recognised Spaces token shapes.
#[derive(Debug, PartialEq, Eq)]
pub enum SpaceTokenKind {
    /// `atproto-space-delegation+jwt`.
    DelegationToken,
    /// `atproto-space-credential+jwt`.
    SpaceCredential,
    /// Anything else (likely an OAuth access token).
    Other(String),
}

/// Convenience over [`classify_token_typ`].
#[must_use]
pub fn classify(token: &str) -> Option<SpaceTokenKind> {
    let typ = classify_token_typ(token)?;
    Some(match typ.as_str() {
        TYP_DELEGATION_TOKEN => SpaceTokenKind::DelegationToken,
        TYP_SPACE_CREDENTIAL => SpaceTokenKind::SpaceCredential,
        _ => SpaceTokenKind::Other(typ),
    })
}

/// Resolve a locally-managed account's signing key in private form.
pub async fn local_signing_key(accounts: &AccountManager, did: &str) -> Result<KeyData, XrpcError> {
    let key_ref: Option<(String,)> =
        sqlx::query_as("SELECT signing_key_ref FROM account WHERE did = ?")
            .bind(did)
            .fetch_optional(accounts.pool())
            .await
            .map_err(|e| {
                XrpcError::new(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "InternalError",
                    format!("lookup signing_key_ref: {e}"),
                )
            })?;
    let key_ref = key_ref
        .ok_or_else(|| {
            XrpcError::new(
                StatusCode::NOT_FOUND,
                "AccountNotFound",
                format!("no account {did}"),
            )
        })?
        .0;
    accounts.key_store().get(&key_ref).await.map_err(|e| {
        XrpcError::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            "InternalError",
            e.to_string(),
        )
    })
}

/// Resolve a locally-managed account's *public* signing key (used for
/// verifying delegation tokens issued by that account).
pub async fn local_public_key(accounts: &AccountManager, did: &str) -> Result<KeyData, XrpcError> {
    let private = local_signing_key(accounts, did).await?;
    to_public(&private).map_err(|e| {
        XrpcError::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            "InternalError",
            format!("derive public key: {e}"),
        )
    })
}

/// Peek the unverified `iss` claim of a delegation token without checking the
/// signature, so the caller knows which member key to resolve.
///
/// # Errors
///
/// Returns 400 `InvalidToken` when the token is structurally malformed.
pub fn peek_delegation_token(grant_jwt: &str) -> Result<DelegationToken, XrpcError> {
    let payload_b64 = grant_jwt.split('.').nth(1).ok_or_else(|| {
        XrpcError::new(
            StatusCode::BAD_REQUEST,
            "InvalidToken",
            "delegation token: missing payload",
        )
    })?;
    let payload_bytes = general_purpose::URL_SAFE_NO_PAD
        .decode(payload_b64.as_bytes())
        .map_err(|_| {
            XrpcError::new(
                StatusCode::BAD_REQUEST,
                "InvalidToken",
                "delegation token: payload not base64url",
            )
        })?;
    serde_json::from_slice(&payload_bytes).map_err(|_| {
        XrpcError::new(
            StatusCode::BAD_REQUEST,
            "InvalidToken",
            "delegation token: payload not JSON",
        )
    })
}

/// Verify a delegation token against a same-PDS member's signing key.
///
/// Returns the decoded payload on success. Used by `getSpaceCredential`.
///
/// # Errors
///
/// - 400 `InvalidToken` if the token is unparseable / expired / claim mismatch.
/// - 404 `AccountNotFound` if the issuer (member) is not known on this PDS.
pub async fn verify_local_delegation_token(
    accounts: &Arc<AccountManager>,
    grant_jwt: &str,
    expected_authority_did: &str,
    expected_space: &SpaceUri,
) -> Result<DelegationToken, XrpcError> {
    // Peek the issuer claim without verifying signature, so we know which
    // member's key to fetch. We re-verify with the proper key below.
    let unverified = peek_delegation_token(grant_jwt)?;

    let member_pub = local_public_key(accounts, &unverified.iss).await?;
    let payload = verify_delegation_token(
        grant_jwt,
        expected_authority_did,
        expected_space,
        &member_pub,
    )
    .map_err(|e| {
        XrpcError::new(
            StatusCode::FORBIDDEN,
            "InvalidToken",
            format!("delegation token verification: {e}"),
        )
    })?;

    Ok(payload)
}

/// Verify a delegation token issued by a member on a *remote* PDS by resolving
/// their DID document for the atproto signing key.
///
/// The flow mirrors [`verify_local_delegation_token`] but the public-key
/// lookup goes through `atproto-identity` instead of the local
/// `AccountManager`:
///
/// 1. Peek the JWT payload to learn the issuer DID.
/// 2. Resolve the issuer's DID document via the configured PLC directory
///    (for `did:plc`) or `.well-known/did.json` (for `did:web`).
/// 3. Find the verification method whose id ends in `#atproto`; decode the
///    multibase public key into a `KeyData`.
/// 4. Re-verify the JWT against that key.
///
/// `plc_directory_hostname` is the configured PLC directory (e.g.
/// `plc.directory`); pass `None` to use the upstream default.
///
/// # Errors
///
/// - 400 `InvalidToken` — token unparseable / claim mismatch.
/// - 401 `AuthenticationRequired` — DID document doesn't resolve, or
///   doesn't carry an `#atproto` verification method.
/// - 403 `InvalidToken` — signature verification failed.
pub async fn verify_remote_delegation_token(
    http: &reqwest::Client,
    grant_jwt: &str,
    expected_authority_did: &str,
    expected_space: &SpaceUri,
    plc_directory_hostname: Option<&str>,
) -> Result<DelegationToken, XrpcError> {
    let unverified = peek_delegation_token(grant_jwt)?;

    let member_pub = remote_atproto_signing_key(http, &unverified.iss, plc_directory_hostname)
        .await
        .map_err(|e| {
            XrpcError::new(
                StatusCode::UNAUTHORIZED,
                "AuthenticationRequired",
                format!("resolve member DID document for {}: {e}", unverified.iss),
            )
        })?;
    let payload = verify_delegation_token(
        grant_jwt,
        expected_authority_did,
        expected_space,
        &member_pub,
    )
    .map_err(|e| {
        XrpcError::new(
            StatusCode::FORBIDDEN,
            "InvalidToken",
            format!("delegation token verification: {e}"),
        )
    })?;

    Ok(payload)
}

/// Fetch a `did:plc:`/`did:web:` DID document for remote verification.
async fn fetch_remote_document(
    http: &reqwest::Client,
    did: &str,
    plc_directory_hostname: Option<&str>,
) -> anyhow::Result<atproto_identity::model::Document> {
    use atproto_identity::plc::query as plc_query;
    use atproto_identity::web::query as web_query;
    if did.starts_with("did:plc:") {
        let host = plc_directory_hostname.unwrap_or("plc.directory");
        Ok(plc_query(http, host, did).await?)
    } else if did.starts_with("did:web:") {
        Ok(web_query(http, did).await?)
    } else {
        anyhow::bail!("unsupported DID method for remote space verification: {did}")
    }
}

/// Turn a multibase / `did:key:` value into `KeyData`.
fn multibase_to_key(mb: &str) -> anyhow::Result<KeyData> {
    use atproto_identity::key::identify_key;
    // `identify_key` accepts either a bare multibase value or a `did:key:`
    // wrapper. Normalize so the call site is robust to either form.
    let did_key = if mb.starts_with("did:key:") {
        mb.to_string()
    } else {
        format!("did:key:{mb}")
    };
    Ok(identify_key(&did_key)?)
}

/// Resolve a remote DID's atproto signing key (the `#atproto` verification
/// method's `publicKeyMultibase`). Returns `KeyData` ready for
/// `verify_delegation_token` etc. The delegation token's `kid` is `#atproto`
/// per 0016 line 162, so this resolves the member's public-data signing key.
async fn remote_atproto_signing_key(
    http: &reqwest::Client,
    did: &str,
    plc_directory_hostname: Option<&str>,
) -> anyhow::Result<KeyData> {
    let document = fetch_remote_document(http, did, plc_directory_hostname).await?;
    let mb = document
        .verification_method_multibase("atproto")
        .ok_or_else(|| {
            anyhow::anyhow!("DID document has no #atproto Multikey verification method")
        })?;
    multibase_to_key(mb)
}

/// Resolve a remote space authority's credential-verification key.
///
/// Per 0016 §"Space authority" (lines 87-92) the authority DID exposes the
/// credential-signing public key as the `#atproto_space` verification method,
/// which MAY coincide in value with `#atproto` (line 92). This prefers the
/// dedicated `#atproto_space` entry and falls back to `#atproto` for authority
/// DID documents that exercise the coincidence allowance without publishing a
/// distinct entry.
pub async fn remote_space_credential_key(
    http: &reqwest::Client,
    authority_did: &str,
    plc_directory_hostname: Option<&str>,
) -> anyhow::Result<KeyData> {
    let document = fetch_remote_document(http, authority_did, plc_directory_hostname).await?;
    let mb = space_credential_multibase(&document).ok_or_else(|| {
        anyhow::anyhow!(
            "authority DID document has no #atproto_space or #atproto Multikey verification method"
        )
    })?;
    multibase_to_key(mb)
}

/// Select the authority's credential-verification public key from a DID
/// document: prefer `#atproto_space`, fall back to `#atproto` (0016 line 92).
fn space_credential_multibase(document: &atproto_identity::model::Document) -> Option<&str> {
    document
        .verification_method_multibase("atproto_space")
        .or_else(|| document.verification_method_multibase("atproto"))
}

/// Resolve a remote space authority's host endpoint.
///
/// Per 0016 §"Space authority" (lines 87-92) the authority DID exposes its host
/// as the `#atproto_space_host` service, which MAY coincide with `#atproto_pds`
/// (line 92). This prefers the dedicated `#atproto_space_host` entry and falls
/// back to `#atproto_pds`.
pub async fn remote_space_host_endpoint(
    http: &reqwest::Client,
    authority_did: &str,
    plc_directory_hostname: Option<&str>,
) -> anyhow::Result<String> {
    let document = fetch_remote_document(http, authority_did, plc_directory_hostname).await?;
    space_host_endpoint(&document)
        .map(|s| s.to_string())
        .ok_or_else(|| {
            anyhow::anyhow!(
                "authority DID document has no #atproto_space_host or #atproto_pds service"
            )
        })
}

/// Select the authority's host endpoint from a DID document: prefer
/// `#atproto_space_host`, fall back to `#atproto_pds` (0016 line 92).
fn space_host_endpoint(document: &atproto_identity::model::Document) -> Option<&str> {
    document
        .service_endpoint("atproto_space_host")
        .or_else(|| document.service_endpoint("atproto_pds"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::account::{AccountDirectory, AccountManager, CreateAccountParams};
    use crate::keys::{KeyStore, MemoryKeyStore};
    use atproto_identity::key::KeyType;
    use atproto_identity::model::Document;
    use atproto_space::credential::{DELEGATION_TOKEN_TTL_SECS, create_delegation_token};
    use atproto_space::types::{SpaceKey, SpaceType};
    use std::sync::Arc;
    use tempfile::TempDir;

    fn doc_from(json: &str) -> Document {
        serde_json::from_str(json).expect("DID document parses")
    }

    #[test]
    fn space_credential_key_prefers_atproto_space_vm() {
        // 0016 lines 87-92: prefer the dedicated #atproto_space VM when present.
        let doc = doc_from(
            r##"{"id":"did:plc:authority",
              "verificationMethod":[
                {"id":"#atproto","type":"Multikey","controller":"did:plc:authority","publicKeyMultibase":"zATPROTO"},
                {"id":"#atproto_space","type":"Multikey","controller":"did:plc:authority","publicKeyMultibase":"zSPACE"}
              ]}"##,
        );
        assert_eq!(space_credential_multibase(&doc), Some("zSPACE"));
    }

    #[test]
    fn space_credential_key_falls_back_to_atproto_vm() {
        // Line 92 MAY-coincide: authorities that don't publish a distinct
        // #atproto_space entry fall back to the #atproto signing key.
        let doc = doc_from(
            r##"{"id":"did:plc:authority",
              "verificationMethod":[
                {"id":"#atproto","type":"Multikey","controller":"did:plc:authority","publicKeyMultibase":"zATPROTO"}
              ]}"##,
        );
        assert_eq!(space_credential_multibase(&doc), Some("zATPROTO"));
    }

    #[test]
    fn space_credential_key_absent_when_neither_present() {
        let doc = doc_from(r##"{"id":"did:plc:authority","verificationMethod":[]}"##);
        assert_eq!(space_credential_multibase(&doc), None);
    }

    #[test]
    fn space_host_prefers_atproto_space_host_service() {
        // 0016 lines 87-92: prefer the dedicated #atproto_space_host service.
        let doc = doc_from(
            r##"{"id":"did:plc:authority",
              "service":[
                {"id":"#atproto_pds","type":"AtprotoPersonalDataServer","serviceEndpoint":"https://pds.example.com"},
                {"id":"#atproto_space_host","type":"AtprotoPersonalDataServer","serviceEndpoint":"https://host.example.com"}
              ]}"##,
        );
        assert_eq!(space_host_endpoint(&doc), Some("https://host.example.com"));
    }

    #[test]
    fn space_host_falls_back_to_atproto_pds_service() {
        // Line 92 MAY-coincide: fall back to #atproto_pds when no dedicated
        // host service is published.
        let doc = doc_from(
            r##"{"id":"did:plc:authority",
              "service":[
                {"id":"#atproto_pds","type":"AtprotoPersonalDataServer","serviceEndpoint":"https://pds.example.com"}
              ]}"##,
        );
        assert_eq!(space_host_endpoint(&doc), Some("https://pds.example.com"));
    }

    #[test]
    fn space_host_absent_when_neither_present() {
        let doc = doc_from(r##"{"id":"did:plc:authority","service":[]}"##);
        assert_eq!(space_host_endpoint(&doc), None);
    }

    async fn fresh_manager(dir: &std::path::Path) -> Arc<AccountManager> {
        let accounts_db = AccountDirectory::open(&dir.join("accounts.sqlite"))
            .await
            .unwrap();
        let key_store: Arc<dyn KeyStore> = Arc::new(MemoryKeyStore::new());
        let manager = Arc::new(AccountManager::new(
            accounts_db.pool().clone(),
            dir.to_path_buf(),
            key_store,
            KeyType::K256Private,
        ));
        for did in ["did:plc:owner", "did:plc:alice"] {
            manager
                .create_account(CreateAccountParams {
                    did,
                    handle: &format!("{}.example", did.trim_start_matches("did:plc:")),
                    email: None,
                    password: "pw",
                    pds_managed_rotation: true,
                    ..Default::default()
                })
                .await
                .unwrap();
        }
        manager
    }

    fn test_space() -> SpaceUri {
        SpaceUri::new(
            "did:plc:owner".to_string(),
            SpaceType::new("app.bsky.group").unwrap(),
            SpaceKey::new("default").unwrap(),
        )
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn classify_token_kinds() {
        // synthetic header-only jwt-shaped strings
        let dt_header = general_purpose::URL_SAFE_NO_PAD
            .encode(br##"{"alg":"ES256","typ":"atproto-space-delegation+jwt","kid":"#atproto"}"##);
        let sc_header = general_purpose::URL_SAFE_NO_PAD.encode(
            br##"{"alg":"ES256","typ":"atproto-space-credential+jwt","kid":"#atproto_space"}"##,
        );
        let jwt_a = format!("{}.payload.sig", dt_header);
        let jwt_b = format!("{}.payload.sig", sc_header);
        assert_eq!(classify(&jwt_a), Some(SpaceTokenKind::DelegationToken));
        assert_eq!(classify(&jwt_b), Some(SpaceTokenKind::SpaceCredential));
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn local_delegation_token_round_trip() {
        let tmp = TempDir::new().unwrap();
        let manager = fresh_manager(tmp.path()).await;
        let alice_priv = local_signing_key(&manager, "did:plc:alice").await.unwrap();

        let space = test_space();
        let grant = create_delegation_token(
            "did:plc:alice",
            &space,
            &alice_priv,
            DELEGATION_TOKEN_TTL_SECS,
        )
        .unwrap();

        let payload = verify_local_delegation_token(&manager, &grant, "did:plc:owner", &space)
            .await
            .unwrap();
        assert_eq!(payload.iss, "did:plc:alice");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn delegation_token_unknown_issuer_rejected() {
        let tmp = TempDir::new().unwrap();
        let manager = fresh_manager(tmp.path()).await;
        let alice_priv = local_signing_key(&manager, "did:plc:alice").await.unwrap();

        let space = test_space();
        // Issue with a *different* iss claim — verify lookup of the unknown
        // issuer fails. We hand-craft the payload to bypass
        // create_delegation_token.
        let header = general_purpose::URL_SAFE_NO_PAD
            .encode(br##"{"alg":"ES256K","typ":"atproto-space-delegation+jwt","kid":"#atproto"}"##);
        let bad_payload = serde_json::to_vec(&serde_json::json!({
            "iss": "did:plc:nobody",
            "aud": "did:plc:owner#atproto_space_host",
            "sub": space.to_string(),
            "iat": 1_700_000_000,
            "exp": 9_999_999_999u64,
            "jti": "nonce",
        }))
        .unwrap();
        let payload_b64 = general_purpose::URL_SAFE_NO_PAD.encode(&bad_payload);
        let signing_input = format!("{}.{}", header, payload_b64);
        let sig = atproto_identity::key::sign(&alice_priv, signing_input.as_bytes()).unwrap();
        let token = format!(
            "{}.{}",
            signing_input,
            general_purpose::URL_SAFE_NO_PAD.encode(&sig)
        );

        let result = verify_local_delegation_token(&manager, &token, "did:plc:owner", &space).await;
        assert!(result.is_err());
    }
}
