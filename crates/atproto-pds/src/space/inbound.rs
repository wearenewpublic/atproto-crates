//! Inbound `notifyWrite` / `notifyMembership` receipt + verification.
//!
//! When a remote peer pushes a `notifyWrite` or `notifyMembership` POST
//! to this PDS, we:
//!
//! 1. Decode the DAG-CBOR body into the payload shape
//!    (`crate::space::notify::NotifyWritePayload` / `NotifyMembershipPayload`).
//! 2. Resolve the issuer's atproto signing key from their DID document
//!    via `atproto-identity::plc::query` or `atproto-identity::web::query`.
//! 3. Verify the embedded `Commit` (HMAC + ECDSA) using
//!    `atproto_space::commit::verify_commit`.
//! 4. INSERT-OR-IGNORE into the local per-actor `space_received_op`
//!    table — the row is keyed on `(space, rev, nsid)` so re-delivery of
//!    the same op is idempotent.
//!
//! Verification failure → 401 / 403; replay (already-seen `(space, rev)`)
//! → 200 (idempotent ack).
//!
//! Today the module ships the security-critical verification + audit
//! trail; "apply received op into a local read-only mirror" is a
//! future enhancement that hooks the same dispatch path.

use crate::actor_store::sql::SqlActorStore;
use crate::errors::{PdsError, PdsResult};
use crate::space::notify::{NotifyMembershipPayload, NotifyWritePayload};
use atproto_identity::key::{KeyData, identify_key};
use atproto_identity::model::VerificationMethod;
use atproto_space::commit::{CommitScope, SpaceContext, verify_commit};
use atproto_space::types::SpaceUri;

/// Decode + verify + persist an inbound `notifyWrite`. Returns Ok(()) on
/// the happy path including the dedup-already-seen path.
pub async fn receive_write(
    http: &reqwest::Client,
    plc_directory_hostname: Option<&str>,
    data_dir: &std::path::Path,
    recipient_did: &str,
    body: &[u8],
) -> PdsResult<()> {
    let payload: NotifyWritePayload =
        atproto_dasl::from_slice(body).map_err(|e| PdsError::Storage {
            reason: format!("decode notifyWrite payload: {e}"),
        })?;
    let space = SpaceUri::parse(&payload.space).map_err(PdsError::Space)?;
    verify_with_owner_key(
        http,
        plc_directory_hostname,
        &space.owner_did,
        &SpaceContext {
            space_did: space.owner_did.clone(),
            space_type: space.space_type.to_string(),
            space_key: space.space_key.to_string(),
            user_did: payload.member.clone(),
            scope: CommitScope::Records,
            rev: payload.commit.rev.clone(),
        },
        &payload.commit,
    )
    .await?;
    persist_receipt(
        data_dir,
        recipient_did,
        &space,
        &payload.commit.rev,
        "notifyWrite",
        &payload.member,
        &payload.commit.set_hash,
    )
    .await
}

/// Decode + verify + persist an inbound `notifyMembership`.
pub async fn receive_membership(
    http: &reqwest::Client,
    plc_directory_hostname: Option<&str>,
    data_dir: &std::path::Path,
    recipient_did: &str,
    body: &[u8],
) -> PdsResult<()> {
    let payload: NotifyMembershipPayload =
        atproto_dasl::from_slice(body).map_err(|e| PdsError::Storage {
            reason: format!("decode notifyMembership payload: {e}"),
        })?;
    let space = SpaceUri::parse(&payload.space).map_err(PdsError::Space)?;
    verify_with_owner_key(
        http,
        plc_directory_hostname,
        &space.owner_did,
        &SpaceContext {
            space_did: space.owner_did.clone(),
            space_type: space.space_type.to_string(),
            space_key: space.space_key.to_string(),
            user_did: space.owner_did.clone(),
            scope: CommitScope::Members,
            rev: payload.commit.rev.clone(),
        },
        &payload.commit,
    )
    .await?;
    persist_receipt(
        data_dir,
        recipient_did,
        &space,
        &payload.commit.rev,
        "notifyMembership",
        &payload.member,
        &payload.commit.set_hash,
    )
    .await
}

/// Resolve the owner's atproto signing key from their DID document and
/// run [`verify_commit`] against the supplied context + commit.
async fn verify_with_owner_key(
    http: &reqwest::Client,
    plc_directory_hostname: Option<&str>,
    owner_did: &str,
    context: &SpaceContext,
    commit: &atproto_space::commit::Commit,
) -> PdsResult<()> {
    let key = atproto_signing_key(http, owner_did, plc_directory_hostname)
        .await
        .map_err(|e| PdsError::Storage {
            reason: format!("resolve owner signing key: {e}"),
        })?;
    verify_commit(context, commit, &key).map_err(PdsError::Space)?;
    Ok(())
}

/// Resolve a DID's atproto signing key (the `#atproto` Multikey
/// verification method) via the configured DID method.
async fn atproto_signing_key(
    http: &reqwest::Client,
    did: &str,
    plc_directory_hostname: Option<&str>,
) -> anyhow::Result<KeyData> {
    use atproto_identity::plc::query as plc_query;
    use atproto_identity::web::query as web_query;
    let document = if did.starts_with("did:plc:") {
        let host = plc_directory_hostname.unwrap_or("plc.directory");
        plc_query(http, host, did).await?
    } else if did.starts_with("did:web:") {
        web_query(http, did).await?
    } else {
        anyhow::bail!("unsupported DID method for inbound notify verification: {did}");
    };
    for method in &document.verification_method {
        if let VerificationMethod::Multikey {
            id,
            public_key_multibase,
            ..
        } = method
            && id.ends_with("#atproto")
        {
            let did_key = if public_key_multibase.starts_with("did:key:") {
                public_key_multibase.clone()
            } else {
                format!("did:key:{}", public_key_multibase)
            };
            return Ok(identify_key(&did_key)?);
        }
    }
    anyhow::bail!("DID document for {did} has no #atproto Multikey verification method")
}

async fn persist_receipt(
    data_dir: &std::path::Path,
    recipient_did: &str,
    space: &SpaceUri,
    rev: &str,
    nsid: &str,
    issuer_did: &str,
    set_hash: &[u8],
) -> PdsResult<()> {
    let store = SqlActorStore::open(data_dir, recipient_did).await?;
    let now = chrono::Utc::now().to_rfc3339();
    sqlx::query(
        "INSERT OR IGNORE INTO space_received_op
            (space, rev, nsid, issuer_did, set_hash, received_at)
         VALUES (?, ?, ?, ?, ?, ?)",
    )
    .bind(space.to_string())
    .bind(rev)
    .bind(nsid)
    .bind(issuer_did)
    .bind(set_hash)
    .bind(&now)
    .execute(store.pool())
    .await
    .map_err(|e| PdsError::Storage {
        reason: format!("persist space_received_op: {e}"),
    })?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::space::notify::NotifyOp;
    use atproto_identity::key::{KeyType, generate_key, to_public};
    use atproto_space::commit::create_commit;
    use atproto_space::set_hash::SetHash;
    use atproto_space::types::{SpaceKey, SpaceType};

    fn test_space() -> SpaceUri {
        SpaceUri::new(
            "did:plc:owner".to_string(),
            SpaceType::new("app.bsky.group").unwrap(),
            SpaceKey::new("default").unwrap(),
        )
    }

    /// Round-trip: build a real signed commit, decode + verify it.
    /// Skips the DID-doc fetch by calling `verify_commit` directly.
    #[tokio::test(flavor = "multi_thread")]
    async fn verify_commit_round_trip() {
        let owner_priv = generate_key(KeyType::P256Private).unwrap();
        let owner_pub = to_public(&owner_priv).unwrap();
        let space = test_space();
        let mut sh = atproto_space::set_hash::XorSha256SetHash::empty();
        sh.add(b"hello");
        let context = SpaceContext {
            space_did: space.owner_did.clone(),
            space_type: space.space_type.to_string(),
            space_key: space.space_key.to_string(),
            user_did: "did:plc:alice".to_string(),
            scope: CommitScope::Records,
            rev: "3kmev1".to_string(),
        };
        let commit = create_commit(&sh, &context, &owner_priv).unwrap();
        verify_commit(&context, &commit, &owner_pub).unwrap();
    }

    /// A tampered commit body must fail verification.
    #[tokio::test(flavor = "multi_thread")]
    async fn tampered_commit_rejected() {
        let owner_priv = generate_key(KeyType::P256Private).unwrap();
        let owner_pub = to_public(&owner_priv).unwrap();
        let space = test_space();
        let mut sh = atproto_space::set_hash::XorSha256SetHash::empty();
        sh.add(b"orig");
        let context = SpaceContext {
            space_did: space.owner_did.clone(),
            space_type: space.space_type.to_string(),
            space_key: space.space_key.to_string(),
            user_did: "did:plc:alice".to_string(),
            scope: CommitScope::Records,
            rev: "3kmev1".to_string(),
        };
        let mut commit = create_commit(&sh, &context, &owner_priv).unwrap();
        // Tamper with the set_hash so the HMAC tag no longer matches.
        commit.set_hash[0] ^= 0xFF;
        let result = verify_commit(&context, &commit, &owner_pub);
        assert!(result.is_err());
    }

    /// `persist_receipt` is idempotent on `(space, rev, nsid)`.
    #[tokio::test(flavor = "multi_thread")]
    async fn persist_is_idempotent() {
        let tmp = tempfile::TempDir::new().unwrap();
        let dir = tmp.path().to_path_buf();
        let recipient = "did:plc:test";
        let space = test_space();
        for _ in 0..3 {
            persist_receipt(
                &dir,
                recipient,
                &space,
                "3kmev1",
                "notifyWrite",
                "did:plc:alice",
                &[0u8; 32],
            )
            .await
            .unwrap();
        }
        let store = SqlActorStore::open(&dir, recipient).await.unwrap();
        let count: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM space_received_op")
            .fetch_one(store.pool())
            .await
            .unwrap();
        assert_eq!(count.0, 1);
    }

    /// Serialize a NotifyWritePayload + decode through receive_write's body
    /// codec to confirm the wire format round-trips.
    #[tokio::test(flavor = "multi_thread")]
    async fn payload_codec_round_trip() {
        let owner_priv = generate_key(KeyType::P256Private).unwrap();
        let space = test_space();
        let mut sh = atproto_space::set_hash::XorSha256SetHash::empty();
        sh.add(b"k");
        let context = SpaceContext {
            space_did: space.owner_did.clone(),
            space_type: space.space_type.to_string(),
            space_key: space.space_key.to_string(),
            user_did: "did:plc:alice".to_string(),
            scope: CommitScope::Records,
            rev: "3kmev1".to_string(),
        };
        let commit = create_commit(&sh, &context, &owner_priv).unwrap();
        let payload = NotifyWritePayload {
            space: space.to_string(),
            member: "did:plc:alice".to_string(),
            commit: commit.clone(),
            ops: vec![NotifyOp {
                action: "create".to_string(),
                collection: "c".to_string(),
                rkey: "k".to_string(),
                cid: Some("bafy...".to_string()),
                value: Some(b"v".to_vec()),
            }],
        };
        let body = atproto_dasl::to_vec(&payload).unwrap();
        let decoded: NotifyWritePayload = atproto_dasl::from_slice(&body).unwrap();
        assert_eq!(decoded.space, payload.space);
        assert_eq!(decoded.member, payload.member);
        assert_eq!(decoded.commit.rev, commit.rev);
    }
}
