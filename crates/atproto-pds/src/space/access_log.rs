//! A record of which applications have read an account's permissioned records.
//!
//! Space credentials are minted by the space authority, so a repo host never
//! sees one being issued — only presented. The read path is therefore the only
//! place this server can answer "who has been reading my records in this
//! space", and this module is the answer's storage.
//!
//! # What an entry can and cannot identify
//!
//! A credential names its holder two ways, and only one of them is stable.
//! `client_id` is the attested application identity, present only when the
//! exchange that minted the credential carried a client attestation. `cnf.jkt`
//! is the thumbprint of the DPoP key the credential is bound to, and the
//! permissioned-data draft recommends generating a fresh keypair per
//! credential and discarding it at expiry.
//!
//! So an attesting application accumulates one row and a read count; a
//! non-attesting one appears as a new anonymous row every time its credential
//! rotates. That is a property of the protocol rather than of this table, and
//! the account holder is shown it plainly rather than being handed a list of
//! hashes that looks like a list of applications.
//!
//! There is a second reason a reader lands in the anonymous case, and it does
//! not depend on the application at all. `client_id` is not a claim the draft
//! defines — it is an extension this server writes when it is the authority
//! minting the credential. A space anchored on another host is read with a
//! credential that host minted, and a conformant one has no reason to carry
//! the claim, so every reader of such a space is anonymous here however
//! diligently it attested. Being named in this table is therefore evidence
//! about the authority as much as about the reader.
//!
//! That bounds what a block can reach, and the bound is worth stating because
//! it is not obvious from the portal: a block is keyed on the identity the
//! credential presents, so blocking an attested `client_id` stops credentials
//! that carry it and does not stop the same application reading with a
//! credential that carries none. Against a space this server is the authority
//! for, an attesting app is named on every credential and the block holds.
//!
//! # Best effort
//!
//! Recording a read must never fail one. Callers log and continue.

use crate::errors::{PdsError, PdsResult};
use atproto_space::credential::SpaceCredential;
use atproto_space::types::SpaceUri;
use chrono::Utc;
use sqlx::SqlitePool;

/// One application's history of reading this account's records in one space.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccessEntry {
    /// Attested application identity, when the credential carried one.
    pub client_id: Option<String>,
    /// DPoP key thumbprint the most recent credential was bound to.
    pub jkt: String,
    /// When this identity first read anything here.
    pub first_seen: String,
    /// When it last did.
    pub last_seen: String,
    /// How many reads have been attributed to it.
    pub reads: i64,
}

impl AccessEntry {
    /// How to name this reader to a person.
    ///
    /// An attested application is named by the `client_id` it proved. Anything
    /// else is anonymous, and saying so is more useful than showing a key
    /// thumbprint that will be different tomorrow.
    #[must_use]
    pub fn is_attested(&self) -> bool {
        self.client_id.is_some()
    }
}

/// The key a credential is recorded under: the attested `client_id`, or the
/// DPoP thumbprint when there is none.
fn identity_of(credential: &SpaceCredential) -> String {
    match &credential.client_id {
        Some(client_id) => client_id.clone(),
        None => format!("jkt:{}", credential.cnf.jkt),
    }
}

/// Attribute one read of `space` to the presenter of `credential`.
///
/// Idempotent per identity: the first read inserts, later ones move
/// `last_seen` and increment the counter.
///
/// # Errors
///
/// [`PdsError::Storage`] if the row cannot be written. Callers treat this as
/// best-effort — a read is not failed because its bookkeeping was.
pub async fn record(
    actor_pool: &SqlitePool,
    space: &SpaceUri,
    credential: &SpaceCredential,
) -> PdsResult<()> {
    let now = Utc::now().to_rfc3339();
    let identity = identity_of(credential);
    sqlx::query(
        "INSERT INTO space_access_log
            (space, identity, client_id, jkt, first_seen, last_seen, reads)
         VALUES (?, ?, ?, ?, ?, ?, 1)
         ON CONFLICT(space, identity) DO UPDATE SET
            last_seen = excluded.last_seen,
            jkt = excluded.jkt,
            reads = reads + 1",
    )
    .bind(space.to_string())
    .bind(&identity)
    .bind(credential.client_id.as_deref())
    .bind(&credential.cnf.jkt)
    .bind(&now)
    .bind(&now)
    .execute(actor_pool)
    .await
    .map_err(|e| PdsError::Storage {
        reason: format!("space access log: {e}"),
    })?;
    Ok(())
}

/// Everything that has read this account's records in `space`, most recent
/// first.
///
/// # Errors
///
/// [`PdsError::Storage`] if the rows cannot be read.
pub async fn list(actor_pool: &SqlitePool, space: &SpaceUri) -> PdsResult<Vec<AccessEntry>> {
    let rows: Vec<(Option<String>, String, String, String, i64)> = sqlx::query_as(
        "SELECT client_id, jkt, first_seen, last_seen, reads FROM space_access_log
         WHERE space = ? ORDER BY last_seen DESC LIMIT 200",
    )
    .bind(space.to_string())
    .fetch_all(actor_pool)
    .await
    .map_err(|e| PdsError::Storage {
        reason: format!("space access log list: {e}"),
    })?;
    Ok(rows
        .into_iter()
        .map(
            |(client_id, jkt, first_seen, last_seen, reads)| AccessEntry {
                client_id,
                jkt,
                first_seen,
                last_seen,
                reads,
            },
        )
        .collect())
}

/// Refuse this identity's reads of the account's records in `space`.
///
/// Idempotent: blocking something already blocked is the same request twice.
///
/// # Errors
///
/// [`PdsError::Storage`] if the row cannot be written.
pub async fn block(actor_pool: &SqlitePool, space: &SpaceUri, identity: &str) -> PdsResult<()> {
    sqlx::query(
        "INSERT INTO space_access_block (space, identity, created_at)
         VALUES (?, ?, ?)
         ON CONFLICT(space, identity) DO NOTHING",
    )
    .bind(space.to_string())
    .bind(identity)
    .bind(Utc::now().to_rfc3339())
    .execute(actor_pool)
    .await
    .map_err(|e| PdsError::Storage {
        reason: format!("space access block: {e}"),
    })?;
    Ok(())
}

/// Lift a block. Returns whether one was there to lift.
///
/// # Errors
///
/// [`PdsError::Storage`] if the delete fails.
pub async fn unblock(actor_pool: &SqlitePool, space: &SpaceUri, identity: &str) -> PdsResult<bool> {
    let result = sqlx::query("DELETE FROM space_access_block WHERE space = ? AND identity = ?")
        .bind(space.to_string())
        .bind(identity)
        .execute(actor_pool)
        .await
        .map_err(|e| PdsError::Storage {
            reason: format!("space access unblock: {e}"),
        })?;
    Ok(result.rows_affected() > 0)
}

/// Whether this credential's presenter is refused.
///
/// Checked on the read path, so it is deliberately one indexed lookup on the
/// primary key. Fails **closed** on a storage error: a block that cannot be
/// read is not evidence that there is none, and the account asked for this
/// reader to be refused.
///
/// # Errors
///
/// [`PdsError::Storage`] if the row cannot be read.
pub async fn is_blocked(
    actor_pool: &SqlitePool,
    space: &SpaceUri,
    credential: &SpaceCredential,
) -> PdsResult<bool> {
    let identity = identity_of(credential);
    let row: Option<i64> = sqlx::query_scalar(
        "SELECT 1 FROM space_access_block WHERE space = ? AND identity = ? LIMIT 1",
    )
    .bind(space.to_string())
    .bind(&identity)
    .fetch_optional(actor_pool)
    .await
    .map_err(|e| PdsError::Storage {
        reason: format!("space access block lookup: {e}"),
    })?;
    Ok(row.is_some())
}

/// Every identity currently refused in `space`.
///
/// # Errors
///
/// [`PdsError::Storage`] if the rows cannot be read.
pub async fn list_blocked(actor_pool: &SqlitePool, space: &SpaceUri) -> PdsResult<Vec<String>> {
    sqlx::query_scalar("SELECT identity FROM space_access_block WHERE space = ? ORDER BY identity")
        .bind(space.to_string())
        .fetch_all(actor_pool)
        .await
        .map_err(|e| PdsError::Storage {
            reason: format!("space access block list: {e}"),
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::actor_store::sql::SqlActorStore;
    use atproto_space::credential::Cnf;

    fn space() -> SpaceUri {
        "at://did:plc:authority/space/app.bsky.group/default"
            .parse()
            .unwrap()
    }

    fn credential(client_id: Option<&str>, jkt: &str) -> SpaceCredential {
        SpaceCredential {
            iss: "did:plc:authority".to_string(),
            sub: space().to_string(),
            cnf: Cnf {
                jkt: jkt.to_string(),
            },
            client_id: client_id.map(str::to_string),
            iat: 0,
            exp: 0,
            jti: "j".to_string(),
        }
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn an_attesting_reader_accumulates_one_row() {
        let store = SqlActorStore::open_memory("did:plc:me").await.unwrap();
        let space = space();
        // Same application, two credentials, two different DPoP keys.
        record(
            store.pool(),
            &space,
            &credential(Some("https://app.example/c.json"), "k1"),
        )
        .await
        .unwrap();
        record(
            store.pool(),
            &space,
            &credential(Some("https://app.example/c.json"), "k2"),
        )
        .await
        .unwrap();

        let entries = list(store.pool(), &space).await.unwrap();
        assert_eq!(entries.len(), 1, "an attested identity is one reader");
        assert_eq!(entries[0].reads, 2);
        assert!(entries[0].is_attested());
        assert_eq!(entries[0].jkt, "k2", "the latest key is kept");
    }

    /// The limitation, asserted rather than described: a reader that does not
    /// attest is a new row per credential, because the only thing naming it is
    /// a key the draft says to rotate.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_non_attesting_reader_cannot_be_followed_across_credentials() {
        let store = SqlActorStore::open_memory("did:plc:me").await.unwrap();
        let space = space();
        record(store.pool(), &space, &credential(None, "k1"))
            .await
            .unwrap();
        record(store.pool(), &space, &credential(None, "k2"))
            .await
            .unwrap();

        let entries = list(store.pool(), &space).await.unwrap();
        assert_eq!(entries.len(), 2, "each rotation is a stranger");
        assert!(entries.iter().all(|e| !e.is_attested()));
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn entries_are_scoped_to_their_space() {
        let store = SqlActorStore::open_memory("did:plc:me").await.unwrap();
        let other: SpaceUri = "at://did:plc:authority/space/app.bsky.group/other"
            .parse()
            .unwrap();
        record(store.pool(), &space(), &credential(Some("a"), "k"))
            .await
            .unwrap();
        assert_eq!(list(store.pool(), &space()).await.unwrap().len(), 1);
        assert!(list(store.pool(), &other).await.unwrap().is_empty());
    }
}
