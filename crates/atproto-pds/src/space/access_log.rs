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
