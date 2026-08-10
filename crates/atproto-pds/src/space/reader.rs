//! `SpaceReader` — dual-auth permissioned-record reads.
//!
//! Spaces reads accept either:
//! - **Own-PDS OAuth** — the caller holds an OAuth bearer for the local
//!   member's account and can read whatever rows their per-actor store has.
//!   The PDS itself is the auth boundary.
//! - **Remote `SpaceCredential`** — a JWT minted by the space owner via
//!   `getSpaceCredential` and bound to a `clientId`. The owner's PDS verifies
//!   the credential against its own signing key, then serves rows from the
//!   per-actor store of the `repo` DID supplied by the caller.
//!
//! `SpaceReader` is intentionally storage-agnostic above the
//! `SpaceRepoStorage` trait: **the PDS does not enforce
//! membership at read time** for own-PDS-OAuth callers — the consumer
//! is responsible for membership checks at sync. For SpaceCredential callers,
//! the credential itself acts as proof that the owner has authorized this
//! `clientId` to read the space.
//!
//! Both auth modes accept an explicit `target_repo` (the DID whose per-actor
//! store to read from). For OAuth, the caller may omit `repo` and the read
//! defaults to their own subject; for SpaceCredential the caller MUST supply
//! `repo` — handler-level validation rejects missing values before they reach
//! the reader.

use crate::actor_store::sql::{SqlActorStore, SqlSpaceRepoStorage};
use crate::errors::{PdsError, PdsResult};
use crate::realm::PdsSetHash;
use crate::space::config::ensure_space_live;
use atproto_identity::key::{KeyData, to_public};
use atproto_space::credential::{SpaceCredential, verify_space_credential};
use atproto_space::space_repo::SpaceRepo;
use atproto_space::storage::{RecordPage, RecordRow};
use atproto_space::types::SpaceUri;
use std::path::PathBuf;
use std::sync::Arc;

/// Authentication mode for a Spaces read.
#[derive(Debug, Clone)]
pub enum SpaceReadAuth<'a> {
    /// Caller holds an OAuth bearer for the named account on this PDS.
    /// Reads happen against that account's per-actor store. No membership
    /// check is performed here — consumers verify at sync time.
    OwnPds {
        /// DID of the local account whose per-actor store to read from.
        ///
        /// Owned, not borrowed. This DID is produced by `subject.sub()`
        /// during request authentication — it is derived, not a slice of the
        /// request — so no caller can ever supply a borrow that outlives the
        /// call. Typing it as `&'a str` did not make the borrow possible; it
        /// made `Box::leak` the only way to satisfy the compiler, which leaked
        /// the DID string on every authenticated space read.
        account_did: String,
    },
    /// Caller presented a `SpaceCredential` JWT minted by the space authority.
    /// Reads happen against the *authority's* per-actor store. The credential's
    /// `client_id` claim is advisory (the trust comes from the authority's
    /// signature), so no expected-client check is performed here.
    SpaceCredential {
        /// The compact-form JWT.
        token: &'a str,
    },
}

/// What to list, and how, for [`SpaceReader::list_records`].
///
/// Grouped rather than passed as four positional parameters: `cursor`, `limit`
/// and `reverse` are one concept, and at the call site
/// `(None, None, 50, false)` says nothing about which is which.
#[derive(Debug, Clone, Copy)]
pub struct RecordListing<'a> {
    /// NSID collection, or `None` to list across every collection in the space.
    pub collection: Option<&'a str>,
    /// Cursor — the last `rkey` from the prior page. Ignored when `collection`
    /// is `None`.
    pub cursor: Option<&'a str>,
    /// Page size. The storage layer clamps to the lexicon's 1–100.
    pub limit: u32,
    /// Walk descending `rkey` order.
    pub reverse: bool,
}

/// Permissioned-record reader.
pub struct SpaceReader {
    data_dir: PathBuf,
    accounts: Arc<crate::account::AccountManager>,
    /// PLC directory hostname, for resolving a **remote** space authority's
    /// credential-signing key. Absent means only local authorities can be
    /// verified — see [`SpaceReader::authority_public_key`].
    plc_directory: Option<String>,
    http_client: reqwest::Client,
}

/// Split a cross-collection cursor into its collection and rkey halves.
///
/// `\u{1}` as the separator because an NSID cannot contain it and an rkey
/// cannot either, so the split is unambiguous in a way that a `/` or a `.`
/// would not be -- both appear in the values being joined.
///
/// A cursor without the separator is treated as naming a collection with no
/// position inside it, which is what a caller hand-writing one would most
/// likely mean and is harmless: the collection restarts.
fn split_cross_cursor(cursor: Option<&str>) -> (Option<&str>, Option<&str>) {
    match cursor {
        None => (None, None),
        Some(raw) => match raw.split_once('\u{1}') {
            Some((coll, rkey)) => (Some(coll), Some(rkey)),
            None => (Some(raw), None),
        },
    }
}

impl SpaceReader {
    /// Construct.
    #[must_use]
    pub fn new(accounts: Arc<crate::account::AccountManager>, data_dir: PathBuf) -> Self {
        Self {
            data_dir,
            accounts,
            plc_directory: None,
            http_client: reqwest::Client::new(),
        }
    }

    /// Point this reader at a PLC directory so it can verify credentials from
    /// authorities it does not host.
    #[must_use]
    pub fn with_plc_directory(mut self, plc_directory: Option<String>) -> Self {
        self.plc_directory = plc_directory;
        self
    }

    /// Fail with `SpaceNotFound` when the space is tombstoned. The tombstone
    /// lives in the space-authority's (`space.space_did`) per-actor store; the
    /// check is a no-op when that store is not local (cross-PDS spaces, where
    /// the authority enforces deletion on its own side).
    async fn ensure_space_live(&self, space: &SpaceUri) -> PdsResult<()> {
        ensure_space_live(&self.data_dir, space).await?;
        Ok(())
    }

    /// `getRecord` — fetch a single record by `(collection, rkey)` from the
    /// per-actor store of `target_repo`.
    ///
    /// `target_repo` is the DID of the member whose records to read from.
    /// For OAuth callers this is typically the caller's own DID (but may
    /// differ if the caller passed `repo` to read another member's repo on
    /// this PDS). For SpaceCredential callers this is the `repo` query
    /// parameter; handler-level validation ensures it is always supplied.
    ///
    /// Returns `Ok(None)` when the record does not exist OR is taken-down
    /// (`space_record_takedown`); returns [`PdsError::AuthDenied`]
    /// for invalid SpaceCredentials.
    pub async fn get_record(
        &self,
        space: &SpaceUri,
        auth: SpaceReadAuth<'_>,
        target_repo: &str,
        collection: &str,
        rkey: &str,
    ) -> PdsResult<Option<RecordRow>> {
        self.verify_auth(space, &auth).await?;
        self.ensure_space_live(space).await?;
        let store = SqlActorStore::open(&self.data_dir, target_repo).await?;

        // Takedown gate — admin moderation hides the record at read time.
        if is_record_taken_down(store.pool(), space, collection, rkey).await? {
            return Ok(None);
        }

        let storage = SqlSpaceRepoStorage::new(store.pool().clone());
        let repo: SpaceRepo<SqlSpaceRepoStorage, PdsSetHash> =
            SpaceRepo::new(space.clone(), storage);
        repo.get_record(collection, rkey)
            .await
            .map_err(PdsError::Space)
    }

    /// Every collection with at least one record in this repo's slice of the
    /// space.
    ///
    /// Used by `getRepo` to enumerate what to export. Auth is the caller's
    /// responsibility — `getRepo` has already resolved and verified it, and
    /// re-checking here would mean threading a second auth argument for no
    /// additional guarantee.
    ///
    /// # Errors
    ///
    /// Storage failures, or [`PdsError::SpaceNotFound`] for a tombstoned space.
    pub async fn list_collections(
        &self,
        space: &SpaceUri,
        target_repo: &str,
    ) -> PdsResult<Vec<String>> {
        self.ensure_space_live(space).await?;
        let store = SqlActorStore::open(&self.data_dir, target_repo).await?;
        let storage = SqlSpaceRepoStorage::new(store.pool().clone());
        let repo: SpaceRepo<SqlSpaceRepoStorage, PdsSetHash> =
            SpaceRepo::new(space.clone(), storage);
        repo.list_collections().await.map_err(PdsError::Space)
    }

    /// `listRecords` — paginated listing within a collection, or across all
    /// collections when `collection` is `None`.
    ///
    /// Both modes page. The cross-collection mode used to concatenate the
    /// first `limit` records of every collection and answer `cursor: None`,
    /// which is two problems wearing one coat: the response could be
    /// `collections × limit` records however small a limit the caller asked
    /// for, and a caller had no way to ask for the rest or to tell that there
    /// was a rest. A short page is the only signal a client has that it has
    /// seen everything, and this mode never sent one.
    ///
    /// Across collections the cursor is `<collection>\u{1}<rkey>`: it names
    /// the last record delivered, so the next call resumes inside the
    /// collection it stopped in rather than at that collection's start.
    /// Collections are always walked in ascending order, `reverse` ordering
    /// records within each, because the cursor has to name a position in a
    /// stable sequence.
    ///
    /// `target_repo` has the same meaning as in [`Self::get_record`].
    pub async fn list_records(
        &self,
        space: &SpaceUri,
        auth: SpaceReadAuth<'_>,
        target_repo: &str,
        listing: RecordListing<'_>,
    ) -> PdsResult<RecordPage> {
        let RecordListing {
            collection,
            cursor,
            limit,
            reverse,
        } = listing;
        self.verify_auth(space, &auth).await?;
        self.ensure_space_live(space).await?;
        let store = SqlActorStore::open(&self.data_dir, target_repo).await?;
        let storage = SqlSpaceRepoStorage::new(store.pool().clone());
        let repo: SpaceRepo<SqlSpaceRepoStorage, PdsSetHash> =
            SpaceRepo::new(space.clone(), storage);

        match collection {
            Some(coll) => {
                let mut page = repo
                    .list_records(coll, cursor, limit, reverse)
                    .await
                    .map_err(PdsError::Space)?;
                let taken: std::collections::HashSet<String> =
                    taken_down_rkeys(store.pool(), space, coll).await?;
                if !taken.is_empty() {
                    page.records.retain(|r| !taken.contains(&r.rkey));
                }
                Ok(page)
            }
            None => {
                let (resume_collection, resume_rkey) = split_cross_cursor(cursor);
                let collections = repo.list_collections().await.map_err(PdsError::Space)?;
                let mut all_records = Vec::new();
                let mut last_key: Option<(String, String)> = None;

                for coll in collections {
                    // `list_collections` is ascending, so anything sorting
                    // before the cursor's collection was delivered already.
                    if let Some(from) = resume_collection
                        && coll.as_str() < from
                    {
                        continue;
                    }
                    let remaining =
                        limit.saturating_sub(u32::try_from(all_records.len()).unwrap_or(u32::MAX));
                    if remaining == 0 {
                        break;
                    }
                    // Only the collection the cursor stopped in resumes from an
                    // rkey; the ones after it start at the beginning.
                    let within = match resume_collection {
                        Some(from) if coll.as_str() == from => resume_rkey,
                        _ => None,
                    };
                    let mut page = repo
                        .list_records(&coll, within, remaining, reverse)
                        .await
                        .map_err(PdsError::Space)?;
                    let taken: std::collections::HashSet<String> =
                        taken_down_rkeys(store.pool(), space, &coll).await?;
                    if !taken.is_empty() {
                        page.records.retain(|r| !taken.contains(&r.rkey));
                    }
                    if let Some(last) = page.records.last() {
                        last_key = Some((coll.clone(), last.rkey.clone()));
                    }
                    all_records.append(&mut page.records);
                }

                // A full page may have more behind it; a short one cannot, and
                // saying so is what lets a client stop. Suppressing the cursor
                // on a short page is the same rule the single-collection mode
                // follows.
                let cursor = (u32::try_from(all_records.len()).unwrap_or(u32::MAX) >= limit)
                    .then(|| last_key.map(|(coll, rkey)| format!("{coll}\u{1}{rkey}")))
                    .flatten();
                Ok(RecordPage {
                    records: all_records,
                    cursor,
                })
            }
        }
    }

    /// Public entry point to verify a record-read auth against `space` without
    /// reading a record. Used by `com.atproto.space.getBlob`, which serves
    /// blob bytes under the same auth gate as `getRecord` / `listRecords`
    /// (space-credential-space-match OR OAuth/session) but does not go through
    /// the record path.
    pub async fn verify_read_auth(
        &self,
        space: &SpaceUri,
        auth: &SpaceReadAuth<'_>,
    ) -> PdsResult<()> {
        self.verify_auth(space, auth).await
    }

    /// Verify a presented `SpaceCredential` JWT against `space` without reading
    /// a record. Resolves the space authority's `#atproto_space` signing key and
    /// runs the full credential check (signature + `iss`/`sub`/`exp` bound to
    /// `space`), returning [`PdsError::AuthDenied`] on any failure.
    ///
    /// Used by the host/sync read methods (`getSpace`, `getRepoState`,
    /// `listRepoOps`, `listRepos`) to verify a credential-`typ` bearer at the
    /// HTTP layer, so a forged, unsigned, expired, or wrong-space credential is
    /// rejected rather than admitted on its `typ` string alone.
    pub async fn verify_space_credential_for(
        &self,
        space: &SpaceUri,
        token: &str,
    ) -> PdsResult<()> {
        self.verify_auth(space, &SpaceReadAuth::SpaceCredential { token })
            .await
    }

    /// Verify the read auth. For SpaceCredential, performs JWT signature
    /// verification against the space authority's `#atproto_space` signing key
    /// plus `iss`/`sub`/`exp` checks. The credential's `client_id` is advisory
    /// and not enforced. For OwnPds, this is a no-op — the HTTP-layer
    /// OAuth/session check already validated the bearer.
    async fn verify_auth(&self, space: &SpaceUri, auth: &SpaceReadAuth<'_>) -> PdsResult<()> {
        match auth {
            SpaceReadAuth::OwnPds { .. } => Ok(()),
            SpaceReadAuth::SpaceCredential { token } => {
                let authority_did = &space.space_did;
                let authority_pub = self.authority_public_key(authority_did).await?;
                let _payload: SpaceCredential =
                    verify_space_credential(token, authority_did, space, &authority_pub).map_err(
                        |e| PdsError::AuthDenied {
                            reason: format!("invalid SpaceCredential: {e}"),
                        },
                    )?;
                Ok(())
            }
        }
    }

    /// Resolve a space authority's credential-signing key in *public* form.
    ///
    /// Local authorities are answered from the account table, which is both
    /// faster and the only path that works before a newly created account has
    /// propagated. Everyone else is resolved from their DID document.
    ///
    /// That second half is the point. A space credential is "signed by the
    /// space authority's signing key, so **any repo host can verify it against
    /// the authority's key without contacting the authority**" — the key comes
    /// from the DID document, which is the same third party every other
    /// atproto signature is checked against. Looking only in the local account
    /// table made a credential verifiable solely on the host that minted it,
    /// which confines a permissioned space to one PDS and is the opposite of
    /// what the design is for.
    ///
    /// Per 0016 the authority's `#atproto_space` verification method MAY
    /// coincide with `#atproto`, so `#atproto_space` is preferred and
    /// `#atproto` accepted as the fallback.
    async fn authority_public_key(&self, authority_did: &str) -> PdsResult<KeyData> {
        match self.local_authority_public_key(authority_did).await {
            Ok(key) => return Ok(key),
            Err(PdsError::NotFound { .. }) => {}
            Err(e) => return Err(e),
        }
        self.remote_authority_public_key(authority_did).await
    }

    /// The authority's key from its DID document.
    async fn remote_authority_public_key(&self, authority_did: &str) -> PdsResult<KeyData> {
        let document = if let Some(rest) = authority_did.strip_prefix("did:web:") {
            let _ = rest;
            atproto_identity::web::query(&self.http_client, authority_did)
                .await
                .map_err(|e| PdsError::AuthDenied {
                    reason: format!("resolve space authority {authority_did}: {e}"),
                })?
        } else {
            let plc = self.plc_directory.as_deref().ok_or_else(|| {
                // Stated rather than silently failing the signature check: a
                // reader with no directory configured cannot verify any remote
                // authority, and that is a deployment problem, not a bad token.
                PdsError::AuthDenied {
                    reason: format!(
                        "space authority {authority_did} is not local and no PLC directory is configured to resolve it"
                    ),
                }
            })?;
            atproto_identity::plc::query(&self.http_client, plc, authority_did)
                .await
                .map_err(|e| PdsError::AuthDenied {
                    reason: format!("resolve space authority {authority_did}: {e}"),
                })?
        };

        let multibase = verification_method_key(&document, "atproto_space")
            .or_else(|| verification_method_key(&document, "atproto"))
            .ok_or_else(|| PdsError::AuthDenied {
                reason: format!(
                    "space authority {authority_did} publishes neither #atproto_space nor #atproto"
                ),
            })?;

        atproto_identity::key::identify_key(multibase).map_err(|e| PdsError::AuthDenied {
            reason: format!("space authority {authority_did} key is unreadable: {e}"),
        })
    }

    async fn local_authority_public_key(&self, authority_did: &str) -> PdsResult<KeyData> {
        let key_ref: Option<(String,)> =
            sqlx::query_as("SELECT signing_key_ref FROM account WHERE did = ?")
                .bind(authority_did)
                .fetch_optional(self.accounts.pool())
                .await
                .map_err(|e| PdsError::Storage {
                    reason: format!("lookup signing_key_ref: {e}"),
                })?;
        let key_ref = key_ref
            .ok_or_else(|| PdsError::NotFound {
                what: format!("account {authority_did} (signing_key_ref)"),
            })?
            .0;
        let private = self.accounts.key_store().get(&key_ref).await?;
        to_public(&private).map_err(|e| PdsError::Storage {
            reason: format!("derive public key: {e}"),
        })
    }
}

/// The multibase key of the verification method with the given fragment.
///
/// Matched on the fragment rather than the whole id, because a DID document
/// spells the id as `<did>#atproto_space` and the fragment is the part the
/// specification names.
fn verification_method_key<'a>(
    document: &'a atproto_identity::model::Document,
    fragment: &str,
) -> Option<&'a str> {
    document.verification_method.iter().find_map(|method| {
        let atproto_identity::model::VerificationMethod::Multikey {
            id,
            public_key_multibase,
            ..
        } = method
        else {
            return None;
        };
        (id.rsplit('#').next() == Some(fragment)).then_some(public_key_multibase.as_str())
    })
}

/// Returns true when a row in `space_record_takedown` matches the
/// `(space, collection, rkey)` triple.
pub(crate) async fn is_record_taken_down(
    pool: &sqlx::SqlitePool,
    space: &SpaceUri,
    collection: &str,
    rkey: &str,
) -> PdsResult<bool> {
    let row: Option<(i64,)> = sqlx::query_as(
        "SELECT 1 FROM space_record_takedown
         WHERE space = ? AND collection = ? AND rkey = ?",
    )
    .bind(space.to_string())
    .bind(collection)
    .bind(rkey)
    .fetch_optional(pool)
    .await
    .map_err(|e| PdsError::Storage {
        reason: format!("space_record_takedown lookup: {e}"),
    })?;
    Ok(row.is_some())
}

/// Returns the set of rkeys taken down within `(space, collection)`. Used
/// by `list_records` to filter a page in one round-trip.
pub(crate) async fn taken_down_rkeys(
    pool: &sqlx::SqlitePool,
    space: &SpaceUri,
    collection: &str,
) -> PdsResult<std::collections::HashSet<String>> {
    let rows: Vec<(String,)> = sqlx::query_as(
        "SELECT rkey FROM space_record_takedown
         WHERE space = ? AND collection = ?",
    )
    .bind(space.to_string())
    .bind(collection)
    .fetch_all(pool)
    .await
    .map_err(|e| PdsError::Storage {
        reason: format!("space_record_takedown list: {e}"),
    })?;
    Ok(rows.into_iter().map(|(r,)| r).collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `OwnPds` must own its DID.
    ///
    /// This is the F-SPACE-30 regression guard, and it is a *compile-time*
    /// one: the DID is built inside a scope that ends before the value is
    /// used, so this only compiles when `account_did` is owned. Reintroducing
    /// `&'a str` brings back the borrow that nothing can satisfy — and with it
    /// the `Box::leak` that leaked the caller's DID on every authenticated
    /// space read.
    ///
    /// There is no runtime assertion available here: the leak was invisible
    /// through the HTTP surface, which is why it survived. The type is the
    /// test.
    #[test]
    fn own_pds_owns_its_did() {
        let auth = {
            let subject_did = format!("did:plc:{}", "derived-at-request-time");
            SpaceReadAuth::OwnPds {
                account_did: subject_did,
            }
        };
        match auth {
            SpaceReadAuth::OwnPds { account_did } => {
                assert_eq!(account_did, "did:plc:derived-at-request-time");
            }
            SpaceReadAuth::SpaceCredential { .. } => unreachable!(),
        }
    }

    /// The lifetime parameter still earns its place: a SpaceCredential really
    /// does borrow the Authorization header, so dropping it entirely would
    /// have meant cloning a JWT on every credential read to fix a leak on a
    /// different variant.
    #[test]
    fn space_credential_still_borrows_its_token() {
        let header = String::from("eyJhbGciOiJFUzI1NiJ9.e30.sig");
        let auth = SpaceReadAuth::SpaceCredential { token: &header };
        match auth {
            SpaceReadAuth::SpaceCredential { token } => assert!(std::ptr::eq(token, &*header)),
            SpaceReadAuth::OwnPds { .. } => unreachable!(),
        }
    }
    use crate::account::{AccountDirectory, AccountManager, CreateAccountParams};
    use crate::keys::{KeyStore, MemoryKeyStore};
    use crate::space::writer::{SpaceWriteAction, SpaceWriteOp, SpaceWriter};
    use atproto_identity::key::KeyType;
    use atproto_space::credential::{SPACE_CREDENTIAL_TTL_SECS, create_space_credential};
    use atproto_space::types::{SpaceKey, SpaceType};
    use tempfile::TempDir;

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
        manager
            .create_account(CreateAccountParams {
                did: "did:plc:owner",
                handle: "owner.example",
                email: None,
                password: "pw",
                pds_managed_rotation: true,
                ..Default::default()
            })
            .await
            .unwrap();
        manager
    }

    fn test_space() -> SpaceUri {
        SpaceUri::new(
            "did:plc:owner".to_string(),
            SpaceType::new("app.bsky.group").unwrap(),
            SpaceKey::new("default").unwrap(),
        )
    }

    async fn seed_record(manager: Arc<AccountManager>, dir: PathBuf, uri: SpaceUri) {
        let writer = SpaceWriter::new(manager, dir);
        writer
            .apply_writes(
                "did:plc:owner",
                &uri,
                vec![SpaceWriteOp {
                    action: SpaceWriteAction::Create,
                    collection: "app.bsky.group.message".to_string(),
                    rkey: "abc".to_string(),
                    value: Some(serde_json::json!({"text": "hi"})),
                }],
            )
            .await
            .unwrap();
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn own_pds_get_record_round_trip() {
        let tmp = TempDir::new().unwrap();
        let dir = tmp.path().to_path_buf();
        let manager = fresh_manager(&dir).await;
        let uri = test_space();
        seed_record(manager.clone(), dir.clone(), uri.clone()).await;

        let reader = SpaceReader::new(manager, dir);
        let row = reader
            .get_record(
                &uri,
                SpaceReadAuth::OwnPds {
                    account_did: "did:plc:owner".to_string(),
                },
                "did:plc:owner",
                "app.bsky.group.message",
                "abc",
            )
            .await
            .unwrap()
            .unwrap();
        assert_eq!(row.collection, "app.bsky.group.message");
        assert_eq!(row.rkey, "abc");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn own_pds_list_records_paginates() {
        let tmp = TempDir::new().unwrap();
        let dir = tmp.path().to_path_buf();
        let manager = fresh_manager(&dir).await;
        let uri = test_space();
        seed_record(manager.clone(), dir.clone(), uri.clone()).await;

        let reader = SpaceReader::new(manager, dir);
        let page = reader
            .list_records(
                &uri,
                SpaceReadAuth::OwnPds {
                    account_did: "did:plc:owner".to_string(),
                },
                "did:plc:owner",
                RecordListing {
                    collection: Some("app.bsky.group.message"),
                    cursor: None,
                    limit: 10,
                    reverse: false,
                },
            )
            .await
            .unwrap();
        assert_eq!(page.records.len(), 1);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn list_records_across_collections_when_collection_none() {
        let tmp = TempDir::new().unwrap();
        let dir = tmp.path().to_path_buf();
        let manager = fresh_manager(&dir).await;
        let uri = test_space();
        let writer = crate::space::writer::SpaceWriter::new(manager.clone(), dir.clone());
        for (collection, rkey) in [
            ("app.bsky.group.message", "m1"),
            ("app.bsky.group.like", "l1"),
        ] {
            writer
                .apply_writes(
                    "did:plc:owner",
                    &uri,
                    vec![SpaceWriteOp {
                        action: SpaceWriteAction::Create,
                        collection: collection.to_string(),
                        rkey: rkey.to_string(),
                        value: Some(serde_json::json!({})),
                    }],
                )
                .await
                .unwrap();
        }

        let reader = SpaceReader::new(manager, dir);
        let page = reader
            .list_records(
                &uri,
                SpaceReadAuth::OwnPds {
                    account_did: "did:plc:owner".to_string(),
                },
                "did:plc:owner",
                RecordListing {
                    collection: None,
                    cursor: None,
                    limit: 10,
                    reverse: false,
                },
            )
            .await
            .unwrap();
        assert_eq!(page.records.len(), 2, "should aggregate across collections");
        assert!(
            page.cursor.is_none(),
            "cross-collection listing has no cursor"
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn space_credential_round_trip() {
        let tmp = TempDir::new().unwrap();
        let dir = tmp.path().to_path_buf();
        let manager = fresh_manager(&dir).await;
        let uri = test_space();
        seed_record(manager.clone(), dir.clone(), uri.clone()).await;

        // Look up the owner's signing key and mint a credential bound to a
        // synthetic clientId.
        let key_ref: (String,) =
            sqlx::query_as("SELECT signing_key_ref FROM account WHERE did = ?")
                .bind("did:plc:owner")
                .fetch_one(manager.pool())
                .await
                .unwrap();
        let signing_key = manager.key_store().get(&key_ref.0).await.unwrap();
        let token = create_space_credential(
            "did:plc:owner",
            &uri,
            Some("https://app.example/client-metadata.json"),
            &signing_key,
            SPACE_CREDENTIAL_TTL_SECS,
        )
        .unwrap();

        let reader = SpaceReader::new(manager, dir);
        let row = reader
            .get_record(
                &uri,
                SpaceReadAuth::SpaceCredential { token: &token },
                "did:plc:owner",
                "app.bsky.group.message",
                "abc",
            )
            .await
            .unwrap()
            .unwrap();
        assert_eq!(row.rkey, "abc");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn space_credential_wrong_space_rejected() {
        let tmp = TempDir::new().unwrap();
        let dir = tmp.path().to_path_buf();
        let manager = fresh_manager(&dir).await;
        let uri = test_space();
        seed_record(manager.clone(), dir.clone(), uri.clone()).await;

        let key_ref: (String,) =
            sqlx::query_as("SELECT signing_key_ref FROM account WHERE did = ?")
                .bind("did:plc:owner")
                .fetch_one(manager.pool())
                .await
                .unwrap();
        let signing_key = manager.key_store().get(&key_ref.0).await.unwrap();
        // Mint a credential bound to a *different* space; the reader must
        // reject it against `uri` on the `sub` claim mismatch.
        let other = SpaceUri::new(
            "did:plc:owner".to_string(),
            atproto_space::types::SpaceType::new("app.bsky.group").unwrap(),
            atproto_space::types::SpaceKey::new("other").unwrap(),
        );
        let token = create_space_credential(
            "did:plc:owner",
            &other,
            None,
            &signing_key,
            SPACE_CREDENTIAL_TTL_SECS,
        )
        .unwrap();

        let reader = SpaceReader::new(manager, dir);
        let result = reader
            .get_record(
                &uri,
                SpaceReadAuth::SpaceCredential { token: &token },
                "did:plc:owner",
                "app.bsky.group.message",
                "abc",
            )
            .await;
        assert!(matches!(result, Err(PdsError::AuthDenied { .. })));
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn verify_space_credential_for_accepts_valid_and_rejects_forged() {
        let tmp = TempDir::new().unwrap();
        let dir = tmp.path().to_path_buf();
        let manager = fresh_manager(&dir).await;
        let uri = test_space();
        seed_record(manager.clone(), dir.clone(), uri.clone()).await;

        let key_ref: (String,) =
            sqlx::query_as("SELECT signing_key_ref FROM account WHERE did = ?")
                .bind("did:plc:owner")
                .fetch_one(manager.pool())
                .await
                .unwrap();
        let signing_key = manager.key_store().get(&key_ref.0).await.unwrap();
        let token = create_space_credential(
            "did:plc:owner",
            &uri,
            None,
            &signing_key,
            SPACE_CREDENTIAL_TTL_SECS,
        )
        .unwrap();

        let reader = SpaceReader::new(manager, dir);
        // A genuinely authority-signed credential verifies.
        reader
            .verify_space_credential_for(&uri, &token)
            .await
            .unwrap();

        // A token that merely *classifies* as a credential (correct typ/kid
        // header) but carries a zero signature must be rejected.
        let header = serde_json::json!({
            "alg": "ES256",
            "typ": "atproto-space-credential+jwt",
            "kid": "#atproto_space"
        });
        let payload = serde_json::json!({
            "iss": "did:plc:owner",
            "sub": uri.to_string(),
            "iat": 0,
            "exp": 9_999_999_999u64,
        });
        use base64::Engine as _;
        let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD;
        let forged = format!(
            "{}.{}.{}",
            b64.encode(serde_json::to_vec(&header).unwrap()),
            b64.encode(serde_json::to_vec(&payload).unwrap()),
            b64.encode([0u8; 64]),
        );
        let result = reader.verify_space_credential_for(&uri, &forged).await;
        assert!(matches!(result, Err(PdsError::AuthDenied { .. })));
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn nonexistent_record_returns_none() {
        let tmp = TempDir::new().unwrap();
        let dir = tmp.path().to_path_buf();
        let manager = fresh_manager(&dir).await;
        let uri = test_space();

        let reader = SpaceReader::new(manager, dir);
        let row = reader
            .get_record(
                &uri,
                SpaceReadAuth::OwnPds {
                    account_did: "did:plc:owner".to_string(),
                },
                "did:plc:owner",
                "app.bsky.group.message",
                "missing",
            )
            .await
            .unwrap();
        assert!(row.is_none());
    }

    /// Takedown gate: a row in `space_record_takedown` hides the
    /// record from `get_record` even when the underlying `space_record`
    /// row is intact. Re-inserting via `list_records` confirms the
    /// page-level filter is also wired.
    #[tokio::test(flavor = "multi_thread")]
    async fn takedown_hides_record_from_get_and_list() {
        let tmp = TempDir::new().unwrap();
        let dir = tmp.path().to_path_buf();
        let manager = fresh_manager(&dir).await;
        let uri = test_space();
        seed_record(manager.clone(), dir.clone(), uri.clone()).await;

        // Insert a takedown row directly into the owner's per-actor store.
        let store = crate::actor_store::sql::SqlActorStore::open(&dir, "did:plc:owner")
            .await
            .unwrap();
        let now = chrono::Utc::now().to_rfc3339();
        sqlx::query(
            "INSERT INTO space_record_takedown (space, collection, rkey, taken_at)
             VALUES (?, ?, ?, ?)",
        )
        .bind(uri.to_string())
        .bind("app.bsky.group.message")
        .bind("abc")
        .bind(&now)
        .execute(store.pool())
        .await
        .unwrap();

        let reader = SpaceReader::new(manager, dir);
        // get_record returns None for taken-down rows.
        let row = reader
            .get_record(
                &uri,
                SpaceReadAuth::OwnPds {
                    account_did: "did:plc:owner".to_string(),
                },
                "did:plc:owner",
                "app.bsky.group.message",
                "abc",
            )
            .await
            .unwrap();
        assert!(row.is_none(), "taken-down record must hide from get_record");

        // list_records page is empty.
        let page = reader
            .list_records(
                &uri,
                SpaceReadAuth::OwnPds {
                    account_did: "did:plc:owner".to_string(),
                },
                "did:plc:owner",
                RecordListing {
                    collection: Some("app.bsky.group.message"),
                    cursor: None,
                    limit: 10,
                    reverse: false,
                },
            )
            .await
            .unwrap();
        assert!(
            page.records.is_empty(),
            "taken-down record must be filtered from list_records"
        );
    }
}

#[cfg(test)]
mod authority_key_resolution {
    use super::*;
    use atproto_identity::model::DocumentBuilder;

    fn document(did: &str, fragments: &[(&str, &str)]) -> atproto_identity::model::Document {
        let mut b = DocumentBuilder::default().id(did.to_string());
        for (fragment, key) in fragments {
            // A DID document spells the id fully qualified, which is exactly
            // what makes fragment matching necessary.
            b = b.add_multikey(
                format!("{did}#{fragment}"),
                did.to_string(),
                (*key).to_string(),
            );
        }
        b.build().expect("document")
    }

    /// `#atproto_space` is preferred; `#atproto` is the fallback.
    ///
    /// 0016 allows the two to coincide, and this PDS's own PLC genesis
    /// publishes both — but an authority elsewhere may publish only one, and a
    /// verifier that insisted on `#atproto_space` would refuse it.
    #[test]
    fn the_space_method_is_preferred_and_atproto_is_the_fallback() {
        let both = document(
            "did:plc:x",
            &[("atproto", "zAAA"), ("atproto_space", "zBBB")],
        );
        assert_eq!(
            verification_method_key(&both, "atproto_space"),
            Some("zBBB")
        );
        assert_eq!(verification_method_key(&both, "atproto"), Some("zAAA"));

        let only_atproto = document("did:plc:x", &[("atproto", "zAAA")]);
        assert_eq!(
            verification_method_key(&only_atproto, "atproto_space"),
            None
        );
        assert_eq!(
            verification_method_key(&only_atproto, "atproto"),
            Some("zAAA")
        );
    }

    /// The fragment is matched, not the whole id.
    ///
    /// A document spells the id as `<did>#atproto_space`, and the DID part
    /// varies per authority — comparing whole ids would match nothing.
    #[test]
    fn the_fragment_is_matched_not_the_whole_id() {
        let doc = document("did:plc:whoever", &[("atproto_space", "zKEY")]);
        let atproto_identity::model::VerificationMethod::Multikey { id, .. } =
            &doc.verification_method[0]
        else {
            panic!("expected a multikey");
        };
        assert!(
            id.contains('#'),
            "id should be fragment-qualified, got {id}"
        );
        assert_eq!(verification_method_key(&doc, "atproto_space"), Some("zKEY"));
    }

    /// A near-miss fragment does not match.
    ///
    /// `#atproto_space_host` is a *service*, not a verification method, and
    /// shares a prefix with the one wanted. A `starts_with` would take it.
    #[test]
    fn a_prefix_of_the_fragment_does_not_match() {
        let doc = document("did:plc:x", &[("atproto_space_host", "zWRONG")]);
        assert_eq!(verification_method_key(&doc, "atproto_space"), None);
    }
}
