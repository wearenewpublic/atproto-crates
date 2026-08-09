//! OAuth in-flight state (PAR / auth-code / refresh-token rotation).
//!
//! Two backends:
//!
//! - [`OAuthState::memory`] — in-process `HashMap`s. Default for tests; not
//!   safe across PDS restarts or multi-process deployments.
//! - [`OAuthState::sql`] — SQLite-backed via the accounts pool. The
//!   production-default; PAR rows, auth codes, and refresh handles all
//!   survive restart.
//!
//! the SQL backend is required for any
//! deployment that wants to survive a single restart without dropping
//! every in-flight OAuth handshake.
//!
//! All operations are `async` so the dispatch can stay uniform across
//! both backends. The memory variant ignores the await points (its locks
//! are synchronous), so the `async` only matters for SQL.

use crate::errors::{PdsError, PdsResult};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::SqlitePool;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

/// Default access-token TTL: 15 min (matches TS PDS).
pub const DEFAULT_ACCESS_TTL_SECS: u64 = 900;

/// Default refresh-token TTL: 30 days.
pub const DEFAULT_REFRESH_TTL_SECS: u64 = 2_592_000;

/// Default authorization-code TTL: 60 seconds.
pub const AUTH_CODE_TTL_SECS: u64 = 60;

/// Default PAR `request_uri` TTL: 60 seconds.
pub const PAR_TTL_SECS: u64 = 60;

/// Stored PAR-staged authorization request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OAuthRequest {
    /// Client identifier (URL of client metadata).
    pub client_id: String,
    /// Redirect URI registered for this request.
    pub redirect_uri: String,
    /// Requested scope (space-separated).
    pub scope: String,
    /// Opaque client state (echoed at redirect).
    pub state: String,
    /// PKCE `code_challenge` (S256).
    pub code_challenge: String,
    /// `code_challenge_method` — must be `S256`.
    pub code_challenge_method: String,
    /// DPoP key thumbprint, if DPoP-bound at PAR time.
    pub dpop_jkt: Option<String>,
    /// Optional login hint (handle/DID).
    pub login_hint: Option<String>,
    /// Issuance timestamp.
    pub created_at: DateTime<Utc>,
}

/// Issued authorization code (one-shot).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthorizationCode {
    /// Account DID this code authorizes.
    pub did: String,
    /// Originating PAR request.
    pub request: OAuthRequest,
    /// Issuance timestamp.
    pub issued_at: DateTime<Utc>,
}

/// Refresh-token rotation tracker — records which `jti`s are still valid
/// (single-use semantics: presenting one consumes it and issues a new one).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RefreshHandle {
    /// Account DID.
    pub did: String,
    /// Client ID this refresh token is bound to.
    pub client_id: String,
    /// DPoP key thumbprint.
    pub dpop_jkt: String,
    /// Granted scope.
    pub scope: String,
    /// Issuance timestamp.
    pub issued_at: DateTime<Utc>,
    /// The authorization grant this token descends from.
    ///
    /// Every token produced by rotating this one shares it, so presenting a
    /// consumed token can end the whole chain rather than just failing.
    pub family_id: String,
}

/// Backend dispatch for OAuth in-flight state.
#[derive(Clone)]
pub enum OAuthState {
    /// In-memory backend. Lost on restart; suitable for unit tests + dev.
    Memory(MemoryBackend),
    /// SQLite-backed via the accounts pool. Persistent across restarts.
    Sql(SqlBackend),
}

impl Default for OAuthState {
    fn default() -> Self {
        OAuthState::Memory(MemoryBackend::default())
    }
}

impl OAuthState {
    /// Construct an empty in-memory backend.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Explicit memory-backed constructor (matches `Self::default`).
    #[must_use]
    pub fn memory() -> Self {
        OAuthState::Memory(MemoryBackend::default())
    }

    /// Construct a SQL-backed backend over the supplied accounts pool.
    /// The pool must point at an `accounts.sqlite` whose migrations
    /// include `oauth_par`, `oauth_code`, `oauth_refresh` (the
    /// `20260505000003_oauth_state` migration).
    #[must_use]
    pub fn sql(pool: SqlitePool) -> Self {
        OAuthState::Sql(SqlBackend { pool })
    }

    /// Store a PAR request keyed by `request_uri`.
    pub async fn store_par(&self, request_uri: String, request: OAuthRequest) -> PdsResult<()> {
        match self {
            OAuthState::Memory(m) => m.store_par(request_uri, request),
            OAuthState::Sql(s) => s.store_par(request_uri, request).await,
        }
    }

    /// Consume a PAR request by `request_uri`. Returns `None` if absent or expired.
    pub async fn take_par(&self, request_uri: &str) -> PdsResult<Option<OAuthRequest>> {
        match self {
            OAuthState::Memory(m) => Ok(m.take_par(request_uri)),
            OAuthState::Sql(s) => s.take_par(request_uri).await,
        }
    }

    /// Peek at a PAR request without consuming it. Used by the consent UI.
    /// Returns `None` if absent or expired.
    pub async fn peek_par(&self, request_uri: &str) -> PdsResult<Option<OAuthRequest>> {
        match self {
            OAuthState::Memory(m) => Ok(m.peek_par(request_uri)),
            OAuthState::Sql(s) => s.peek_par(request_uri).await,
        }
    }

    /// Issue an authorization code for a previously-staged PAR request.
    pub async fn issue_code(
        &self,
        code: String,
        did: String,
        request: OAuthRequest,
    ) -> PdsResult<()> {
        match self {
            OAuthState::Memory(m) => {
                m.issue_code(code, did, request);
                Ok(())
            }
            OAuthState::Sql(s) => s.issue_code(code, did, request).await,
        }
    }

    /// Consume an authorization code. Returns `None` if absent or expired.
    pub async fn take_code(&self, code: &str) -> PdsResult<Option<AuthorizationCode>> {
        match self {
            OAuthState::Memory(m) => Ok(m.take_code(code)),
            OAuthState::Sql(s) => s.take_code(code).await,
        }
    }

    /// Register a refresh-token jti as live.
    pub async fn register_refresh(&self, jti: String, handle: RefreshHandle) -> PdsResult<()> {
        match self {
            OAuthState::Memory(m) => {
                m.register_refresh(jti, handle);
                Ok(())
            }
            OAuthState::Sql(s) => s.register_refresh(jti, handle).await,
        }
    }

    /// Atomically consume a refresh-token jti and replace it with a new one
    /// (single-use rotation). Returns the consumed handle if found.
    pub async fn rotate_refresh(
        &self,
        old_jti: &str,
        new_jti: String,
    ) -> PdsResult<Option<RefreshHandle>> {
        match self {
            OAuthState::Memory(m) => Ok(m.rotate_refresh(old_jti, new_jti)),
            OAuthState::Sql(s) => s.rotate_refresh(old_jti, new_jti).await,
        }
    }

    /// Read a refresh handle without consuming it.
    ///
    /// Rotation is destructive, so everything that decides *whether* to rotate
    /// has to be able to see the handle first. It could not, which is why the
    /// DPoP-binding and account-state checks used to run after the rotation
    /// they were supposed to gate.
    pub async fn peek_refresh(&self, jti: &str) -> PdsResult<Option<RefreshHandle>> {
        match self {
            OAuthState::Memory(m) => Ok(m.peek_refresh(jti)),
            OAuthState::Sql(s) => s.peek_refresh(jti).await,
        }
    }

    /// Revoke every refresh token descended from one authorization grant.
    ///
    /// Returns how many were removed. OAuth 2.1 requires this when an
    /// already-rotated token is presented: the explanations are a leaked token
    /// in use or a client racing itself, and ending the grant is the right
    /// answer to both.
    pub async fn revoke_refresh_family(&self, family_id: &str) -> PdsResult<u64> {
        match self {
            OAuthState::Memory(m) => Ok(m.revoke_refresh_family(family_id)),
            OAuthState::Sql(s) => s.revoke_refresh_family(family_id).await,
        }
    }

    /// Revoke a refresh-token jti. Returns `true` if a row was removed.
    pub async fn revoke_refresh(&self, jti: &str) -> PdsResult<bool> {
        match self {
            OAuthState::Memory(m) => Ok(m.revoke_refresh(jti)),
            OAuthState::Sql(s) => s.revoke_refresh(jti).await,
        }
    }

    // --- Diagnostics (test-only). ---

    #[doc(hidden)]
    pub async fn par_count(&self) -> PdsResult<usize> {
        match self {
            OAuthState::Memory(m) => Ok(m.par_count()),
            OAuthState::Sql(s) => s.par_count().await,
        }
    }

    #[doc(hidden)]
    pub async fn code_count(&self) -> PdsResult<usize> {
        match self {
            OAuthState::Memory(m) => Ok(m.code_count()),
            OAuthState::Sql(s) => s.code_count().await,
        }
    }

    #[doc(hidden)]
    pub async fn refresh_count(&self) -> PdsResult<usize> {
        match self {
            OAuthState::Memory(m) => Ok(m.refresh_count()),
            OAuthState::Sql(s) => s.refresh_count().await,
        }
    }
}

// ---------------------------------------------------------------------------
//  In-memory backend.
// ---------------------------------------------------------------------------

/// In-memory `OAuthState` storage. Suitable for tests and single-process dev
/// builds; production should use [`OAuthState::sql`] so PAR + auth-code +
/// refresh-token state survives restart.
#[derive(Clone, Default)]
pub struct MemoryBackend {
    inner: Arc<Mutex<MemoryInner>>,
}

#[derive(Default)]
struct MemoryInner {
    par_requests: HashMap<String, OAuthRequest>,
    auth_codes: HashMap<String, AuthorizationCode>,
    refresh_tokens: HashMap<String, RefreshHandle>,
}

impl MemoryBackend {
    fn store_par(&self, request_uri: String, request: OAuthRequest) -> PdsResult<()> {
        let mut inner = self.inner.lock().unwrap();
        inner.par_requests.insert(request_uri, request);
        Self::gc_locked(&mut inner);
        Ok(())
    }

    fn take_par(&self, request_uri: &str) -> Option<OAuthRequest> {
        let mut inner = self.inner.lock().unwrap();
        Self::gc_locked(&mut inner);
        let req = inner.par_requests.remove(request_uri)?;
        if Utc::now() - req.created_at > chrono::Duration::seconds(PAR_TTL_SECS as i64) {
            return None;
        }
        Some(req)
    }

    fn peek_par(&self, request_uri: &str) -> Option<OAuthRequest> {
        let mut inner = self.inner.lock().unwrap();
        Self::gc_locked(&mut inner);
        let req = inner.par_requests.get(request_uri)?;
        if Utc::now() - req.created_at > chrono::Duration::seconds(PAR_TTL_SECS as i64) {
            return None;
        }
        Some(req.clone())
    }

    fn issue_code(&self, code: String, did: String, request: OAuthRequest) {
        let mut inner = self.inner.lock().unwrap();
        inner.auth_codes.insert(
            code,
            AuthorizationCode {
                did,
                request,
                issued_at: Utc::now(),
            },
        );
        Self::gc_locked(&mut inner);
    }

    fn take_code(&self, code: &str) -> Option<AuthorizationCode> {
        let mut inner = self.inner.lock().unwrap();
        Self::gc_locked(&mut inner);
        let auth = inner.auth_codes.remove(code)?;
        if Utc::now() - auth.issued_at > chrono::Duration::seconds(AUTH_CODE_TTL_SECS as i64) {
            return None;
        }
        Some(auth)
    }

    fn register_refresh(&self, jti: String, handle: RefreshHandle) {
        let mut inner = self.inner.lock().unwrap();
        inner.refresh_tokens.insert(jti, handle);
    }

    fn rotate_refresh(&self, old_jti: &str, new_jti: String) -> Option<RefreshHandle> {
        let mut inner = self.inner.lock().unwrap();
        let handle = inner.refresh_tokens.remove(old_jti)?;
        inner.refresh_tokens.insert(
            new_jti,
            RefreshHandle {
                family_id: "test-family".to_string(),
                issued_at: Utc::now(),
                ..handle.clone()
            },
        );
        Some(handle)
    }

    fn peek_refresh(&self, jti: &str) -> Option<RefreshHandle> {
        let inner = self.inner.lock().unwrap();
        inner.refresh_tokens.get(jti).cloned()
    }

    fn revoke_refresh_family(&self, family_id: &str) -> u64 {
        let mut inner = self.inner.lock().unwrap();
        let doomed: Vec<String> = inner
            .refresh_tokens
            .iter()
            .filter(|(_, handle)| handle.family_id == family_id)
            .map(|(jti, _)| jti.clone())
            .collect();
        for jti in &doomed {
            inner.refresh_tokens.remove(jti);
        }
        doomed.len() as u64
    }

    fn revoke_refresh(&self, jti: &str) -> bool {
        let mut inner = self.inner.lock().unwrap();
        inner.refresh_tokens.remove(jti).is_some()
    }

    fn gc_locked(inner: &mut MemoryInner) {
        let now = Utc::now();
        let par_ttl = chrono::Duration::seconds(PAR_TTL_SECS as i64);
        let code_ttl = chrono::Duration::seconds(AUTH_CODE_TTL_SECS as i64);
        inner
            .par_requests
            .retain(|_, r| now - r.created_at <= par_ttl);
        inner
            .auth_codes
            .retain(|_, c| now - c.issued_at <= code_ttl);
    }

    fn par_count(&self) -> usize {
        self.inner.lock().unwrap().par_requests.len()
    }
    fn code_count(&self) -> usize {
        self.inner.lock().unwrap().auth_codes.len()
    }
    fn refresh_count(&self) -> usize {
        self.inner.lock().unwrap().refresh_tokens.len()
    }
}

// ---------------------------------------------------------------------------
//  SQL backend.
// ---------------------------------------------------------------------------

/// SQLite-backed `OAuthState` storage over the shared accounts pool.
#[derive(Clone)]
pub struct SqlBackend {
    pool: SqlitePool,
}

impl SqlBackend {
    async fn store_par(&self, request_uri: String, request: OAuthRequest) -> PdsResult<()> {
        let expires_at =
            (request.created_at + chrono::Duration::seconds(PAR_TTL_SECS as i64)).to_rfc3339();
        sqlx::query(
            "INSERT OR REPLACE INTO oauth_par
                (request_uri, client_id, redirect_uri, scope, state_param,
                 code_challenge, code_challenge_method, dpop_jkt, login_hint,
                 created_at, expires_at)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(&request_uri)
        .bind(&request.client_id)
        .bind(&request.redirect_uri)
        .bind(&request.scope)
        .bind(&request.state)
        .bind(&request.code_challenge)
        .bind(&request.code_challenge_method)
        .bind(request.dpop_jkt.as_deref())
        .bind(request.login_hint.as_deref())
        .bind(request.created_at.to_rfc3339())
        .bind(&expires_at)
        .execute(&self.pool)
        .await
        .map_err(|e| PdsError::Storage {
            reason: format!("oauth_par insert: {e}"),
        })?;
        // Opportunistically prune expired PARs and codes.
        let _ = self.gc().await;
        Ok(())
    }

    async fn take_par(&self, request_uri: &str) -> PdsResult<Option<OAuthRequest>> {
        let row = self.fetch_par(request_uri).await?;
        if row.is_some() {
            sqlx::query("DELETE FROM oauth_par WHERE request_uri = ?")
                .bind(request_uri)
                .execute(&self.pool)
                .await
                .map_err(|e| PdsError::Storage {
                    reason: format!("oauth_par delete: {e}"),
                })?;
        }
        Ok(row)
    }

    async fn peek_par(&self, request_uri: &str) -> PdsResult<Option<OAuthRequest>> {
        self.fetch_par(request_uri).await
    }

    async fn fetch_par(&self, request_uri: &str) -> PdsResult<Option<OAuthRequest>> {
        type Row = (
            String,
            String,
            String,
            String,
            String,
            String,
            Option<String>,
            Option<String>,
            String,
            String,
        );
        let row: Option<Row> = sqlx::query_as(
            "SELECT client_id, redirect_uri, scope, state_param,
                    code_challenge, code_challenge_method, dpop_jkt, login_hint,
                    created_at, expires_at
             FROM oauth_par WHERE request_uri = ?",
        )
        .bind(request_uri)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| PdsError::Storage {
            reason: format!("oauth_par select: {e}"),
        })?;
        let Some(row) = row else { return Ok(None) };
        let expires_at = chrono::DateTime::parse_from_rfc3339(&row.9)
            .map_err(|e| PdsError::Storage {
                reason: format!("parse expires_at: {e}"),
            })?
            .with_timezone(&Utc);
        if Utc::now() > expires_at {
            return Ok(None);
        }
        let created_at = chrono::DateTime::parse_from_rfc3339(&row.8)
            .map_err(|e| PdsError::Storage {
                reason: format!("parse created_at: {e}"),
            })?
            .with_timezone(&Utc);
        Ok(Some(OAuthRequest {
            client_id: row.0,
            redirect_uri: row.1,
            scope: row.2,
            state: row.3,
            code_challenge: row.4,
            code_challenge_method: row.5,
            dpop_jkt: row.6,
            login_hint: row.7,
            created_at,
        }))
    }

    async fn issue_code(&self, code: String, did: String, request: OAuthRequest) -> PdsResult<()> {
        let now = Utc::now();
        let expires_at = (now + chrono::Duration::seconds(AUTH_CODE_TTL_SECS as i64)).to_rfc3339();
        let request_json = serde_json::to_string(&request).map_err(|e| PdsError::Storage {
            reason: format!("serialize PAR request: {e}"),
        })?;
        sqlx::query(
            "INSERT OR REPLACE INTO oauth_code
                (code, did, request_json, issued_at, expires_at)
             VALUES (?, ?, ?, ?, ?)",
        )
        .bind(&code)
        .bind(&did)
        .bind(&request_json)
        .bind(now.to_rfc3339())
        .bind(&expires_at)
        .execute(&self.pool)
        .await
        .map_err(|e| PdsError::Storage {
            reason: format!("oauth_code insert: {e}"),
        })?;
        let _ = self.gc().await;
        Ok(())
    }

    async fn take_code(&self, code: &str) -> PdsResult<Option<AuthorizationCode>> {
        let row: Option<(String, String, String, String)> = sqlx::query_as(
            "SELECT did, request_json, issued_at, expires_at FROM oauth_code WHERE code = ?",
        )
        .bind(code)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| PdsError::Storage {
            reason: format!("oauth_code select: {e}"),
        })?;
        let Some((did, request_json, issued_at, expires_at)) = row else {
            return Ok(None);
        };
        sqlx::query("DELETE FROM oauth_code WHERE code = ?")
            .bind(code)
            .execute(&self.pool)
            .await
            .map_err(|e| PdsError::Storage {
                reason: format!("oauth_code delete: {e}"),
            })?;
        let exp = chrono::DateTime::parse_from_rfc3339(&expires_at)
            .map_err(|e| PdsError::Storage {
                reason: format!("parse expires_at: {e}"),
            })?
            .with_timezone(&Utc);
        if Utc::now() > exp {
            return Ok(None);
        }
        let issued = chrono::DateTime::parse_from_rfc3339(&issued_at)
            .map_err(|e| PdsError::Storage {
                reason: format!("parse issued_at: {e}"),
            })?
            .with_timezone(&Utc);
        let request: OAuthRequest =
            serde_json::from_str(&request_json).map_err(|e| PdsError::Storage {
                reason: format!("parse PAR request_json: {e}"),
            })?;
        Ok(Some(AuthorizationCode {
            did,
            request,
            issued_at: issued,
        }))
    }

    async fn register_refresh(&self, jti: String, handle: RefreshHandle) -> PdsResult<()> {
        sqlx::query(
            "INSERT OR REPLACE INTO oauth_refresh
                (jti, did, client_id, dpop_jkt, scope, issued_at, family_id)
             VALUES (?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(&jti)
        .bind(&handle.did)
        .bind(&handle.client_id)
        .bind(&handle.dpop_jkt)
        .bind(&handle.scope)
        .bind(handle.issued_at.to_rfc3339())
        .bind(&handle.family_id)
        .execute(&self.pool)
        .await
        .map_err(|e| PdsError::Storage {
            reason: format!("oauth_refresh insert: {e}"),
        })?;
        Ok(())
    }

    async fn rotate_refresh(
        &self,
        old_jti: &str,
        new_jti: String,
    ) -> PdsResult<Option<RefreshHandle>> {
        let mut tx = self.pool.begin().await.map_err(|e| PdsError::Storage {
            reason: format!("oauth_refresh begin: {e}"),
        })?;
        let row: Option<(String, String, String, String, String, String)> = sqlx::query_as(
            "SELECT did, client_id, dpop_jkt, scope, issued_at, family_id
             FROM oauth_refresh WHERE jti = ?",
        )
        .bind(old_jti)
        .fetch_optional(&mut *tx)
        .await
        .map_err(|e| PdsError::Storage {
            reason: format!("oauth_refresh select: {e}"),
        })?;
        let Some((did, client_id, dpop_jkt, scope, issued_at, family_id)) = row else {
            return Ok(None);
        };
        sqlx::query("DELETE FROM oauth_refresh WHERE jti = ?")
            .bind(old_jti)
            .execute(&mut *tx)
            .await
            .map_err(|e| PdsError::Storage {
                reason: format!("oauth_refresh delete: {e}"),
            })?;
        let now = Utc::now();
        sqlx::query(
            "INSERT INTO oauth_refresh
                (jti, did, client_id, dpop_jkt, scope, issued_at, family_id)
             VALUES (?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(&new_jti)
        .bind(&did)
        .bind(&client_id)
        .bind(&dpop_jkt)
        .bind(&scope)
        .bind(now.to_rfc3339())
        .bind(&family_id)
        .execute(&mut *tx)
        .await
        .map_err(|e| PdsError::Storage {
            reason: format!("oauth_refresh insert (rotate): {e}"),
        })?;
        tx.commit().await.map_err(|e| PdsError::Storage {
            reason: format!("oauth_refresh commit: {e}"),
        })?;
        let original_issued = chrono::DateTime::parse_from_rfc3339(&issued_at)
            .map_err(|e| PdsError::Storage {
                reason: format!("parse issued_at: {e}"),
            })?
            .with_timezone(&Utc);
        Ok(Some(RefreshHandle {
            did,
            client_id,
            dpop_jkt,
            scope,
            issued_at: original_issued,
            family_id,
        }))
    }

    async fn peek_refresh(&self, jti: &str) -> PdsResult<Option<RefreshHandle>> {
        let row: Option<(String, String, String, String, String, String)> = sqlx::query_as(
            "SELECT did, client_id, dpop_jkt, scope, issued_at, family_id
             FROM oauth_refresh WHERE jti = ?",
        )
        .bind(jti)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| PdsError::Storage {
            reason: format!("oauth_refresh peek: {e}"),
        })?;
        let Some((did, client_id, dpop_jkt, scope, issued_at, family_id)) = row else {
            return Ok(None);
        };
        Ok(Some(RefreshHandle {
            did,
            client_id,
            dpop_jkt,
            scope,
            issued_at: chrono::DateTime::parse_from_rfc3339(&issued_at)
                .map_err(|e| PdsError::Storage {
                    reason: format!("parse issued_at: {e}"),
                })?
                .with_timezone(&Utc),
            family_id,
        }))
    }

    async fn revoke_refresh_family(&self, family_id: &str) -> PdsResult<u64> {
        let result = sqlx::query("DELETE FROM oauth_refresh WHERE family_id = ?")
            .bind(family_id)
            .execute(&self.pool)
            .await
            .map_err(|e| PdsError::Storage {
                reason: format!("oauth_refresh family delete: {e}"),
            })?;
        Ok(result.rows_affected())
    }

    async fn revoke_refresh(&self, jti: &str) -> PdsResult<bool> {
        let result = sqlx::query("DELETE FROM oauth_refresh WHERE jti = ?")
            .bind(jti)
            .execute(&self.pool)
            .await
            .map_err(|e| PdsError::Storage {
                reason: format!("oauth_refresh delete: {e}"),
            })?;
        Ok(result.rows_affected() > 0)
    }

    async fn par_count(&self) -> PdsResult<usize> {
        let (n,): (i64,) = sqlx::query_as("SELECT COUNT(*) FROM oauth_par")
            .fetch_one(&self.pool)
            .await
            .map_err(|e| PdsError::Storage {
                reason: format!("oauth_par count: {e}"),
            })?;
        Ok(n as usize)
    }

    async fn code_count(&self) -> PdsResult<usize> {
        let (n,): (i64,) = sqlx::query_as("SELECT COUNT(*) FROM oauth_code")
            .fetch_one(&self.pool)
            .await
            .map_err(|e| PdsError::Storage {
                reason: format!("oauth_code count: {e}"),
            })?;
        Ok(n as usize)
    }

    async fn refresh_count(&self) -> PdsResult<usize> {
        let (n,): (i64,) = sqlx::query_as("SELECT COUNT(*) FROM oauth_refresh")
            .fetch_one(&self.pool)
            .await
            .map_err(|e| PdsError::Storage {
                reason: format!("oauth_refresh count: {e}"),
            })?;
        Ok(n as usize)
    }

    /// Best-effort cleanup of expired PAR and auth-code rows. Refresh tokens
    /// don't carry an expiry — they live until revoked or rotated.
    async fn gc(&self) -> PdsResult<()> {
        let now = Utc::now().to_rfc3339();
        sqlx::query("DELETE FROM oauth_par WHERE expires_at <= ?")
            .bind(&now)
            .execute(&self.pool)
            .await
            .map_err(|e| PdsError::Storage {
                reason: format!("oauth_par gc: {e}"),
            })?;
        sqlx::query("DELETE FROM oauth_code WHERE expires_at <= ?")
            .bind(&now)
            .execute(&self.pool)
            .await
            .map_err(|e| PdsError::Storage {
                reason: format!("oauth_code gc: {e}"),
            })?;
        Ok(())
    }
}

#[allow(dead_code)] // Re-export convenience for downstream consumers.
const TICK: Duration = Duration::from_secs(1);

#[cfg(test)]
mod tests {
    use super::*;

    fn req() -> OAuthRequest {
        OAuthRequest {
            client_id: "https://app.example/client-metadata.json".to_string(),
            redirect_uri: "https://app.example/cb".to_string(),
            scope: "atproto transition:generic".to_string(),
            state: "abc".to_string(),
            code_challenge: "xyz".to_string(),
            code_challenge_method: "S256".to_string(),
            dpop_jkt: None,
            login_hint: None,
            created_at: Utc::now(),
        }
    }

    async fn sql_backend() -> OAuthState {
        let dir = AccountDirectory::open_memory().await.unwrap();
        OAuthState::sql(dir.pool().clone())
    }

    use crate::account::AccountDirectory;

    #[tokio::test]
    async fn par_round_trip_memory() {
        let state = OAuthState::memory();
        state.store_par("uri1".to_string(), req()).await.unwrap();
        assert_eq!(state.par_count().await.unwrap(), 1);
        assert!(state.take_par("uri1").await.unwrap().is_some());
        assert_eq!(state.par_count().await.unwrap(), 0);
    }

    #[tokio::test]
    async fn par_round_trip_sql() {
        let state = sql_backend().await;
        state.store_par("uri1".to_string(), req()).await.unwrap();
        assert_eq!(state.par_count().await.unwrap(), 1);
        assert!(state.take_par("uri1").await.unwrap().is_some());
        assert_eq!(state.par_count().await.unwrap(), 0);
    }

    #[tokio::test]
    async fn par_expired_returns_none() {
        let state = OAuthState::memory();
        let mut r = req();
        r.created_at = Utc::now() - chrono::Duration::seconds(120);
        state.store_par("uri1".to_string(), r).await.unwrap();
        assert!(state.take_par("uri1").await.unwrap().is_none());
    }

    #[tokio::test]
    async fn par_expired_returns_none_sql() {
        let state = sql_backend().await;
        let mut r = req();
        r.created_at = Utc::now() - chrono::Duration::seconds(120);
        state.store_par("uri1".to_string(), r).await.unwrap();
        assert!(state.take_par("uri1").await.unwrap().is_none());
    }

    #[tokio::test]
    async fn auth_code_round_trip_memory() {
        let state = OAuthState::memory();
        state
            .issue_code("code-1".to_string(), "did:plc:alice".to_string(), req())
            .await
            .unwrap();
        let consumed = state.take_code("code-1").await.unwrap().unwrap();
        assert_eq!(consumed.did, "did:plc:alice");
        assert!(state.take_code("code-1").await.unwrap().is_none());
    }

    #[tokio::test]
    async fn auth_code_round_trip_sql() {
        let state = sql_backend().await;
        state
            .issue_code("code-1".to_string(), "did:plc:alice".to_string(), req())
            .await
            .unwrap();
        let consumed = state.take_code("code-1").await.unwrap().unwrap();
        assert_eq!(consumed.did, "did:plc:alice");
        assert!(state.take_code("code-1").await.unwrap().is_none());
    }

    fn handle() -> RefreshHandle {
        RefreshHandle {
            family_id: "test-family".to_string(),
            did: "did:plc:alice".to_string(),
            client_id: "client".to_string(),
            dpop_jkt: "thumb".to_string(),
            scope: "atproto".to_string(),
            issued_at: Utc::now(),
        }
    }

    #[tokio::test]
    async fn refresh_rotation_replaces_jti_memory() {
        let state = OAuthState::memory();
        state
            .register_refresh("jti-1".to_string(), handle())
            .await
            .unwrap();
        let consumed = state
            .rotate_refresh("jti-1", "jti-2".to_string())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(consumed.did, "did:plc:alice");
        assert!(
            state
                .rotate_refresh("jti-1", "jti-3".to_string())
                .await
                .unwrap()
                .is_none()
        );
        assert_eq!(state.refresh_count().await.unwrap(), 1);
    }

    #[tokio::test]
    async fn refresh_rotation_replaces_jti_sql() {
        let state = sql_backend().await;
        state
            .register_refresh("jti-1".to_string(), handle())
            .await
            .unwrap();
        let consumed = state
            .rotate_refresh("jti-1", "jti-2".to_string())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(consumed.did, "did:plc:alice");
        assert!(
            state
                .rotate_refresh("jti-1", "jti-3".to_string())
                .await
                .unwrap()
                .is_none()
        );
        assert_eq!(state.refresh_count().await.unwrap(), 1);
    }

    #[tokio::test]
    async fn refresh_revoke_memory() {
        let state = OAuthState::memory();
        state
            .register_refresh("jti-1".to_string(), handle())
            .await
            .unwrap();
        assert!(state.revoke_refresh("jti-1").await.unwrap());
        assert!(!state.revoke_refresh("jti-1").await.unwrap());
    }

    #[tokio::test]
    async fn refresh_revoke_sql() {
        let state = sql_backend().await;
        state
            .register_refresh("jti-1".to_string(), handle())
            .await
            .unwrap();
        assert!(state.revoke_refresh("jti-1").await.unwrap());
        assert!(!state.revoke_refresh("jti-1").await.unwrap());
    }
}
