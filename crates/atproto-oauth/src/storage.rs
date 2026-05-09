//! OAuth request storage abstraction.
//!
//! Storage trait for OAuth request CRUD operations supporting multiple
//! backends with state tracking and expiration handling.

use anyhow::Result;

use crate::workflow::OAuthRequest;

/// Trait for implementing OAuth request CRUD operations across different storage backends.
///
/// This trait provides an abstraction layer for storing and retrieving OAuth authorization request
/// state, allowing different implementations for various storage systems such as databases, file systems,
/// in-memory stores, or cloud storage services.
///
/// All methods return `anyhow::Result` to allow implementations to use their own error types
/// while providing a consistent interface for callers. Implementations should handle their
/// specific error conditions and convert them to appropriate error messages.
///
/// ## Thread Safety
///
/// This trait requires implementations to be thread-safe (`Send + Sync`), meaning:
/// - `Send`: The storage implementation can be moved between threads
/// - `Sync`: The storage implementation can be safely accessed from multiple threads simultaneously
///
/// This is essential for async applications where the storage might be accessed from different
/// async tasks running on different threads. Implementations should use appropriate
/// synchronization primitives (like `Arc<Mutex<>>`, `RwLock`, or database connection pools)
/// to ensure thread safety.
///
/// ## OAuth Request Lifecycle
///
/// OAuth requests have a natural lifecycle with expiration times. Implementations should:
/// - Store requests with their creation and expiration timestamps
/// - Support efficient lookup by OAuth state parameter
/// - Provide cleanup mechanisms for expired requests
/// - Handle concurrent access safely
///
/// ## Usage
///
/// Implementors of this trait can provide storage for OAuth requests in any backend:
///
/// ```rust,ignore
/// use atproto_oauth::storage::OAuthRequestStorage;
/// use atproto_oauth::workflow::OAuthRequest;
/// use anyhow::Result;
/// use std::sync::Arc;
/// use tokio::sync::RwLock;
/// use std::collections::HashMap;
/// use chrono::{DateTime, Utc};
///
/// // Thread-safe in-memory storage using Arc<RwLock<>>
/// #[derive(Clone)]
/// struct InMemoryOAuthStorage {
///     requests: Arc<RwLock<HashMap<String, OAuthRequest>>>, // state -> request mapping
/// }
///
/// #[async_trait::async_trait]
/// impl OAuthRequestStorage for InMemoryOAuthStorage {
///     async fn get_oauth_request_by_state(&self, state: &str) -> Result<Option<OAuthRequest>> {
///         let requests = self.requests.read().await;
///         Ok(requests.get(state).cloned())
///     }
///
///     async fn insert_oauth_request(&self, request: OAuthRequest) -> Result<()> {
///         let mut requests = self.requests.write().await;
///         requests.insert(request.oauth_state.clone(), request);
///         Ok(())
///     }
///
///     async fn delete_oauth_request_by_state(&self, state: &str) -> Result<()> {
///         let mut requests = self.requests.write().await;
///         requests.remove(state);
///         Ok(())
///     }
///
///     async fn clear_expired_oauth_requests(&self) -> Result<u64> {
///         let mut requests = self.requests.write().await;
///         let now = Utc::now();
///         let initial_count = requests.len();
///
///         requests.retain(|_, req| req.expires_at > now);
///         let final_count = requests.len();
///
///         Ok((initial_count - final_count) as u64)
///     }
/// }
///
/// // Database storage with thread-safe connection pool
/// struct DatabaseOAuthStorage {
///     pool: sqlx::Pool<sqlx::Postgres>, // Thread-safe connection pool
/// }
///
/// #[async_trait::async_trait]
/// impl OAuthRequestStorage for DatabaseOAuthStorage {
///     async fn get_oauth_request_by_state(&self, state: &str) -> Result<Option<OAuthRequest>> {
///         let row: Option<_> = sqlx::query_as!(
///             OAuthRequestRow,
///             "SELECT oauth_state, issuer, did, nonce, pkce_verifier, signing_public_key,
///              dpop_private_key, created_at, expires_at
///              FROM oauth_requests WHERE oauth_state = $1 AND expires_at > NOW()"
///         )
///         .bind(state)
///         .fetch_optional(&self.pool)
///         .await?;
///
///         Ok(row.map(|r| r.into_oauth_request()))
///     }
///
///     async fn insert_oauth_request(&self, request: OAuthRequest) -> Result<()> {
///         sqlx::query!(
///             "INSERT INTO oauth_requests
///              (oauth_state, issuer, authorization_server, nonce, pkce_verifier, signing_public_key,
///               dpop_private_key, created_at, expires_at)
///              VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)",
///             request.oauth_state,
///             request.issuer,
///             request.authorization_server,
///             request.nonce,
///             request.pkce_verifier,
///             request.signing_public_key,
///             request.dpop_private_key,
///             request.created_at,
///             request.expires_at
///         )
///         .execute(&self.pool)
///         .await?;
///         Ok(())
///     }
///
///     async fn delete_oauth_request_by_state(&self, state: &str) -> Result<()> {
///         sqlx::query!("DELETE FROM oauth_requests WHERE oauth_state = $1", state)
///             .execute(&self.pool)
///             .await?;
///         Ok(())
///     }
///
///     async fn clear_expired_oauth_requests(&self) -> Result<u64> {
///         let result = sqlx::query!("DELETE FROM oauth_requests WHERE expires_at <= NOW()")
///             .execute(&self.pool)
///             .await?;
///         Ok(result.rows_affected())
///     }
/// }
/// ```
#[async_trait::async_trait]
pub trait OAuthRequestStorage: Send + Sync {
    /// Retrieves an OAuth request by its state parameter.
    ///
    /// This method looks up an OAuth authorization request using the state parameter,
    /// which is a unique identifier for each OAuth flow used to prevent CSRF attacks.
    /// The state parameter is generated during the initial authorization request and
    /// used to correlate the callback with the original request.
    ///
    /// Implementations should:
    /// - Return only non-expired requests (check `expires_at` against current time)
    /// - Handle the case where the state doesn't exist gracefully (return `None`)
    /// - Ensure thread-safe access to the underlying storage
    ///
    /// # Arguments
    /// * `state` - The OAuth state parameter to look up. This is a randomly generated
    ///            string that uniquely identifies the OAuth authorization request.
    ///
    /// # Returns
    /// * `Ok(Some(request))` - If a valid, non-expired OAuth request is found
    /// * `Ok(None)` - If no request exists for the given state or if the request has expired
    /// * `Err(error)` - If an error occurs during retrieval (storage failure, etc.)
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// let storage = MyOAuthStorage::new();
    /// let request = storage.get_oauth_request_by_state("unique-state-value").await?;
    /// match request {
    ///     Some(req) => {
    ///         println!("Found OAuth request for issuer: {}", req.issuer);
    ///         // Continue with OAuth flow
    ///     },
    ///     None => {
    ///         println!("No valid OAuth request found for this state");
    ///         // Handle invalid/expired state
    ///     }
    /// }
    /// ```
    async fn get_oauth_request_by_state(&self, state: &str) -> Result<Option<OAuthRequest>>;

    /// Deletes an OAuth request by its state parameter.
    ///
    /// This method removes an OAuth authorization request from storage using its state parameter.
    /// This is typically called after the OAuth flow completes successfully or when cleaning up
    /// failed/abandoned flows.
    ///
    /// Implementations should:
    /// - Handle the case where the state doesn't exist gracefully (return `Ok(())`)
    /// - Ensure the deletion is atomic
    /// - Clean up any related data or indexes
    /// - Be thread-safe for concurrent access
    ///
    /// # Arguments
    /// * `state` - The OAuth state parameter identifying the request to delete.
    ///
    /// # Returns
    /// * `Ok(())` - If the OAuth request was successfully deleted or didn't exist
    /// * `Err(error)` - If an error occurs during deletion (storage failure, etc.)
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// let storage = MyOAuthStorage::new();
    /// // After successful OAuth completion
    /// storage.delete_oauth_request_by_state("completed-state-value").await?;
    /// println!("OAuth request cleaned up successfully");
    /// ```
    async fn delete_oauth_request_by_state(&self, state: &str) -> Result<()>;

    /// Inserts a new OAuth request into storage.
    ///
    /// This method stores a new OAuth authorization request, typically called at the beginning
    /// of an OAuth flow when the authorization request is initiated. The request contains all
    /// the necessary state information to complete the OAuth flow.
    ///
    /// Implementations should:
    /// - Store all fields of the `OAuthRequest` struct
    /// - Handle duplicate state parameters appropriately (either reject or replace)
    /// - Ensure the insertion is atomic
    /// - Maintain indexes for efficient lookups by state
    /// - Be thread-safe for concurrent insertions
    ///
    /// # Arguments
    /// * `request` - The complete OAuth request to store, including state, timing,
    ///              cryptographic keys, and user information.
    ///
    /// # Returns
    /// * `Ok(())` - If the OAuth request was successfully stored
    /// * `Err(error)` - If an error occurs during insertion (storage failure,
    ///                 constraint violation, etc.)
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// use chrono::{Utc, Duration};
    ///
    /// let storage = MyOAuthStorage::new();
    /// let request = OAuthRequest {
    ///     oauth_state: "unique-random-state".to_string(),
    ///     issuer: "https://pds.example.com".to_string(),
    ///     did: "did:plc:example123".to_string(),
    ///     nonce: "random-nonce".to_string(),
    ///     pkce_verifier: "code-verifier".to_string(),
    ///     signing_public_key: "public-key-data".to_string(),
    ///     dpop_private_key: "private-key-data".to_string(),
    ///     created_at: Utc::now(),
    ///     expires_at: Utc::now() + Duration::minutes(10),
    /// };
    ///
    /// storage.insert_oauth_request(request).await?;
    /// println!("OAuth request stored successfully");
    /// ```
    async fn insert_oauth_request(&self, request: OAuthRequest) -> Result<()>;

    /// Clears all expired OAuth requests from storage.
    ///
    /// This method performs cleanup by removing OAuth requests that have passed their
    /// expiration time. This is important for:
    /// - Preventing storage bloat from abandoned OAuth flows
    /// - Maintaining security by ensuring expired flows cannot be resumed
    /// - Optimizing storage performance by removing stale data
    ///
    /// Implementations should:
    /// - Compare `expires_at` against the current time (`Utc::now()`)
    /// - Remove all requests where `expires_at <= current_time`
    /// - Return the count of removed requests for monitoring/logging
    /// - Be efficient for large datasets (use bulk operations when possible)
    /// - Be thread-safe and handle concurrent access appropriately
    ///
    /// This method is typically called:
    /// - Periodically by a background cleanup task
    /// - Before inserting new requests to maintain storage hygiene
    /// - During application startup to clean stale data
    ///
    /// # Returns
    /// * `Ok(count)` - The number of expired requests that were successfully removed
    /// * `Err(error)` - If an error occurs during cleanup (storage failure, etc.)
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// let storage = MyOAuthStorage::new();
    ///
    /// // Periodic cleanup
    /// let removed_count = storage.clear_expired_oauth_requests().await?;
    /// println!("Cleaned up {} expired OAuth requests", removed_count);
    ///
    /// // In a background task
    /// tokio::spawn(async move {
    ///     let mut interval = tokio::time::interval(Duration::from_secs(300)); // 5 minutes
    ///     loop {
    ///         interval.tick().await;
    ///         if let Err(e) = storage.clear_expired_oauth_requests().await {
    ///             eprintln!("Error during OAuth cleanup: {}", e);
    ///         }
    ///     }
    /// });
    /// ```
    async fn clear_expired_oauth_requests(&self) -> Result<u64>;
}
