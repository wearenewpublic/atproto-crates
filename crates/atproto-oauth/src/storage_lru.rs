//! LRU cache implementation for OAuth request storage.
//!
//! Thread-safe in-memory storage with automatic eviction of least recently used
//! OAuth requests when capacity is reached.

use std::num::NonZeroUsize;
use std::sync::{Arc, Mutex};

use anyhow::Result;
use chrono::Utc;
use lru::LruCache;

use crate::errors::OAuthStorageError;
use crate::storage::OAuthRequestStorage;
use crate::workflow::OAuthRequest;

/// An LRU-based implementation of `OAuthRequestStorage` that maintains a fixed-size cache of OAuth requests.
///
/// This storage implementation uses an LRU (Least Recently Used) cache to store OAuth requests
/// in memory with automatic eviction of the least recently accessed entries when the cache reaches
/// its capacity. This is ideal for scenarios where you want to cache frequently accessed OAuth requests
/// while keeping memory usage bounded.
///
/// ## Thread Safety
///
/// This implementation is thread-safe through the use of `Arc<Mutex<LruCache<String, OAuthRequest>>>`.
/// All operations are protected by a mutex, ensuring safe concurrent access from multiple threads
/// or async tasks.
///
/// ## Cache Behavior
///
/// - **Get operations**: Move accessed entries to the front of the LRU order
/// - **Insert operations**: Add new entries at the front, evicting the least recently used if at capacity
/// - **Delete operations**: Remove entries from the cache entirely
/// - **Capacity management**: Automatically evicts least recently used entries when capacity is exceeded
/// - **Expiration handling**: Returns only non-expired OAuth requests based on `expires_at` timestamp
///
/// ## Use Cases
///
/// This implementation is particularly suitable for:
/// - Caching OAuth authorization requests during the OAuth flow
/// - Scenarios with bounded memory requirements for OAuth state management
/// - Applications where some OAuth request lookup misses are acceptable
/// - High-performance applications requiring fast in-memory OAuth state access
/// - Stateless OAuth servers that need temporary request storage
///
/// ## Limitations
///
/// - **Persistence**: Data is lost when the application restarts
/// - **Capacity**: Limited to the configured cache size
/// - **Cache misses**: Older entries may be evicted and need OAuth flow restart
/// - **Memory usage**: All cached OAuth data is kept in memory
/// - **Request size**: OAuth requests with large key data consume more memory per entry
///
/// ## Examples
///
/// ```rust
/// use atproto_oauth::storage_lru::LruOAuthRequestStorage;
/// use atproto_oauth::storage::OAuthRequestStorage;
/// use atproto_oauth::workflow::OAuthRequest;
/// use std::num::NonZeroUsize;
/// use chrono::{Utc, Duration};
///
/// # tokio::runtime::Runtime::new().unwrap().block_on(async {
/// // Create an LRU cache with capacity for 1000 OAuth requests
/// let storage = LruOAuthRequestStorage::new(NonZeroUsize::new(1000).unwrap());
///
/// // Create a sample OAuth request
/// let request = OAuthRequest {
///     oauth_state: "unique-state-123".to_string(),
///     subject: "did:plc:example123".to_string(),
///     issuer: "https://pds.example.com".to_string(),
///     authorization_server: "https://pds.example.com".to_string(),
///     nonce: "secure-nonce".to_string(),
///     pkce_verifier: "code-verifier".to_string(),
///     signing_public_key: "public-key-data".to_string(),
///     dpop_private_key: "private-key-data".to_string(),
///     created_at: Utc::now(),
///     expires_at: Utc::now() + Duration::minutes(10),
/// };
///
/// // Store the OAuth request
/// storage.insert_oauth_request(request.clone()).await?;
///
/// // Retrieve the OAuth request
/// let retrieved = storage.get_oauth_request_by_state("unique-state-123").await?;
/// assert_eq!(retrieved.as_ref().map(|r| &r.oauth_state), Some(&request.oauth_state));
///
/// // Delete the OAuth request
/// storage.delete_oauth_request_by_state("unique-state-123").await?;
/// let retrieved = storage.get_oauth_request_by_state("unique-state-123").await?;
/// assert_eq!(retrieved, None);
/// # Ok::<(), anyhow::Error>(())
/// # }).unwrap();
/// ```
///
/// ## Capacity Planning
///
/// When choosing the cache capacity, consider:
/// - **Expected concurrent OAuth flows**: Size cache to hold active OAuth requests
/// - **Memory constraints**: Each entry uses approximately (request size + state length + overhead) bytes
/// - **OAuth request complexity**: Requests with large key data use more memory
/// - **Access patterns**: Higher capacity reduces cache misses for concurrent OAuth flows
/// - **Performance requirements**: Larger caches may have slightly higher lookup times
///
/// ```rust
/// use atproto_oauth::storage_lru::LruOAuthRequestStorage;
/// use std::num::NonZeroUsize;
///
/// // Small cache for testing or low-traffic scenarios
/// let small_cache = LruOAuthRequestStorage::new(NonZeroUsize::new(100).unwrap());
///
/// // Medium cache for typical applications
/// let medium_cache = LruOAuthRequestStorage::new(NonZeroUsize::new(10_000).unwrap());
///
/// // Large cache for high-traffic OAuth services
/// let large_cache = LruOAuthRequestStorage::new(NonZeroUsize::new(100_000).unwrap());
/// ```
#[derive(Clone)]
pub struct LruOAuthRequestStorage {
    /// The LRU cache storing state -> OAuthRequest mappings, protected by a mutex for thread safety.
    ///
    /// We use the OAuth state parameter as the key since the primary operation is looking up
    /// requests by state during OAuth callback processing. The cache is wrapped in Arc<Mutex<>>
    /// to ensure thread-safe access across multiple async tasks and threads.
    cache: Arc<Mutex<LruCache<String, OAuthRequest>>>,
}

impl LruOAuthRequestStorage {
    /// Creates a new `LruOAuthRequestStorage` with the specified capacity.
    ///
    /// The capacity determines the maximum number of OAuth requests that can be stored
    /// in the cache. When the cache reaches this capacity, the least recently used
    /// entries will be automatically evicted to make room for new entries.
    ///
    /// # Arguments
    /// * `capacity` - The maximum number of OAuth requests to store. Must be greater than 0.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use atproto_oauth::storage_lru::LruOAuthRequestStorage;
    /// use std::num::NonZeroUsize;
    ///
    /// // Create a cache that can hold up to 5000 OAuth requests
    /// let storage = LruOAuthRequestStorage::new(NonZeroUsize::new(5000).unwrap());
    /// ```
    ///
    /// # Performance Considerations
    ///
    /// - Larger capacities provide better cache hit rates but use more memory
    /// - The underlying LRU implementation has O(1) access time for all operations
    /// - Memory usage is approximately: capacity * (average_request_size + state_size + overhead)
    /// - OAuth request size varies based on key data and metadata
    pub fn new(capacity: NonZeroUsize) -> Self {
        Self {
            cache: Arc::new(Mutex::new(LruCache::new(capacity))),
        }
    }

    /// Returns the current number of entries in the cache.
    ///
    /// This method provides visibility into cache usage for monitoring and debugging purposes.
    /// The count represents the current number of OAuth requests stored in the cache.
    ///
    /// # Returns
    /// The number of entries currently stored in the cache.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use atproto_oauth::storage_lru::LruOAuthRequestStorage;
    /// use atproto_oauth::storage::OAuthRequestStorage;
    /// use atproto_oauth::workflow::OAuthRequest;
    /// use std::num::NonZeroUsize;
    /// use chrono::{Utc, Duration};
    ///
    /// # tokio::runtime::Runtime::new().unwrap().block_on(async {
    /// let storage = LruOAuthRequestStorage::new(NonZeroUsize::new(100).unwrap());
    /// assert_eq!(storage.len(), 0);
    ///
    /// let request = OAuthRequest {
    ///     oauth_state: "state1".to_string(),
    ///     subject: "did:plc:example123".to_string(),
    ///     issuer: "https://pds.example.com".to_string(),
    ///     authorization_server: "https://pds.example.com".to_string(),
    ///     nonce: "nonce1".to_string(),
    ///     pkce_verifier: "verifier1".to_string(),
    ///     signing_public_key: "pubkey1".to_string(),
    ///     dpop_private_key: "privkey1".to_string(),
    ///     created_at: Utc::now(),
    ///     expires_at: Utc::now() + Duration::minutes(10),
    /// };
    /// storage.insert_oauth_request(request).await?;
    /// assert_eq!(storage.len(), 1);
    /// # Ok::<(), anyhow::Error>(())
    /// # }).unwrap();
    /// ```
    pub fn len(&self) -> usize {
        self.cache.lock().unwrap().len()
    }

    /// Returns whether the cache is empty.
    ///
    /// # Returns
    /// `true` if the cache contains no entries, `false` otherwise.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use atproto_oauth::storage_lru::LruOAuthRequestStorage;
    /// use std::num::NonZeroUsize;
    ///
    /// let storage = LruOAuthRequestStorage::new(NonZeroUsize::new(100).unwrap());
    /// assert!(storage.is_empty());
    /// ```
    pub fn is_empty(&self) -> bool {
        self.cache.lock().unwrap().is_empty()
    }

    /// Returns the maximum capacity of the cache.
    ///
    /// This returns the capacity that was set when the cache was created and represents
    /// the maximum number of OAuth requests that can be stored before eviction occurs.
    ///
    /// # Returns
    /// The maximum capacity of the cache.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use atproto_oauth::storage_lru::LruOAuthRequestStorage;
    /// use std::num::NonZeroUsize;
    ///
    /// let capacity = NonZeroUsize::new(500).unwrap();
    /// let storage = LruOAuthRequestStorage::new(capacity);
    /// assert_eq!(storage.capacity().get(), 500);
    /// ```
    pub fn capacity(&self) -> NonZeroUsize {
        self.cache.lock().unwrap().cap()
    }

    /// Clears all entries from the cache.
    ///
    /// This method removes all OAuth requests from the cache, effectively resetting
    /// it to an empty state. This can be useful for testing or when you need to
    /// invalidate all cached OAuth data.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use atproto_oauth::storage_lru::LruOAuthRequestStorage;
    /// use atproto_oauth::storage::OAuthRequestStorage;
    /// use atproto_oauth::workflow::OAuthRequest;
    /// use std::num::NonZeroUsize;
    /// use chrono::{Utc, Duration};
    ///
    /// # tokio::runtime::Runtime::new().unwrap().block_on(async {
    /// let storage = LruOAuthRequestStorage::new(NonZeroUsize::new(100).unwrap());
    /// let request = OAuthRequest {
    ///     oauth_state: "test-state".to_string(),
    ///     subject: "did:plc:example123".to_string(),
    ///     issuer: "https://pds.example.com".to_string(),
    ///     authorization_server: "https://pds.example.com".to_string(),
    ///     nonce: "test-nonce".to_string(),
    ///     pkce_verifier: "test-verifier".to_string(),
    ///     signing_public_key: "test-pubkey".to_string(),
    ///     dpop_private_key: "test-privkey".to_string(),
    ///     created_at: Utc::now(),
    ///     expires_at: Utc::now() + Duration::minutes(10),
    /// };
    /// storage.insert_oauth_request(request).await?;
    /// assert_eq!(storage.len(), 1);
    ///
    /// storage.clear();
    /// assert_eq!(storage.len(), 0);
    /// assert!(storage.is_empty());
    /// # Ok::<(), anyhow::Error>(())
    /// # }).unwrap();
    /// ```
    pub fn clear(&self) {
        self.cache.lock().unwrap().clear();
    }
}

#[async_trait::async_trait]
impl OAuthRequestStorage for LruOAuthRequestStorage {
    /// Retrieves an OAuth request by its state parameter from the LRU cache.
    ///
    /// This method looks up an OAuth authorization request using the state parameter
    /// that is currently cached. If the state is found in the cache, the entry is moved
    /// to the front of the LRU order (marking it as recently used) and the request is returned.
    ///
    /// Expired requests (where `expires_at < current_time`) are automatically filtered out
    /// and not returned, ensuring only valid OAuth requests are accessible.
    ///
    /// # Arguments
    /// * `state` - The OAuth state parameter to look up in the cache
    ///
    /// # Returns
    /// * `Ok(Some(request))` - If the state is found in the cache and not expired
    /// * `Ok(None)` - If the state is not found in the cache or the request has expired
    /// * `Err(error)` - If an error occurs (primarily mutex poisoning, which is very rare)
    ///
    /// # Cache Behavior
    ///
    /// When a request is successfully retrieved, it's marked as recently used in the LRU order,
    /// making it less likely to be evicted in future operations. Expired requests are treated
    /// as cache misses.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use atproto_oauth::storage_lru::LruOAuthRequestStorage;
    /// use atproto_oauth::storage::OAuthRequestStorage;
    /// use atproto_oauth::workflow::OAuthRequest;
    /// use std::num::NonZeroUsize;
    /// use chrono::{Utc, Duration};
    ///
    /// # tokio::runtime::Runtime::new().unwrap().block_on(async {
    /// let storage = LruOAuthRequestStorage::new(NonZeroUsize::new(100).unwrap());
    ///
    /// // Cache miss - state not in cache
    /// let request = storage.get_oauth_request_by_state("unknown-state").await?;
    /// assert_eq!(request, None);
    ///
    /// // Add request to cache
    /// let oauth_req = OAuthRequest {
    ///     oauth_state: "valid-state-123".to_string(),
    ///     subject: "did:plc:example123".to_string(),
    ///     issuer: "https://pds.example.com".to_string(),
    ///     authorization_server: "https://pds.example.com".to_string(),
    ///     nonce: "secure-nonce".to_string(),
    ///     pkce_verifier: "code-verifier".to_string(),
    ///     signing_public_key: "public-key-data".to_string(),
    ///     dpop_private_key: "private-key-data".to_string(),
    ///     created_at: Utc::now(),
    ///     expires_at: Utc::now() + Duration::minutes(10),
    /// };
    /// storage.insert_oauth_request(oauth_req.clone()).await?;
    ///
    /// // Cache hit - state found in cache
    /// let request = storage.get_oauth_request_by_state("valid-state-123").await?;
    /// assert_eq!(request.as_ref().map(|r| &r.oauth_state), Some(&oauth_req.oauth_state));
    /// # Ok::<(), anyhow::Error>(())
    /// # }).unwrap();
    /// ```
    async fn get_oauth_request_by_state(&self, state: &str) -> Result<Option<OAuthRequest>> {
        let mut cache = self
            .cache
            .lock()
            .map_err(|e| OAuthStorageError::CacheLockFailedGet {
                details: e.to_string(),
            })?;

        if let Some(request) = cache.get(state) {
            // Check if the request has expired
            let now = Utc::now();
            if request.expires_at > now {
                Ok(Some(request.clone()))
            } else {
                // Request has expired, remove it from cache and return None
                cache.pop(state);
                Ok(None)
            }
        } else {
            Ok(None)
        }
    }

    /// Deletes an OAuth request from the LRU cache by its state parameter.
    ///
    /// This method removes an OAuth authorization request from the cache using its state parameter.
    /// If the state exists in the cache, it is removed entirely, freeing up space for new entries.
    ///
    /// # Arguments
    /// * `state` - The OAuth state parameter identifying the request to delete
    ///
    /// # Returns
    /// * `Ok(())` - If the OAuth request was successfully deleted or didn't exist
    /// * `Err(error)` - If an error occurs (primarily mutex poisoning, which is very rare)
    ///
    /// # Cache Behavior
    ///
    /// - If the state exists in the cache, it is removed completely
    /// - If the state doesn't exist, the operation succeeds without error
    /// - Removing entries frees up capacity for new entries
    ///
    /// # Examples
    ///
    /// ```rust
    /// use atproto_oauth::storage_lru::LruOAuthRequestStorage;
    /// use atproto_oauth::storage::OAuthRequestStorage;
    /// use atproto_oauth::workflow::OAuthRequest;
    /// use std::num::NonZeroUsize;
    /// use chrono::{Utc, Duration};
    ///
    /// # tokio::runtime::Runtime::new().unwrap().block_on(async {
    /// let storage = LruOAuthRequestStorage::new(NonZeroUsize::new(100).unwrap());
    ///
    /// // Add an OAuth request
    /// let request = OAuthRequest {
    ///     oauth_state: "deletable-state".to_string(),
    ///     subject: "did:plc:example123".to_string(),
    ///     issuer: "https://pds.example.com".to_string(),
    ///     authorization_server: "https://pds.example.com".to_string(),
    ///     nonce: "test-nonce".to_string(),
    ///     pkce_verifier: "test-verifier".to_string(),
    ///     signing_public_key: "test-pubkey".to_string(),
    ///     dpop_private_key: "test-privkey".to_string(),
    ///     created_at: Utc::now(),
    ///     expires_at: Utc::now() + Duration::minutes(10),
    /// };
    /// storage.insert_oauth_request(request).await?;
    /// let retrieved = storage.get_oauth_request_by_state("deletable-state").await?;
    /// assert!(retrieved.is_some());
    ///
    /// // Delete the request
    /// storage.delete_oauth_request_by_state("deletable-state").await?;
    /// let retrieved = storage.get_oauth_request_by_state("deletable-state").await?;
    /// assert_eq!(retrieved, None);
    ///
    /// // Deleting non-existent entry is safe
    /// storage.delete_oauth_request_by_state("non-existent-state").await?;
    /// # Ok::<(), anyhow::Error>(())
    /// # }).unwrap();
    /// ```
    async fn delete_oauth_request_by_state(&self, state: &str) -> Result<()> {
        let mut cache =
            self.cache
                .lock()
                .map_err(|e| OAuthStorageError::CacheLockFailedDelete {
                    details: e.to_string(),
                })?;

        cache.pop(state);
        Ok(())
    }

    /// Inserts a new OAuth request into the LRU cache.
    ///
    /// This method stores an OAuth authorization request in the cache. If a request with the
    /// same state already exists in the cache, it is replaced and the entry is moved to the front
    /// of the LRU order. If the state is new and the cache is at capacity, the least recently
    /// used entry is evicted to make room.
    ///
    /// # Arguments
    /// * `request` - The complete OAuth request to store. The request's `oauth_state` field
    ///              will be used as the storage key.
    ///
    /// # Returns
    /// * `Ok(())` - If the OAuth request was successfully stored
    /// * `Err(error)` - If an error occurs (primarily mutex poisoning, which is very rare)
    ///
    /// # Cache Behavior
    ///
    /// - If the cache is at capacity and this is a new state, the least recently used entry is evicted
    /// - The new or updated entry is placed at the front of the LRU order
    /// - Existing entries with the same state are replaced in place
    ///
    /// # Examples
    ///
    /// ```rust
    /// use atproto_oauth::storage_lru::LruOAuthRequestStorage;
    /// use atproto_oauth::storage::OAuthRequestStorage;
    /// use atproto_oauth::workflow::OAuthRequest;
    /// use std::num::NonZeroUsize;
    /// use chrono::{Utc, Duration};
    ///
    /// # tokio::runtime::Runtime::new().unwrap().block_on(async {
    /// let storage = LruOAuthRequestStorage::new(NonZeroUsize::new(2).unwrap()); // Small cache for demo
    ///
    /// // Add first request
    /// let req1 = OAuthRequest {
    ///     oauth_state: "state1".to_string(),
    ///     subject: "did:plc:example123".to_string(),
    ///     issuer: "https://pds.example.com".to_string(),
    ///     authorization_server: "https://pds.example.com".to_string(),
    ///     nonce: "nonce1".to_string(),
    ///     pkce_verifier: "verifier1".to_string(),
    ///     signing_public_key: "pubkey1".to_string(),
    ///     dpop_private_key: "privkey1".to_string(),
    ///     created_at: Utc::now(),
    ///     expires_at: Utc::now() + Duration::minutes(10),
    /// };
    /// storage.insert_oauth_request(req1).await?;
    /// assert_eq!(storage.len(), 1);
    ///
    /// // Add second request
    /// let req2 = OAuthRequest {
    ///     oauth_state: "state2".to_string(),
    ///     subject: "did:plc:example123".to_string(),
    ///     issuer: "https://pds.example.com".to_string(),
    ///     authorization_server: "https://pds.example.com".to_string(),
    ///     nonce: "nonce2".to_string(),
    ///     pkce_verifier: "verifier2".to_string(),
    ///     signing_public_key: "pubkey2".to_string(),
    ///     dpop_private_key: "privkey2".to_string(),
    ///     created_at: Utc::now(),
    ///     expires_at: Utc::now() + Duration::minutes(10),
    /// };
    /// storage.insert_oauth_request(req2).await?;
    /// assert_eq!(storage.len(), 2);
    ///
    /// // Add third request - this will evict the least recently used entry (state1)
    /// let req3 = OAuthRequest {
    ///     oauth_state: "state3".to_string(),
    ///     subject: "did:plc:example123".to_string(),
    ///     issuer: "https://pds.example.com".to_string(),
    ///     authorization_server: "https://pds.example.com".to_string(),
    ///     nonce: "nonce3".to_string(),
    ///     pkce_verifier: "verifier3".to_string(),
    ///     signing_public_key: "pubkey3".to_string(),
    ///     dpop_private_key: "privkey3".to_string(),
    ///     created_at: Utc::now(),
    ///     expires_at: Utc::now() + Duration::minutes(10),
    /// };
    /// storage.insert_oauth_request(req3).await?;
    /// assert_eq!(storage.len(), 2); // Still at capacity
    ///
    /// // state1 should be evicted
    /// let request = storage.get_oauth_request_by_state("state1").await?;
    /// assert_eq!(request, None);
    ///
    /// // state2 and state3 should still be present
    /// let req2_retrieved = storage.get_oauth_request_by_state("state2").await?;
    /// let req3_retrieved = storage.get_oauth_request_by_state("state3").await?;
    /// assert!(req2_retrieved.is_some());
    /// assert!(req3_retrieved.is_some());
    /// # Ok::<(), anyhow::Error>(())
    /// # }).unwrap();
    /// ```
    async fn insert_oauth_request(&self, request: OAuthRequest) -> Result<()> {
        let mut cache =
            self.cache
                .lock()
                .map_err(|e| OAuthStorageError::CacheLockFailedInsert {
                    details: e.to_string(),
                })?;

        cache.put(request.oauth_state.clone(), request);
        Ok(())
    }

    /// Clears all expired OAuth requests from the LRU cache.
    ///
    /// This method performs cleanup by removing OAuth requests that have passed their
    /// expiration time (`expires_at <= current_time`). This is important for maintaining
    /// security and preventing storage bloat from abandoned OAuth flows.
    ///
    /// # Returns
    /// * `Ok(count)` - The number of expired requests that were successfully removed
    /// * `Err(error)` - If an error occurs (primarily mutex poisoning, which is very rare)
    ///
    /// # Cache Behavior
    ///
    /// - Compares each request's `expires_at` against the current time (`Utc::now()`)
    /// - Removes all requests where `expires_at <= current_time`
    /// - Maintains LRU order for remaining valid requests
    /// - Frees up capacity for new OAuth requests
    ///
    /// # Examples
    ///
    /// ```rust
    /// use atproto_oauth::storage_lru::LruOAuthRequestStorage;
    /// use atproto_oauth::storage::OAuthRequestStorage;
    /// use atproto_oauth::workflow::OAuthRequest;
    /// use std::num::NonZeroUsize;
    /// use chrono::{Utc, Duration};
    ///
    /// # tokio::runtime::Runtime::new().unwrap().block_on(async {
    /// let storage = LruOAuthRequestStorage::new(NonZeroUsize::new(100).unwrap());
    ///
    /// // Add a request that will expire soon
    /// let expired_request = OAuthRequest {
    ///     oauth_state: "soon-expired".to_string(),
    ///     subject: "did:plc:example123".to_string(),
    ///     issuer: "https://pds.example.com".to_string(),
    ///     authorization_server: "https://pds.example.com".to_string(),
    ///     nonce: "nonce1".to_string(),
    ///     pkce_verifier: "verifier1".to_string(),
    ///     signing_public_key: "pubkey1".to_string(),
    ///     dpop_private_key: "privkey1".to_string(),
    ///     created_at: Utc::now() - Duration::minutes(20),
    ///     expires_at: Utc::now() - Duration::minutes(10), // Already expired
    /// };
    /// storage.insert_oauth_request(expired_request).await?;
    ///
    /// // Add a valid request
    /// let valid_request = OAuthRequest {
    ///     oauth_state: "still-valid".to_string(),
    ///     subject: "did:plc:example123".to_string(),
    ///     issuer: "https://pds.example.com".to_string(),
    ///     authorization_server: "https://pds.example.com".to_string(),
    ///     nonce: "nonce2".to_string(),
    ///     pkce_verifier: "verifier2".to_string(),
    ///     signing_public_key: "pubkey2".to_string(),
    ///     dpop_private_key: "privkey2".to_string(),
    ///     created_at: Utc::now(),
    ///     expires_at: Utc::now() + Duration::minutes(10), // Still valid
    /// };
    /// storage.insert_oauth_request(valid_request).await?;
    ///
    /// assert_eq!(storage.len(), 2);
    ///
    /// // Clean up expired requests
    /// let removed_count = storage.clear_expired_oauth_requests().await?;
    /// assert_eq!(removed_count, 1); // One expired request removed
    /// assert_eq!(storage.len(), 1); // One valid request remains
    ///
    /// // Verify the valid request is still accessible
    /// let remaining = storage.get_oauth_request_by_state("still-valid").await?;
    /// assert!(remaining.is_some());
    /// # Ok::<(), anyhow::Error>(())
    /// # }).unwrap();
    /// ```
    async fn clear_expired_oauth_requests(&self) -> Result<u64> {
        let mut cache =
            self.cache
                .lock()
                .map_err(|e| OAuthStorageError::CacheLockFailedCleanup {
                    details: e.to_string(),
                })?;

        let now = Utc::now();

        // Collect keys of expired requests
        let expired_keys: Vec<String> = cache
            .iter()
            .filter_map(|(key, request)| {
                if request.expires_at <= now {
                    Some(key.clone())
                } else {
                    None
                }
            })
            .collect();

        // Remove expired requests
        for key in &expired_keys {
            cache.pop(key);
        }

        Ok(expired_keys.len() as u64)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{Duration, Utc};
    use std::num::NonZeroUsize;

    fn create_test_oauth_request(state: &str, issuer: &str, did: &str) -> OAuthRequest {
        OAuthRequest {
            oauth_state: state.to_string(),
            subject: did.to_string(),
            issuer: issuer.to_string(),
            authorization_server: issuer.to_string(),
            nonce: format!("nonce-{}", state),
            pkce_verifier: format!("verifier-{}", state),
            signing_public_key: format!("pubkey-{}", state),
            dpop_private_key: format!("privkey-{}", state),
            created_at: Utc::now(),
            expires_at: Utc::now() + Duration::minutes(10),
        }
    }

    fn create_expired_oauth_request(state: &str, issuer: &str, did: &str) -> OAuthRequest {
        OAuthRequest {
            oauth_state: state.to_string(),
            subject: did.to_string(),
            issuer: issuer.to_string(),
            authorization_server: issuer.to_string(),
            nonce: format!("nonce-{}", state),
            pkce_verifier: format!("verifier-{}", state),
            signing_public_key: format!("pubkey-{}", state),
            dpop_private_key: format!("privkey-{}", state),
            created_at: Utc::now() - Duration::minutes(20),
            expires_at: Utc::now() - Duration::minutes(10), // Already expired
        }
    }

    #[tokio::test]
    async fn test_new_storage() {
        let storage = LruOAuthRequestStorage::new(NonZeroUsize::new(100).unwrap());
        assert_eq!(storage.len(), 0);
        assert!(storage.is_empty());
        assert_eq!(storage.capacity().get(), 100);
    }

    #[tokio::test]
    async fn test_basic_operations() -> Result<()> {
        let storage = LruOAuthRequestStorage::new(NonZeroUsize::new(10).unwrap());

        // Test get on empty cache
        let result = storage.get_oauth_request_by_state("unknown-state").await?;
        assert_eq!(result, None);

        // Test insert and get
        let request =
            create_test_oauth_request("test-state", "https://pds.example.com", "did:plc:test");
        storage.insert_oauth_request(request.clone()).await?;
        let result = storage.get_oauth_request_by_state("test-state").await?;
        assert!(result.is_some());
        assert_eq!(result.as_ref().unwrap().oauth_state, request.oauth_state);
        assert_eq!(storage.len(), 1);

        // Test update existing
        let updated_request = create_test_oauth_request(
            "test-state",
            "https://updated.example.com",
            "did:plc:updated",
        );
        storage
            .insert_oauth_request(updated_request.clone())
            .await?;
        let result = storage.get_oauth_request_by_state("test-state").await?;
        assert!(result.is_some());
        assert_eq!(result.as_ref().unwrap().issuer, updated_request.issuer);
        assert_eq!(storage.len(), 1); // Should still be 1

        // Test delete
        storage.delete_oauth_request_by_state("test-state").await?;
        let result = storage.get_oauth_request_by_state("test-state").await?;
        assert_eq!(result, None);
        assert_eq!(storage.len(), 0);

        Ok(())
    }

    #[tokio::test]
    async fn test_expiration_handling() -> Result<()> {
        let storage = LruOAuthRequestStorage::new(NonZeroUsize::new(10).unwrap());

        // Insert an expired request
        let expired_request = create_expired_oauth_request(
            "expired-state",
            "https://pds.example.com",
            "did:plc:expired",
        );
        storage.insert_oauth_request(expired_request).await?;
        assert_eq!(storage.len(), 1);

        // Try to get the expired request - should return None and remove from cache
        let result = storage.get_oauth_request_by_state("expired-state").await?;
        assert_eq!(result, None);
        assert_eq!(storage.len(), 0); // Should be removed from cache

        Ok(())
    }

    #[tokio::test]
    async fn test_lru_eviction() -> Result<()> {
        let storage = LruOAuthRequestStorage::new(NonZeroUsize::new(2).unwrap());

        // Fill cache to capacity
        let req1 = create_test_oauth_request("state1", "https://pds.example.com", "did:plc:user1");
        let req2 = create_test_oauth_request("state2", "https://pds.example.com", "did:plc:user2");
        storage.insert_oauth_request(req1.clone()).await?;
        storage.insert_oauth_request(req2).await?;
        assert_eq!(storage.len(), 2);

        // Access req1 to make it recently used
        let _ = storage.get_oauth_request_by_state("state1").await?;

        // Add req3, which should evict req2 (least recently used)
        let req3 = create_test_oauth_request("state3", "https://pds.example.com", "did:plc:user3");
        storage.insert_oauth_request(req3.clone()).await?;
        assert_eq!(storage.len(), 2);

        // req1 and req3 should be present, req2 should be evicted
        let result1 = storage.get_oauth_request_by_state("state1").await?;
        assert!(result1.is_some());
        assert_eq!(result1.unwrap().oauth_state, req1.oauth_state);

        let result3 = storage.get_oauth_request_by_state("state3").await?;
        assert!(result3.is_some());
        assert_eq!(result3.unwrap().oauth_state, req3.oauth_state);

        assert_eq!(storage.get_oauth_request_by_state("state2").await?, None);

        Ok(())
    }

    #[tokio::test]
    async fn test_clear() -> Result<()> {
        let storage = LruOAuthRequestStorage::new(NonZeroUsize::new(10).unwrap());

        // Add some entries
        let req1 = create_test_oauth_request("state1", "https://pds.example.com", "did:plc:user1");
        let req2 = create_test_oauth_request("state2", "https://pds.example.com", "did:plc:user2");
        storage.insert_oauth_request(req1).await?;
        storage.insert_oauth_request(req2).await?;
        assert_eq!(storage.len(), 2);

        // Clear cache
        storage.clear();
        assert_eq!(storage.len(), 0);
        assert!(storage.is_empty());

        // Verify entries are gone
        assert_eq!(storage.get_oauth_request_by_state("state1").await?, None);
        assert_eq!(storage.get_oauth_request_by_state("state2").await?, None);

        Ok(())
    }

    #[tokio::test]
    async fn test_clear_expired_requests() -> Result<()> {
        let storage = LruOAuthRequestStorage::new(NonZeroUsize::new(10).unwrap());

        // Add expired and valid requests
        let expired1 =
            create_expired_oauth_request("expired1", "https://pds.example.com", "did:plc:expired1");
        let expired2 =
            create_expired_oauth_request("expired2", "https://pds.example.com", "did:plc:expired2");
        let valid1 =
            create_test_oauth_request("valid1", "https://pds.example.com", "did:plc:valid1");
        let valid2 =
            create_test_oauth_request("valid2", "https://pds.example.com", "did:plc:valid2");

        storage.insert_oauth_request(expired1).await?;
        storage.insert_oauth_request(valid1).await?;
        storage.insert_oauth_request(expired2).await?;
        storage.insert_oauth_request(valid2).await?;
        assert_eq!(storage.len(), 4);

        // Clear expired requests
        let removed_count = storage.clear_expired_oauth_requests().await?;
        assert_eq!(removed_count, 2); // Two expired requests removed
        assert_eq!(storage.len(), 2); // Two valid requests remain

        // Verify only valid requests remain
        assert!(
            storage
                .get_oauth_request_by_state("valid1")
                .await?
                .is_some()
        );
        assert!(
            storage
                .get_oauth_request_by_state("valid2")
                .await?
                .is_some()
        );
        assert_eq!(storage.get_oauth_request_by_state("expired1").await?, None);
        assert_eq!(storage.get_oauth_request_by_state("expired2").await?, None);

        Ok(())
    }

    #[tokio::test]
    async fn test_delete_nonexistent() -> Result<()> {
        let storage = LruOAuthRequestStorage::new(NonZeroUsize::new(10).unwrap());

        // Deleting non-existent entry should not error
        storage
            .delete_oauth_request_by_state("non-existent-state")
            .await?;
        assert_eq!(storage.len(), 0);

        Ok(())
    }

    #[tokio::test]
    async fn test_thread_safety() -> Result<()> {
        let storage = Arc::new(LruOAuthRequestStorage::new(NonZeroUsize::new(100).unwrap()));
        let mut handles = Vec::new();

        // Spawn multiple tasks that concurrently access the storage
        for i in 0..10 {
            let storage_clone = Arc::clone(&storage);
            let handle = tokio::spawn(async move {
                let state = format!("state{}", i);
                let issuer = format!("https://pds{}.example.com", i);
                let did = format!("did:plc:user{}", i);
                let request = create_test_oauth_request(&state, &issuer, &did);

                // Insert a request
                storage_clone.insert_oauth_request(request.clone()).await?;

                // Get the request back
                let result = storage_clone.get_oauth_request_by_state(&state).await?;
                assert!(result.is_some());
                assert_eq!(result.unwrap().oauth_state, request.oauth_state);

                // Delete the request
                storage_clone.delete_oauth_request_by_state(&state).await?;
                let result = storage_clone.get_oauth_request_by_state(&state).await?;
                assert_eq!(result, None);

                Ok::<(), anyhow::Error>(())
            });
            handles.push(handle);
        }

        // Wait for all tasks to complete
        for handle in handles {
            handle.await??;
        }

        // Storage should be empty after all deletions
        assert_eq!(storage.len(), 0);
        Ok(())
    }
}
