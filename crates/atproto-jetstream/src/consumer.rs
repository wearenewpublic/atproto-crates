//! Async stream consumer for Jetstream events.
//!
//! WebSocket event consumption with background processing and
//! customizable event handler dispatch.
//!
//! ## Memory Efficiency
//!
//! This module is optimized for high-throughput event processing with minimal allocations:
//!
//! - **Arc-based event sharing**: Events are wrapped in `Arc` and shared across all handlers,
//!   avoiding expensive clones of event data structures.
//! - **Zero-copy handler IDs**: Handler identifiers use string slices to avoid allocations
//!   during registration and dispatch.
//! - **Optimized query building**: WebSocket query strings are built with pre-allocated
//!   capacity to minimize reallocations.
//!
//! ## Usage
//!
//! Implement the `EventHandler` trait to process events:
//!
//! ```rust
//! use atproto_jetstream::{EventHandler, JetstreamEvent};
//! use async_trait::async_trait;
//! use std::sync::Arc;
//! use anyhow::Result;
//!
//! struct MyHandler;
//!
//! #[async_trait]
//! impl EventHandler for MyHandler {
//!     async fn handle_event(&self, event: Arc<JetstreamEvent>) -> Result<()> {
//!         // Process event without cloning
//!         Ok(())
//!     }
//!
//!     fn handler_id(&self) -> &str {
//!         "my-handler"
//!     }
//! }
//! ```

use crate::errors::ConsumerError;
use anyhow::Result;
use async_trait::async_trait;
use futures::{SinkExt, StreamExt};
use http::Uri;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::{collections::HashMap, str::FromStr};
use tokio::sync::{RwLock, broadcast};
use tokio::time::{Instant, sleep};
use tokio_util::sync::CancellationToken;
use tokio_websockets::{ClientBuilder, Message};
use tracing::Instrument;

const MAX_MESSAGE_SIZE: usize = 56000;

/// Configuration for the Jetstream consumer task
#[derive(Debug, Clone)]
pub struct ConsumerTaskConfig {
    /// User-Agent header value for WebSocket connections
    pub user_agent: String,
    /// Enable Zstandard compression for messages
    pub compression: bool,
    /// Path to Zstandard dictionary file (required if compression is enabled)
    pub zstd_dictionary_location: String,
    /// Hostname of the Jetstream instance to connect to
    pub jetstream_hostname: String,
    /// AT Protocol collections to subscribe to (empty for all)
    pub collections: Vec<String>,
    /// DIDs to filter events for (empty for all)
    pub dids: Vec<String>,
    /// Maximum message size in bytes (None for unlimited)
    pub max_message_size_bytes: Option<u64>,
    /// Optional cursor position to start streaming from
    pub cursor: Option<i64>,
    /// Whether to require a hello message before receiving events
    pub require_hello: bool,
}

/// Event data structure for Jetstream events
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum JetstreamEvent {
    /// Repository commit event (create/update operations)
    Commit {
        /// DID of the repository that was updated
        did: String,
        /// Event timestamp in microseconds since Unix epoch
        time_us: u64,
        /// Event type identifier
        kind: String,
        /// Commit operation details
        commit: JetstreamEventCommit,
    },

    /// Repository delete event
    Delete {
        /// DID of the repository that was updated
        did: String,
        /// Event timestamp in microseconds since Unix epoch
        time_us: u64,
        /// Event type identifier
        kind: String,
        /// Delete operation details
        commit: JetstreamEventDelete,
    },

    /// Identity document update event
    Identity {
        /// DID whose identity was updated
        did: String,
        /// Event timestamp in microseconds since Unix epoch
        time_us: u64,
        /// Event type identifier
        kind: String,
        /// Identity document data
        identity: serde_json::Value,
    },

    /// Account-related event
    Account {
        /// DID of the account
        did: String,
        /// Event timestamp in microseconds since Unix epoch
        time_us: u64,
        /// Event type identifier
        kind: String,
        /// Account data
        account: serde_json::Value,
    },
}

/// Repository commit operation details
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JetstreamEventCommit {
    /// Repository revision identifier
    pub rev: String,
    /// Operation type (create, update)
    pub operation: String,
    /// AT Protocol collection name
    pub collection: String,
    /// Record key within the collection
    pub rkey: String,
    /// Content identifier (CID) of the record
    pub cid: String,
    /// Record data as JSON
    pub record: serde_json::Value,
}

/// Repository delete operation details
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JetstreamEventDelete {
    /// Repository revision identifier
    pub rev: String,
    /// Operation type (delete)
    pub operation: String,
    /// AT Protocol collection name
    pub collection: String,
    /// Record key that was deleted
    pub rkey: String,
}

/// Trait for handling Jetstream events
#[async_trait]
pub trait EventHandler: Send + Sync {
    /// Handle a received event
    ///
    /// Events are wrapped in Arc to enable efficient sharing across multiple handlers
    /// without cloning the entire event data structure.
    async fn handle_event(&self, event: Arc<JetstreamEvent>) -> Result<()>;

    /// Get the handler's identifier
    ///
    /// Returns a string slice to avoid unnecessary allocations.
    fn handler_id(&self) -> &str;
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", content = "payload")]
pub(crate) enum SubscriberSourcedMessage {
    #[serde(rename = "options_update")]
    Update {
        #[serde(
            rename = "wantedCollections",
            skip_serializing_if = "Vec::is_empty",
            default
        )]
        wanted_collections: Vec<String>,

        #[serde(rename = "wantedDids", skip_serializing_if = "Vec::is_empty", default)]
        wanted_dids: Vec<String>,

        #[serde(rename = "maxMessageSizeBytes")]
        max_message_size_bytes: u64,

        #[serde(skip_serializing_if = "Option::is_none")]
        cursor: Option<i64>,
    },
}

/// Main consumer structure for handling async streams and event dispatching
pub struct Consumer {
    config: ConsumerTaskConfig,
    handlers: Arc<RwLock<HashMap<String, Arc<dyn EventHandler>>>>,
    event_sender: Arc<RwLock<Option<broadcast::Sender<Arc<JetstreamEvent>>>>>,
}

impl Consumer {
    /// Create a new consumer with the given configuration
    pub fn new(config: ConsumerTaskConfig) -> Self {
        Self {
            config,
            handlers: Arc::new(RwLock::new(HashMap::new())),
            event_sender: Arc::new(RwLock::new(None)),
        }
    }

    /// Register an event handler
    pub async fn register_handler(&self, handler: Arc<dyn EventHandler>) -> Result<()> {
        let handler_id = handler.handler_id();
        let mut handlers = self.handlers.write().await;

        if handlers.contains_key(handler_id) {
            return Err(ConsumerError::HandlerRegistrationFailed(format!(
                "Handler with ID '{}' already registered",
                handler_id
            ))
            .into());
        }

        handlers.insert(handler_id.to_string(), handler);
        Ok(())
    }

    /// Unregister an event handler
    pub async fn unregister_handler(&self, handler_id: &str) -> Result<()> {
        let mut handlers = self.handlers.write().await;
        handlers.remove(handler_id);
        Ok(())
    }

    /// Get a broadcast receiver for events
    ///
    /// Events are wrapped in Arc to enable efficient sharing without cloning.
    pub async fn get_event_receiver(&self) -> Result<broadcast::Receiver<Arc<JetstreamEvent>>> {
        let sender_guard = self.event_sender.read().await;
        match sender_guard.as_ref() {
            Some(sender) => Ok(sender.subscribe()),
            None => Err(ConsumerError::EventSenderNotInitialized(
                "consumer not running".to_string(),
            )
            .into()),
        }
    }

    /// Run the consumer in the background
    ///
    /// # Example
    /// ```rust,no_run
    /// use atproto_jetstream::{Consumer, ConsumerTaskConfig, CancellationToken};
    ///
    /// # async fn example() -> anyhow::Result<()> {
    /// let config = ConsumerTaskConfig {
    ///     user_agent: "my-app/1.0".to_string(),
    ///     compression: false,
    ///     zstd_dictionary_location: String::new(),
    ///     jetstream_hostname: "jetstream1.us-east.bsky.network".to_string(),
    ///     collections: vec!["app.bsky.feed.post".to_string()],
    ///     dids: vec![], // Subscribe to all DIDs
    ///     max_message_size_bytes: None, // No limit
    ///     cursor: None, // Live-tail from current time
    ///     require_hello: true, // Wait for initial options update
    /// };
    ///
    /// let consumer = Consumer::new(config);
    /// let cancellation_token = CancellationToken::new();
    ///
    /// // To cancel the consumer later:
    /// // cancellation_token.cancel();
    ///
    /// consumer.run_background(cancellation_token).await?;
    /// # Ok(())
    /// # }
    /// ```
    pub async fn run_background(&self, cancellation_token: CancellationToken) -> Result<()> {
        tracing::info!("Starting Jetstream consumer");

        // Build WebSocket URL with query parameters
        // Pre-allocate capacity to avoid reallocations during string building
        let capacity = 50 // Base parameters
            + self.config.collections.len() * 30 // Estimate per collection
            + self.config.dids.len() * 60; // Estimate per DID
        let mut query_string = String::with_capacity(capacity);

        // Add compression parameter
        query_string.push_str("compress=");
        query_string.push_str(if self.config.compression {
            "true"
        } else {
            "false"
        });

        // Add requireHello parameter
        query_string.push_str("&requireHello=");
        query_string.push_str(if self.config.require_hello {
            "true"
        } else {
            "false"
        });

        // Add wantedCollections if specified (each collection as a separate query parameter)
        if !self.config.collections.is_empty() && !self.config.require_hello {
            for collection in &self.config.collections {
                query_string.push_str("&wantedCollections=");
                query_string.push_str(&urlencoding::encode(collection));
            }
        }

        // Add wantedDids if specified (each DID as a separate query parameter)
        if !self.config.dids.is_empty() && !self.config.require_hello {
            for did in &self.config.dids {
                query_string.push_str("&wantedDids=");
                query_string.push_str(&urlencoding::encode(did));
            }
        }

        // Add maxMessageSizeBytes if specified
        if let Some(max_size) = self.config.max_message_size_bytes {
            use std::fmt::Write;
            write!(&mut query_string, "&maxMessageSizeBytes={}", max_size).unwrap();
        }

        // Add cursor if specified
        if let Some(cursor) = self.config.cursor {
            use std::fmt::Write;
            write!(&mut query_string, "&cursor={}", cursor).unwrap();
        }
        let ws_url = Uri::from_str(&format!(
            "wss://{}/subscribe?{}",
            self.config.jetstream_hostname, query_string
        ))?;

        let (mut client, _) = ClientBuilder::from_uri(ws_url)
            .add_header(
                http::header::USER_AGENT,
                http::HeaderValue::from_str(&self.config.user_agent)?,
            )?
            .connect()
            .await?;

        let update = SubscriberSourcedMessage::Update {
            wanted_collections: self.config.collections.clone(),
            wanted_dids: self.config.dids.clone(),
            max_message_size_bytes: self
                .config
                .max_message_size_bytes
                .unwrap_or(MAX_MESSAGE_SIZE as u64),
            cursor: self.config.cursor,
        };
        let serialized_update = serde_json::to_string(&update)
            .map_err(|err| ConsumerError::UpdateSerializationFailed(err.to_string()))?;

        client
            .send(Message::text(serialized_update))
            .await
            .map_err(|err| ConsumerError::UpdateSendFailed(err.to_string()))?;

        let mut decompressor = if self.config.compression {
            // mkdir -p data/ && curl -o data/zstd_dictionary https://github.com/bluesky-social/jetstream/raw/refs/heads/main/pkg/models/zstd_dictionary
            let data: Vec<u8> = std::fs::read(self.config.zstd_dictionary_location.clone())?;
            zstd::bulk::Decompressor::with_dictionary(&data)
                .map_err(|err| ConsumerError::DecompressorCreationFailed(err.to_string()))?
        } else {
            zstd::bulk::Decompressor::new()
                .map_err(|err| ConsumerError::DecompressorCreationFailed(err.to_string()))?
        };

        let interval = std::time::Duration::from_secs(120);
        let sleeper = sleep(interval);
        tokio::pin!(sleeper);

        loop {
            tokio::select! {
                () = cancellation_token.cancelled() => {
                    break;
                },
                () = &mut sleeper => {
                        sleeper.as_mut().reset(Instant::now() + interval);
                },
                item = client.next() => {
                    if item.is_none() {
                        tracing::warn!("jetstream connection closed");
                        break;
                    }
                    let item = item.unwrap();

                    if let Err(err) = item {
                        tracing::error!(error = ?err, "error processing jetstream message");
                        continue;
                    }
                    let item = item.unwrap();

                    let event = if self.config.compression {
                        if !item.is_binary() {
                            tracing::debug!("compression enabled but message from jetstream is not binary");
                            continue;
                        }
                        let payload = item.into_payload();

                        let decoded = decompressor.decompress(&payload, MAX_MESSAGE_SIZE * 3);
                        if let Err(err) = decoded {
                            tracing::debug!(err = ?err, "cannot decompress message");
                            continue;
                        }
                        let decoded = decoded.unwrap();
                        serde_json::from_slice::<JetstreamEvent>(&decoded)
                        .map_err(|err| ConsumerError::DeserializationFailed(err.to_string()))
                    } else {
                        if !item.is_text() {
                            tracing::debug!("compression disabled but message from jetstream is binary");
                            continue;
                        }
                        item.as_text()
                            .ok_or_else(|| ConsumerError::MessageConversionFailed("cannot convert message to text".to_string()))
                            .and_then(|value| {
                                serde_json::from_str::<JetstreamEvent>(value)
                                .map_err(|err| ConsumerError::DeserializationFailed(err.to_string()))
                            })
                    };
                    if let Err(err) = event {
                        tracing::error!(error = ?err, "error processing jetstream message");

                        continue;
                    }
                    let event = event.unwrap();

                    if let Err(err) = self.dispatch_to_handlers(event).await {
                        tracing::error!(error = ?err, "Failed to process message");
                    }

                }
            }
        }

        // Clean up
        {
            let mut sender_guard = self.event_sender.write().await;
            *sender_guard = None;
        }

        Ok(())
    }

    /// Dispatch event to all registered handlers
    ///
    /// Wraps the event in Arc once and shares it across all handlers,
    /// avoiding expensive clones of the event data structure.
    async fn dispatch_to_handlers(&self, event: JetstreamEvent) -> Result<()> {
        let handlers = self.handlers.read().await;
        let event = Arc::new(event);

        for (handler_id, handler) in handlers.iter() {
            let handler_span = tracing::debug_span!("handler_dispatch", handler_id = %handler_id);
            let event_ref = Arc::clone(&event);
            async {
                if let Err(err) = handler.handle_event(event_ref).await {
                    tracing::error!(
                        error = ?err,
                        handler_id = %handler_id,
                        "Handler failed to process event"
                    );
                }
            }
            .instrument(handler_span)
            .await;
        }

        Ok(())
    }
}

/// Example event handler implementation
pub struct LoggingHandler {
    id: String,
}

impl LoggingHandler {
    /// Create a new logging handler with the specified ID
    pub fn new(id: String) -> Self {
        Self { id }
    }
}

#[async_trait]
impl EventHandler for LoggingHandler {
    async fn handle_event(&self, _event: Arc<JetstreamEvent>) -> Result<()> {
        Ok(())
    }

    fn handler_id(&self) -> &str {
        &self.id
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_account_event() {
        let json_str = r#"{"did":"did:plc:yn72uqr4ihkjfbz7us7buqsq","time_us":1757517640675638,"kind":"account","account":{"active":false,"did":"did:plc:yn72uqr4ihkjfbz7us7buqsq","seq":13206502767,"status":"takendown","time":"2025-09-10T15:20:40.439Z"}}"#;

        let event = serde_json::from_str::<JetstreamEvent>(json_str)
            .expect("Failed to parse account event JSON");

        match event {
            JetstreamEvent::Account {
                did,
                time_us,
                kind,
                account: identity,
            } => {
                assert_eq!(did, "did:plc:yn72uqr4ihkjfbz7us7buqsq");
                assert_eq!(time_us, 1757517640675638);
                assert_eq!(kind, "account");

                // Verify the account data structure
                assert!(identity.is_object());
                let account_obj = identity.as_object().unwrap();
                assert_eq!(
                    account_obj.get("active").unwrap(),
                    &serde_json::json!(false)
                );
                assert_eq!(
                    account_obj.get("did").unwrap(),
                    &serde_json::json!("did:plc:yn72uqr4ihkjfbz7us7buqsq")
                );
                assert_eq!(
                    account_obj.get("seq").unwrap(),
                    &serde_json::json!(13206502767i64)
                );
                assert_eq!(
                    account_obj.get("status").unwrap(),
                    &serde_json::json!("takendown")
                );
                assert_eq!(
                    account_obj.get("time").unwrap(),
                    &serde_json::json!("2025-09-10T15:20:40.439Z")
                );
            }
            _ => panic!("Expected JetstreamEvent::Account variant, got {:?}", event),
        }
    }

    #[test]
    fn test_parse_identity_event() {
        let json_str = r#"{"did":"did:plc:mbuadp4xzlbmc2ncqp3pmtox","time_us":1757517628039893,"kind":"identity","identity":{"did":"did:plc:mbuadp4xzlbmc2ncqp3pmtox","handle":"nhieothv.bsky.social","seq":13206497272,"time":"2025-09-10T15:20:27.610Z"}}"#;

        let event = serde_json::from_str::<JetstreamEvent>(json_str)
            .expect("Failed to parse identity event JSON");

        match event {
            JetstreamEvent::Identity {
                did,
                time_us,
                kind,
                identity,
            } => {
                assert_eq!(did, "did:plc:mbuadp4xzlbmc2ncqp3pmtox");
                assert_eq!(time_us, 1757517628039893);
                assert_eq!(kind, "identity");

                // Verify the identity data structure
                assert!(identity.is_object());
                let identity_obj = identity.as_object().unwrap();
                assert_eq!(
                    identity_obj.get("did").unwrap(),
                    &serde_json::json!("did:plc:mbuadp4xzlbmc2ncqp3pmtox")
                );
                assert_eq!(
                    identity_obj.get("handle").unwrap(),
                    &serde_json::json!("nhieothv.bsky.social")
                );
                assert_eq!(
                    identity_obj.get("seq").unwrap(),
                    &serde_json::json!(13206497272i64)
                );
                assert_eq!(
                    identity_obj.get("time").unwrap(),
                    &serde_json::json!("2025-09-10T15:20:27.610Z")
                );
            }
            _ => panic!("Expected JetstreamEvent::Identity variant, got {:?}", event),
        }
    }

    #[test]
    fn test_parse_delete_event() {
        let json_str = r#"{"did":"did:plc:5ozthefrqdo5kqnxzfgthhpp","time_us":1757519323847323,"kind":"commit","commit":{"rev":"3lyileto4q52k","operation":"delete","collection":"app.bsky.graph.follow","rkey":"3lxqxntaew32z"}}"#;

        let event = serde_json::from_str::<JetstreamEvent>(json_str)
            .expect("Failed to parse delete event JSON");

        match event {
            JetstreamEvent::Delete {
                did,
                time_us,
                kind,
                commit,
            } => {
                assert_eq!(did, "did:plc:5ozthefrqdo5kqnxzfgthhpp");
                assert_eq!(time_us, 1757519323847323);
                assert_eq!(kind, "commit");

                // Verify the delete operation details
                assert_eq!(commit.rev, "3lyileto4q52k");
                assert_eq!(commit.operation, "delete");
                assert_eq!(commit.collection, "app.bsky.graph.follow");
                assert_eq!(commit.rkey, "3lxqxntaew32z");
            }
            _ => panic!("Expected JetstreamEvent::Delete variant, got {:?}", event),
        }
    }

    #[test]
    fn test_parse_commit_event() {
        let json_str = r#"{"did":"did:plc:suq5ijgyqmsawwf5tskf654x","time_us":1757519323848962,"kind":"commit","commit":{"rev":"3lyiletdopl2c","operation":"create","collection":"app.bsky.feed.like","rkey":"3lyiletddxt2c","record":{"$type":"app.bsky.feed.like","createdAt":"2025-09-10T15:47:13.086Z","subject":{"cid":"bafyreib2pygab7z5l7nkqf6bchcvgt4jwsqiaenpf3sr65lugum2uvzzf4","uri":"at://did:plc:yw65rktdby2chplqdytqzcao/app.bsky.feed.post/3lyildyjxgs2o"}},"cid":"bafyreigroo6vhxt62ufcndhaxzas6btq4jmniuz4egszbwuqgiyisqwqoy"}}"#;

        let event = serde_json::from_str::<JetstreamEvent>(json_str)
            .expect("Failed to parse commit event JSON");

        match event {
            JetstreamEvent::Commit {
                did,
                time_us,
                kind,
                commit,
            } => {
                assert_eq!(did, "did:plc:suq5ijgyqmsawwf5tskf654x");
                assert_eq!(time_us, 1757519323848962);
                assert_eq!(kind, "commit");

                // Verify the commit operation details
                assert_eq!(commit.rev, "3lyiletdopl2c");
                assert_eq!(commit.operation, "create");
                assert_eq!(commit.collection, "app.bsky.feed.like");
                assert_eq!(commit.rkey, "3lyiletddxt2c");
                assert_eq!(
                    commit.cid,
                    "bafyreigroo6vhxt62ufcndhaxzas6btq4jmniuz4egszbwuqgiyisqwqoy"
                );

                // Verify the record data structure
                assert!(commit.record.is_object());
                let record_obj = commit.record.as_object().unwrap();
                assert_eq!(
                    record_obj.get("$type").unwrap(),
                    &serde_json::json!("app.bsky.feed.like")
                );
                assert_eq!(
                    record_obj.get("createdAt").unwrap(),
                    &serde_json::json!("2025-09-10T15:47:13.086Z")
                );

                // Verify the subject within the record
                let subject = record_obj.get("subject").unwrap().as_object().unwrap();
                assert_eq!(
                    subject.get("cid").unwrap(),
                    &serde_json::json!(
                        "bafyreib2pygab7z5l7nkqf6bchcvgt4jwsqiaenpf3sr65lugum2uvzzf4"
                    )
                );
                assert_eq!(
                    subject.get("uri").unwrap(),
                    &serde_json::json!(
                        "at://did:plc:yw65rktdby2chplqdytqzcao/app.bsky.feed.post/3lyildyjxgs2o"
                    )
                );
            }
            _ => panic!("Expected JetstreamEvent::Commit variant, got {:?}", event),
        }
    }

    #[test]
    fn test_parse_commit_update_event() {
        let json_str = r#"{"did":"did:plc:mek6cpladv2xrlu2zdykoxgz","time_us":1757519523286358,"kind":"commit","commit":{"rev":"3lyilmalk762z","operation":"update","collection":"app.bsky.actor.profile","rkey":"self","record":{"$type":"app.bsky.actor.profile","avatar":{"$type":"blob","ref":{"$link":"bafkreibmn7xi5iwugioov463wux62dg4m4w6qqrbsnileaobrzgxdwbsqy"},"mimeType":"image/jpeg","size":289838},"banner":{"$type":"blob","ref":{"$link":"bafkreicjgdlfs6fyyddjklfzrf6w2boychodkdebtjaiwavhcffjtuavsi"},"mimeType":"image/jpeg","size":676693},"description":"ela/dela | parte da fauna fantástica do céu azul | praticamente inofensiva","displayName":"la mucura mística","pinnedPost":{"cid":"bafyreihn2t4efvipbcignd6rlybmoecb7hx4jgntsojhpibjzxno3zhbuq","uri":"at://did:plc:mek6cpladv2xrlu2zdykoxgz/app.bsky.feed.post/3lxarfbd4ts2j"}},"cid":"bafyreifpmgw3podvvm4raq6zewn6jhoa73t7mlgf3f7hty2adb6f2ga7j4"}}"#;

        let event = serde_json::from_str::<JetstreamEvent>(json_str)
            .expect("Failed to parse commit update event JSON");

        match event {
            JetstreamEvent::Commit {
                did,
                time_us,
                kind,
                commit,
            } => {
                assert_eq!(did, "did:plc:mek6cpladv2xrlu2zdykoxgz");
                assert_eq!(time_us, 1757519523286358);
                assert_eq!(kind, "commit");

                // Verify the commit operation details
                assert_eq!(commit.rev, "3lyilmalk762z");
                assert_eq!(commit.operation, "update");
                assert_eq!(commit.collection, "app.bsky.actor.profile");
                assert_eq!(commit.rkey, "self");
                assert_eq!(
                    commit.cid,
                    "bafyreifpmgw3podvvm4raq6zewn6jhoa73t7mlgf3f7hty2adb6f2ga7j4"
                );

                // Verify the record data structure
                assert!(commit.record.is_object());
                let record_obj = commit.record.as_object().unwrap();
                assert_eq!(
                    record_obj.get("$type").unwrap(),
                    &serde_json::json!("app.bsky.actor.profile")
                );
                assert_eq!(
                    record_obj.get("description").unwrap(),
                    &serde_json::json!(
                        "ela/dela | parte da fauna fantástica do céu azul | praticamente inofensiva"
                    )
                );
                assert_eq!(
                    record_obj.get("displayName").unwrap(),
                    &serde_json::json!("la mucura mística")
                );

                // Verify avatar blob
                let avatar = record_obj.get("avatar").unwrap().as_object().unwrap();
                assert_eq!(avatar.get("$type").unwrap(), &serde_json::json!("blob"));
                assert_eq!(
                    avatar.get("mimeType").unwrap(),
                    &serde_json::json!("image/jpeg")
                );
                assert_eq!(avatar.get("size").unwrap(), &serde_json::json!(289838));

                // Verify banner blob
                let banner = record_obj.get("banner").unwrap().as_object().unwrap();
                assert_eq!(banner.get("$type").unwrap(), &serde_json::json!("blob"));
                assert_eq!(
                    banner.get("mimeType").unwrap(),
                    &serde_json::json!("image/jpeg")
                );
                assert_eq!(banner.get("size").unwrap(), &serde_json::json!(676693));

                // Verify pinned post
                let pinned_post = record_obj.get("pinnedPost").unwrap().as_object().unwrap();
                assert_eq!(
                    pinned_post.get("cid").unwrap(),
                    &serde_json::json!(
                        "bafyreihn2t4efvipbcignd6rlybmoecb7hx4jgntsojhpibjzxno3zhbuq"
                    )
                );
                assert_eq!(
                    pinned_post.get("uri").unwrap(),
                    &serde_json::json!(
                        "at://did:plc:mek6cpladv2xrlu2zdykoxgz/app.bsky.feed.post/3lxarfbd4ts2j"
                    )
                );
            }
            _ => panic!("Expected JetstreamEvent::Commit variant, got {:?}", event),
        }
    }
}
