//! Shared trait definitions for AT Protocol identity operations.
//!
//! This module centralizes async traits used across the identity crate so they can
//! be implemented without introducing circular module dependencies.

use anyhow::Result;
use async_trait::async_trait;

use crate::errors::ResolveError;
use crate::key::KeyData;
use crate::model::Document;

/// Trait for AT Protocol identity resolution.
///
/// Implementations must resolve handles or DIDs to canonical DID documents.
#[async_trait]
pub trait IdentityResolver: Send + Sync {
    /// Resolves an AT Protocol subject to its DID document.
    async fn resolve(&self, subject: &str) -> Result<Document>;
}

/// Trait for DNS resolution operations used during handle lookups.
#[async_trait]
pub trait DnsResolver: Send + Sync {
    /// Resolves TXT records for a given domain name.
    async fn resolve_txt(&self, domain: &str) -> Result<Vec<String>, ResolveError>;
}

#[async_trait]
impl<T: DnsResolver + ?Sized> DnsResolver for std::sync::Arc<T> {
    async fn resolve_txt(&self, domain: &str) -> Result<Vec<String>, ResolveError> {
        (**self).resolve_txt(domain).await
    }
}

/// Trait for retrieving private keys by identifier.
#[async_trait]
/// Trait for resolving key references (e.g., DID verification methods) to [`KeyData`].
#[async_trait]
pub trait KeyResolver: Send + Sync {
    /// Resolves a key reference string into key material.
    async fn resolve(&self, key: &str) -> Result<KeyData>;
}

/// Trait for DID document storage backends.
#[async_trait]
pub trait DidDocumentStorage: Send + Sync {
    /// Retrieves a DID document if present.
    async fn get_document_by_did(&self, did: &str) -> Result<Option<Document>>;

    /// Stores or updates a DID document.
    async fn store_document(&self, document: Document) -> Result<()>;

    /// Deletes a DID document by DID.
    async fn delete_document_by_did(&self, did: &str) -> Result<()>;
}
