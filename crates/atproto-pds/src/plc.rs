//! PLC genesis + update orchestration.
//!
//!  the PDS holds the
//! canonical rotation key for accounts that opted into PDS-managed rotation.
//! When a caller invokes `createAccount` without supplying a `did`, this
//! module:
//!
//! 1. Generates a fresh rotation key (P-256 by default) and stores it in
//!    the [`KeyStore`].
//! 2. Generates a fresh atproto signing key and stores it.
//! 3. Builds a PLC genesis operation listing both keys plus the PDS service
//!    endpoint and the requested handle as `alsoKnownAs`.
//! 4. POSTs the signed op to the configured PLC directory.
//! 5. Returns the derived `did:plc:...` identifier and the key refs.
//!
//! The HTTP layer then proceeds with the normal `AccountManager::create_account`
//! flow using the derived DID.

use crate::errors::{PdsError, PdsResult};
use crate::keys::KeyStore;
use atproto_identity::key::{KeyData, KeyType, generate_key, to_public};
use atproto_identity::plc::{self, DidBuilder, ServiceEndpoint};
use std::collections::HashMap;
use std::sync::Arc;
use tracing::{Instrument, info_span};

/// Outcome of a PLC genesis: the derived DID + key refs persisted in the
/// PDS [`KeyStore`].
#[derive(Debug, Clone)]
pub struct PlcGenesisOutcome {
    /// Newly-derived `did:plc:...` identifier.
    pub did: String,
    /// Reference under which the rotation key is persisted in the KeyStore.
    pub rotation_key_ref: String,
    /// Reference under which the atproto signing key is persisted in the KeyStore.
    pub signing_key_ref: String,
}

/// Configuration for the PLC service.
#[derive(Clone)]
pub struct PlcConfig {
    /// PLC directory hostname (e.g., `plc.directory`). Without scheme.
    pub directory_hostname: String,
    /// PDS service DID (e.g., `did:web:pds.example.com`). Used as the
    /// `service.atproto_pds.serviceEndpoint`.
    pub service_did: String,
    /// PDS public-facing URL (e.g., `https://pds.example.com`). Used as the
    /// service endpoint for the `atproto_pds` service.
    pub service_endpoint: String,
    /// Key type for the freshly-generated rotation key.
    pub rotation_key_type: KeyType,
    /// Key type for the freshly-generated signing key.
    pub signing_key_type: KeyType,
    /// Externally-supplied PDS-level rotation key.
    /// When `Some(...)`, every PLC genesis op lists this key in
    /// `rotation_keys` ALONGSIDE the freshly-generated per-account key —
    /// giving the PDS a fallback-recovery path. Loaded from
    /// `PDS_PLC_ROTATION_KEY_DID_KEY` + `PDS_PLC_ROTATION_KEY_PRIVATE`
    /// at startup.
    pub external_rotation_key: Option<KeyData>,
}

impl PlcConfig {
    /// Construct a new PlcConfig with sensible defaults.
    #[must_use]
    pub fn new(directory_hostname: String, service_did: String, service_endpoint: String) -> Self {
        Self {
            directory_hostname,
            service_did,
            service_endpoint,
            rotation_key_type: KeyType::P256Private,
            signing_key_type: KeyType::K256Private,
            external_rotation_key: None,
        }
    }

    /// Attach an externally-supplied PDS-level rotation key (REMAINING-
    /// WORK §11d). The key is included in every PLC genesis op so the
    /// PDS retains rotation authority across accounts. Pass the
    /// **private** form; the public form is derived for the operation.
    #[must_use]
    pub fn with_rotation_key(mut self, key: KeyData) -> Self {
        self.external_rotation_key = Some(key);
        self
    }
}

/// PLC genesis service.
///
/// Holds the configuration + a `reqwest::Client` for PLC submission. Cheap
/// to clone (Arc-wrapped internally).
pub struct PlcService {
    config: Arc<PlcConfig>,
    key_store: Arc<dyn KeyStore>,
    http_client: reqwest::Client,
}

impl PlcService {
    /// Construct a new PlcService.
    #[must_use]
    pub fn new(config: PlcConfig, key_store: Arc<dyn KeyStore>) -> Self {
        Self::with_http_client(config, key_store, reqwest::Client::new())
    }

    /// PLC directory hostname this service is configured against.
    #[must_use]
    pub fn directory_hostname(&self) -> &str {
        &self.config.directory_hostname
    }

    /// PDS public-facing service endpoint URL configured at boot. Used by
    /// `getRecommendedDidCredentials` to advertise
    /// the right `services.atproto_pds.endpoint` shape to migration
    /// callers.
    #[must_use]
    pub fn service_endpoint(&self) -> &str {
        &self.config.service_endpoint
    }

    /// Construct with a caller-supplied HTTP client (useful for tests).
    #[must_use]
    pub fn with_http_client(
        config: PlcConfig,
        key_store: Arc<dyn KeyStore>,
        http_client: reqwest::Client,
    ) -> Self {
        Self {
            config: Arc::new(config),
            key_store,
            http_client,
        }
    }

    /// Generate a fresh rotation key + signing key, build a PLC genesis op
    /// listing the supplied handle as `alsoKnownAs`, sign with the rotation
    /// key, and submit to the configured PLC directory.
    ///
    /// On success, both keys are already persisted to the KeyStore and the
    /// returned `PlcGenesisOutcome` carries their refs ready for use by
    /// `AccountManager::create_account`.
    pub async fn genesis(&self, handle: &str) -> PdsResult<PlcGenesisOutcome> {
        // 1. Generate keys.
        let rotation_priv = generate_key(self.config.rotation_key_type.clone()).map_err(|e| {
            PdsError::PlcRotationKey {
                reason: format!("generate rotation key: {e}"),
            }
        })?;
        let signing_priv =
            generate_key(self.config.signing_key_type.clone()).map_err(|e| PdsError::Storage {
                reason: format!("generate signing key: {e}"),
            })?;
        let signing_pub = to_public(&signing_priv).map_err(|e| PdsError::Storage {
            reason: format!("derive signing pub: {e}"),
        })?;

        // 2. Build PLC op via the DidBuilder. The builder takes the rotation
        //    key in private form and the signing key in private form (it
        //    derives the public form internally).
        let mut services = HashMap::new();
        services.insert(
            "atproto_pds".to_string(),
            ServiceEndpoint {
                service_type: "AtprotoPersonalDataServer".to_string(),
                endpoint: self.config.service_endpoint.clone(),
            },
        );
        // 0016 §"Space authority" (lines 87-92): the authority DID MUST expose
        // a `#atproto_space_host` service. Per line 92 it MAY resolve to the
        // same endpoint as `#atproto_pds`; reuse this PDS's endpoint.
        services.insert(
            "atproto_space_host".to_string(),
            ServiceEndpoint {
                service_type: "AtprotoPersonalDataServer".to_string(),
                endpoint: self.config.service_endpoint.clone(),
            },
        );
        let handle_uri = if handle.starts_with("at://") {
            handle.to_string()
        } else {
            format!("at://{handle}")
        };

        let mut builder = DidBuilder::new().add_rotation_key(rotation_priv.clone());
        // §11d — when an externally-supplied PDS rotation key is configured,
        // list it as an additional rotation key on every genesis op. The
        // PDS then retains rotation authority for any account it issued
        // even if the per-account key is lost.
        if let Some(extra) = self.config.external_rotation_key.as_ref() {
            builder = builder.add_rotation_key(extra.clone());
        }
        // 0016 §"Space authority" (lines 87-92): the authority DID MUST expose
        // a `#atproto_space` verification method carrying the credential-signing
        // key. Per line 92 it MAY coincide with `#atproto`; reuse the account's
        // atproto signing key.
        let (did, signed_op, _builder_keys) = builder
            .add_verification_method("atproto".to_string(), signing_pub.clone())
            .add_verification_method("atproto_space".to_string(), signing_pub)
            .add_also_known_as(handle_uri)
            .add_service("atproto_pds".to_string(), services["atproto_pds"].clone())
            .add_service(
                "atproto_space_host".to_string(),
                services["atproto_space_host"].clone(),
            )
            .build()
            .map_err(|e| PdsError::PlcRotationKey {
                reason: format!("build PLC op: {e}"),
            })?;

        // 3. Submit to PLC directory.
        let did_str = did.to_string();
        plc::submit(
            &self.http_client,
            &self.config.directory_hostname,
            &did_str,
            &signed_op,
        )
        .instrument(info_span!("plc_submit", did = %did_str))
        .await
        .map_err(|e| PdsError::PlcRotationKey {
            reason: format!("submit to PLC: {e}"),
        })?;

        // 4. Persist both keys to the KeyStore *after* successful submission
        //    (so a failed submit doesn't litter the keystore).
        let rotation_key_ref = self.key_store.put(&rotation_priv).await?;
        let signing_key_ref = self.key_store.put(&signing_priv).await?;

        Ok(PlcGenesisOutcome {
            did: did_str,
            rotation_key_ref,
            signing_key_ref,
        })
    }

    /// Submit an already-signed PLC `Operation` to the configured directory
    /// for the given `did`. Used by `submitPlcOperation` to apply user-signed
    /// updates (key rotations, service-endpoint changes).
    pub async fn submit_operation(
        &self,
        did: &str,
        op: &atproto_identity::plc::Operation,
    ) -> PdsResult<()> {
        plc::submit(&self.http_client, &self.config.directory_hostname, did, op)
            .instrument(info_span!("plc_submit_update", did))
            .await
            .map_err(|e| PdsError::PlcRotationKey {
                reason: format!("submit PLC op: {e}"),
            })
    }

    /// Generate keys + build a PLC genesis op WITHOUT submitting to the
    /// directory. Useful for offline/test paths and the migration flow where
    /// the new PDS receives a pre-signed `plcOp` from the old PDS.
    ///
    /// The caller is responsible for persisting the returned keys + DID.
    pub async fn genesis_dry_run(
        &self,
        handle: &str,
    ) -> PdsResult<(String, atproto_identity::plc::Operation, KeyData, KeyData)> {
        let rotation_priv = generate_key(self.config.rotation_key_type.clone()).map_err(|e| {
            PdsError::PlcRotationKey {
                reason: format!("generate rotation key: {e}"),
            }
        })?;
        let signing_priv =
            generate_key(self.config.signing_key_type.clone()).map_err(|e| PdsError::Storage {
                reason: format!("generate signing key: {e}"),
            })?;
        let signing_pub = to_public(&signing_priv).map_err(|e| PdsError::Storage {
            reason: format!("derive signing pub: {e}"),
        })?;

        let handle_uri = if handle.starts_with("at://") {
            handle.to_string()
        } else {
            format!("at://{handle}")
        };
        let svc = ServiceEndpoint {
            service_type: "AtprotoPersonalDataServer".to_string(),
            endpoint: self.config.service_endpoint.clone(),
        };
        // 0016 §"Space authority" (lines 87-92): expose `#atproto_space_host`
        // alongside `#atproto_pds`, reusing this PDS's endpoint (line 92 MAY).
        let space_host_svc = ServiceEndpoint {
            service_type: "AtprotoPersonalDataServer".to_string(),
            endpoint: self.config.service_endpoint.clone(),
        };

        let (did, op, _) = DidBuilder::new()
            .add_rotation_key(rotation_priv.clone())
            .add_verification_method("atproto".to_string(), signing_pub.clone())
            .add_verification_method("atproto_space".to_string(), signing_pub)
            .add_also_known_as(handle_uri)
            .add_service("atproto_pds".to_string(), svc)
            .add_service("atproto_space_host".to_string(), space_host_svc)
            .build()
            .map_err(|e| PdsError::PlcRotationKey {
                reason: format!("build PLC op: {e}"),
            })?;

        Ok((did.to_string(), op, rotation_priv, signing_priv))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::MemoryKeyStore;

    fn fresh_service() -> PlcService {
        let config = PlcConfig::new(
            "plc.example.com".to_string(),
            "did:web:pds.example.com".to_string(),
            "https://pds.example.com".to_string(),
        );
        let store: Arc<dyn KeyStore> = Arc::new(MemoryKeyStore::new());
        PlcService::new(config, store)
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn genesis_dry_run_returns_did_and_keys() {
        let svc = fresh_service();
        let (did, op, rotation, signing) = svc.genesis_dry_run("alice.example").await.unwrap();
        assert!(did.starts_with("did:plc:"));
        assert_eq!(did.len(), 32, "did:plc: prefix + 24-char hash");
        assert!(op.is_genesis(), "PLC op must be a genesis (prev=None)");
        assert!(matches!(
            rotation.key_type(),
            KeyType::P256Private
                | KeyType::P384Private
                | KeyType::K256Private
                | KeyType::Ed25519Private
        ));
        assert!(matches!(
            signing.key_type(),
            KeyType::P256Private
                | KeyType::P384Private
                | KeyType::K256Private
                | KeyType::Ed25519Private
        ));
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn genesis_dry_run_uses_supplied_handle() {
        let svc = fresh_service();
        let (_did, op, _, _) = svc.genesis_dry_run("alice.example").await.unwrap();
        // Inspect the operation by serializing to JSON and checking handle URI is present.
        let json = serde_json::to_value(&op).unwrap();
        let aka = json["alsoKnownAs"].as_array().unwrap();
        assert!(aka.iter().any(|v| v.as_str() == Some("at://alice.example")));
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn genesis_dry_run_includes_pds_service_endpoint() {
        let svc = fresh_service();
        let (_did, op, _, _) = svc.genesis_dry_run("alice.example").await.unwrap();
        let json = serde_json::to_value(&op).unwrap();
        let services = &json["services"]["atproto_pds"];
        assert_eq!(services["type"], "AtprotoPersonalDataServer");
        assert_eq!(services["endpoint"], "https://pds.example.com");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn genesis_dry_run_exposes_atproto_space_verification_method() {
        // 0016 §"Space authority" (lines 87-92): the authority DID MUST expose
        // an `#atproto_space` verification method. Per line 92 it MAY coincide
        // in value with `#atproto`; this PDS reuses the atproto signing key, so
        // the two entries carry the same did:key.
        let svc = fresh_service();
        let (_did, op, _, _) = svc.genesis_dry_run("alice.example").await.unwrap();
        let json = serde_json::to_value(&op).unwrap();
        let vms = &json["verificationMethods"];
        let atproto = vms["atproto"]
            .as_str()
            .expect("#atproto verification method present");
        let atproto_space = vms["atproto_space"]
            .as_str()
            .expect("#atproto_space verification method present");
        assert!(atproto.starts_with("did:key:"));
        assert_eq!(
            atproto, atproto_space,
            "#atproto_space coincides with #atproto per line 92"
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn genesis_dry_run_exposes_atproto_space_host_service() {
        // 0016 §"Space authority" (lines 87-92): the authority DID MUST expose
        // an `#atproto_space_host` service. Per line 92 it MAY resolve to the
        // same endpoint as `#atproto_pds`.
        let svc = fresh_service();
        let (_did, op, _, _) = svc.genesis_dry_run("alice.example").await.unwrap();
        let json = serde_json::to_value(&op).unwrap();
        let host = &json["services"]["atproto_space_host"];
        assert_eq!(host["type"], "AtprotoPersonalDataServer");
        assert_eq!(host["endpoint"], "https://pds.example.com");
        // Coincides with the #atproto_pds endpoint.
        assert_eq!(
            host["endpoint"],
            json["services"]["atproto_pds"]["endpoint"]
        );
    }
}
