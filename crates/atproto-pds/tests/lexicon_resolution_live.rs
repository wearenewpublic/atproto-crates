//! Live lexicon resolution against the public network.
//!
//! `#[ignore]`d: it needs DNS and the public PLC directory, so it cannot run in
//! CI or offline. Run it deliberately:
//!
//! ```sh
//! cargo test -p atproto-pds --test lexicon_resolution_live -- --ignored --nocapture
//! ```
//!
//! It exists because the unit tests in `repo::lexicon` use a stub resolver, and
//! a stub cannot show that the resolution *path* is right — the DNS name
//! construction, the DID document walk, the `com.atproto.lexicon.schema`
//! fetch, and the transitive closure over a real schema's references. This
//! resolves `app.bsky.feed.post`, which references `app.bsky.richtext.facet`
//! and several embed types, and validates a real post against it.
//!
//! It cannot run against the atpint rig, whose `PDS_DID_PLC_URL` is a private
//! local directory that does not know Bluesky's DIDs. That is a property of
//! the rig, not of the resolver.

use atproto_pds::repo::lexicon::{CatalogOutcome, NetworkLexiconResolver, resolve_catalog};
use std::sync::Arc;

fn resolver() -> NetworkLexiconResolver {
    let dns = atproto_identity::resolve::HickoryDnsResolver::create_resolver(&[]);
    let http = reqwest::Client::builder()
        .user_agent("atpint-lexicon-test")
        .timeout(std::time::Duration::from_secs(20))
        .build()
        .expect("http client");
    NetworkLexiconResolver::new(Arc::new(dns), http, "plc.directory".to_string())
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "requires DNS and the public PLC directory"]
async fn a_published_lexicon_resolves_with_its_whole_reference_closure() {
    let catalog = match resolve_catalog(&resolver(), "app.bsky.feed.post").await {
        CatalogOutcome::Ready(c) => c,
        CatalogOutcome::Unresolvable => {
            panic!("app.bsky.feed.post did not resolve; Bluesky publishes _lexicon.feed.bsky.app")
        }
        CatalogOutcome::IncompleteClosure { missing } => {
            panic!("reference closure incomplete, missing {missing}")
        }
    };

    assert!(
        catalog.get_schema("app.bsky.feed.post").is_some(),
        "the collection's own schema should be in the catalog",
    );
    // The point of the closure: a post cites facets and embeds, and validating
    // without them yields UnresolvedReference on a perfectly good record.
    assert!(
        catalog.get_schema("app.bsky.richtext.facet").is_some(),
        "a referenced schema should have been pulled in too",
    );
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "requires DNS and the public PLC directory"]
async fn a_real_post_validates_against_the_resolved_schema() {
    let CatalogOutcome::Ready(catalog) = resolve_catalog(&resolver(), "app.bsky.feed.post").await
    else {
        panic!("app.bsky.feed.post did not resolve")
    };
    let schema = catalog
        .get_schema("app.bsky.feed.post")
        .expect("schema in catalog")
        .clone();

    let record = serde_json::json!({
        "$type": "app.bsky.feed.post",
        "text": "a perfectly ordinary post",
        "createdAt": "2026-01-01T00:00:00.000Z",
    });
    atproto_lexicon::validation::validate::validate_record_with_schema(
        &record,
        &schema,
        catalog.as_ref(),
        atproto_lexicon::validation::flags::ValidateFlags::default(),
    )
    .expect("a valid post should validate against the published schema");
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "requires DNS and the public PLC directory"]
async fn a_malformed_post_is_rejected_by_the_resolved_schema() {
    let CatalogOutcome::Ready(catalog) = resolve_catalog(&resolver(), "app.bsky.feed.post").await
    else {
        panic!("app.bsky.feed.post did not resolve")
    };
    let schema = catalog
        .get_schema("app.bsky.feed.post")
        .expect("schema in catalog")
        .clone();

    // `createdAt` is required by the schema. Without validation this record is
    // accepted and the defect surfaces wherever it is read.
    let record = serde_json::json!({
        "$type": "app.bsky.feed.post",
        "text": "missing createdAt",
    });
    let err = atproto_lexicon::validation::validate::validate_record_with_schema(
        &record,
        &schema,
        catalog.as_ref(),
        atproto_lexicon::validation::flags::ValidateFlags::default(),
    )
    .expect_err("a post without createdAt should be rejected");
    let msg = err.to_string();
    assert!(
        msg.contains("createdAt"),
        "the error should name the missing field, got: {msg}",
    );
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "requires DNS and the public PLC directory"]
async fn an_unpublished_collection_is_not_a_known_lexicon() {
    // Nobody publishes `_lexicon.invalid.example`, so this is the shape that
    // makes `validate: true` a refusal rather than a check.
    assert!(matches!(
        resolve_catalog(&resolver(), "com.example.invalid.nothing").await,
        CatalogOutcome::Unresolvable
    ));
}
