//! Resolving a `com.atproto.repo.strongRef`.
//!
//! A strongRef is `(uri, cid)`, and the CID is the entire reason it is worth
//! embedding: a record fetched at that pair is immutable, so a cache keyed on
//! it can never go stale. The resolver used to pass `None` for the CID and
//! discard the one that came back, which turns "I fetched what this reference
//! names" into "I fetched what was at this address".

use std::collections::HashMap;
use std::sync::Arc;

use anyhow::Result;
use async_trait::async_trait;
use atproto_client::record_resolver::record_cid;
use atproto_client::{HttpRecordResolver, RecordResolver};
use atproto_identity::model::{Document, Service};
use atproto_identity::traits::IdentityResolver;
use serde::Deserialize;

mod support;
use support::{Reply, Scripted};

/// A well-formed `did:plc`, because `ATURI` validates the authority and a
/// placeholder would fail parsing rather than the check under test.
const AUTHORITY: &str = "did:plc:cbkjy5n7bk3ax2wplmtjofq2";

/// A resolver that points every DID at one host.
struct OneHost(String);

#[async_trait]
impl IdentityResolver for OneHost {
    async fn resolve(&self, subject: &str) -> Result<Document> {
        Ok(Document {
            context: vec![],
            id: subject.to_string(),
            also_known_as: vec![],
            service: vec![Service {
                id: format!("{subject}#atproto_pds"),
                r#type: "AtprotoPersonalDataServer".to_string(),
                service_endpoint: self.0.clone(),
                extra: HashMap::new(),
            }],
            verification_method: vec![],
            extra: HashMap::new(),
        })
    }
}

#[derive(Debug, Deserialize, PartialEq)]
struct Note {
    text: String,
}

fn a_record() -> serde_json::Value {
    serde_json::json!({"$type": "app.test.note", "text": "pinned"})
}

fn envelope(value: &serde_json::Value, claimed_cid: &str) -> String {
    serde_json::json!({
        "uri": format!("at://{AUTHORITY}/app.test.note/abc"),
        "cid": claimed_cid,
        "value": value,
    })
    .to_string()
}

/// The CID travels in the query, so the server is asked for that version.
#[tokio::test]
async fn a_pinned_resolution_asks_for_the_version_it_names() {
    let record = a_record();
    let cid = record_cid(&record).expect("cid");
    let server = Scripted::start(vec![Reply::new(
        200,
        Box::leak(envelope(&record, &cid).into_boxed_str()),
    )])
    .await;

    let resolver = HttpRecordResolver::new(
        reqwest::Client::new(),
        Arc::new(OneHost(server.base_url.clone())),
    );

    let note: Note = resolver
        .resolve_pinned(&format!("at://{AUTHORITY}/app.test.note/abc"), &cid)
        .await
        .expect("resolve");
    assert_eq!(note.text, "pinned");

    let request = &server.requests().await[0];
    assert!(
        request.request_line.contains(&format!("cid={cid}")),
        "{}",
        request.request_line
    );
}

/// The test that makes the feature a guarantee rather than a query parameter.
///
/// A server that ignores `cid` and answers with the current version is caught,
/// because the check recomputes the CID over what actually arrived. Note the
/// envelope still *claims* the requested CID -- comparing against that field
/// would compare the server's claim to itself and pass.
#[tokio::test]
async fn a_server_that_ignores_the_pin_is_caught() {
    let asked_for = record_cid(&a_record()).expect("cid");
    let served = serde_json::json!({"$type": "app.test.note", "text": "edited since"});

    let server = Scripted::start(vec![Reply::new(
        200,
        Box::leak(envelope(&served, &asked_for).into_boxed_str()),
    )])
    .await;

    let resolver = HttpRecordResolver::new(
        reqwest::Client::new(),
        Arc::new(OneHost(server.base_url.clone())),
    );

    let error = resolver
        .resolve_pinned::<Note>(&format!("at://{AUTHORITY}/app.test.note/abc"), &asked_for)
        .await
        .expect_err("the pin was not honoured");

    assert!(
        error.to_string().contains("error-atproto-client-http-6"),
        "{error}"
    );
}

/// A record carrying a `cid-link` still computes the CID the repository did.
///
/// AT Protocol's JSON spells a link as `{"$link": …}`. Encoding that as an
/// ordinary map would give different bytes and therefore a different CID, so
/// every pinned resolution of a record with a link would fail -- and the
/// failure would read as a lying server.
#[test]
fn a_cid_link_is_hashed_as_a_link_and_not_as_a_map() {
    let subject = "bafyreie5cvv4h45feadgeuwhbcutmh6t2ceseocckahdoe6uat64zmz454";
    let record = serde_json::json!({
        "$type": "app.test.note",
        "subject": {"$link": subject},
    });

    let through_json = record_cid(&record).expect("cid");

    // What the repository computes: the same value in the data model, with a
    // real link rather than a map.
    let mut map = std::collections::BTreeMap::new();
    map.insert(
        "$type".to_string(),
        atproto_dasl::Ipld::String("app.test.note".to_string()),
    );
    map.insert(
        "subject".to_string(),
        atproto_dasl::Ipld::Link(atproto_dasl::Cid(subject.parse().expect("cid"))),
    );
    let expected = atproto_dasl::cid::compute_cid(
        &atproto_dasl::to_vec(&atproto_dasl::Ipld::Map(map)).expect("encode"),
    )
    .to_string();

    assert_eq!(through_json, expected);
}

/// The unpinned path is unchanged: no `cid` asked for, none checked.
#[tokio::test]
async fn an_unpinned_resolution_is_unchanged() {
    let record = a_record();
    let server = Scripted::start(vec![Reply::new(
        200,
        Box::leak(envelope(&record, "bafysomethingelse").into_boxed_str()),
    )])
    .await;

    let resolver = HttpRecordResolver::new(
        reqwest::Client::new(),
        Arc::new(OneHost(server.base_url.clone())),
    );

    let note: Note = resolver
        .resolve(&format!("at://{AUTHORITY}/app.test.note/abc"))
        .await
        .expect("resolve");
    assert_eq!(note.text, "pinned");

    let request = &server.requests().await[0];
    assert!(
        !request.request_line.contains("cid="),
        "{}",
        request.request_line
    );
}
