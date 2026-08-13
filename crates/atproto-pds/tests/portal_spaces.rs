//! Integration tests for administering a space from the portal.
//!
//! The browser at `/account/repository/space/…` answers "what is in this
//! space"; this section answers "who is in it and what may reach it", and the
//! controls it offers are the ones only an authority may use. These tests
//! drive the real handlers against the real service, so a control that renders
//! but does not act is a failure rather than an assertion that adapts to it.

use atproto_identity::key::KeyType;
use atproto_pds::account::{AccountDirectory, AccountManager, CreateAccountParams, portal};
use atproto_pds::http::{HttpState, build_router};
use atproto_pds::keys::{KeyStore, MemoryKeyStore};
use atproto_pds::repo::{RepoReader, RepoWriter};
use atproto_pds::space::config::{AppAccess, MintPolicy, SpaceConfig};
use atproto_pds::space::{SpaceReader, SpaceService, SpaceSync, SpaceWriter};
use atproto_space::types::SpaceUri;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use std::sync::Arc;
use tempfile::TempDir;
use tower::ServiceExt;

const OWNER: &str = "did:plc:spaceadminfixture0000000000";
const OWNER_HANDLE: &str = "owner.pds.test";
const MEMBER: &str = "did:plc:spacememberfixture000000000";
const SPACE_TYPE: &str = "app.bsky.group";
const SPACE_KEY: &str = "default";

struct Fixture {
    app: axum::Router,
    svc: Arc<SpaceService>,
    cookie: String,
    space: SpaceUri,
    _tmp: TempDir,
}

impl Fixture {
    /// The server's data directory, for tests that seed per-actor state.
    fn dir(&self) -> &std::path::Path {
        self._tmp.path()
    }
}

/// An account that owns one space, with a portal session.
async fn fixture() -> Fixture {
    let tmp = TempDir::new().unwrap();
    let dir = tmp.path().to_path_buf();
    let accounts = AccountDirectory::open(&dir.join("accounts.sqlite"))
        .await
        .unwrap();
    let key_store: Arc<dyn KeyStore> = Arc::new(MemoryKeyStore::new());
    let manager = Arc::new(AccountManager::new(
        accounts.pool().clone(),
        dir.clone(),
        key_store,
        KeyType::K256Private,
    ));
    let writer = Arc::new(RepoWriter::new(manager.clone(), dir.clone()));
    let reader = Arc::new(RepoReader::new(accounts, dir.clone()));

    let svc = Arc::new(SpaceService::with_accounts(dir.clone(), manager.clone()));
    let space_writer = Arc::new(SpaceWriter::new(manager.clone(), dir.clone()));
    let space_reader = Arc::new(SpaceReader::new(manager.clone(), dir.clone()));
    let space_sync = Arc::new(SpaceSync::new(dir.clone()));

    let state = HttpState::with_account_manager(
        reader,
        manager.clone(),
        "did:web:pds.test".to_string(),
        b"test-secret-do-not-use-in-prod-32!".to_vec(),
        false,
    )
    .with_writer(writer.clone())
    .with_spaces(svc.clone(), space_writer, space_reader, space_sync)
    .with_service_handle_domains(vec!["pds.test".to_string()]);
    let app = build_router(state);

    manager
        .create_account(CreateAccountParams::new(OWNER, OWNER_HANDLE, "pw"))
        .await
        .expect("fixture account");
    writer
        .create_genesis_commit(OWNER)
        .await
        .expect("fixture genesis");

    let info = svc
        .create_space(OWNER, SPACE_TYPE, SPACE_KEY, SpaceConfig::default())
        .await
        .expect("fixture space");
    let space = SpaceUri::parse(&info.uri).expect("fixture space uri");

    let cookie = format!("cookie-for-{OWNER}");
    portal::create_session(&manager.account_pool(), &cookie, OWNER, 0, None)
        .await
        .expect("fixture session");

    Fixture {
        app,
        svc,
        cookie,
        space,
        _tmp: tmp,
    }
}

impl Fixture {
    fn base(&self) -> String {
        format!(
            "/account/spaces/{}/{}/{}",
            urlenc(&self.space.space_did),
            urlenc(self.space.space_type.as_str()),
            urlenc(self.space.space_key.as_str())
        )
    }

    async fn get(&self, path: &str) -> (StatusCode, String, Option<String>) {
        let req = Request::builder()
            .uri(path)
            .header("sec-fetch-site", "same-origin")
            .header("cookie", format!("atproto_pds_portal={}", self.cookie))
            .body(Body::empty())
            .unwrap();
        let resp = self.app.clone().oneshot(req).await.unwrap();
        let status = resp.status();
        let location = resp
            .headers()
            .get("location")
            .and_then(|v| v.to_str().ok())
            .map(str::to_string);
        let body = String::from_utf8_lossy(&resp.into_body().collect().await.unwrap().to_bytes())
            .to_string();
        (status, body, location)
    }

    async fn post(&self, path: &str, body: &str) -> (StatusCode, Option<String>) {
        let req = Request::builder()
            .uri(path)
            .method("POST")
            .header("sec-fetch-site", "same-origin")
            .header("cookie", format!("atproto_pds_portal={}", self.cookie))
            .header("content-type", "application/x-www-form-urlencoded")
            .body(Body::from(body.to_string()))
            .unwrap();
        let resp = self.app.clone().oneshot(req).await.unwrap();
        (
            resp.status(),
            resp.headers()
                .get("location")
                .and_then(|v| v.to_str().ok())
                .map(str::to_string),
        )
    }
}

fn urlenc(s: &str) -> String {
    s.bytes()
        .map(|b| match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                (b as char).to_string()
            }
            other => format!("%{other:02X}"),
        })
        .collect()
}

#[tokio::test(flavor = "multi_thread")]
async fn the_index_separates_spaces_you_host_from_spaces_you_are_in() {
    let f = fixture().await;
    let (status, body, _) = f.get("/account/spaces").await;
    assert_eq!(status, StatusCode::OK);
    assert!(body.contains("Spaces you host"), "body: {body}");
    assert!(body.contains("Spaces you are in"), "body: {body}");
    // The owned space is listed and links into its settings page.
    assert!(
        body.contains(&f.base()),
        "the owned space should link to its settings: {body}"
    );
}

/// The settings page shows the space's current configuration, not defaults it
/// assumed.
#[tokio::test(flavor = "multi_thread")]
async fn the_settings_page_reflects_stored_configuration() {
    let f = fixture().await;
    f.svc
        .update_space(
            OWNER,
            &f.space,
            atproto_pds::space::config::SpaceConfigPatch {
                mint_policy: Some(MintPolicy::Public),
                app_access: Some(AppAccess::AllowList {
                    allowed: vec!["https://app.example/oauth-client-metadata.json".to_string()],
                }),
                managing_app: Some("did:web:manager.example#svc".to_string()),
            },
        )
        .await
        .expect("seed config");

    let (status, body, _) = f.get(&f.base()).await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        body.contains(r#"value="public" selected"#),
        "the stored mint policy should be selected: {body}"
    );
    assert!(
        body.contains(r#"value="allow-list" checked"#),
        "the stored app-access mode should be checked: {body}"
    );
    assert!(
        body.contains("https://app.example/oauth-client-metadata.json"),
        "the allow list should be shown: {body}"
    );
    assert!(
        body.contains("did:web:manager.example#svc"),
        "the managing app should be shown: {body}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn saving_the_form_changes_the_space() {
    let f = fixture().await;
    let (status, location) = f
        .post(
            &format!("{}/config", f.base()),
            "policy=managing-app&app_access=allow-list\
             &allowed=https%3A%2F%2Fone.example%2Fc.json%0Ahttps%3A%2F%2Ftwo.example%2Fc.json\
             &managing_app=did%3Aweb%3Amanager.example%23svc",
        )
        .await;
    assert_eq!(status, StatusCode::SEE_OTHER);
    assert_eq!(
        location.as_deref(),
        Some(format!("{}?msg=config-saved", f.base()).as_str())
    );

    let inputs = f
        .svc
        .load_mint_authz_inputs(&f.space, OWNER)
        .await
        .expect("read back");
    assert_eq!(inputs.config.mint_policy, MintPolicy::ManagingApp);
    assert_eq!(
        inputs.config.app_access,
        AppAccess::AllowList {
            allowed: vec![
                "https://one.example/c.json".to_string(),
                "https://two.example/c.json".to_string()
            ]
        }
    );
    assert_eq!(
        inputs.config.managing_app.as_deref(),
        Some("did:web:manager.example#svc")
    );
}

/// An allow list with nothing in it is refused rather than saved.
///
/// It is the shape the form submits when the radio is chosen and the box left
/// blank, and storing it would lock every application out of the space —
/// including the one the owner is sitting in.
#[tokio::test(flavor = "multi_thread")]
async fn an_empty_allow_list_is_refused() {
    let f = fixture().await;
    let (status, location) = f
        .post(
            &format!("{}/config", f.base()),
            "policy=member-list&app_access=allow-list&allowed=%20%0A%20&managing_app=",
        )
        .await;
    assert_eq!(status, StatusCode::SEE_OTHER);
    assert_eq!(
        location.as_deref(),
        Some(format!("{}?msg=err-allow-list-needs-an-entry", f.base()).as_str())
    );

    let inputs = f
        .svc
        .load_mint_authz_inputs(&f.space, OWNER)
        .await
        .expect("read back");
    assert_eq!(
        inputs.config.app_access,
        AppAccess::Open,
        "the space should have been left as it was"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn members_can_be_added_and_removed() {
    let f = fixture().await;

    let (status, location) = f
        .post(&format!("{}/members", f.base()), &format!("did={MEMBER}"))
        .await;
    assert_eq!(status, StatusCode::SEE_OTHER);
    assert_eq!(
        location.as_deref(),
        Some(format!("{}?msg=member-added", f.base()).as_str())
    );

    let (_, body, _) = f.get(&f.base()).await;
    assert!(
        body.contains(MEMBER),
        "the new member should be listed: {body}"
    );

    // Adding the same account twice is the owner's mistake to read, not a 500.
    let (_, location) = f
        .post(&format!("{}/members", f.base()), &format!("did={MEMBER}"))
        .await;
    assert_eq!(
        location.as_deref(),
        Some(format!("{}?msg=err-already-a-member", f.base()).as_str())
    );

    let (status, location) = f
        .post(
            &format!("{}/members/remove", f.base()),
            &format!("did={MEMBER}"),
        )
        .await;
    assert_eq!(status, StatusCode::SEE_OTHER);
    assert_eq!(
        location.as_deref(),
        Some(format!("{}?msg=member-removed", f.base()).as_str())
    );

    let page = f
        .svc
        .list_members(&f.space, None, 100)
        .await
        .expect("members");
    assert!(
        !page.members.iter().any(|m| m.did == MEMBER),
        "the member should be gone: {:?}",
        page.members
    );
}

/// The authority is a member of its own space and cannot leave it, so the row
/// carries no control rather than a button that returns an error.
#[tokio::test(flavor = "multi_thread")]
async fn the_authority_row_offers_no_remove_control() {
    let f = fixture().await;
    let (_, body, _) = f.get(&f.base()).await;
    let owner_row = body
        .split("<tr>")
        .find(|row| row.contains(OWNER))
        .expect("the authority should be listed as a member");
    assert!(
        !owner_row.contains("members/remove"),
        "the authority row should not offer removal: {owner_row}"
    );
}

/// A space the account neither hosts nor holds records in is not a page.
#[tokio::test(flavor = "multi_thread")]
async fn a_space_with_no_relationship_is_not_served() {
    let f = fixture().await;
    let stranger = format!(
        "/account/spaces/{}/{}/{}",
        urlenc("did:plc:someoneelseshost000000000000"),
        urlenc(SPACE_TYPE),
        urlenc(SPACE_KEY)
    );
    let (status, _, location) = f.get(&stranger).await;
    assert_eq!(status, StatusCode::SEE_OTHER);
    assert_eq!(
        location.as_deref(),
        Some("/account/spaces?msg=err-unknown-space")
    );
}

/// Every control here is a state change behind a cookie, so a cross-site POST
/// must not reach the service.
#[tokio::test(flavor = "multi_thread")]
async fn a_cross_site_post_is_refused() {
    let f = fixture().await;
    for path in [
        format!("{}/config", f.base()),
        format!("{}/members", f.base()),
        format!("{}/members/remove", f.base()),
    ] {
        let req = Request::builder()
            .uri(&path)
            .method("POST")
            .header("sec-fetch-site", "cross-site")
            .header("cookie", format!("atproto_pds_portal={}", f.cookie))
            .header("content-type", "application/x-www-form-urlencoded")
            .body(Body::from(format!(
                "did={MEMBER}&policy=public&app_access=open"
            )))
            .unwrap();
        let resp = f.app.clone().oneshot(req).await.unwrap();
        assert_ne!(
            resp.status(),
            StatusCode::SEE_OTHER,
            "{path} accepted a cross-site POST"
        );
    }

    let page = f
        .svc
        .list_members(&f.space, None, 100)
        .await
        .expect("members");
    assert!(
        !page.members.iter().any(|m| m.did == MEMBER),
        "a cross-site POST changed the member list"
    );
}

/// Signed-out browsers get the sign-in page, not a space.
#[tokio::test(flavor = "multi_thread")]
async fn the_section_requires_a_session() {
    let f = fixture().await;
    for path in ["/account/spaces".to_string(), f.base()] {
        let req = Request::builder()
            .uri(&path)
            .header("sec-fetch-site", "same-origin")
            .header("cookie", "atproto_pds_portal=not-a-real-session")
            .body(Body::empty())
            .unwrap();
        let resp = f.app.clone().oneshot(req).await.unwrap();
        assert_eq!(
            resp.headers().get("location").and_then(|v| v.to_str().ok()),
            Some("/account/signin"),
            "{path} served something to a request with no session"
        );
    }
}

/// An owner sees who has been reading their records, and an application that
/// proved its identity is named.
#[tokio::test(flavor = "multi_thread")]
async fn the_space_page_lists_what_has_read_your_records() {
    let f = fixture().await;
    let store = atproto_pds::actor_store::sql::SqlActorStore::open(f.dir(), OWNER)
        .await
        .expect("owner store");
    atproto_pds::space::access_log::record(
        store.pool(),
        &f.space,
        &credential_for(&f.space, Some("https://reader.example/c.json"), "k1"),
    )
    .await
    .expect("seed log");

    let (status, body, _) = f.get(&f.base()).await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        body.contains("Who has read your records"),
        "the readers section should render: {body}"
    );
    assert!(
        body.contains("https://reader.example/c.json"),
        "an attested reader should be named: {body}"
    );
    assert!(
        !body.contains("Unidentified application"),
        "an attested reader is not anonymous: {body}"
    );
}

/// A reader that did not attest is shown as unidentified, with the reason,
/// rather than as a key thumbprint that looks like a name.
#[tokio::test(flavor = "multi_thread")]
async fn an_unattested_reader_is_shown_as_unidentified() {
    let f = fixture().await;
    let store = atproto_pds::actor_store::sql::SqlActorStore::open(f.dir(), OWNER)
        .await
        .expect("owner store");
    atproto_pds::space::access_log::record(
        store.pool(),
        &f.space,
        &credential_for(&f.space, None, "thumbprint-abc"),
    )
    .await
    .expect("seed log");

    let (_, body, _) = f.get(&f.base()).await;
    assert!(
        body.contains("Unidentified application"),
        "an unattested reader should be named as such: {body}"
    );
    // The thumbprint appears in the Block control's form value, because that is
    // what identifies the row to block. What it must never be is the reader's
    // displayed name.
    assert!(
        !body.contains("<code>jkt:thumbprint-abc</code>"),
        "the DPoP thumbprint must not be rendered as an identity: {body}"
    );
    assert!(
        body.contains("only appears by name"),
        "the page should explain why it cannot say more: {body}"
    );
}

/// A member of someone else's space gets the readers list for their own
/// records — and none of the controls that belong to the authority.
#[tokio::test(flavor = "multi_thread")]
async fn a_member_sees_readers_but_no_settings() {
    let f = fixture().await;
    // A space hosted elsewhere that this account holds records in: the space
    // row in its own store is what `listSpaces` reports.
    let remote: SpaceUri = "at://did:plc:elsewherehost0000000000000/space/app.bsky.group/shared"
        .parse()
        .unwrap();
    let store = atproto_pds::actor_store::sql::SqlActorStore::open(f.dir(), OWNER)
        .await
        .expect("owner store");
    sqlx::query(
        "INSERT INTO space (uri, is_owner, is_member, created_at)
         VALUES (?, 0, 1, '2026-08-13T00:00:00Z')",
    )
    .bind(remote.to_string())
    .execute(store.pool())
    .await
    .expect("seed membership");
    atproto_pds::space::access_log::record(
        store.pool(),
        &remote,
        &credential_for(&remote, Some("https://reader.example/c.json"), "k1"),
    )
    .await
    .expect("seed log");

    let path = format!(
        "/account/spaces/{}/{}/{}",
        urlenc(&remote.space_did),
        urlenc(remote.space_type.as_str()),
        urlenc(remote.space_key.as_str())
    );
    let (status, body, _) = f.get(&path).await;
    assert_eq!(status, StatusCode::OK, "body: {body}");
    assert!(
        body.contains("Who has read your records"),
        "a member should still see who read their records: {body}"
    );
    assert!(
        !body.contains("Save settings"),
        "a member must not be offered the authority's controls: {body}"
    );
    assert!(
        !body.contains("Add member"),
        "a member must not be offered the member list: {body}"
    );
}

fn credential_for(
    space: &SpaceUri,
    client_id: Option<&str>,
    jkt: &str,
) -> atproto_space::credential::SpaceCredential {
    atproto_space::credential::SpaceCredential {
        iss: space.space_did.clone(),
        sub: space.to_string(),
        cnf: atproto_space::credential::Cnf {
            jkt: jkt.to_string(),
        },
        client_id: client_id.map(str::to_string),
        iat: 0,
        exp: 0,
        jti: "j".to_string(),
    }
}

/// A managing-app policy with no managing app named is refused.
///
/// The mint path has nowhere to ask and answers `NotAuthorized`, so saving the
/// pair produces a space that looks configured and admits nobody — the same
/// trap as an empty allow list, arrived at from the other selector.
#[tokio::test(flavor = "multi_thread")]
async fn the_managing_app_policy_needs_a_managing_app() {
    let f = fixture().await;
    let (status, location) = f
        .post(
            &format!("{}/config", f.base()),
            "policy=managing-app&app_access=open&allowed=&managing_app=%20",
        )
        .await;
    assert_eq!(status, StatusCode::SEE_OTHER);
    assert_eq!(
        location.as_deref(),
        Some(format!("{}?msg=err-managing-app-needs-a-service", f.base()).as_str())
    );

    let inputs = f
        .svc
        .load_mint_authz_inputs(&f.space, OWNER)
        .await
        .expect("read back");
    assert_eq!(
        inputs.config.mint_policy,
        MintPolicy::MemberList,
        "the space should have been left as it was"
    );
}

/// The access controls say what they do to the space, not what they are called
/// in the schema.
///
/// Each of these options gives away other people's records — the members' —
/// rather than only the owner's, and the first version of this form named the
/// mechanisms ("Anyone", "Whatever the managing app decides") in a dropdown
/// where a mis-click publishes an outline to the network. This pins the
/// consequences into the page so they cannot quietly soften back.
#[tokio::test(flavor = "multi_thread")]
async fn the_access_controls_state_their_consequences() {
    let f = fixture().await;
    let (_, body, _) = f.get(&f.base()).await;
    // Asserted against the prose rather than its line breaks: the copy is
    // wrapped for the source file, and a reflow is not a regression.
    let flat = body.split_whitespace().collect::<Vec<_>>().join(" ");

    for phrase in [
        // The public policy names its reach rather than saying "anyone".
        "readable network-wide",
        // A credential is not scoped to the requester's own records.
        "every member's records, not only their own",
        // Nor does it make anyone a member, or let them write.
        "neither adds anyone to the member list nor lets them write",
        // The managing app is asked per request, and its absence closes the
        // space rather than opening it.
        "While that service is unreachable, nobody new is admitted",
        // The two axes are ANDed, which decides whether an allow list helps.
        "both</b> must say yes",
        // An allow list excludes software that cannot identify itself, which
        // is not obvious from the option's name.
        "Software that cannot prove an identity is refused",
    ] {
        assert!(
            flat.contains(phrase),
            "the access section should say {phrase:?}: {flat}"
        );
    }
}

/// Blocking a reader refuses its next read, and unblocking restores it.
///
/// This is the only lever an account has over a credential the space authority
/// already minted: nothing revokes one, so the choice is to serve it or not.
#[tokio::test(flavor = "multi_thread")]
async fn a_blocked_reader_is_refused_and_can_be_restored() {
    let f = fixture().await;
    let store = atproto_pds::actor_store::sql::SqlActorStore::open(f.dir(), OWNER)
        .await
        .expect("owner store");
    let credential = credential_for(&f.space, Some("https://reader.example/c.json"), "k1");
    atproto_pds::space::access_log::record(store.pool(), &f.space, &credential)
        .await
        .expect("seed log");

    assert!(
        !atproto_pds::space::access_log::is_blocked(store.pool(), &f.space, &credential)
            .await
            .unwrap(),
        "nothing is blocked to begin with"
    );

    let (status, location) = f
        .post(
            &format!("{}/readers/block", f.base()),
            "identity=https%3A%2F%2Freader.example%2Fc.json",
        )
        .await;
    assert_eq!(status, StatusCode::SEE_OTHER);
    assert_eq!(
        location.as_deref(),
        Some(format!("{}?msg=reader-blocked", f.base()).as_str())
    );
    assert!(
        atproto_pds::space::access_log::is_blocked(store.pool(), &f.space, &credential)
            .await
            .unwrap(),
        "the read path should now refuse this credential"
    );

    // The row shows its state and offers the way back.
    let (_, body, _) = f.get(&f.base()).await;
    assert!(body.contains("blocked"), "the row should say so: {body}");
    assert!(
        body.contains("readers/unblock"),
        "a block must be liftable: {body}"
    );

    let (_, location) = f
        .post(
            &format!("{}/readers/unblock", f.base()),
            "identity=https%3A%2F%2Freader.example%2Fc.json",
        )
        .await;
    assert_eq!(
        location.as_deref(),
        Some(format!("{}?msg=reader-unblocked", f.base()).as_str())
    );
    assert!(
        !atproto_pds::space::access_log::is_blocked(store.pool(), &f.space, &credential)
            .await
            .unwrap()
    );
}

/// A block is scoped to the identity that was blocked, not to the space.
#[tokio::test(flavor = "multi_thread")]
async fn blocking_one_reader_leaves_the_others_served() {
    let f = fixture().await;
    let store = atproto_pds::actor_store::sql::SqlActorStore::open(f.dir(), OWNER)
        .await
        .expect("owner store");
    let blocked = credential_for(&f.space, Some("https://one.example/c.json"), "k1");
    let allowed = credential_for(&f.space, Some("https://two.example/c.json"), "k2");

    atproto_pds::space::access_log::block(store.pool(), &f.space, "https://one.example/c.json")
        .await
        .expect("block");

    assert!(
        atproto_pds::space::access_log::is_blocked(store.pool(), &f.space, &blocked)
            .await
            .unwrap()
    );
    assert!(
        !atproto_pds::space::access_log::is_blocked(store.pool(), &f.space, &allowed)
            .await
            .unwrap(),
        "another application must be unaffected"
    );
}

/// The page says what a block does not do, since the obvious reading —
/// "this application can no longer read my records" — is wrong everywhere
/// except this server.
#[tokio::test(flavor = "multi_thread")]
async fn the_page_bounds_what_blocking_achieves() {
    let f = fixture().await;
    let (_, body, _) = f.get(&f.base()).await;
    let flat = body.split_whitespace().collect::<Vec<_>>().join(" ");
    for phrase in [
        "It cannot cancel the credential it holds",
        "keeps reading every other member's records wherever those are hosted",
        "removing the account from the member list below is the stronger step",
    ] {
        assert!(
            flat.contains(phrase),
            "the page should say {phrase:?}: {flat}"
        );
    }
}
