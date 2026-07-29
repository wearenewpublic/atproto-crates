# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]
### Security
- `atproto-pds`: anyone could claim any DID. `createAccount` took no request parts at all — it could
  not read a header if it wanted to — and used a caller-supplied `did` verbatim. An attacker got a
  session bound to the victim's identity, had this server answer `describeRepo`, `getRepo` and
  firehose events for it, and permanently denied the victim an inbound migration here. Forged commits
  fail relay signature verification, so the damage was bounded; the lockout was not.

  A caller-supplied DID now requires an inbound service-auth token issued by that DID's **current**
  host: `iss` is the DID being claimed, `aud` is this server, `lxm` is `com.atproto.server.
  createAccount`, and the signature is checked against the `#atproto` key in the DID's own document,
  fetched live. Only whoever controls that identity today can move it here. This is also the first
  canonical endpoint on this server to accept an inbound service-auth token at all — `verify_service_
  auth` previously had two callers, both in Spaces.

  **There is no way to switch this off.** An escape hatch would be set on exactly the deployments
  that most need the check.

  A verified inbound migration now lands **deactivated**, as the canonical sequence requires —
  create → import → `submitPlcOperation` → activate. Landing active meant the repository was
  publicly readable and emitting firehose events before the DID document pointed here, and left
  `activateAccount` with nothing to gate.

  `reserveSigningKey` is session-gated and idempotent. Unauthenticated, it generated a fresh keypair
  on every call and wrote a reservation row for whatever `did` the caller named — unbounded key
  generation and reservation squatting for anyone who could reach it. Worse, the row id was a
  millisecond timestamp, so the first reservation was kept while every subsequent call handed back a
  *different* key: the key returned and the key reserved diverged after the first request. A repeat
  call now returns the key already reserved, and a caller may only reserve against its own DID.

- `atproto-pds`: a takedown did almost nothing. Account state was enforced on two public read paths
  and nowhere else, so a moderation action removed record-level reads while the account's complete
  repository CAR, its raw blocks and every blob stayed anonymously downloadable — and the account
  kept writing, kept refreshing its session, and could restore itself with one unprivileged call.
  Five findings, one sentence.
  - **Reads.** `getRepo`, `getBlocks`, `getBlob`, `listBlobs`, `getLatestCommit` and `describeRepo`
    had no state check at all; the sync and blob files contained no reference to `AccountState` of
    any kind. All nine public read paths now share one gate and answer with the errors their
    lexicons declare — `RepoTakendown`, `RepoSuspended`, `RepoDeactivated` — which were previously
    unreachable on the five endpoints that declare them. `getRecord` and `listRecords` move from a
    generic `403 Forbidden` to the same named errors, so a caller branching on state needs one
    branch rather than one per endpoint.
  - **Writes.** `AccountState::allows_writes` existed with no caller anywhere, and the write guard
    never read account state. A taken-down account kept writing records and publishing firehose
    commits until its refresh token expired — up to 90 days after the moderation action.
  - **Refresh.** Neither `refreshSession` nor the OAuth refresh grant looked at state;
    `refreshSession` already had the account row in hand and read only its `did`. Without this the
    write gate is bounded by a 90-day token rather than by the moderation decision.
  - **Activation.** `activateAccount` called `set_state(Active)` unconditionally, so an admin
    takedown was reversible by its subject. Deactivation stays self-service — it is a pause the user
    chose, and the inbound-migration flow depends on undoing it.
  - **Storage.** Both blob handlers opened the per-actor store before any check, and
    `SqlActorStore::open` runs `create_dir_all` and migrations, so an unauthenticated caller could
    materialise a SQLite file for every DID it cared to invent. The gate now runs first.

  **Deactivated accounts can no longer perform ordinary writes**, which matches `allows_writes` and
  the reference. `importRepo`, `uploadBlob` and `listMissingBlobs` deliberately still work while
  deactivated: inbound migration is prescribed as create → deactivate → import → upload → activate,
  so refusing those would make the ordinary migration path impossible. Moderated states are refused
  there too — a taken-down account must not import a repository either.

  This hides a taken-down account's data; it does not erase it. `deleteAccount` still performs no
  data erasure, so a "deleted" account's repository and blobs remain on disk behind these gates.

- `atproto-pds`: the spaces client-attestation path dereferenced attacker-named URLs with no
  restriction, making the endpoint a request generator pointed wherever a caller liked — a cloud
  metadata service, an internal admin port, a neighbour on the same host. Three fetches, on one
  attacker-controlled input:
  - the attestation's `client_id`, checked only for an `https://` prefix, which stops none of the
    above;
  - the `jwks_uri` from the document that fetch returns, checked not at all;
  - and, from the same `client_id`, the recipient resolver's `.well-known/atproto-did` lookup and
    the DID-document fetch behind it — a pair the finding does not name.

  All three now pass `atproto_identity::validation::validate_service_endpoint`, the same policy the
  OAuth client-metadata path has used since the PAR fixes: HTTPS only, no address literal in any
  form a resolver accepts, no embedded userinfo, no port but 443, and the reserved `.localhost`,
  `.internal`, `.arpa` and `.local` suffixes refused. The recipient resolver falls back to a stub on
  any failure, so a refusal is logged at WARN — otherwise a guarded host and an unreachable one are
  indistinguishable, including to whoever is debugging it.

  **This is a syntactic guard.** It performs no DNS resolution, so it does not defend against
  rebinding, nor against a public name whose A record points at a private address. It is the layer
  this workspace has, not a complete SSRF control.

  Operators running a spaces deployment against client metadata on an IP literal, a non-443 port, or
  a `.localhost` host will find those attestations now refused.

- `atproto-pds`: the single secret guarding every admin verb was comparable by timing, guessable
  without limit, and — in any deployment that had not set `PDS_PRODUCTION=true` — published in this
  repository. Three defects on one door:
  - **Non-constant-time compare.** `admin/handlers.rs` and `admin/dashboard.rs` used `!=` on `&str`,
    which short-circuits at the first differing byte, so rejection time revealed how much of the
    prefix was right. Both now go through one shared `secret_eq`, which MACs each side under a
    per-call key and compares through HMAC's verifier — constant-time in the contents and
    independent of length, so neither the password nor its size leaks.
  - **No rate limit.** An attacker who can guess without limit does not need a side-channel at all.
    Both surfaces now pass through the existing sliding-window limiter before comparing.
  - **A live default password.** `admin-default-CHANGE-ME` is a constant in this crate, and it was
    refused only when `PDS_PRODUCTION=true` — so *forgetting* the flag selected the insecure branch.
    Startup now refuses the sentinel everywhere unless `PDS_ALLOW_DEV_DEFAULTS=true` says the
    deployment is unreachable by anyone else, and that opt-in cannot be combined with
    `PDS_PRODUCTION`.

  **Operators and developers:** a PDS with no `PDS_ADMIN_PASSWORD` set now fails to start. Set a real
  password, or set `PDS_ALLOW_DEV_DEFAULTS=true` for a local instance. This is deliberate — absence
  of configuration used to fail open.

- `atproto-pds`: an uploaded blob could render as a document on this origin — stored XSS against the
  authorization server. `com.atproto.sync.getBlob` set only `Content-Type`, echoing the MIME the
  uploader declared in its request header, which is neither validated nor sniffed. Upload
  `text/html`, get someone to open the blob URL, and the script runs on the origin that also serves
  the OAuth consent screen and its session cookies — which chains straight into account takeover.

  `getBlob` now sends the same three headers `space.getBlob` has always sent: `nosniff`, so a
  browser does not second-guess a benign declared type; `content-disposition: attachment`, so the
  response downloads rather than renders; and `default-src 'none'; sandbox`, so anything rendered
  regardless can do nothing. The MIME is still unvalidated — sniffing it is a separate change — but
  it can no longer be turned into script on this origin.

- `atproto-pds`: password-reset and account-deletion tokens were written to the application log at
  INFO, in the only build that shipped. `EmailService::Disabled::send` logged the full rendered body,
  and that body carries the confirmation URL for password reset, account deletion and email change.
  The stub is meant for development and says so — but the published image always selected it,
  because `smtp` is not a default feature and the Dockerfile did not ask for it. Logs are routinely
  lower-trust than the credential store they were protecting: shipped to aggregators, mounted into
  sidecars, swept up by crash reporters. Anyone who could read one could complete a reset for any
  account on the instance.

  The body is no longer logged. The recipient and subject still are, so an operator can see that a
  send was attempted and to whom. `PDS_EMAIL_LOG_BODIES=true` restores the body for local
  development — at DEBUG, never INFO — and warns at startup, in as many words, that anyone who can
  read the log can take over any account.

  The image now builds with `smtp`, so it can deliver mail at all; `lettre` was already pinned to
  rustls, so no OpenSSL enters the runtime image. When SMTP is unconfigured the service now warns at
  startup rather than noting it at INFO, because an unconfigured mailer means `requestPasswordReset`
  and `requestAccountDelete` return success and send nothing — a failure the caller cannot see.

- `atproto-pds`: closed an authorization-code exfiltration chain ending in full account takeover.
  Three defects composed, and the compromise was invisible to the victim because the `client_id`
  shown on the consent screen was genuine:
  - **`redirect_uri` was never validated.** PAR stored whatever the caller sent and the consent page
    navigated to it, so an authorization code issued for a trusted client could be delivered to an
    attacker's destination. PAR now resolves the client's metadata and requires the requested
    redirect to be one the client published, compared for exact equality per RFC 6749 §3.1.2.3.
  - **The token endpoint required no proof of possession.** A stolen code or a leaked refresh token
    was redeemable by whoever held it. Both grants now require a DPoP proof bound to the token
    endpoint (RFC 9449 §5 — no `ath`, since no access token exists yet), with the proof's `jti`
    recorded against replay.
  - **The caller chose its own `cnf.jkt`.** `token.rs` preferred a request-body `dpop_jkt` over the
    thumbprint pinned at authorization, so an attacker redeeming a stolen code received a token
    DPoP-bound to their own key — DPoP was decorative. The binding now comes from the signed proof
    and nothing else; the `dpop_jkt` request field is gone. When authorization pinned a thumbprint
    the proof must match it, and a refresh token is usable only by the key it is bound to.

  This chain was unexploitable in practice only because of the encoding bug fixed below, which is
  why the two ship together: fixing the encoding alone would have converted an unreachable defect
  into a reachable one.

  Client metadata is fetched from an unauthenticated caller's URL, so both that fetch and any
  `jwks_uri` reached through it are gated by
  `atproto_identity::validation::validate_service_endpoint`, which rejects non-HTTPS schemes,
  address literals in every resolver-accepted form, embedded userinfo, non-443 ports and reserved
  suffixes. The guard is syntactic and does not defend against DNS rebinding.

- `atproto-pds`: service auth could mint an unrestricted cross-service credential. Any authenticated
  account could call `getServiceAuth` with no `lxm` and receive a token scoped to nothing — which
  satisfies every method a receiving service gates by one — for up to ten minutes, with no
  protected-method, privileged-method or takedown gate, and no way to revoke it. The only thing
  keeping that from working against real peers was a wrong `typ` header, which is fixed in the same
  change; fixing the header alone would have made it live. Now:
  - `PROTECTED_METHODS` (16 account-management NSIDs) can never be reached through service auth.
  - `PRIVILEGED_METHODS` — `com.atproto.server.createAccount`, the migration credential, and the
    `chat.bsky.*` namespace — require a privileged session.
  - A taken-down account may mint only `com.atproto.server.createAccount`, so a takedown cannot
    strand an account but cannot be worked around either.
  - Inbound verification requires `lxm` to be present *and* match. Previously it compared only when
    the claim happened to be there.
  - `com.atproto.admin.revokeServiceAuth` now takes effect. It wrote a blacklist row that no
    verifier read, so an operator revoking a leaked token got 200 OK and nothing happened — a
    security control that reads as working is worse than an absent one.

### Fixed
- `atproto-pds`: no route sent CORS headers, so no browser client worked. A browser OAuth client runs
  on some other origin; without `Access-Control-Allow-Origin` the browser refuses to hand it the
  response body, so discovery failed before the authorization request was attempted — and had it got
  past that, every XRPC call would have failed the same way.

  `CorsLayer` now covers the whole surface: the four discovery documents, the OAuth endpoints, and
  the XRPC routes. The finding scopes this to discovery and OAuth, but a client that completes the
  token exchange and then cannot call a single method is still blocked, so the fix follows the
  consequence rather than the letter.

  The policy is `Allow-Origin: *` with **no** `Allow-Credentials`. That is safe precisely because
  AT Protocol authenticates with `Authorization` and `DPoP` request headers and never with cookies:
  a browser attaches neither cross-origin unless the calling script sets them, and a script that can
  set them already holds the token — so the wildcard grants a hostile page nothing it could not get
  by calling this server from its own backend. `Allow-Credentials: true` is the switch that would
  change that, by making the browser send ambient credentials and hand over the response; combined
  with a wildcard origin it is also forbidden by the Fetch standard. It is deliberately absent and a
  test fails if it ever appears.

  `dpop-nonce`, `WWW-Authenticate` and `atproto-repo-rev` are exposed, since a client cannot read a
  response header it was not told about and each of those exists to be acted on.

- `atproto-identity`: P-256 and P-384 signatures were not low-S normalized, and verification accepted
  the high-S form. ECDSA signatures are malleable — for every valid `(r, s)` the pair `(r, -s)`
  verifies just as well — and AT Protocol requires the canonical low-S form. `k256` normalizes inside
  its own signing primitive, which is why K-256 account keys were never affected; `p256` and `p384`
  ship an empty `SignPrimitive` impl, so nothing normalized theirs.

  Measured rather than assumed: signing 64 times with a fresh P-256 key produced **27 high-S
  signatures**, a coin flip as predicted. A peer enforcing low-S rejects each of those, so a P-256
  key was failing roughly half its signatures at random, permanently.

  `sign` now normalizes for all three curves, and `validate` refuses a high-S signature outright
  (`error-atproto-identity-key-14`) rather than accepting either form. Accepting both was the second
  half of the problem: anyone holding a valid signature could derive a different byte string that
  also verified, so "the signature over this commit" was not a unique value — which is exactly what
  anything content-addressing or deduplicating a signature relies on.

  This is a published library other projects sign with, so the blast radius was never limited to this
  PDS. **Verification is now stricter**: a high-S signature produced by an older version of this
  crate, or by another implementation that does not normalize, is rejected where it used to pass.

- `atproto-pds`: five admin request/response shapes did not match their lexicons, so a canonical
  client failed against every one of them. Verified against the published schemas rather than
  against the report's summary, which surfaced two things the report does not mention.
  - **`com.atproto.admin.defs#accountView`** requires `did`, `handle` and `indexedAt`, and declares
    no `createdAt`. This server emitted `createdAt` and `state` and omitted `indexedAt`, so a
    validating client rejected every account it described. There is now one `AccountView` used by
    `getAccountInfo`, `getAccountInfos` **and `searchAccounts`** — the last returns `accountView`
    refs too, and had its own separate struct with the same defect, which a fix aimed only at the
    first two would have left in place.
  - **`searchAccounts`** declares `email`, `limit` and `cursor` — and no `q`. It required an
    undeclared `q` and ignored `email`, so a conformant caller got a 400 and an operator's `email=`
    was silently dropped. `limit` now defaults to the declared 50 rather than 25.
  - **`updateAccountEmail`** names the account `account`, typed `at-identifier`. This server read
    `did` — a hard deserialization failure for a canonical request — and accepted only a DID. It now
    reads `account` and resolves a handle as readily as a DID.
  - **`sendEmail`** requires `senderDid` and leaves `subject` optional. This server had no
    `senderDid` at all and required `subject`. Both corrected, and the declared `comment` field is
    accepted; a message with no subject gets a neutral one rather than a rejection.
  - **`disableAccountInvites` / `enableAccountInvites`** are `com.atproto.admin.*`, not
    `com.atproto.server.*`, and name their subject `account`. Moved and renamed; the optional `note`
    is accepted.

  **These are breaking wire changes**, deliberately without aliases: the old spellings were
  unreachable by any conformant client, so nothing standards-compliant regresses. Callers of the old
  shapes must move to the canonical field names and the two relocated routes. The bundled
  `atproto-pds-admin` CLI is updated with them.

- `atproto-pds`: the 16 MiB blob ceiling was dead code — the real limit was axum's 2 MiB default, so
  a typical phone photo failed to upload and inbound migration failed for any non-trivial
  repository. `uploadBlob` and `importRepo` extracted `axum::body::Bytes`, which applies
  `DEFAULT_LIMIT = 2_097_152` unless a body-limit layer says otherwise, and no layer existed. The
  refusal was `text/plain` — `Failed to buffer the request body: length limit exceeded` — not the
  XRPC error shape every other failure on that surface uses, so a client's error handling never saw
  it. `README.md` meanwhile told operators to size their reverse proxy for bodies over 1 GiB while
  the application rejected at 2 MiB.

  Both handlers now take the body and buffer it under a ceiling of their own, so the limit is the
  one the operator configured and an over-sized request is refused as `BlobTooLarge` or
  `RepoTooLarge` with a JSON body. Two knobs, neither feature-gated so both work in the shipped
  image: `PDS_BLOB_UPLOAD_LIMIT` (default 16 MiB) and `PDS_IMPORT_LIMIT` (default 1 GiB, matching
  what the README asks of the proxy). `MAX_BLOB_BYTES` was a `const` no operator could change; it is
  now `DEFAULT_BLOB_UPLOAD_LIMIT_BYTES`, a default, and `put_blob` takes the limit as an argument
  rather than reading a global.

  Per-account blob quotas remain unimplemented.

- `atproto-pds`: the OAuth token binding is no longer optional in the type system. `issue_pair` took
  `Option<String>` and stored an absent thumbprint as an empty string, which came back as
  `cnf.jkt = ""` and matched no proof for the life of the session — a permanent `InvalidDpopProof`
  with no way out. That path stopped being reachable when the token endpoint began requiring a DPoP
  proof of every grant, so the defect is already closed; what remained was a trap, where a future
  caller passing `None` would silently re-create it with no error at the point of the mistake. The
  parameter is now `&str`, `cnf` is unconditional, and `token_type` is the constant `"DPoP"`. No wire
  change — every token this server issues was already DPoP-bound.

- **The release build was broken, so the container could not be built at all.** Seven crates derived
  `Debug` under `#[cfg_attr(any(debug_assertions, test), ...)]`, which makes a public type implement
  the trait in a debug build and not in a release one. `atproto-pds` derives `Debug` on a struct
  holding a `BlobRef`, so `cargo build --release` failed on `atproto_record::lexicon::Blob doesn't
  implement std::fmt::Debug` — the Dockerfile's exact command. Tests, clippy and CI all run the dev
  profile, so nothing ever exercised it.

  `Debug` is now unconditional across all 60 sites in the seven crates. A published type that
  implements a trait only in debug builds is a latent break for every downstream consumer, not just
  this workspace. CI gains a `cargo check --release` step using the Dockerfile's own feature set, so
  an unbuildable image fails the build rather than the release.

- `atproto-pds`: the firehose named records without shipping them. `#commit.blocks` is a required
  `bytes` field the lexicon describes as a CAR rooted at the commit block, and it was zero bytes —
  no CAR was ever built, because `car_export` was reachable only from `getRepo` and `getBlocks`.
  A consumer learned that a record had changed and had to come back over XRPC to learn what it
  said, which makes the stream a notification feed rather than the thing federation runs on.
  `#sync.blocks` had the matching gap: it once carried a block *count*, and since the previous
  release a well-typed empty byte string.

  Both now carry a real CARv1. `RecordingBlockStorage` wraps the storage the MST writes through and
  keeps every block written during the commit, so the diff is captured by construction — the writer
  puts exactly the record blocks and MST nodes the commit creates — rather than re-derived
  afterwards by comparing two trees. Recording alone over-collects, because a multi-operation batch
  rewrites intermediate MST nodes the final root never references, so the recorded set is filtered
  to what the new commit can reach. Blocks the commit did not write are left out even when
  reachable: the consumer already has them, and that is what makes this a diff rather than a
  snapshot. `#sync` carries the commit block alone, which is what a consumer needs to re-anchor.

  **This is not the Sync 1.1 covering proof.** A proof also carries the blocks needed to verify the
  prior state of each touched key, so a consumer can check the operation inductively without
  holding the repository; that is a separate piece of work, and the vendored
  `firehose/commit-proof-fixtures.json` describes that larger block set. Until it lands, consumers
  that verify inductively will still reject these frames. Consumers that trust the PDS can now read
  the records off the stream. `blobs` also remains empty.

- `atproto-pds`: `seq` numbered a repository rather than the stream, so the firehose cursor meant
  nothing. `outbox.seq` was an `AUTOINCREMENT` column inside each per-actor database, which made
  every account's first event `seq = 1` — two repositories were handed the same number, a resuming
  relay could not tell those events apart, and a repository created after a subscriber connected
  restarted at 1 and had its entire history discarded as already-seen. The subscriber loop then
  drained one account's outbox fully before touching the next, so frames left out of order even
  where the numbers happened to differ.

  There is now one ordered event log for the whole server, in the accounts database — which is
  opened under every storage profile, so a single schema serves both the SQLite and fjall
  deployments. `seq` is allocated by the INSERT into that log, which is what makes it monotonic:
  allocation order *is* commit order. Handing out globally-unique numbers over per-actor storage
  would not have been enough, because a subscriber merging those rows can still observe a later
  number before an earlier one commits.

  `subscribeRepos` accordingly tails one log with one cursor. Three limits disappear with the
  per-account bookkeeping: a connection no longer covers at most 1000 accounts, an account created
  after a subscriber connects now appears without reconnecting, and the per-account outbox is no
  longer reopened on every poll tick. `?did=` remains as a filter over the stream and does not
  renumber it, so a filtered subscriber's cursor stays valid against the unfiltered stream.

  One trade is deliberate: a `#commit` is no longer written in the same transaction as the commit
  it describes, because the repository lives in a per-actor store and the log is server-global. The
  event is published only once the commit is durable, so a crash between the two loses an event
  rather than announcing one that never happened — the case `#sync` and `getRepo` re-anchoring
  exist to repair. The reference implementation splits them the same way.

  The per-actor `outbox` table is left in place but is no longer written or read; dropping it is a
  separate change.

- `atproto-pds`: no relay could consume this server's firehose. `com.atproto.sync.subscribeRepos`
  publishes a closed union — a subscriber decodes each frame against `#commit`, `#sync`, `#identity`
  or `#account` and rejects anything matching none of them — and every frame this server emitted
  matched none. Two defects, which is why they ship together:
  - **The body was an envelope, not the event.** Frames carried
    `{seq, repo, time, payload: {…}}`, wrapping the event inside a `payload` field the lexicon does
    not declare, while none of the eight required `#commit` fields (`rebase`, `tooBig`, `commit`,
    `rev`, `since`, `blocks`, `ops`, `blobs`) appeared at the level a decoder reads them. Bodies are
    now the lexicon shape itself, with only `seq` and `time` — which belong to the delivery, not the
    event — spliced in when the frame is built.
  - **Bodies round-tripped through JSON.** JSON has no link type and no byte-string type, so the two
    types this union depends on could not survive storage: `commit` and each `ops[].cid` arrived as
    text where a decoder expects a CBOR tag-42 link, and `blocks` could not be represented at all.
    Bodies are now stored and spliced as DAG-CBOR throughout, so a link stays a link.

  `blocks` is present, well-typed and empty pending the commit path building a CARv1 slice; a test
  pins that so the remaining gap stays visible rather than reading as complete. Also corrected along
  the way: `#sync` was emitting `head` (not a field of the event) and a block *count* where the
  lexicon specifies a CARv1; `#account` emitted `status: "active"` where the field is optional and
  must be omitted for an active account; `#commit` emitted `data` (not a field) and omitted `since`,
  which is required-and-nullable and tells a resuming subscriber where the gap starts.

  The existing unit tests passed throughout because they asserted the envelope they were given —
  `body["payload"]["rev"]` — rather than the lexicon. The new conformance harness checks bodies
  against the published `subscribeRepos` schema.

- `atproto-pds`: AppView proxying was non-functional as routed, so no Bluesky client worked against
  this server. The route `/xrpc/app.bsky.{*nsid}` captures only what follows the literal prefix, so
  `app.bsky.feed.getTimeline` arrived as `feed.getTimeline`. The default-pin test
  `nsid.starts_with("app.bsky.")` could therefore never match — every unheadered call returned 503 —
  and a headered one forwarded to `{appview}/xrpc/feed.getTimeline` with the query string dropped
  entirely. The NSID and query now come from the original request URI.

  The unit tests passed throughout because they called `resolve_target` with a hand-written full
  NSID rather than routing a request. The new tests go through the real router and assert what a
  stand-in upstream actually receives.

### Added
- `atproto-pds`: `Atproto-Proxy: <did>#<service-id>` now resolves the named DID's document and
  forwards to the service carrying that fragment, instead of refusing every DID except the
  operator-pinned AppView. This is what makes labelers, feed generators, chat and Ozone reachable.
  Endpoints are read through `Document::service_endpoint_validated`, so an attacker-supplied DID
  cannot direct the server at an internal address; resolutions are cached with a five-minute TTL,
  negative results included, so a bad header cannot drive one outbound request per inbound one.
- `atproto-pds`: routes for `chat.bsky.*`, `tools.ozone.*` and `com.atproto.label.*`.
  `com.atproto.label.` specifically rather than `com.atproto.`, which would shadow the many methods
  served locally.
- `atproto-pds` / `atproto-dasl`: records were DAG-CBOR-encoded straight from JSON, so a record
  containing a blob ref hashed to a CID no other implementation computes. The AT Protocol data model
  has one shape and two encodings: DAG-CBOR expresses links and byte strings directly, while JSON
  spells them `{"$link": …}` and `{"$bytes": …}`. Handing a `serde_json::Value` to the encoder stored
  a literal map with a reserved key where a link belonged, and passed floats through even though the
  data model has no floating-point type.

  New `atproto_dasl::atproto_json` reads the JSON representation into the data model and renders it
  back: `$link` becomes a link, `$bytes` a byte string, an integral number an integer whether it was
  written `123` or `123.0`, and a fractional number is refused. Malformed sentinels — a non-string
  value, a bogus CID, an extra key alongside the reserved one — are refused rather than guessed at.
  The record read path renders the inverse, so a record comes back in the shape it went in.

  All three `data-model` interop fixtures now match, up from one. The two vendored-but-unused
  `data-model-valid` and `data-model-invalid` fixture files are now wired as harnesses too.
- `atproto-repo`: the MST write path never built subtrees, so every repository was a single node
  and every root CID was wrong at any realistic size. A key's layer is fixed by its hash — `sha256`,
  leading zero bits, in pairs — and `key_height` computed it correctly and then discarded it
  (`let _target_height = …`). `insert_recursive` never called itself and never set `l` or `t`.
  Keys reach layer ≥ 1 with probability 1/4, so a repository of a dozen records already diverged.

  Insert is now height-aware: a key at the node's layer slots in, splitting any subtree that spans
  its position; a key below descends, creating intermediate layers as needed; a key above splits the
  existing tree and becomes a new root over both halves. Delete recurses, merges the subtrees a
  removed leaf leaves adjacent, and trims layers that no longer hold a key.

  **All six upstream commit-proof vectors now pass, before and after commit** — the first time this
  workspace has produced MST roots a peer can recompute. They were red through the encoding fix in
  0.15.0-rc.2 and stayed red: F-REPO-01 corrected the node bytes and F-REPO-04 the tree shape, and
  neither alone moved a single vector.

  Two read paths changed with it. `get` descended on a height heuristic that only worked when no
  subtree existed; it now follows the structural position. `delete` recurses, where it previously
  ignored `l` and `t` entirely — harmless while nothing built them, silent data loss the moment
  anything did.
- `atproto-repo`: `Mst::delete` silently corrupted neighbouring records. MST entries are
  prefix-compressed against the full key of the preceding entry, so removing one changes the base
  its successor was encoded against. Repairing that needs two steps in order — reconstruct the
  successor's key against the entry being deleted, then re-compress against the entry before that —
  and `delete_recursive` performed only the second, reconstructing against the wrong base. The
  result was not an error: a neighbouring record's key was rewritten in place, and because every
  later entry reconstructs against the rewritten one, the damage ran to the end of the node.

  Measured on a 20-key, four-collection repository, deleting each key in turn from a fresh tree:
  **3 of 20 deletes corrupted the tree**, one of them mangling nine records — `app.bsky.feed.like`
  and `app.bsky.feed.post` entries reappearing as `app.bsky.actorpost/aaaa` and similar. An ordinary
  user deleting one record moved unrelated records to keys that were never inserted, and the result
  was committed and signed.

  `delete_recursive` now derives every full key in the node, removes the deleted one, and rebuilds
  the entry list's compression from the resulting key list. There is no index arithmetic left to get
  backwards, which is how the reference and every port avoid this class entirely.
- `atproto-pds`: `listRecords` emitted a `cursor` on every non-empty page, including the last, and
  serialized it as `null` when there genuinely was none. The lexicon types `cursor` as a plain
  string, so the final iteration of every pagination loop threw in a validating client. A cursor is
  now emitted only when the page was full — a partial page cannot have more behind it — and the key
  is omitted rather than nulled when absent.
- `atproto-repo`: `#repoOp.cid` carried `skip_serializing_if`, dropping the key for deletions where
  the lexicon requires it present-and-null. Now serialized as an explicit `null`. `prev` keeps its
  `skip_serializing_if`, which is not symmetric and not an oversight: the lexicon declares `prev`
  optional — "for creations, field should not be defined" — rather than nullable.
- `atproto-pds`: `applyWrites` results matched no member of the closed output union. Each entry now
  carries a `$type` of `#createResult`, `#updateResult` or `#deleteResult`. Two further corrections
  fall out of the schema: neither create nor update results carry `commit` — that appears once at
  the top level — and `#deleteResult` is an empty object, where results previously carried a `uri`
  the schema does not define.
- `atproto-pds`: `describeRepo` omitted `didDoc`, which the lexicon marks required, so the call
  threw in a validating client and broke the migration handshake. The document is synthesised from
  local state rather than resolved from PLC: `didDoc` being required means a resolver would turn a
  directory outage into a hard failure, for a field whose useful contents — the handle, the signing
  key, the PDS endpoint — this server is itself the authority for.
- `atproto-pds`: service-auth JWTs carried `typ: "at+jwt"`. `@atproto/xrpc-server` throws
  `BadJwtType` for exactly that value, so every token this PDS minted was refused by the Bluesky
  AppView, by Ozone, and by any service built on that library — before the signature was checked.
  All five minters and both verifier constants now emit `"JWT"`, which is what seven of the
  comparison implementations emit and none emits `at+jwt`.
- `atproto-pds`: `getServiceAuth` read `exp` as a lifetime rather than an absolute epoch-seconds
  instant. A client asking for 30 seconds received 600, and a client naming a real timestamp got a
  token lasting until the clamp. `exp` is now absolute, with `BadExpiration` for an instant in the
  past, beyond an hour, or beyond a minute for a token with no `lxm`.
- CI ran an unpinned toolchain, so `cargo clippy` locally and in the spindle were different
  compilers that disagreed about lints. A `clippy::const_is_empty` failure reached `main` after
  passing on a developer machine: `assert!(!BUILD_REV.is_empty())` calls `is_empty()` on a `const`
  filled by `env!`, which the compiler decides, so the assertion can never do work at run time.
  `rust-toolchain.toml` now pins 1.90 — matching the workspace `rust-version` and the Dockerfile's
  builder stage — and the workflow installs it through `rustup` and prints the active version. The
  assertion is replaced by one that reads the build rev back out of the formatted `user_agent()`
  string, which keeps the property under test and cannot be const-folded.
- `atproto-pds`: `com.atproto.repo.uploadBlob` returned `{"$link", "mimeType", "size"}`, an envelope
  matching neither JSON form the AT Protocol data model accepts. The two accepted shapes are the
  typed `{"$type": "blob", "ref": {"$link": …}, "mimeType", "size"}` and the legacy two-key
  `{"cid", "mimeType"}`, both declared strict upstream — and the legacy form is rejected at write
  time regardless. `$link` is a key in neither, and it belongs nested under `ref` as a cid-link
  rather than spliced into the envelope. `@atproto/api` threw on the upload call itself, and a
  client that embedded the returned object produced a record the reference validator rejected, so
  media was broken against every real client.

  The envelope is now `atproto_record::lexicon::TypedBlob`, the workspace's existing representation
  of this shape, rather than a second local definition. Blob storage, ref-tracking rows and the
  `listMissingBlobs` output are unchanged; only the returned envelope moves.
- `atproto-pds`: `/oauth/par` and `/oauth/token` accepted `application/json` only, where RFC 9126 §2
  and RFC 6749 §4.1.3 specify `application/x-www-form-urlencoded` and every standard AT Protocol
  OAuth client sends it. `@atproto/oauth-client-node` and `-browser` received HTTP 415 and could not
  complete a single flow, making an extensively implemented authorization server unreachable.
  `/oauth/revoke` had always used `Form`, which is what showed the inconsistency was unintentional.
  Both endpoints now accept either encoding.

  Two consequences worth noting. Every issued token is now DPoP-bound and `token_type` is `DPoP`
  rather than `Bearer`, which is what the server's own
  `require_dpop_bound_access_tokens: true` metadata has always advertised. And a `client_id` must
  now be resolvable: either an HTTPS URL serving a client metadata document, or a loopback
  identifier of the form `http://localhost[/][?scope=…&redirect_uri=…]`, whose metadata is derived
  from the identifier itself and defaults to `http://127.0.0.1/` and `http://[::1]/`.

- `atproto-repo`: `prevData` was carried inside the signed commit body, making the commit a six-key
  object where the AT Protocol commit schema has five. `prevData` — the prior MST root CID used for
  Sync 1.1 inductive verification — is a `com.atproto.sync.subscribeRepos#commit` **event** field.
  It is per-delivery information, not repository state, and not something the account signs.
  Carrying it in the commit meant the commit CID and the signature still differed from a conformant
  peer's even after the nullable-key fix above: a non-initial commit encoded to 208 bytes and `a6`
  against the canonical 158 and `a5`.

  `Commit::new_unsigned_with_prev_data` and `UnsignedCommit::new_with_prev_data` are removed along
  with the field; use `new_unsigned` / `new`. Subscribers are unaffected — the firehose payload
  already carried `prevData` (`crates/atproto-pds/src/repo/writer.rs`), and the `commit_obj`
  `prev_data_cid` column is unchanged, now populated by walking the commit chain rather than reading
  a self-declared value off the commit.

  **Operational note:** commits written before this change carry the extra key. They still decode —
  the field is ignored — but their signatures no longer verify, because signature checking
  reconstructs the signed bytes from the decoded struct and those bytes no longer include
  `prevData`. In practice this means a CAR previously exported by this server will fail
  signature-verified re-import. Those repositories were already unverifiable by any peer for the
  same reason, so nothing that worked stops working.

- `atproto-repo`: MST nodes and commits omitted map keys the AT Protocol data model requires to be
  present-and-null, so **every MST root CID and every commit CID this workspace produced was
  unrecomputable by any peer** — including for a single-record repository, where tree shape cannot
  differ. `MstNode.l`, `TreeEntry.t` and `Commit.prev`/`UnsignedCommit.prev` are nullable, not
  optional; `skip_serializing_if = "Option::is_none"` dropped the key instead of writing `null`,
  turning the node map from `a2` into `a1`, the entry map from `a4` into `a3`, and the signed commit
  from a five-key object into a four-key one. A single-entry node encoded to 76 bytes against the
  canonical 82. The attribute on `UnsignedCommit.prev` is the one on the signing path, so commit
  signatures were computed over the wrong bytes as well.

  **Operational note:** this changes the bytes every node and commit hashes to. Existing
  repositories get a new MST root CID and a new commit CID on their next write, and the blocks
  written under the old encoding become unreferenced. Reading is unaffected in both directions —
  nodes stored without `l`/`t` still decode, and re-encoding one now yields the canonical form.

  `prevData` inside the signed commit body is a separate divergence and is unchanged here.

  Covered by byte-level known-answer vectors in
  `crates/atproto-repo/tests/known_answer_encoding.rs`, asserted against DAG-CBOR written out from
  the specification rather than against this crate's own output. The pre-existing round-trip tests
  passed throughout.

- `Cargo.lock` was corrupt and no crate in the workspace built from a clean checkout. A bad merge
  concatenated two resolutions of the AWS SDK dependency subtree, leaving 35 duplicate `[[package]]`
  entries and an inconsistent `data-encoding` selection, so `cargo` refused to parse the file at all
  (`package 'aws-config' is specified twice in the lockfile`). Regenerated; 716 package entries
  down to 577. This shipped in `0.15.0-rc.1` because nothing ran a build.
- Removed `crates/atproto-space/benches/set_hash.rs`, which had not compiled since the set-hash
  rewrite: it declares no `[[bench]]` target, has no `criterion` dev-dependency, and imports
  `XorSha256SetHash` (renamed to `LtHash`) from `set_hash_ecmh` (never declared as a module). Its
  presence made `cargo clippy --workspace --all-targets` fail.

### Added
- `atproto-pds`: four discovery endpoints that were never routed.
  - `com.atproto.server.describeServer` — the first call a client makes, and the one account
    migration reads the new PDS's `did` from to learn the `aud` for the service-auth token the old
    PDS must mint. Migration failed at step two without it.
  - `com.atproto.sync.listRepos` — how a relay discovers which accounts this server hosts, with
    `{did, head, rev}` per repo plus `active`/`status`, `limit`/`cursor` pagination, and accounts
    with no commits omitted rather than announced with a head a relay would fail to fetch.
  - `/.well-known/atproto-did` — resolves a handle hosted on this server's own domain to its DID
    from the request `Host`. Without it the PDS could not host handles on its own domain unless an
    operator stood up a separate web server to synthesise the response, which was documented
    nowhere.
  - `/.well-known/did.json` — this server's own `did:web` document, synthesised from
    `PDS_SERVICE_DID`. Peers resolving this PDS for spaces or service auth need it.
- Continuous integration at `.tangled/workflows/ci.yml`, running `cargo fmt --all -- --check`,
  `cargo clippy --workspace --all-targets -- -D warnings` and `cargo test --workspace` on every push
  to `main` and every pull request, with a recursive submodule checkout so the DASL CBOR compliance
  fixtures are actually present. Previously no workflow ran the test suite, and 13 `atproto-dasl`
  compliance cases failed on a missing fixture from a fresh clone.
- Known-answer conformance vectors from `bluesky-social/atproto-interop-tests` (CC-0, pinned at
  `056e574`), vendored at `tests/interop/`, with three harnesses:
  `crates/atproto-repo/tests/interop_mst.rs` (MST key heights, common prefixes, and commit root
  CIDs), `crates/atproto-dasl/tests/interop_data_model.rs` (canonical DAG-CBOR bytes and CIDs), and
  `crates/atproto-pds/tests/interop_firehose.rs` (frame headers against hand-decoded CBOR, the
  `#commit` body against the `subscribeRepos` lexicon, and the first end-to-end WebSocket test of
  the firehose). Every prior encoding test in the workspace was a round trip, which passes just as
  happily against a wrong encoding; these are the first that compare against an external oracle.
  Vectors that do not pass yet are enumerated in each harness's `KNOWN_FAILURES` table with the
  defect that explains them, and are required to keep failing until it is fixed.
- `atproto_repo::mst::common_prefix_len` is now re-exported alongside `compare_keys` and
  `key_height`.

### Removed
- `deploy/well-known/` — three hand-maintained `did.json` files that were never mounted by
  `docker-compose.yml` and are now redundant: each container already sets `PDS_SERVICE_DID` to the
  DID those files described, and the server synthesises the identical document. A static file is a
  second source of truth that can drift from the DID the server actually runs as.

## [0.15.0-rc.1] - 2026-07-27
### Security
- `atproto-lexicon`: bounded `ref`/`union` traversal during data validation. A `union` def that
  referenced itself, or an acyclic chain of ~2500 `union` defs (~105 KB of lexicon JSON), drove
  unbounded recursion on the same `DataValue` and overflowed the stack. A stack overflow aborts the
  whole process with `SIGABRT`, so a single unauthenticated request killed every in-flight request on
  the server; `catch_unwind` cannot catch it. `validate_union` now honours `visited_refs` and
  `ValidateFlags::STRICT_RECURSIVE_VALIDATION` the same way `validate_ref` always did, and
  `ValidationLimits` adds a recursion depth cap (`max_ref_depth`, default 256) plus a total traversal
  step budget (`max_ref_steps` + `max_ref_steps_per_node`). Reported by Lexicon Garden.
- `atproto-lexicon`: bounded the `union` fan-out search. When a value carried no `$type`, every ref
  was tried against the same value and each nested union retried all of its own refs, so a 978-byte
  lexicon plus a 34-byte request body consumed ~25 s of CPU. The step budget above bounds it; the
  same payload now fails in ~39 ms.
- `atproto-dasl`: DRISL decoding no longer panics on a hostile collection header. A 9-byte input
  declaring an array of 2^63 elements reached `Vec::reserve` with the wire-declared count and panicked
  with `capacity overflow` under both `DecodeConfig::default()` and `non_strict()`. Pre-allocation is
  now clamped, a declared count exceeding the remaining input is rejected
  (`DecodeError::CollectionLengthExceedsInput`), and `max_array_elements` / `max_map_entries` default
  to 2^24 instead of `0` (unlimited).
- `atproto-dasl`: CAR block reads no longer allocate from an unvalidated wire length. A 10-byte input
  declaring a 2^63-byte block panicked with `capacity overflow`. `CarBlock::read_from` /
  `from_bytes` and the async block reader now enforce `LimitsConfig::max_block_size` *before*
  allocating and read incrementally via `Vec::try_reserve`. `CarReader::next_block` was affected too:
  it checked `max_block_size` only *after* `read_block` had already allocated, so the documented
  limit provided no protection.
- `atproto-identity`: hardened the SSRF surface around DID and handle hosts. `is_valid_hostname`
  accepted integer, hexadecimal and octal IP forms (`2852039166`, `0xA9FEA9FE`,
  `0250.0376.0250.0376`, and empty-hex labels such as `0x7f.0x.0x.0x1`), all of which resolvers and
  `reqwest` normalize back into addresses like `169.254.169.254` and `127.0.0.1`. Neither
  `did_web_to_url` nor `did_webvh_to_url` validated the host at all before building a URL. Hosts are
  now rejected syntactically and cross-checked against the `url` parser, a shared method-aware
  `did_host()` helper avoids consumers re-deriving host extraction (`did:webvh` places the SCID
  first), and `Document::pds_endpoints()` documents that `serviceEndpoint` is attacker-controlled
  alongside a new validating accessor.
- `atproto-oauth`: `oauth_complete` now requires an expected subject and rejects a `TokenResponse`
  whose `sub` does not match it. Previously `sub` was never bound to the DID the flow began for, so
  an attacker running their own authorization server could return any victim's DID and have the
  relying app mint a session as that victim. JWT verification now requires an `exp` claim, since a
  token omitting it never expired.

### Changed
- **Breaking** `atproto-oauth`: `oauth_complete` takes an additional expected-subject argument.
  Callers must pass the DID the authorization flow started for.
- **Breaking** `atproto-oauth`: `oauth_refresh` keeps its signature, but now binds the returned `sub`
  to the `document` it was called with and rejects a mismatch. A refresh whose authorization server
  returns a different subject now fails where it previously succeeded. Because the signature is
  unchanged, this one does not surface as a compile error.
- **Breaking** `atproto-lexicon`: data validation now bounds `ref`/`union` traversal, so a document
  needing more than `DEFAULT_MAX_REF_DEPTH` (256) nested ref/union hops — or more traversal steps
  than `DEFAULT_MAX_REF_STEPS` (100,000) plus `DEFAULT_MAX_REF_STEPS_PER_NODE` (16) per value node
  allows — is now rejected where it previously validated. Ordinary records, including legitimately
  self-referential ones such as threaded replies, are unaffected. Tune the bounds with
  `ValidationLimits` through the new `validate_record_with_limits` and matching
  `validate_query_params_with_limits` / `validate_procedure_params_with_limits` /
  `validate_procedure_input_with_limits` entry points (and their `_with_schema_and_limits` variants).
- **Breaking** `atproto-identity`: `did_web_to_url` and `did_webvh_to_url` now return an error for
  hosts that are address literals or fall under the reserved suffixes `.local`, `.internal`,
  `.localhost` and `.arpa`. This blocks `metadata.google.internal`, but also rejects
  cluster-internal names such as `pds.svc.cluster.local` and `host.docker.internal` that previously
  produced a URL — deployments publishing a PDS under a cluster-internal name need a routable
  hostname. Bare `localhost` (with or without a port) is unaffected. `did:web` path segments are
  also restricted to `[A-Za-z0-9._-]`, which rejects the percent-encoded segments the DID Core
  `idchar` grammar permits.
- **Breaking** `atproto-dasl`: `CarBlock::read_from` and `CarBlock::from_bytes` are now bounded by
  `LimitsConfig::default()` (1 MB) instead of being unlimited. Use `read_from_with_limits` /
  `from_bytes_with_limits` to widen. Callers going through `CarReader` are unaffected.
- **Breaking** `atproto-dasl`: `DecodeConfig::max_array_elements` and `max_map_entries` default to
  2^24 rather than `0` (unlimited). Because `serde` encodes a plain `Vec<u8>` as a CBOR array, a
  `Vec<u8>` larger than 16 MiB no longer round-trips under the defaults; use `serde_bytes` /
  `Ipld::Bytes`, or `with_unlimited_array_elements()`.

## [0.15.0-alpha.2] - 2026-06-26
### Changed
- Re-aligned permissioned-data Spaces (`atproto-space`, `atproto-pds`) to the published [0016 "Permissioned Data"](https://github.com/bluesky-social/proposals/blob/06d439e6be9004a086f392008e41acddd1a444ff/0016-permissioned-data/README.md) draft, taking the spec as the source of truth over the reference implementation: LtHash set-hash commits, the delegation-token / space-credential JWT shapes, the OAuth `space:` scope grammar, and the `com.atproto.simplespace` mint-policy / `appAccess` / `managingApp` configuration.
- Unified space-declaration resolution across the OAuth consent screen and the `space:` scope gate behind a shared resolver.

### Removed
- Permissioned-data member-sync machinery (`getMemberState` / `getMemberOplog` / `notifyMembership`); member-list management (`addMember` / `removeMember` / `listMembers`) is retained.

## [0.15.0-alpha.1] - 2026-05-09
### Added
- AT Protocol PDS + permissioned-data Spaces (alpha-ready) — new `atproto-pds` and `atproto-space` crates introducing a Personal Data Server implementation and permissioned-data Space primitives (commits, credentials, recon, set hashing, members, repo, storage).
- `atproto-repo`: inductive verification (`src/repo/inductive.rs`) and MST diffing (`src/mst/diff.rs`).

## [0.14.6] - 2026-04-22
### Added
- `atpmcp login <identifier> [password]` subcommand mirroring the atpxrpc login UX. Resolves the identifier, creates a session via `com.atproto.server.createSession`, and upserts the account into the shared `~/.config/atpxrpc/config.json` so credentials are usable by both binaries.

## [0.14.5] - 2026-04-02
### Fixed
- Fixed panproto strategies bypassing `$type` rewriting for nested union types

### Changed
- Updated dependency versions: criterion 0.8, compact_str 0.9, data-encoding 2.10, sha2 0.11, tokio 1.50, unicode-segmentation 1.13, proptest 1.11

## [0.14.4] - 2026-04-02
### Added
- `transmogrify_record` tool to atpmcp MCP server
- `transmogrify_record` function in atproto-lexicon library
- Scenario triggers, parameter examples, and error guidance to atpmcp tool descriptions
- `lenient_optional_format` datetime module and malformed `createdAt` test
- Default values to `alt` and `role` fields in Media type
- Unified `atpdid` CLI tool for DID management (key generate/inspect, resolve, PLC audit/create/update/submit, did:webvh verify/create/update)
- did:webvh v1.0 resolution with full spec compliance
- DiskRepository with `from_car` support

### Changed
- Made lexicon main definition optional per AT Protocol spec
- Moved transmogrify and compatibility into atproto-lexicon library
- Replaced deprecated `plugin-types` CSP directive with `media-src`

## [0.14.3] - 2026-03-12
### Added
- Unknown variant to LocationOrRef and EventLocation enums for calendar events
- `--version` flag to atpmcp CLI

## [0.14.2] - 2026-03-09
### Added
- `atptid` CLI tool for generating and parsing AT Protocol Timestamp Identifiers
- `get_lexicon` tool to atpmcp MCP server for fetching lexicon schema records
- `invoke_xrpc` tool to atpmcp MCP server
- `generate_tid` tool to atpmcp MCP server
- `validate_xrpc` tool to atpmcp MCP server

### Changed
- Updated release workflow and README to include atptid and atpcid binaries

## [0.14.1] - 2026-03-08
### Added
- `atpxrpc` CLI tool for persistent XRPC session management with proxy support
- `--out` argument for atpxrpc proxy and base commands for output control
- `--bytes` and `--manual` proxy flags to atpxrpc CLI
- 5 new tools to atpmcp MCP server

### Changed
- Updated GitHub Actions workflow to build atpxrpc and atpmcp release binaries
- Updated README to reflect full Rust crates workspace

## [0.14.0] - 2026-02-21

## [0.13.0] - 2025-09-21
### Added
- New `atproto-lexicon` crate for AT Protocol lexicon resolution and validation
- `atproto-lexicon-resolve` CLI tool for resolving lexicons via DNS and XRPC
- Comprehensive lexicon reference extraction and recursive resolution capabilities
- Full support for NSID validation and DNS-based lexicon discovery

### Changed
- Updated Rust minimum version requirement to 1.90
- Enhanced error management across atproto-lexicon crate
- Improved project documentation with atproto-lexicon integration

### Improved
- Code formatting and linting across all crates
- Updated README documentation to include atproto-lexicon references

## [0.12.0] - 2025-09-17
### Added
- Unified `Auth` enum for authentication methods in `atproto-client` supporting None, DPoP, and AppPassword authentication
- `com.atproto.server.deleteSession` support in `atproto-client` with AppPassword authentication requirement
- `com.atproto.identity.resolveHandle` support in `atproto-client` for handle resolution
- OAuth client credentials token flow in `atproto-oauth-aip` for service-to-service authentication
- `session_exchange_with_options` function with optional `access_token_type` and `subject` parameters
- Documentation for all Auth enum variants and authentication methods

### Changed
- Updated all XRPC client methods to use the unified `Auth` enum pattern instead of optional DPoP parameters
- Made `refresh_token` field optional in `TokenResponse` structure as not all token responses include refresh tokens
- Refactored `session_exchange` to use `session_exchange_with_options` internally with backward compatibility
- Enhanced error handling with new `InvalidAuthMethod` error variant in client errors

### Fixed
- Removed unused imports and cleaned up code after Auth enum refactoring
- Fixed doctest failures from outdated function signatures
- Resolved compilation errors from type mismatches in error handling

## [0.11.3] - 2025-09-03
### Added
- OAuth scope types, parsing, and utilities for the `atproto-oauth` crate
- Comprehensive support for AT Protocol OAuth 2.0 scope handling

## [0.11.2] - 2025-08-20
### Fixed
- Fixed `atproto-jetstream` consumer to correctly send multiple query parameters for `wantedCollections` and `wantedDids` instead of joining them with commas

## [0.11.1] - 2025-08-20
### Fixed
- Base64 decoding in `atproto-record` now accepts both padded and unpadded base64 strings for better compatibility with various AT Protocol implementations
- Updated `signature::verify` function to only accept `{"$bytes": "..."}` format for signatures

### Added
- Comprehensive unit tests for record signature creation and verification across P-256, P-384, and K-256 curves
- Unit test for deserializing real-world RSVP records with signatures

### Changed
- Made `create` and `verify` functions in the signature module synchronous (removed `async`) as they don't perform async operations

## [0.11.0] - 2025-08-18
### Added
- Document builder functionality for AT Protocol documents
- New `atproto-oauth-service-token` CLI tool for OAuth service token management
- Community lexicon support for extended AT Protocol functionality

### Changed
- Updated record signature and verification to align with current AT Protocol proposal
- Removed `issuedAt` field as required signature field
- Streamlined Debug derive implementations across crates

### Improved
- Removed unused dependencies for smaller build size
- Release preparation and project maintenance

## [0.10.0] - 2025-07-28
### Changed
- Version release 0.10.0 with updated dependencies and stability improvements

## [0.9.7] - 2025-07-13
### Changed
- Updated `list_records` method to support optional DPoP authentication for enhanced security

## [0.9.6] - 2025-07-11
### Improved
- Enhanced DID method validation for did-method-plc and did-method-web
- Updated validation examples and documentation for better clarity

## [0.9.5] - 2025-07-09
### Changed
- Refactored OAuth components to support blind OAuth workflows for enhanced security and privacy

## [0.9.4] - 2025-07-09
### Fixed
- Fixed issue where login_hint was always sent in OAuth initialization

## [0.9.3] - 2025-07-06
### Added
- `delete_record` method to atproto-client for removing AT Protocol records

## [0.9.2] - 2025-06-30
### Added
- Optional `zeroize` feature for secure memory handling of sensitive cryptographic data

## [0.9.1] - 2025-06-29
### Changed
- Updated dependency versions for improved compatibility

## [0.9.0] - 2025-06-29
### Security
- Explicitly forbid unsafe code usage across all crates for enhanced security

### Changed
- Reduced debug information exposure in production builds
- Improved sensitive data handling and reduced exposure
- Cleaned up tracing instrumentation for better performance

### Improved
- Enhanced documentation across all crates and modules

## [0.8.1] - 2025-06-21
### Improved
- Enhanced module documentation across all crates with comprehensive usage examples
- Standardized error handling with consistent naming and unique identifiers
- Updated OAuth AIP crate with detailed API documentation and security considerations
- Improved project documentation and README files across all crates

### Fixed
- Code formatting compliance with rustfmt standards
- Consistent error message formatting and numbering

## [0.8.0] - 2025-06-18
### Added
- OAuth Authorization Initiation Protocol (AIP) crate for AT Protocol OAuth workflows

## [0.7.0] - 2025-06-16
### Added
- DPoP validation support for enhanced security
- Embedded JWKS in OAuth metadata
- P-384 cryptographic curve support and JWK conversion
- App password creation method to atproto-client
- Client authentication binaries for app password and session management

### Changed
- Standardized CLI tools with clap for consistent command-line interfaces
- Enhanced security measures across client tools
- Streamlined documentation structure

### Fixed
- Error cleanup and improved error handling throughout codebase
- Removed unused issuer field from DPoP implementation

## [0.6.0] - 2025-06-08
### Added
- AT Protocol event streaming via atproto-jetstream crate with WebSocket support

## [0.5.0] - 2025-06-05
### Added
- XRPC service helpers and framework crate
- PORT environment variable support for service configuration
- Enhanced DPoP client support for query and procedure methods

### Changed
- Improved tracing and logging throughout the codebase
- Updated Docker configuration to include additional binaries

### Fixed
- Removed hardcoded OAuth metadata field values
- Added missing crate metadata fields

## [0.4.0] - 2025-06-03
### Added
- Initial OAuth client implementation
- Basic AT Protocol identity resolution
- Core DID document handling
- Cryptographic key operations for P-256 curves

[0.15.0-rc.1]: https://tangled.org/ngerakines.me/atproto-crates/tree/v0.15.0-rc.1
[0.15.0-alpha.2]: https://tangled.org/ngerakines.me/atproto-crates/tree/v0.15.0-alpha.2
[0.15.0-alpha.1]: https://tangled.org/ngerakines.me/atproto-crates/tree/v0.15.0-alpha.1
[0.14.6]: https://tangled.org/ngerakines.me/atproto-crates/tree/v0.14.6
[0.14.5]: https://tangled.org/ngerakines.me/atproto-crates/tree/v0.14.5
[0.14.4]: https://tangled.org/ngerakines.me/atproto-crates/tree/v0.14.4
[0.14.3]: https://tangled.org/ngerakines.me/atproto-crates/tree/v0.14.3
[0.14.2]: https://tangled.org/ngerakines.me/atproto-crates/tree/v0.14.2
[0.14.1]: https://tangled.org/ngerakines.me/atproto-crates/tree/v0.14.1
[0.14.0]: https://tangled.org/ngerakines.me/atproto-crates/tree/v0.14.0
[0.13.0]: https://tangled.org/ngerakines.me/atproto-crates/tree/v0.13.0
[0.12.0]: https://tangled.org/ngerakines.me/atproto-crates/tree/v0.12.0
[0.11.3]: https://tangled.org/ngerakines.me/atproto-crates/tree/v0.11.3
[0.11.2]: https://tangled.org/ngerakines.me/atproto-crates/tree/v0.11.2
[0.11.1]: https://tangled.org/ngerakines.me/atproto-crates/tree/v0.11.1
[0.11.0]: https://tangled.org/ngerakines.me/atproto-crates/tree/v0.11.0
[0.10.0]: https://tangled.org/ngerakines.me/atproto-crates/tree/v0.10.0
[0.9.7]: https://tangled.org/ngerakines.me/atproto-crates/tree/v0.9.7
[0.9.6]: https://tangled.org/ngerakines.me/atproto-crates/tree/v0.9.6
[0.9.5]: https://tangled.org/ngerakines.me/atproto-crates/tree/v0.9.5
[0.9.4]: https://tangled.org/ngerakines.me/atproto-crates/tree/v0.9.4
[0.9.3]: https://tangled.org/ngerakines.me/atproto-crates/tree/v0.9.3
[0.9.2]: https://tangled.org/ngerakines.me/atproto-crates/tree/v0.9.2
[0.9.1]: https://tangled.org/ngerakines.me/atproto-crates/tree/v0.9.1
[0.9.0]: https://tangled.org/ngerakines.me/atproto-crates/tree/v0.9.0
[0.8.1]: https://tangled.org/ngerakines.me/atproto-crates/tree/v0.8.1
[0.8.0]: https://tangled.org/ngerakines.me/atproto-crates/tree/v0.8.0
[0.7.0]: https://tangled.org/ngerakines.me/atproto-crates/tree/v0.7.0
[0.6.0]: https://tangled.org/ngerakines.me/atproto-crates/tree/v0.6.0
[0.5.0]: https://tangled.org/ngerakines.me/atproto-crates/tree/v0.5.0
[0.4.0]: https://tangled.org/ngerakines.me/atproto-crates/tree/v0.4.0