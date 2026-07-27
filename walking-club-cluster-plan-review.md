# Walking-Club Cluster Plan — Review Report

## 1. Executive Summary

This review evaluates `walking-club-cluster-plan.md` against the published 0016 permissioned-data spec (pinned `06d439e`) and the actual implementation in `atproto-pds`, `atproto-oauth`, `atproto-space`, `atproto-client`, and `atproto-dasl`. The plan is operationally sound for the bootstrap/management flows and the bulk of its citations are accurate, but it carries **44 confirmed findings**: **5 critical**, **15 high**, **7 medium**, and **17 low**. The defects concentrate in two areas: (a) the OAuth `space:` scope grammar in §3.2 is malformed in a way that silently passes authorization but 403s every space operation, and (b) the commit/setHash wire-encoding model in the read/verify perimeter (R8, §3.5F, §7.1) is described as uniform hex when the code actually emits read-side commit byte fields as base64 `$bytes` and the write-side `setHash` as hex of the full 2048-byte LtHash state. A third recurring theme is the HOP-2 notify recipient `aud`, which the plan assumes is the AppView's DID but which the code derives from a stub (member DID) or the `client_id` URL. **Overall verdict: the plan is structurally faithful to the spec's intent and most of its mechanics, but it cannot be executed as written — the scope string, the setHash/commit.hash reconciliation, and the notify `aud` checks will all fail and must be corrected before the cluster's read and live-feed paths work.**

## 2. Confirmed Findings

| # | Severity | Kind | Area | Summary |
|---|----------|------|------|---------|
| 1 | critical | discrepancy | tokens-oauth | Scope `space:read`/`space:create?collection=…` puts action positionally; parses as space-type NSID, authorizes nothing → 403 |
| 22 | critical | discrepancy | commit-lthash-cid | Read-side commit `hash/mac/ikm/sig` are base64 `$bytes`, not hex |
| 23 | critical | discrepancy | commit-lthash-cid | `setHash` is hex of full 2048-byte LtHash state (4096 chars), not 64-char `hex(sha256(state))` |
| 24 | critical | discrepancy | commit-lthash-cid | R8 hex-to-hex `setHash == commit.hash` impossible (2048-byte state vs 32-byte sha256) |
| 2 | high | discrepancy | tokens-oauth | §3.2 prose `space:read`/`space:create?collection`/`space:manage` bare-token grammar wrong (action/manage go in query) |
| 4 | high | discrepancy | read-perimeter | R8/§3.5F claim read-flow commit fields hex-encoded; they are base64 `$bytes` |
| 5 | high | discrepancy | read-perimeter | Write `setHash` and read `commit.hash` are not the same wire form; differ in encoding AND content |
| 6 | high | discrepancy | read-perimeter | HOP-2 `aud` on explicit registerNotify is the client_id URL, not AppView DID |
| 7 | high | gap | read-perimeter | Self-register needs `/.well-known/atproto-did`, which the AppView never serves → stub on member DID |
| 10 | high | discrepancy | write-notify | getRepoState/listRepoOps commit byte fields are base64 `$bytes`, not hex |
| 11 | high | discrepancy | write-notify | `setHash` = hex of 2048-byte state; `commit.hash` = sha256(state); equality claim false |
| 12 | high | gap | write-notify | HOP-2 `aud` not guaranteed to be AppView DID; AppView lacks atproto-did + PDS service |
| 16 | high | discrepancy | mgmt-did-space | `registerNotify` endpoint passed as full `/xrpc/…` URL → doubled path → 404, never delivers |
| 26 | high | discrepancy | commit-lthash-cid | Space record URI is 6 segments, not 3; 3-segment example is rejected by RecordUri::parse |
| 29 | high | discrepancy | citation-config-error | R8 "hex on the wire" for commit fields contradicts base64 `$bytes` DTO |
| 30 | high | discrepancy | citation-config-error | R8 hex-to-hex compare against base64 `commit.hash` fails |
| 31 | high | discrepancy | citation-config-error | §7.1/§7.2-13 conflate hex `setHash` with base64 read commit fields |
| 38 | high | discrepancy | devops-feasibility | §3.5F/R8/§7.1 "compare hex-to-hex" wrong: hex setHash vs base64 commit.hash |
| 39 | high | issue | devops-feasibility | AppView inbound `aud==AppView DID` check rejects every fan-out (stub/client_id aud) |
| 17 | high | issue | mgmt-did-space | Self-register always falls to member-DID stub; every registered recipient's token is rejected |
| 9 | medium | discrepancy | write-notify | createRecord returns `WriteRecordResponse{uri,cid,validationStatus?}`, not `SpaceCommitResult` |
| 13 | medium | gap | write-notify | `atproto_client::com::atproto::space::create_record` does not exist |
| 18 | medium | gap | mgmt-did-space | Member-operated AppView's `listMembers` returns 403 NotSpaceOwner |
| 27 | medium | discrepancy | commit-lthash-cid | Empty-repo helper computes digest, not the wire setHash form (`0`*4096) |
| 32 | medium | discrepancy | citation-config-error | Line-1296 parenthetical correct, but surrounding commit.hash claims are base64 not hex |
| 34 | medium | issue | citation-config-error | W1 "Save the post's setHash" not executable from a createRecord response |
| 41 | medium | gap | devops-feasibility | Missing `/.well-known/atproto-did` route blocks recipient resolution |
| 3 | low | issue | tokens-oauth | `read_self does NOT satisfy` cites `:1432`; should be `:1442` |
| 8 | low | issue | read-perimeter | Same `:1432`→`:1442` miscitation for read_self gate |
| 14 | low | issue | write-notify | PDS does not use `atproto_xrpcs::authorization::Authorization` extractor for notifyWrite |
| 15 | low | issue | write-notify | `verify_commit_signature(ctx,…)` passes ctx; signature takes `SpaceContext{space,rev}` |
| 19 | low | issue | mgmt-did-space | createSpace owner check is in the HANDLER, not the service layer |
| 20 | low | issue | mgmt-did-space | `managingApp` bare origin can never satisfy a real managing-app mint (resolution fails) |
| 21 | low | gap | mgmt-did-space | Host does not pin attestation `alg`; §3.7 enumeration accurate (advisory only) |
| 25 | low | issue | commit-lthash-cid | `op.cid` is a base32 CID string, not a hex/byte field |
| 28 | low | issue | commit-lthash-cid | Undefined "vlv[…]" shorthand for ctx; framing is fixed uint16be length prefixes |
| 33 | low | discrepancy | citation-config-error | Header mislabels createRecord output as `SpaceCommitResult` |
| 35 | low | discrepancy | citation-config-error | `config.rs:35-47` ambiguous/wrong: two different files; `#open` default not in that range |
| 36 | low | issue | citation-config-error | M3 ellipsis omits distinctive "space-management operation" wording |
| 37 | low | issue | citation-config-error | `PDS_DID_PLC_URL` takes a bare hostname; `_URL` suffix misleading |
| 40 | low | issue | devops-feasibility | Line 1199 wrong: self-register alone does NOT deliver notifies (bare-origin stub) |
| 42 | low | issue | devops-feasibility | Step 8 heading loosely worded; stub-recipient nuance undocumented |
| 43 | low | issue | devops-feasibility | `space:read_self` redundant (read implies it); OAuth de-dup concern disproven |
| 44 | low | issue | devops-feasibility | "WAL; single writer" inaccurate — multiple concurrent logical writers |

## 3. Detailed Findings by Severity

### CRITICAL

#### Finding 1 — Scope string puts the action positionally; authorizes nothing (403 everywhere)
- **Plan location:** §3.2 `client-metadata.json`, line 155.
- **Plan says:** `"scope": "atproto transition:generic space:read space:read_self space:create?collection=community.lexicon.calendar.event space:create?collection=app.bsky.feed.post"` — treats the segment after `space:` as an action.
- **Ground truth:** The grammar is `space:<spaceType>[?…&action=<a>]`; the positional segment is ALWAYS the spaceType NSID. `parse_type` (`crates/atproto-oauth/src/scopes/space_permission.rs:517-522`) accepts any non-`*` string as `SpaceType::Nsid(value)` with no NSID validation, so `space:read` → `Nsid("read")`, `space:create?…` → `Nsid("create")`. The real space type is `city.thegem.walkingclub.space` (plan lines 861, 958). `tuple_overlaps` (`space_permission.rs:622-627`) returns false whenever the grant's `Nsid` type ≠ the target type, so these grants match nothing. Result: OAuth authorization succeeds (malformed types parse), but `getDelegationToken` (needs whole-space Read, `:675`) and every `space.createRecord` (needs Create+collection, `:690-694`) 403. Correct form per tests: `space_permission.rs:884` (`space:com.example.space?…&action=read&action=create`), `:908` (`space:com.example.space?action=read_self`).
- **Fix:** Rewrite line 155 to `atproto transition:generic space:city.thegem.walkingclub.space?action=read space:city.thegem.walkingclub.space?action=create&collection=community.lexicon.calendar.event space:city.thegem.walkingclub.space?action=create&collection=app.bsky.feed.post` (drop redundant `read_self`); validate each token with `Scope::parse` against the real space type before publishing.

#### Finding 22 — Read-side commit byte fields are base64 `$bytes`, not hex
- **Plan location:** R8 lines 1260, 1264; echoed §3.5 Step F (line 256) and data-model note (lines 372, 1322, 1339).
- **Plan says:** `commit.{hash,mac,ikm,sig}` from getRepoState/listRepoOps are hex-encoded (hash = 64 hex chars); AppView should hex-decode.
- **Ground truth:** `SignedCommitDto` types these four fields as `BytesValue`; `BytesValue::serialize` (`crates/atproto-pds/src/http/space_handlers.rs:1165-1176`) emits `{"$bytes": base64::STANDARD_NO_PAD.encode(...)}`. Doc comment (`:1140-1145`) is explicit. Integration test `crates/atproto-pds/tests/http_phase7_spaces.rs:901-905` asserts nested `commit["hash"]["$bytes"]` etc. No `hex::encode` exists in the file. (Related: the write-response `setHash` is the algorithm-name string `"lthash"` per `realm.rs:28`, confirmed by `http_phase7_spaces.rs:585`.)
- **Fix:** Replace every "hex-encoded"/"64 hex chars" claim about the read commit byte fields (lines 256, 372, 1260, 1264, 1322, 1339) with `{"$bytes":"<base64 standard, unpadded>"}`; the AppView base64-decodes (STANDARD_NO_PAD) before HMAC/sig/hash verification.

#### Finding 23 — `setHash` is hex of the full 2048-byte LtHash state, not a 64-char digest
- **Plan location:** Part 6 (B) line 1124; line 1138; R8 line 1264; data-model note line 372.
- **Plan says:** `setHash` is a 64-char hex string equal to `hex(sha256(state))`.
- **Ground truth:** `crates/atproto-pds/src/space/writer.rs:309` `set_hash_hex = hex::encode(&prepared.storage_commit.new_set_hash)` (→ `:349`). `new_set_hash` = `set_hash.state_bytes()` (`crates/atproto-space/src/space_repo.rs:264,269`, comment `:261-263`: "full lattice STATE (2048 bytes for LtHash)... 32-byte commitment computed separately"). `state_bytes()` returns 2048 bytes (`crates/atproto-space/src/set_hash.rs:128-136`; `STATE_BYTES = 2048`). So `setHash` = 4096 hex chars of raw state. `commit.hash` = `digest()` = `Sha256::digest(state_bytes())` = 32 bytes (`set_hash.rs:154-155`, `commit.rs:120`).
- **Fix:** State `setHash` = hex of 2048-byte LtHash state (4096 chars; empty repo = `0`*4096); `commit.hash` = base64 `$bytes` of the 32-byte sha256(state). Drop "64-char" and `setHash == commit.hash` claims.

#### Finding 24 — R8 hex-to-hex `setHash == commit.hash` is impossible
- **Plan location:** R8 line 1264; (B) line 1138 ("Save the post's setHash for R8").
- **Plan says:** `hex(sha256(state)) == commit.hash == setHash`, comparable hex-to-hex.
- **Ground truth:** `commit.hash` = sha256(state) = 32 bytes / 64 hex (`crates/atproto-space/src/commit.rs:113-120`, `set_hash.rs:154-155`); `setHash` = 2048-byte state hex = 4096 hex (`writer.rs:309`, `space_repo.rs:264`). Different length and content; they can never be equal. (Minor: read `commit.hash` is base64 `$bytes`, not hex — see Findings 22/4/10/29.)
- **Fix:** Reconcile as `sha256(hex_decode(setHash)) == base64_decode(commit.hash)` (equivalently `LtHash::from_state_bytes(hex_decode(setHash)).digest()`); drop the hex-to-hex `setHash==commit.hash` comparison and the "64-char hex setHash" claim.

> **Note on Findings 4, 5, 10, 11, 22, 23, 24, 29, 30, 31, 38** — these eleven findings, raised independently by different review passes (read-perimeter, write-notify, commit-lthash-cid, citation-config-error, devops-feasibility), all describe the **same two-axis encoding defect**: (a) read-side `commit.{hash,mac,ikm,sig}` are base64 `$bytes`, the plan says hex; (b) write-side `setHash` is hex of the 2048-byte state, the plan says 64-char `hex(sha256(state))`. They are retained separately because each cites a distinct plan location/line that must be edited, but a single coordinated fix across lines 256, 372, 1124, 1138, 1260, 1264, 1296, 1322, 1339 resolves all of them. Findings 22/23/24 are escalated to critical because they sit at the data-model core (R8 + data-model note) and break the entire read-verification perimeter; the others are the high/medium-severity restatements at their respective plan locations.

### HIGH

#### Finding 2 — §3.2 prose restates the malformed scope grammar
- **Plan location:** §3.2 lines 164-166.
- **Plan says:** Refers to grants as bare `space:read`, `space:create?collection=…`, `space:manage`.
- **Ground truth:** `parse_suffix`/`parse_type` (`space_permission.rs:374-385,427-430,517-522`) take the pre-`?` segment as the positional space type. `space:manage` → space of type "manage", etc. — none confer anything on the club space. `to_scope_string` emits `space:<positional>?…action=…&manage=…` (`:564-608`); `assert_space_manage`'s denial reports `e.scope` (`crates/atproto-pds/src/http/space_handlers.rs:1937-1944`). The plan's own M3 assertion (line 1120) correctly quotes `space:…?manage=update…`, contradicting line 166.
- **Fix:** Rewrite lines 155 & 164-166 to the query grammar: `space:<spaceType>?action=read`, `space:<spaceType>?action=create&collection=<nsid>` per collection, and (if owner-operated) `space:<spaceType>?manage=update`.

#### Finding 6 — HOP-2 `aud` on explicit registerNotify is the client_id URL
- **Plan location:** §3.6 line 275; R9 line 1273.
- **Plan says:** Owner's HOP-2 fan-out carries `aud = AppView DID`; AppView verifies `aud == its DID`.
- **Ground truth:** Explicit registerNotify sets `service_did = credential.client_id.unwrap_or(iss)` with no resolution (`space_handlers.rs:2499-2502`); the walking-club credential carries `client_id = https://walking-club-appview.ngerakines.dev/client-metadata.json` (plan lines 1199, 294). Fan-out mints `aud = service_did` (`crates/atproto-pds/src/space/notify.rs:222-229`; `service_auth.rs:93-95`). So `aud` = the client-metadata URL, not a DID; an `aud==DID` check 401s. **Nuance:** the implicit self-registration path (during getSpaceCredential, `space_handlers.rs:1660-1714`) resolves to a real DID via `resolve_recipient`/`stub_recipient`, so the plan's primary R9 flow may still mint a DID-valued aud — the discrepancy is specific to the explicit registerNotify curl (lines 1268-1271) and the §3.6 design.
- **Fix:** Either resolve `credential.client_id` to a DID before storing (mirroring getSpaceCredential), or have the AppView accept `aud == its client_id URL`; document that HOP-2 `aud` is host-derived from the credential's `client_id`.

#### Finding 7 — Self-register requires `/.well-known/atproto-did`, which the AppView never serves
- **Plan location:** R2 line 1199; §3.5 Step C line 249; route table §3.3 lines 174-192.
- **Plan says:** getSpaceCredential self-registers the AppView as a recipient sufficient for R9; AppView serves only `/.well-known/did.json`.
- **Ground truth:** `resolve_recipient` (`crates/atproto-pds/src/space/recipient.rs:54-71`) derives the host from `client_id` and calls `resolve_handle_http`, which fetches ONLY `https://<host>/.well-known/atproto-did` with no DNS-TXT fallback (`crates/atproto-identity/src/resolve.rs:122-147`). The AppView route table (plan line 179) lists only `/.well-known/did.json`; `/.well-known/atproto-did` appears in the plan solely for the PDS hosts (lines 702, 1330). So resolution 404s → `stub_recipient` (`recipient.rs:176-183`): `service_did = payload.iss` (the MEMBER DID), `fully_resolved=false`. Fan-out keys `aud = member DID` (`notify.rs:170-227`).
- **Fix:** Add `GET /.well-known/atproto-did` returning the AppView's `did:web` so self-register resolves to the AppView DID + PDS endpoint; otherwise the recipient is a member-DID stub and the inbound `aud` check must be reconciled to the member DID.

#### Finding 12 — HOP-2 `aud` not guaranteed to be AppView DID; AppView lacks DID infrastructure
- **Plan location:** §3.6 line 275; R9 line 1273; routes §3.3 lines 184-192; identity §3.2 lines 140-160.
- **Plan says:** HOP-2 tokens carry `aud = AppView DID` and the AppView verifies it; AppView is set up with only an OAuth `client_id` URL + JWKS.
- **Ground truth:** Owner mints `aud = r.service_did` (`notify.rs:222-229`); receiver verifies `aud == expected_aud` exactly (`crates/atproto-pds/src/space/service_auth.rs:145`). `service_did` comes from recipient discovery (resolves `<client_id host>/.well-known/atproto-did` → `AtprotoPersonalDataServer`, `recipient.rs:48-99`), falling back to a stub `service_did = grant.iss = member DID`. The AppView serves no `/.well-known/atproto-did` and its `did:web` doc carries no `AtprotoPersonalDataServer` service, so resolution → stub → `aud = member did:plc`. An inbound handler hard-checking `aud == AppView DID` 401s every fan-out, breaking the M7 live-notify gate.
- **Fix:** Serve `/.well-known/atproto-did` returning the AppView DID + a `did:web` doc with an `AtprotoPersonalDataServer` service (then verify `aud == that DID`); or correct §3.6/R9 to verify against whatever is actually signed (resolved DID / client_id URL / member did:plc).

#### Finding 16 — registerNotify endpoint passed as full XRPC URL → doubled `/xrpc/…` → 404
- **Plan location:** §3.6 line 267; Step 8c line 1040; R9 line 1271.
- **Plan says:** `endpoint` = `https://walking-club-appview.ngerakines.dev/xrpc/com.atproto.space.notifyWrite`.
- **Ground truth:** `register_notify` stores `input.endpoint` verbatim as `service_endpoint` (`space_handlers.rs:2510` → `upsert_subscription`); the notifier composes the delivery URL as `format!("{}/xrpc/{}", target_endpoint, nsid)` (`crates/atproto-pds/src/notifier.rs:277`) with `nsid = com.atproto.space.notifyWrite` (`notify.rs:235`). Result: POST `…/xrpc/com.atproto.space.notifyWrite/xrpc/com.atproto.space.notifyWrite` → 404; the subscription silently never delivers. The AppView's inbound route is mounted at `/xrpc/com.atproto.space.notifyWrite` (plan line 189), so a base-origin endpoint works.
- **Fix:** Set `endpoint` to the base origin `https://walking-club-appview.ngerakines.dev` only — the notifier appends `/xrpc/com.atproto.space.notifyWrite`.

#### Finding 17 — Every registered recipient yields a rejected fan-out token
- **Plan location:** §2.3 line 75; §3.5 Step C line 249; R2 line 1199; Step 8c line 1035.
- **Plan says:** Minting the credential auto-registers the AppView so HOP-2 tokens arrive with `aud = AppView DID` and are accepted.
- **Ground truth:** Self-register resolution needs `/.well-known/atproto-did` + an `AtprotoPersonalDataServer` service; the AppView serves neither (plan §3.2 line 170), so resolution always falls to `stub_recipient` → `service_did = payload.iss` (member DID) (`recipient.rs:55-93,176-183`; `space_handlers.rs:1681,1697`). The explicit registerNotify path registers `service_did = credential.client_id` (the URL) (`space_handlers.rs:2499-2502`); both rows coexist keyed `(space,repo,service_did)` (`notify.rs:147-153`). Inbound accepts only `aud = AppView DID` (plan line 275), so both tokens are rejected. R9 live re-index silently never fires; correctness is preserved only by the §3.5H debounce/manual-resync fallback — hence high, not critical.
- **Fix:** State explicitly which `aud` the inbound handler must accept and make a registered recipient's `service_did` match it (serve `/.well-known/atproto-did` + PDS service, OR accept `aud == client_id URL`).

#### Finding 26 — Space record URI is 6 segments, not 3
- **Plan location:** (B) line 1138; Step E line 251; Step F line 256.
- **Plan says:** `ats://{authorDid}/{collection}/{rkey}` (3 segments).
- **Ground truth:** `crates/atproto-pds/src/space/writer.rs:275-278` builds `format!("ats://{}/{}/{}/{}/{}/{}", space_did, space_type, space_key, member_did, collection, rkey)` = 6 segments. `RecordUri::parse` (`crates/atproto-space/src/types.rs:230-258`) requires exactly 6 non-empty segments and rejects fewer as `InvalidSpaceUri`. Spec confirms: `ats://{spaceDid}/{spaceType}/{skey}/{authorDid}/{collection}/{rkey}`.
- **Fix:** Change the asserted URI to `ats://$DID3/<spaceType>/<skey>/$DID3/<collection>/<tid>` (spaceDid = authorDid = `$DID3` for owner-as-member writes, but spaceType and skey segments are mandatory).

#### Findings 4, 5, 10, 11, 29, 30, 31, 38, 39 (consolidated)
These nine high-severity findings restate the encoding and notify-`aud` defects detailed above, each at a distinct plan location:
- **4, 10, 29, 31, 38 (encoding axis A):** read-flow `commit.{hash,mac,ikm,sig}` are base64 `$bytes`, not hex — cited at §3.5F line 256, R8 lines 1260/1264, §7.1 line 1322, §7.2-13 line 1339. Code: `space_handlers.rs:1146-1176`.
- **5, 11, 30 (encoding axis B + reconciliation):** write `setHash` (hex of 2048-byte state) and read `commit.hash` (base64 of sha256(state)) differ in both encoding and content; hex-to-hex compare fails. Code: `writer.rs:56-57,231,309,349` vs `space_handlers.rs:1171`.
- **39 (notify aud):** AppView's `aud==AppView DID` check rejects every fan-out because both the self-register stub (`aud = member DID`) and registerNotify (`aud = client_id URL`) paths produce a non-DID/non-AppView aud. Code: `notify.rs:222-228`, `recipient.rs:48-100,176-183`, `service_auth.rs:125-150`.

**Combined fix:** apply the coordinated encoding correction across lines 256, 372, 1260, 1264, 1322, 1339 (read = base64 `$bytes`; write `setHash` = hex of 2048-byte state; reconcile by decoding both sides to raw bytes and applying sha256 to the state), and reconcile the notify `aud` per Findings 7/12/17.

### MEDIUM

#### Finding 9 — createRecord returns `WriteRecordResponse`, not `SpaceCommitResult`
- **Plan location:** Part 6 (B) line 1124; W1 line 1138.
- **Plan says:** W1/W2/W3 (all `com.atproto.space.createRecord`) return `SpaceCommitResult {rev, setHash, uris[], cids[]}`; W1's `setHash` can be saved for R8.
- **Ground truth:** `create_record_write` returns `Json<WriteRecordResponse>` via `single_write_response` (`space_handlers.rs:729-758`); `WriteRecordResponse` (`:699-708`) = `{uri, cid, validationStatus?}` only. `single_write_response` (`:871-888`) discards `result.rev`/`result.set_hash`. Only `apply_writes` (`:631-688`) returns `SpaceCommitResult`. **Nuance:** the same plan paragraph already correctly states the response is `{uri,cid,validationStatus?}` and sources `rev` from a separate getRepoState call — internally inconsistent, not wholly wrong.
- **Fix:** At line 1124, scope `SpaceCommitResult` to `applyWrites`; at line 1138 drop the createRecord `setHash` assertion and derive the R8 digest from getRepoState's `commit.hash`.

#### Finding 13 — `atproto_client::com::atproto::space::create_record` does not exist
- **Plan location:** §3.4 line 228.
- **Plan says:** Compose write uses `atproto_client::com::atproto::space::create_record(..., CreateRecordRequest{…})`.
- **Ground truth:** `crates/atproto-client/src/lib.rs:31-48` exposes only `com::atproto::{repo, server, identity}`; no `com::atproto::space` module (zero space references in `crates/atproto-client/src`). `create_record`/`CreateRecordRequest` exist only under `com::atproto::repo` (`com_atproto_repo.rs:257,314`), targeting `com.atproto.repo.createRecord`. The space write endpoint is server-side only (`space_handlers.rs:728`, input `CreateRecordInput{space,repo,collection,rkey?,validate?,record}` at `:712-726`).
- **Fix:** Either POST raw to `{pds_url}/xrpc/com.atproto.space.createRecord` with the DPoP auth and a body matching `CreateRecordInput`, or add a `space::create_record` helper to atproto-client.

#### Finding 18 — Member-operated AppView's `listMembers` returns 403 NotSpaceOwner
- **Plan location:** §3.5 Step G line 257; §3.6/§3.9 members table; M1.
- **Plan says:** AppView (member OAuth) loads the member set via `simplespace.listMembers` for a defense-in-depth perimeter.
- **Ground truth:** `list_members` (`crates/atproto-pds/src/space/service.rs:504-508`) returns `NotSpaceOwner` whenever `uri.space_did != owner_did`; `get_members` (`space_handlers.rs:571-572`) sets `owner = subject.sub()`, so the caller must be the authority. The AppView is a "pure member/consumer client" (plan line 166) running under "session (member)" auth (plan line 184), so its `listMembers` 403s. The only successful calls in the plan (Step 6 line 985, M1 line 1097) run as owner identity3.
- **Fix:** Mark Step G's `listMembers` perimeter as authority-only; rely on the host's `mintPolicy=member-list` gate plus `listRepos` (Step D), or have the owner publish the member set out-of-band.

#### Findings 27, 32, 34 (consolidated, medium)
- **27 (commit-lthash-cid):** the line-1296 helper `sha256(b'\x00'*2048).hexdigest()` computes the 32-byte commit.hash/digest, NOT the wire setHash (empty-repo wire setHash = `0`*4096). Code: `set_hash.rs:186-197`, `writer.rs:309`, `space_repo.rs:264`. (File path note: the real file is `crates/atproto-space/src/space_repo.rs`, not `crates/atproto-pds/src/space/space_repo.rs`.)
- **32 (citation-config-error):** the line-1296 parenthetical "matches the wire setHash form" is itself correct for the hex `setHash`; the real defect is the surrounding commit.hash claims (lines 254, 1264, 1322, 1339, 372) asserting hex where the code is base64. Code: `writer.rs:56-57` vs `space_handlers.rs:1146-1176`.
- **34 (citation-config-error):** W1's "Save the post's `setHash` for R8" is not executable from a createRecord response (`WriteRecordResponse` has no setHash, `space_handlers.rs:698-708,871-891`); obtain the digest from getRepoState's `commit.hash` (base64) instead, or switch W1 to applyWrites.

**Combined fix:** relabel line 1296 as computing the empty-repo digest (not setHash; empty-repo wire setHash = `0`*4096); correct the commit.hash hex claims to base64 `$bytes`; drop "Save the post's setHash" from W1 in favor of getRepoState.

#### Finding 41 — Missing `/.well-known/atproto-did` route blocks recipient resolution
- **Plan location:** §3.3 routes table lines 174-192; §4.4 Option A.
- **Plan says:** AppView publishes `/client-metadata.json`, `/jwks.json`, `/.well-known/did.json` but no `/.well-known/atproto-did`.
- **Ground truth:** getSpaceCredential calls `resolve_recipient` → `resolve_handle_http` which fetches exactly `https://walking-club-appview.ngerakines.dev/.well-known/atproto-did` (`recipient.rs:55-71`, `resolve.rs:123,129,143`). With no such route, the fetch 404s → stub: `service_did = payload.iss` (member DID), `service_endpoint = bare client_id origin`. Fan-out then mints `aud = member DID` (`notify.rs:222-229`). Notify is best-effort (writes unaffected) → medium.
- **Fix:** Add a `GET /.well-known/atproto-did` handler returning the AppView's `did:web` as text/plain; otherwise relax the inbound `aud==AppView-DID` check.

### LOW

#### Findings 3 & 8 — `read_self` gate citation should be `:1442`, not `:1432`
- **Plan location:** §3.2 line 164.
- **Plan says:** "`read_self` does NOT satisfy it (`:1432`)".
- **Ground truth:** `space_handlers.rs:1432` is `if subject.client_id().is_none()` → 403 "requires OAuth auth with a client_id" — an app-password/OAuth presence check, unrelated to read vs read_self. The actual gate is `assert_space_scope(…, SpaceAction::Read, None)` at `:1442` (`space_permission.rs:668-697`: ReadSelf does not confer Read). The substantive claim is correct; only the cite is wrong. (Findings 3 and 8 are the same defect raised by two passes.)
- **Fix:** Change the parenthetical from `:1432` to `:1442`; reserve `:1432` for the separate app-password rejection.

#### Finding 14 — PDS does not use the `Authorization` extractor for notifyWrite
- **Plan location:** §3.6 line 275.
- **Plan says:** AppView verifies inbound service-auth via `atproto_xrpcs::authorization::Authorization` "exactly as the PDS does".
- **Ground truth:** `notify_write` (`space_handlers.rs:2069-2113`) decodes the payload first, reads the bearer via `bearer_token(&parts)` (`:2095`), then calls `verify_service_auth(…, &space.space_did, NOTIFY_WRITE_NSID)` (`:2096-2104`). No axum `Authorization(` extractor is used anywhere in `crates/atproto-pds/src/http/`.
- **Fix:** Drop "exactly as the PDS does"; the PDS decodes the `{space,repo,rev}` body first, then verifies via `bearer_token` + `verify_service_auth(aud=owner DID, lxm=notifyWrite)`.

#### Finding 15 — `verify_commit_signature` takes `SpaceContext`, not a pre-built ctx
- **Plan location:** §3.5 Step F item 3 (line 255).
- **Plan says:** `verify_commit_signature(ctx, commit, writer_key)`.
- **Ground truth:** `crates/atproto-space/src/commit.rs:228-236` — `verify_commit_signature(context: &SpaceContext, commit: &Commit, verifying_key: &KeyData)`; it rebuilds ctx internally via `encode_ctx(context, &commit.ikm)` (`:233`). Contradicts the plan's own preceding line 254 (`verify_commit(SpaceContext{space, rev}, commit)`).
- **Fix:** Change to `verify_commit_signature(SpaceContext{space, rev}, &commit, &writer_key)`.

#### Finding 19 — createSpace owner check is in the handler, not the service layer
- **Plan location:** Step 5 line 950.
- **Plan says:** App-password createSpace is "owner-checked in the service layer".
- **Ground truth:** `space_handlers.rs:186-196` sets `authority_did = caller` and rejects explicit `did != caller` with 403 NotSpaceOwner; the service `create_space` (`service.rs:45-124`) does no ownership check (only seeds rows + auto-adds owner as first member). The `uri.space_did != owner_did` service checks exist only for update/add/remove/delete (`service.rs:235,302,475,504,519`), NOT createSpace.
- **Fix:** Reword: createSpace binds authority = caller in the HANDLER; there is no service-layer owner check for createSpace.

#### Finding 20 — `managingApp` bare origin cannot satisfy a real managing-app mint
- **Plan location:** M2 line 1104.
- **Plan says:** Sets `managingApp` to the AppView base origin; asserts getSpace echoes it.
- **Ground truth:** The round-trip/echo is correct (`service.rs:64-72,279-292,634-657`). But at mint time, `resolve_service_endpoint(managing_app)` (`space_handlers.rs:1609-1622`, `recipient.rs:149-170`) splits on `#` into `<did>#<fragment>`; `fetch_did_document` (`recipient.rs:122-136`) only handles `did:plc:`/`did:web:` and returns `Ok(None)` otherwise. The bare URL has no `#` and is not a DID → `Ok(None)` → 403 NotAuthorized "could not resolve managingApp service endpoint"; `checkUserAccess` is never reached. M2 restores to `member-list` immediately, so the test passes. (Minor: failure is at endpoint resolution, one step before the `checkUserAccess` GET.)
- **Fix:** Keep M2 as a config round-trip only; note `managingApp` must be a DID service identifier (`did:web:host#fragment`); restore to `member-list`.

#### Finding 21 — Host does not pin attestation `alg` (advisory only)
- **Plan location:** §3.7 line 294.
- **Plan says:** Enumerates host attestation checks; implies ES256 verification.
- **Ground truth:** `AttestationHeader` declares only `typ`+`kid` (`mint_authz.rs:151-158`); `alg` is never read. Signature verification (`:373`) uses the JWKS-selected `KeyData` type, not the token's `alg`. However, the §3.7 enumeration does NOT claim `alg` enforcement — every listed item matches the code, and "verifies the JWS" is exactly `:373`. No plan defect.
- **Fix:** No change required. Optionally note: "host does not pin attestation `alg`; the AppView must publish an ES256/P-256 JWK to match the `alg:ES256` it signs."

#### Finding 25 — `op.cid` is a base32 CID string, not a hex/byte field
- **Plan location:** R8 line 1262; Step F line 256.
- **Plan says:** Blanket "all byte fields are hex-encoded" (line 1264) implies `cid` is a byte/hex field.
- **Ground truth:** `RecordOpEntry.cid: Option<String>` is plain serde (`space_handlers.rs:1284-1295`); `RecordRow.cid: String`/`OplogEntry.cid: Option<String>` (`storage.rs:97,133`); element uses the textual cid (`set_hash.rs:166-169`). Only `hash/mac/ikm/sig` are byte fields (`commit.rs:88-98`), and those are base64 `$bytes`, not hex. `compute_cid` yields CIDv1/dag-cbor(0x71)/sha2-256 (`crates/atproto-dasl/src/cid/mod.rs:687-698`), so the recompute is right but the comparison is CID-string to CID-string.
- **Fix:** Narrow line 1264: `op.cid` is a base32 CID string compared via `compute_cid(...).to_string() == op.cid`; commit byte fields are base64 `$bytes`.

#### Finding 28 — Undefined "vlv[…]" ctx shorthand; framing is fixed uint16be
- **Plan location:** Step F line 254; R8 line 1264.
- **Plan says:** `ctx = "atproto-space-v1" ‖ vlv[space_uri, rev, ikm]` ("vlv" never defined).
- **Ground truth:** `encode_ctx` (`crates/atproto-space/src/commit.rs:70-81`) frames as `DOMAIN_PREFIX` (unprefixed) then, per field, a fixed big-endian `uint16` length prefix (`(field.len() as u16).to_be_bytes()`, `:77`) + field bytes — matching the spec. "vlv" could be misread as varint, producing a non-interoperable ctx.
- **Fix:** Replace "vlv[…]" with explicit `uint16be(len)||value` framing per field; note implementers should call `atproto_space::commit::encode_ctx`.

#### Finding 33 — Header mislabels createRecord output as `SpaceCommitResult`
- **Plan location:** (B) WRITE intro, line 1124.
- **Plan says:** W1/W2/W3 (createRecord) output `SpaceCommitResult {rev, setHash, uris[], cids[]}`.
- **Ground truth:** createRecord/putRecord return `WriteRecordResponse {uri, cid, validationStatus?}` via `single_write_response` (`space_handlers.rs:700-708,871-891`); only applyWrites returns `SpaceCommitResult` (`:631-635`, `writer.rs:53-62`). The plan's own §3.4 line 238 and W1 Assert line 1138 already show the correct shape. Low because every operational Assert already tests `{uri,cid}` and fetches rev separately.
- **Fix:** Scope `SpaceCommitResult` to applyWrites; createRecord/putRecord return `{uri, cid, validationStatus?}`, rev/setHash via getRepoState.

#### Finding 35 — `config.rs:35-47` citation is ambiguous and wrong-ranged
- **Plan location:** Step 5 line 950 vs Step 0 line 867.
- **Plan says:** `config.rs:35-47` documents member-list/`#open` defaults; `config.rs:45-58` is the production validator.
- **Ground truth:** Two different files. The production validator is `crates/atproto-pds/src/config.rs` (`validate_production_safety:42-75`; jwt/admin sentinel `:53-58` — so line 867's `config.rs:45-58` is accurate for that file). The space-config defaults live in `crates/atproto-pds/src/space/config.rs`: `MintPolicy::MemberList` default at lines 35-47, but `AppAccess::Open` (the `#open` default) at lines 77-87, NOT in 35-47. Line 950's bare `config.rs:35-47` collides with the unqualified path at 867 and excludes the `#open` default.
- **Fix:** At line 950, cite `space/config.rs:35-47` (member-list) + `space/config.rs:77-87` (`#open`); keep `src/config.rs:45-58` for the production validator.

#### Finding 36 — M3 ellipsis omits the distinctive "space-management" wording
- **Plan location:** M3 Assert line 1120.
- **Plan says:** removeMember without manage → 403 InvalidToken "insufficient OAuth scope … need `space:…?manage=update…`".
- **Ground truth:** removeMember is gated by `assert_space_manage(Update)` (`space_handlers.rs:519-523`), whose message is "insufficient OAuth scope for this space-management operation; need `{scope}`" (`:1937-1944`). The distinct record/read path (`assert_space_scope`) emits "this space operation" (`:1905`). Error name (InvalidToken), 403, and the `manage=update` shape are all correct; the ellipsis is compatible but under-specified.
- **Fix:** Quote the manage wording verbatim ("…for this space-management operation; need `space:…?manage=update…`") so the assertion can't match the record-scope message.

#### Finding 37 — `PDS_DID_PLC_URL` takes a bare hostname (name is misleading)
- **Plan location:** env/pds1.env line 779 (also Step 2 line 883).
- **Plan says:** `PDS_DID_PLC_URL=plc.directory`.
- **Ground truth:** `pds.rs:93-94` binds it to `plc_directory`, passed as `directory_hostname` (`plc.rs:42-43`, doc: "Without scheme"); consumed bare (`plc.rs:213`, `identity_handlers.rs:216`), with `https://` prepended downstream. A scheme-prefixed value would yield `https://https://…`. The plan value is correct; only the `_URL` suffix on the env var name is misleading.
- **Fix:** Keep `plc.directory`; add a note that this var takes a bare hostname (no scheme).

#### Findings 40, 42, 43, 44 (consolidated, low — devops/operational)
- **40:** Line 1199's claim that getSpaceCredential self-register "makes R9 work without explicit registerNotify" is false — the stub stores a bare origin + member DID, so a HOP-2 POST 404s; explicit registerNotify is mandatory (`space_handlers.rs:1678-1697`, `recipient.rs:176-198`). Fix: correct line 1199; explicit registerNotify (R9) is required for the live feed.
- **42:** Step 8 heading (line 1016) is loosely worded ("ensure the authority is a notifyWrite subscriber path"), but line 1018 already disclaims outward authority registration. The undocumented nuance: under the recommended `#open`/no-attestation config, the self-registered row is a member-DID stub (`space_handlers.rs:1697`). Fix: note the stub.
- **43:** `space:read_self` in line 155 is redundant (`read` implies it, `space_permission.rs:677-686`); the OAuth de-dup/last-wins concern is disproven — `ScopesSet` stores raw `Vec<String>` with OR enforcement (`scopes.rs:1050,1099-1103`) and exact-equality grants preserve both collection grants (`:893-896`). Fix: drop `space:read_self`; no OAuth-side change needed.
- **44:** "WAL; single writer" (lines 339, 426) is inaccurate — the design has multiple concurrent logical writers (3 firehose tasks, notify reader worker, oauth_request inserts, jti pruner) into one WAL file; SQLite WAL is one-writer-at-a-time and extra writers serialize/can hit SQLITE_BUSY. Workable for a 3-PDS testbed (`busy_timeout=5000`), so low. Fix: drop "single writer" wording or funnel all writes through one serialized task.

## 4. Spec-vs-Implementation Divergences

These are cases where the implementation itself differs from a literal reading of the 0016 spec — the reader should know these are code/lexicon choices the plan must follow, not plan errors:

1. **Commit byte-field wire encoding (Findings 4/10/22/29/31/38).** The 0016 `#signedCommit` table specifies the *semantics* of `hash/mac/ikm/sig` but does not mandate a JSON on-wire encoding. The impl chose the atproto lex-data `{"$bytes":"<base64 STANDARD_NO_PAD>"}` convention (`space_handlers.rs:1146-1176`), not hex. Any spec-only AppView that assumed hex would fail; the plan must follow the impl's base64 form.

2. **`setHash` field content (Findings 11/23/27).** The write-response `setHash` is hex of the full 2048-byte LtHash *state* (`writer.rs:309`, `space_repo.rs:261-269`), while the spec's notion of a commit "hash" is the 32-byte `sha256(state)`. These are two different objects in the impl (state vs digest); the spec discusses the commitment digest, the impl additionally exposes the raw state hex as `setHash`. (Separately, the *write-time* `setHash` returned by createRecord is the algorithm-name string `"lthash"` per `realm.rs:28`.)

3. **Attestation `alg` (Finding 21).** The spec example pins `alg=ES256`; the impl does not read or enforce `alg` at all, verifying with the JWKS-selected key type (`mint_authz.rs:151-158,373`). Permissive, not breaking, for an ES256-signing AppView.

4. **HOP-2 `aud` derivation (Findings 6/7/12/17/39/41).** The spec frames the AppView as a notify recipient identified by its DID; the impl derives the fan-out `aud` from recipient resolution (`/.well-known/atproto-did` → PDS service) or, on failure, a stub keyed on the member DID, or (registerNotify) the raw `client_id` URL (`notify.rs:222-229`, `recipient.rs:48-100,176-183`, `space_handlers.rs:2499-2502`). The "AppView DID" assumption is only valid if the AppView publishes the DID infrastructure the impl resolves.

## 5. What the Plan Got Right (Verified-Correct)

The check confirmed the following are accurate, so the reader knows the review's scope:
- **HTTP status discipline:** scope-shortfall → 403 `InvalidToken` (M3 line 1120, R1(a) line 1189); credential-required → 401 (R4-neg line 1223, cite `:2336`). Both match `assert_space_scope` (`:1901-1908`) and `require_space_credential` (`:1799-1804`).
- **`PDS_DID_PLC_URL=plc.directory`** as a bare hostname is the correct form (`pds.rs:480`, `plc.rs:43`, `atproto-identity/src/plc/mod.rs:64`).
- **Direct-curl `createAccount` bootstrap** (Part 5 Step 3, lines 897-919): public unauthenticated POST, correct input shape, `PDS_INVITE_REQUIRED` default false, PLC genesis on omitted `did`, handle-domain suffix gate, and the admin CLI lacking account/invite-create — all verified accurate.
- **PDS `/metrics` + smtp feature note** (§7.1 line 1323): the default image omits `metrics`/`smtp`; rebuild requirement correctly stated (Dockerfile:82-84, Cargo.toml:128-131).
- **M2 config round-trip/echo** for `managingApp` (persist + getSpace echo + clear-on-restore) is correct (`service.rs:634-657`).
- **R1 read-gate cite `:1442`** (line 1189) is correct (only the §3.2 duplicate cite at `:1432` is wrong).
- **M3 manage-scope shape** `space:…?manage=update…` (line 1120) is correct and contradicts §3.2's bare-token error.
- **HOP1/HOP2 push topology** (Step 8 line 1018): "authority does not register itself on writer PDSes" is correct.
- **createSpace conclusion** that an app-password owner session suffices and the OAuth manage gate is a no-op (Finding 19 — only the enforcement-location attribution was wrong).
- **The empty-repo digest value** `sha256(2048 zeros)` is genuinely the empty-repo commit.hash (`set_hash.rs:186-197`) — correct as a digest, mislabeled only as "setHash form".

## 6. Findings Rejected as False Positives

**Four** candidate findings were investigated and rejected. Three were self-declared "no defect" by the verifier and confirmed factually correct: (a) the 403/401 status-code split on space methods (plan and code agree, and the plan never conflates them); (b) the AppView `/metrics` prometheus endpoint and the §7.1 note that the default PDS image excludes `metrics`/`smtp` (Dockerfile and feature flags confirm the rebuild requirement is accurately stated); and (c) `PDS_DID_PLC_URL=plc.directory` as a bare hostname (the consumers prepend `https://`, so the plan's value is the right form — flagged only because the var name's `_URL` suffix is misleading, which is captured non-rejected as the low-severity Finding 37). The fourth rejection covers the direct-curl `createAccount` bootstrap (Part 5 Step 3), where every ground-truth claim — public unauthenticated handler, input shape, invite/PLC defaults, handle-domain gate, admin-CLI surface — reproduced exactly, so the plan has no error. In all four cases the proposed "fix" was explicitly "no change needed."
