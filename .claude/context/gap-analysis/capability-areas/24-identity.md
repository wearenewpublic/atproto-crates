# D. Identity & DID

_Part of the atproto-crates 0.15.0-rc.1 release-candidate gap analysis. See [README](../README.md) · [inventory](../00-atproto-crates-inventory.md) · [coverage matrix](../20-coverage-matrix.md) · [synthesis & roadmap](../50-synthesis-and-roadmap.md) · [permissioned data](../permissioned/40-permissioned-overview.md)._

_Comparison notes referenced throughout: [bluesky-reference](../impl-notes/bluesky-reference.md) · [tranquil-pds](../impl-notes/tranquil-pds.md) · [cocoon](../impl-notes/cocoon.md) · [rsky-pds](../impl-notes/rsky-pds.md) · [metalbear](../impl-notes/metalbear.md) · [cirrus](../impl-notes/cirrus.md) · [arroba](../impl-notes/arroba.md) · [pegasus](../impl-notes/pegasus.md) · [alteran](../impl-notes/alteran.md) · [zds](../impl-notes/zds.md) · [dnproto](../impl-notes/dnproto.md)._

## Assessment

Identity is the one area where atproto-crates arrives with a real structural advantage and then largely fails to spend it. The workspace ships `atproto-identity`: a spec-compliant concurrent DNS-TXT-plus-HTTPS handle resolver with conflict detection (`crates/atproto-identity/src/resolve.rs:616-641`), a full PLC operation model covering genesis, update and tombstone (`crates/atproto-identity/src/plc/operations.rs:84-118`), an operation-chain validator (`crates/atproto-identity/src/plc/chain.rs:261`), did:web and did:webvh syntax validation (`crates/atproto-identity/src/validation.rs:517`, `:607`), and SSRF-safe handle/hostname validation (`:391`, `:178`). No comparison implementation has a library asset of that quality behind its PDS. But a library is not a server. The PDS wires in three things — key generation and signing, `plc::{query,fetch_audit_log,submit}`, and `resolve::resolve_handle`. The validation module has **zero** call sites in `crates/atproto-pds/src/` (grep for `atproto_identity::validation` and `validation::` returns only `atproto_lexicon::validation` in the spaces code). The chain validator is likewise unused by the server.

All seven `com.atproto.identity.*` methods the reference treats as PDS-side are routed (`crates/atproto-pds/src/http/router.rs:193-222`), plus `refreshIdentity`, which the reference does *not* route. That reads as full coverage — better than cirrus (no `updateHandle`), alteran (`updateHandle` is an unconditional 501), arroba (only a proxied `resolveHandle`) and dnproto (`resolveHandle` delegated to the public AppView). Reading the handlers inverts the picture. `updateHandle` performs the PLC leg correctly and nothing else: no handle syntax validation, no TLD check, no service-domain constraint, no reserved-subdomain check, no bidirectional resolution proof for an off-service domain, no uniqueness pre-check, no rate limit, and — the item this chapter was asked to check — **no `#identity` firehose event**. `signPlcOperation` takes a different input shape than the lexicon and drops the emailed confirmation token that is the whole security premise of the endpoint. `submitPlcOperation` performs none of the reference's server-side sanity checks and emits no event. `refreshIdentity` reads the wrong input field and returns a body that is not `identityInfo`. `createAccount` accepts an arbitrary caller-supplied `did` from an unauthenticated request and creates an *active* account bound to it.

The calibration does not favour atproto-crates. These are not "only the reference does this" gaps. zds — a Zig PDS — implements `updateHandle` with account-state gating, 10-per-5-minutes and 50-per-day per-DID limits matching the reference exactly, handle normalization, hosted-domain validation, external-handle bidirectional resolution, a did:web document cross-check, a uniqueness check, a tombstone check, a rotation-key-authorization check, and an `#identity` sequence on both the changed and unchanged paths (`/tmp/gap-scratch/zds/src/atproto/identity.zig:188-296`). tranquil-pds does the same class of work in Rust (`/tmp/gap-scratch/tranquil-pds/crates/tranquil-api/src/identity/did.rs:523-700`). pegasus, rsky-pds, cocoon and metalbear all sequence `#identity` on handle change. Ten of eleven comparisons serve `GET /.well-known/atproto-did`; atproto-crates serves neither that nor `/.well-known/did.json`, so a self-hosted deployment cannot host a handle on its own domain without an external web server in front.

Where atproto-crates is genuinely ahead: `getRecommendedDidCredentials` returns the account's *actual* rotation key, where metalbear (`/tmp/gap-scratch/metalbear/src/server.c:1268-1270`) and cirrus (`packages/pds/src/xrpc/identity.ts:74`) both mistakenly return the signing key — producing a DID document their own server could not rotate. Foreign handle resolution uses the real concurrent dual lookup with conflict detection, stronger than metalbear (local registry only), cirrus, alteran, arroba and dnproto (all proxy or delegate). And did:plc genesis puts an optional operator-held fallback rotation key alongside the per-account key on every op (`crates/atproto-pds/src/plc.rs:183-190`), a recovery affordance most of the field lacks. The foundations are sound; the endpoints on top of them are not finished.

## Per-capability analysis

### Handle resolution: `resolveHandle` — PARTIAL

Routed at `router.rs:201`, handled at `crates/atproto-pds/src/http/identity_handlers.rs:60-107`. It checks the local directory first (`:65-71`); on a miss, when `HttpState::dns_resolver` is populated it calls `atproto_identity::resolve::resolve_handle` (`:87`), which runs DNS TXT at `_atproto.<handle>` and HTTPS `/.well-known/atproto-did` concurrently and returns `ConflictingDIDsFound` on disagreement (`crates/atproto-identity/src/resolve.rs:624-640`). `hickory-dns` is a default feature (`crates/atproto-pds/Cargo.toml:96`) and the resolver is wired at `crates/atproto-pds/src/bin/pds.rs:568-571`, `:639`, so a stock build does the real dual lookup; without it the handler silently degrades to HTTP-only (`:98`).

Two defects. **No input normalization or validation**: `lookup_handle` issues `WHERE handle = ?` with the raw query string (`crates/atproto-pds/src/account/directory.rs:234-238`), so `?handle=Alice.Example` misses an account stored lowercase and an `at://` or `@` prefix passes through to the network resolver. The reference normalizes first (`/tmp/gap-scratch/atproto/packages/pds/src/api/com/atproto/identity/resolveHandle.ts:10`), as does zds (`identity.zig:265`). `is_valid_handle` and `strip_handle_prefixes` exist in the workspace and are never called. **No account-state gate**: a takendown account still resolves; metalbear checks `metalbear_account_is_active` first (`/tmp/gap-scratch/metalbear/src/server.c:783`).

Also absent is the "supported domain ⇒ fail fast" branch the reference has (`resolveHandle.ts:20-26`), rsky-pds has (`apis/com/atproto/identity/resolve_handle.rs:50-57`) and zds has (`identity.zig:272-273`). atproto-crates goes out to the network for an unregistered handle under its own domain, which is a wasted round trip at best and returns a foreign DID for a handle in its own namespace at worst.

### `/.well-known/atproto-did` and `/.well-known/did.json` — MISSING

Neither route exists. `crates/atproto-pds/src/http/router.rs:27-433` registers exactly two `.well-known` paths, both OAuth (`:253`, `:257`); a tree-wide grep for `well-known` in `crates/atproto-pds/src/` returns only OAuth metadata, doc comments, and *outbound* client fetches in the spaces code (`space/recipient.rs:59`, `space_auth.rs:195`).

`/.well-known/atproto-did` — the HTTPS half of handle resolution, without which a PDS cannot host `alice.pds.example.com` — is served by the reference (`packages/pds/src/well-known.ts:8-29`), tranquil-pds (`crates/tranquil-api/src/lib.rs:472`), cocoon (`server/server.go:508`), rsky-pds (`src/well_known.rs:23`), metalbear (`src/server.c:6392-6393`), cirrus (`index.ts:118`), pegasus (`lib/api/well_known.ml:69-83`), alteran (`src/entrypoints/well-known/atproto-did.ts:12-21`), zds (`src/http/router.zig:137`) and dnproto (`src/pds/Pds.cs:216`). Ten of eleven, including both projects below the "serious" line. Only arroba omits it, and arroba is a repo library with a demo app rather than a hosting PDS.

`/.well-known/did.json` is different: the reference does **not** serve it either — a grep for `did.json` across `/tmp/gap-scratch/atproto/packages/pds/src/` and `/tmp/gap-scratch/bsky-pds/` returns nothing — and rsky-pds omits it too. It is served by tranquil-pds (`lib.rs:471`, plus per-account `/u/{handle}/did.json` at `:496`), cocoon (`server/handle_well_known.go:53-67`), metalbear (`server.c:6390`, plus `/acct/<name>/did.json`), cirrus (`index.ts:113`), pegasus (`bin/main.ml:15`), alteran, zds (`router.zig:136`) and dnproto (`Pds.cs:215`).

### `updateHandle` — PARTIAL, with a validation hole

`identity_handlers.rs:136-145` authenticates via `require_authn_sub` — session *or* OAuth+DPoP, which is correct and better than the `require_access_jwt` sites elsewhere in the crate — and delegates to `do_update_handle` (`:155-280`). That function is a faithful PLC update: look up the rotation key ref (`:180-196`), fetch the audit log and take the last non-nullified entry (`:216-231`), rebuild `Operation::new_update` preserving rotation keys, verification methods and services while replacing `alsoKnownAs` (`:238-250`), sign, submit, `set_handle` locally (`:259-277`). Tombstone and legacy-create states are correctly refused (`:251-257`).

Everything *around* that leg is absent. The reference's `normalizeAndValidateHandle` (`packages/pds/src/account-manager/account-manager.ts:164-217`) normalizes, rejects invalid TLDs, rejects explicit slurs, enforces service-domain constraints (no interior dots, 3–18 characters, not reserved — `packages/pds/src/handle/index.ts:19-48`) and, for an off-service domain, **resolves the handle and requires it to resolve back to the caller's DID** (`:208-212`). `validateHandleUpdate` pre-checks uniqueness (`:362-373`), and the endpoint is rate-limited 10/5min and 50/day per DID (`api/com/atproto/identity/updateHandle.ts:19-30`).

atproto-crates does none of this. `PDS_SERVICE_HANDLE_DOMAINS` defaults empty (`bin/pds.rs:241-242`) and even when set is consulted only by `createAccount` (`http/auth_handlers.rs:93-110`) — never by `updateHandle`. So any authenticated account can set its handle to an arbitrary string it does not own. A conformant relay doing bidirectional verification will refuse the handle, so the damage does not propagate — but *this PDS* thereafter answers `resolveHandle?handle=bsky.app` from its local directory (`identity_handlers.rs:65-71`) with the squatter's DID. The only backstop is the `UNIQUE` constraint on `account.handle` (`crates/atproto-pds/migrations/accounts/20260501000001_init.sql:11`), and with no pre-check a collision surfaces as a 500 from `set_handle` (`:271-277`) *after* the PLC operation has already been submitted, leaving the DID document and the local row permanently out of sync.

Cirrus does not route `updateHandle` and alteran returns 501 — defensible single-user/hobby scope decisions, marked `n/a`.

### `#identity` firehose events on handle change — MISSING

The explicit check for this chapter: no. `emit_identity_event` (`identity_handlers.rs:688-706`) has exactly one call site, at `:664` inside `refreshIdentity`. A tree-wide grep for `EventType::Identity` in `crates/atproto-pds/src/` returns that one production site plus outbox tests. Concretely: `updateHandle` (`:136`) emits nothing; `admin.updateAccountHandle` (`crates/atproto-pds/src/admin/handlers.rs:628`, which reuses `do_update_handle`) emits nothing; `submitPlcOperation` (`http/auth_handlers.rs:1685-1710`) emits nothing; `createAccount` emits nothing at all — `AccountManager::create_account` contains no outbox append (`crates/atproto-pds/src/account/manager.rs:83-240`); `activateAccount` (`auth_handlers.rs:677-688`) emits `#account` only, via `set_state` → `emit_account_event` (`manager.rs:359-390`).

The reference sequences `#identity` from `updateAccountHandle` (`account-manager.ts:386-393`), from `submitPlcOperation` (`api/com/atproto/identity/submitPlcOperation.ts:53`), atomically with `#account`+`#commit`+`#sync` at account creation (`sequencer/sequencer.ts:200-210`), and again on activation (`:214-224`). Every serious independent does the handle-change half: cocoon (`server/handle_identity_update_handle.go:91`), rsky-pds (`apis/com/atproto/identity/update_handle.rs:60-70`), pegasus (`lib/identity_util.ml:106`), tranquil-pds (`identity/did.rs:612`, `:638`, `:695`), zds (`identity.zig:225`, `:292`), and metalbear (`metalbear_sequencer_identity` inside `update_handle`, with an explicit comment about ordering it after the record that makes the handle resolve). Consequence: a rename on this PDS is invisible to the network until an unrelated cache expiry.

A second, separate defect affects the one `#identity` that *is* emitted. The lexicon body requires top-level `seq`, `did`, `time` with optional `handle` (`/tmp/gap-scratch/atproto/lexicons/com/atproto/sync/subscribeRepos.json` `#identity`). The CBOR encoder nests it: `{"seq":…,"repo":…,"time":…,"payload":{"did":…,"handle":…}}` (`crates/atproto-pds/src/sequencer/frame.rs:104-122`). A conformant consumer finds no `did` at the top level. That framing defect is shared by every event type and belongs primarily to the sync chapter, but it means the single `#identity` this PDS can emit is also unreadable by a real relay.

### The PLC signing trio — DIVERGENT

| Method | atproto-crates | Lexicon / reference |
|---|---|---|
| `requestPlcOperationSignature` | Returns `{token}` — a 60 s service-auth JWT signed with the caller's own `#atproto` key, `lxm` pinned (`identity_handlers.rs:299-341`) | Lexicon declares **no output** and describes "Request an email with a code". Reference mails a `plc_operation` token (`requestPlcOperationSignature.ts:36-56`) |
| `signPlcOperation` | Requires a single `op` field holding a complete `UnsignedOperation` (`auth_handlers.rs:1592-1596`, deserialized at `:1650`); gated on a session JWT only (`:1619`) | Lexicon input is `{token?, rotationKeys?, alsoKnownAs?, verificationMethods?, services?}`; reference **requires** the email token (`signPlcOperation.ts:41-51`), refuses tombstoned DIDs (`:53-56`), composes the update itself (`:57-73`) |
| `submitPlcOperation` | Deserializes and POSTs, scoped to `claims.sub` (`auth_handlers.rs:1685-1710`) | Reference validates op shape, server rotation key present, `atproto_pds` service type and endpoint, `verificationMethods.atproto`, and `alsoKnownAs[0]`, then sequences `#identity` (`submitPlcOperation.ts:19-53`) |

The `signPlcOperation` divergence is both an interop break and a security regression. No canonical client — `goat`, `@atproto/api`'s migration flow, the reference's own tooling — sends an `op` field, so all of them fail with a 400. And the emailed token is the second factor that makes DID-key rotation safe: without it, a stolen 2-hour access token (not invalidated by password reset, per the auth inventory §N) is enough to have the PDS sign an arbitrary rotation operation with the account's rotation key, including one that replaces every rotation key and repoints `atproto_pds`. The reference, rsky-pds (`sign_plc_operation.rs:29-36`), cocoon (`handle_identity_sign_plc_operation.go:56-90`), pegasus (`signPlcOperation.ml:14-57`), zds (`identity.zig:65-114`) and metalbear all gate on an emailed token. cirrus and alteran deliberately skip it — cirrus obtains the token out-of-band via its CLI (`xrpc/identity.ts:122-129`), alteran accepts and ignores it (`signPlcOperation.ts:13-14,37`) — documented single-user decisions in both cases, so both are `n/a`.

`submitPlcOperation`'s missing validation is the mirror image: because `signPlcOperation` will sign anything and `submitPlcOperation` will submit anything, the pair provides no server-side protection against an operation that bricks the account's identity. pegasus performs equivalent handle-and-signing-key validation (`submitPlcOperation.ml:18-27`) and zds calls `validatePlcOperation` before POSTing (`identity.zig:131`).

### `getRecommendedDidCredentials` — PARTIAL, the strongest endpoint here

`identity_handlers.rs:410-510` builds the response from local state with no PLC round trip: the account's real `#atproto` signing key in public form (`:448-460`), its real rotation key in public form (`:462-478`), `alsoKnownAs` from the stored handle (`:483-487`), and an `atproto_pds` service entry with a did:web-derived fallback endpoint (`:489-502`). All four output properties are emitted; the lexicon marks none required. This is correct where metalbear and cirrus are wrong (see Assessment).

One real omission: `PlcService::genesis` puts the operator-configured external rotation key into every genesis operation alongside the per-account key (`crates/atproto-pds/src/plc.rs:183-190`), but `get_recommended_did_credentials` never consults `PlcConfig::external_rotation_key` — it reads only `account.rotation_key_ref` (`:462-478`) and `plc_service.service_endpoint()` (`:491-494`). A migration following the recommended credentials literally therefore **drops the operator's recovery rotation key from the DID document**. The reference prepends `cfg.identity.recoveryDidKey` when configured (`getRecommendedDidCredentials.ts:26-30`). Minor second point: the lexicon says `rotationKeys` "Should be undefined (or ignored) for did:webs"; atproto-crates always emits the array, where tranquil returns an empty one for did:web accounts (`identity/did.rs:497-504`).

### `refreshIdentity` — DIVERGENT

Routed at `router.rs:219`, handled at `identity_handlers.rs:572-684`. Three divergences against `/tmp/gap-scratch/atproto/lexicons/com/atproto/identity/refreshIdentity.json`. The lexicon requires input `identifier` (format `at-identifier`); `RefreshIdentityInput` declares `did` (`:530-534`), so canonical requests fail deserialization. The lexicon output is `com.atproto.identity.defs#identityInfo` requiring `did`, `handle` and `didDoc`; the handler returns `{did, handle?, handleUpdated, identityEventEmitted}` (`:539-555`) with no `didDoc` and two non-lexicon fields. And non-PLC DIDs skip the document fetch entirely (`:604-627`), reporting `handle: null`.

Any authenticated caller may refresh any DID (`:580`, documented at `:568-571`), defensible since the operation is read-only against PLC — but combined with the outbox write at `:664` it lets any account append `#identity` rows to any other local account's outbox. A minor abuse vector, not a privilege escalation.

In fairness, the reference does **not** route `refreshIdentity` at all, treating it as directory-side (`../impl-notes/bluesky-reference.md:188-189`), and neither do tranquil, cocoon, pegasus, zds, cirrus, alteran, arroba or dnproto. Only rsky-pds (`refresh_identity.rs:21-24`) and metalbear (`server.c:1204-1210`) route it, and both are conformant. atproto-crates gets credit for reach and a mark against for shape.

### `resolveDid` / `resolveIdentity` — OUT-OF-SCOPE

Neither is routed (confirmed absent from `router.rs:193-222`). The reference does not route them either; only metalbear (`server.c:6651`, `:6654`) and rsky-pds (`resolve_identity.rs:115`) do. These describe general identity-directory behaviour a PDS is not obliged to serve, and `resolveHandle` covers the half clients actually call against a PDS. Defensible to ship without.

### did:plc genesis, key hierarchy, recovery — PARTIAL

`PlcService::genesis` (`crates/atproto-pds/src/plc.rs:141-233`) generates a P-256 rotation key and a K-256 signing key (`:71-72`), builds the operation through `DidBuilder` with `alsoKnownAs`, `atproto` and `atproto_space` verification methods plus `atproto_pds` and `atproto_space_host` services (`:159-207`), submits to the directory (`:211-221`), and persists both keys only afterwards (`:225-226`) so a failed submit leaves no orphans. The operator key is added as a second rotation key on every op when configured (`:183-190`).

The key hierarchy is correct: per-account rotation key (signs PLC updates), per-account signing key (the `#atproto` verification method and commit signer), optional PDS-wide external rotation key, and client-held DPoP keys the PDS only validates. The storage is not: `FileKeyStore::put` writes private keys as plaintext `did:key:` strings at mode 0600 while the trait doc says implementations "are expected to encrypt at rest" (`crates/atproto-pds/src/keys.rs:19-21`, `:63-103`) — flagged in the auth inventory §M and repeated here because rotation keys are the highest-value secret in the identity system.

`createAccount` ignores the lexicon's `recoveryKey` (`CreateAccountInput`, `auth_handlers.rs:28-41`, has no such field) where the reference prepends it to `rotationKeys` (`createAccount.ts:289-291`), and ignores `plcOp`, so the bring-your-own-signed-genesis migration path is unsupported. Tombstone is unreachable through the server — the library has `Operation::new_tombstone` (`plc/operations.rs:116-118`) and `do_update_handle` correctly *detects* a tombstoned DID (`identity_handlers.rs:251-257`), but nothing creates one; `admin.deleteAccount` sets `state = Deleted` and stops (`admin/handlers.rs:266-269`). That matches the reference, which also does not tombstone.

### Bring-your-own-DID at `createAccount` — DIVERGENT, security-relevant

`create_account` is public: its signature is `(State, Json<Input>)` with no `Parts` extractor and no guard call (`auth_handlers.rs:81-84`), routed at `router.rs:117`. When `input.did` is present the handler takes it verbatim and skips PLC genesis (`:184-185`), and `create_account` inserts the row with `AccountState::Active` (`account/manager.rs:158`). `PDS_INVITE_REQUIRED` defaults to `false` (`bin/pds.rs:88-89`). Nothing verifies the caller controls the DID, that the document's `atproto_pds` endpoint points here, or that its signing key matches what the PDS will use.

The reference gates this hard — `if (input.did !== requester) throw new AuthRequiredError(...)` (`createAccount.ts:252-257`) — and even then creates the account **deactivated** so `activateAccount` can validate the document first. cocoon requires a service-auth JWT with `lxm=com.atproto.server.createAccount` from the incoming DID (`handle_server_create_account.go:81-95`); tranquil-pds requires the same (`../impl-notes/tranquil-pds.md:260`); pegasus verifies a `createAccount`-bound service JWT and creates the account deactivated (`api/account_/migrate/ops.ml:8-27, 84, 91-94`).

Blast radius, stated honestly: the attacker gets an active local account and a session JWT with `sub = <victim DID>`. Repo writes under that DID are signed with a key not in the victim's DID document, so a relay verifying commit signatures rejects them and the forgery does not propagate. What the attacker does get is denial of hosting (the `did` primary key is taken, so the real owner can never be created here), local impersonation via this PDS's `describeRepo`/`getRepo`/`resolveHandle`, and a firehose carrying the victim's DID. On a shared or public-signup deployment that is a real problem. Compounding it, `activateAccount` (`auth_handlers.rs:677-688`) sets state to `Active` with **no DID document validation**, where the reference calls `assertValidDidDocumentForService` first (`account-manager.ts:458`).

### did:web — service DID vs account DIDs — PARTIAL

The service DID is `did:web:<host>` by convention (`derive_service_endpoint`, `identity_handlers.rs:512-523`). As covered above, `/.well-known/did.json` is not served, so it is not self-resolvable — the same posture as the reference and rsky-pds, unlike the other nine.

Foreign did:web *is* resolved: `fetch_remote_document` (`crates/atproto-pds/src/http/space_auth.rs:244-260`) dispatches `did:plc:` → `plc::query` and `did:web:` → `atproto_identity::web::query`, bailing on anything else; the same pattern appears at `crates/atproto-pds/src/space/recipient.rs:121-130` and `crates/atproto-pds/src/space/service_auth.rs:187-192`. So did:web is first-class for service auth and the spaces credential paths.

For *account* DIDs it is worse than most of the field. A did:web account can exist (via the unguarded BYO-DID path above), but identity operations on it break rather than degrade: `do_update_handle` fetches the PLC audit log unconditionally (`identity_handlers.rs:216-224`), so `updateHandle` returns a 502 `PlcUnavailable`; `refreshIdentity` silently no-ops. Compare cocoon, which degrades `updateHandle` to a DB-only update (`handle_identity_update_handle.go:43-102`) and hard-refuses the PLC methods with a clear error (`handle_identity_sign_plc_operation.go:40-42`); pegasus, which skips the PLC leg (`identity_util.ml:61, 99`) and hard-rejects the PLC methods (`signPlcOperation.ml:7-8`); tranquil-pds, which refuses did:web on both (`plc/sign.rs:44`, `plc/submit.rs:29`) and gives did:web accounts `alsoKnownAs` override rows plus `/u/{handle}/did.json` publishing; and zds, which cross-checks the did:web document inside `updateHandle` (`identity.zig:240-255`). `did:webvh` is validated by the library (`validation.rs:607`, `crates/atproto-identity/src/webvh/`) and resolved by nobody, including every comparison — a uniform field-wide gap, not an atproto-crates one.

### Non-findings (calibration)

**`com.atproto.server.reserveSigningKey` has no authentication — and should not.** The lexicon states "Public and does not require auth; implemented by PDS" (`/tmp/gap-scratch/atproto/lexicons/com/atproto/server/reserveSigningKey.json`) and the reference registers no `auth` verifier (`api/com/atproto/server/reserveSigningKey.ts:6-14`). The auth inventory flags this as its finding §B; on the identity axis it must not be counted. What *is* mildly wrong is that the reservation is not idempotent despite its doc comment (`auth_handlers.rs:887-889`): each call generates a fresh key and a fresh row id `reserved-<millis>` (`:920-924`), so the `INSERT OR IGNORE` / `ON CONFLICT (id)` guard (`account/manager.rs:948-980`) never fires, and `create_account` never reads the reservation table (`manager.rs:125-132`). The reserved key is orphaned. The canonical migration flow reads keys from `getRecommendedDidCredentials`, so this is cosmetic — see finding 16.

**No did:plc tombstone endpoint.** The reference has none either. Out of scope.

## Findings

**1. No `#identity` firehose event on handle change.** CLASS: MISSING · **rc-blocker**
Evidence: `emit_identity_event` (`identity_handlers.rs:688-706`) is called only from `refreshIdentity` (`:664`); `do_update_handle` (`:155-280`), `admin.updateAccountHandle` (`admin/handlers.rs:628`), `submitPlcOperation` (`auth_handlers.rs:1685-1710`) and `createAccount` emit none.
Comparison: reference `account-manager.ts:386-393`; cocoon `handle_identity_update_handle.go:91`; rsky `update_handle.rs:60-70`; pegasus `identity_util.ml:106`; tranquil `identity/did.rs:612,638,695`; zds `identity.zig:225,292`; metalbear `update_handle`.
Consequence: renames never reach relays or AppViews; the new handle silently does not work off this PDS.

**2. `updateHandle` performs no handle validation and no ownership proof.** CLASS: PARTIAL · **rc-blocker**
Evidence: `do_update_handle` (`identity_handlers.rs:155-280`) goes straight from the raw string to the PLC op; `PDS_SERVICE_HANDLE_DOMAINS` is consulted only by `createAccount` (`auth_handlers.rs:93-110`) and defaults empty (`bin/pds.rs:241-242`).
Comparison: reference `account-manager.ts:164-217, 362-373`; zds `identity.zig:217-260`; tranquil `identity/did.rs:539-585, 645`.
Consequence: any account claims any handle string; this PDS then answers `resolveHandle` for it. A `UNIQUE` collision surfaces as a 500 *after* the PLC op is submitted, permanently desynchronising the DID document from the local row.

**3. `signPlcOperation` uses a non-lexicon input shape and drops the email-token gate.** CLASS: DIVERGENT · **rc-blocker**
Evidence: `SignPlcOperationInput { op }` (`auth_handlers.rs:1592-1596`, deserialized at `:1650`); auth is `require_access_jwt` only (`:1619`).
Comparison: reference `signPlcOperation.ts:41-51`; rsky `sign_plc_operation.rs:29-36`; pegasus `signPlcOperation.ml:14-57`; zds `identity.zig:65-114`; cocoon `handle_identity_sign_plc_operation.go:56-90`.
Consequence: every canonical migration client 400s. Separately, a stolen 2-hour access token suffices to have the PDS sign an arbitrary key-rotation operation.

**4. `createAccount` accepts an arbitrary caller-supplied `did` with no proof of control, and creates the account active.** CLASS: DIVERGENT · **rc-blocker** (security)
Evidence: handler unauthenticated (`auth_handlers.rs:81-84`, `router.rs:117`); `did` used verbatim (`:184-185`); row inserted `Active` (`account/manager.rs:158`); `PDS_INVITE_REQUIRED` defaults false (`bin/pds.rs:88-89`).
Comparison: reference `createAccount.ts:252-257`; cocoon `handle_server_create_account.go:81-95`; tranquil; pegasus `migrate/ops.ml:8-27, 84, 91-94`.
Consequence: DID squatting and local impersonation. Forged commits fail relay signature verification so damage is bounded, but the victim is permanently locked out of this host.

**5. `GET /.well-known/atproto-did` is not served.** CLASS: MISSING · **rc-blocker**
Evidence: only two `.well-known` routes exist, both OAuth (`router.rs:253, 257`).
Comparison: served by 10 of 11 (see the per-capability section for all ten citations).
Consequence: the PDS cannot host a handle on its own domain; a self-hosted deployment needs an external web server to synthesise the response, which is documented nowhere in the repo.

**6. `submitPlcOperation` performs no server-side validation of the operation.** CLASS: PARTIAL · **stable-gap**
Evidence: `auth_handlers.rs:1685-1710` deserializes and POSTs; the only binding is `claims.sub`.
Comparison: reference `submitPlcOperation.ts:19-53`; pegasus `submitPlcOperation.ml:18-27`; zds `identity.zig:131`.
Consequence: a user or compromised client can submit an op that removes the server's rotation key or repoints `atproto_pds`, orphaning the account with no warning.

**7. `activateAccount` does not validate the DID document and emits no `#identity`/`#sync`.** CLASS: PARTIAL · **stable-gap**
Evidence: `auth_handlers.rs:677-688` calls `set_state` and returns; `set_state` emits `#account` only (`account/manager.rs:359-390`).
Comparison: reference `account-manager.ts:458` + `sequencer.ts:214-224`; rsky `activate_account.rs:21, 46-52`; metalbear `sequencer.c:210-238`; cirrus `account-do.ts:1297-1330`; zds `server.zig:963-965`; dnproto `Pds.cs:299-320`.
Consequence: an inbound migration completes even when the DID document still points at the old host, and nothing downstream learns the account went live.

**8. `getRecommendedDidCredentials` omits the operator's external rotation key.** CLASS: PARTIAL · **stable-gap**
Evidence: `identity_handlers.rs:462-478` builds `rotationKeys` from `account.rotation_key_ref` only; `PlcConfig::external_rotation_key` (`plc.rs:60`, used at `:183-190`) is never consulted.
Comparison: reference prepends `cfg.identity.recoveryDidKey` (`getRecommendedDidCredentials.ts:26-30`).
Consequence: a migration that follows the recommended credentials silently deletes the deployment's fallback recovery key from the DID document.

**9. `refreshIdentity` reads `did` instead of `identifier` and returns a non-`identityInfo` body.** CLASS: DIVERGENT · **stable-gap**
Evidence: `RefreshIdentityInput { did }` (`identity_handlers.rs:530-534`); response `:539-555` lacks `didDoc`; non-PLC DIDs skip the fetch (`:604-627`).
Comparison: rsky `refresh_identity.rs:21-24` and metalbear `server.c:1204-1210` are both conformant; the reference does not route it.
Consequence: canonical requests 400; the two clients that call this method get an unparseable body.

**10. `resolveHandle` does not normalize or validate its input and ignores account state.** CLASS: PARTIAL · **stable-gap**
Evidence: `identity_handlers.rs:65-71` → `account/directory.rs:234-238` (exact match, no lowercasing, no prefix stripping); no state filter. `is_valid_handle` (`crates/atproto-identity/src/validation.rs:391`) and `strip_handle_prefixes` (`:425`) have no PDS call sites.
Comparison: reference `resolveHandle.ts:10`; zds `identity.zig:265`; metalbear `server.c:783`.
Consequence: mixed-case and prefixed handles fail for local accounts; takendown accounts still resolve.

**11. `updateHandle` / `signPlcOperation` / `submitPlcOperation` are not rate-limited.** CLASS: MISSING · **stable-gap**
Evidence: the only four rate-limited call sites in the crate are `createAccount` (`auth_handlers.rs:87`), `createSession` (`:300`), `requestPasswordReset` (`:1402-1405`) and `/oauth/token` (`oauth/token.rs:105`) — the first two via the `enforce_rate_limit` helper (`auth_handlers.rs:69-78`), the latter two calling `rate_limiter.try_acquire` directly (`/tmp/gap-scratch/verified-commit-divergences.md` §R1); no limiter call appears in `identity_handlers.rs` or the PLC handlers.
Comparison: reference 10/5min + 50/day per DID (`updateHandle.ts:19-30`); zds the same two windows (`identity.zig:202-209`); tranquil both (`identity/did.rs:539-547`); pegasus opts in.
Consequence: unbounded PLC churn against plc.directory on behalf of one account — a self-inflicted rate-limit risk with the directory operator and a spam vector.

**12. `createAccount` ignores the lexicon's `recoveryKey` and `plcOp`.** CLASS: MISSING · **stable-gap**
Evidence: `CreateAccountInput` (`auth_handlers.rs:28-41`) declares neither.
Comparison: reference `createAccount.ts:289-291` and `:131-160`.
Consequence: users cannot supply a recovery rotation key at signup, and the BYO-signed-genesis migration path is unavailable.

**13. did:web account DIDs break rather than degrade on identity operations.** CLASS: PARTIAL · **stable-gap**
Evidence: `do_update_handle` fetches the PLC audit log unconditionally (`identity_handlers.rs:216-224`) → 502 `PlcUnavailable`; `refreshIdentity` no-ops (`:621-627`).
Comparison: cocoon `handle_identity_update_handle.go:43-102`; pegasus `identity_util.ml:61, 99`; tranquil `plc/sign.rs:44`; zds `identity.zig:240-255`.
Consequence: a migrated did:web account is stuck, and the failure reads as "PLC unavailable" rather than "unsupported DID method".

**14. `resolveHandle` has no service-domain fast-fail.** CLASS: PARTIAL · **cosmetic**
Evidence: `identity_handlers.rs:73-105` falls through to network resolution unconditionally on a local miss.
Comparison: reference `resolveHandle.ts:20-26`; rsky `resolve_handle.rs:50-57`; zds `identity.zig:272-273`.
Consequence: an unregistered handle under this PDS's own domain triggers an outbound lookup and may return a foreign DID for a handle in the server's own namespace.

**15. `/.well-known/did.json` is not served for the service DID.** CLASS: MISSING · **cosmetic**
Evidence: as finding 5. The reference and rsky-pds also omit it.
Comparison: served by tranquil `lib.rs:471`, cocoon `handle_well_known.go:53-67`, metalbear `server.c:6390`, cirrus `index.ts:113`, pegasus `bin/main.ml:15`, alteran, zds `router.zig:136`, dnproto `Pds.cs:215`.
Consequence: `did:web:<host>` is not resolvable without external infrastructure — relevant to spaces/service-auth peers that must resolve this PDS's own document.

**16. `reserveSigningKey` reservations are orphaned and non-idempotent.** CLASS: PARTIAL · **cosmetic**
Evidence: a fresh key is generated on every call (`auth_handlers.rs:897`) under a fresh row id `reserved-<millis>` (`:920-924`), so the dedupe guard (`account/manager.rs:948-980`) never fires; `create_account` never reads the table (`manager.rs:125-132`). The doc comment at `:887-889` claims idempotency.
Comparison: the reference also generates fresh on the local path, so this is not a parity break.
Consequence: keystore growth and a false doc comment. No functional break.

## Confidence & unknowns

Every atproto-crates claim was read in source at the cited line, and the five blocker-grade findings were re-opened after the first pass. All lexicon assertions were checked against the canonical JSON under `/tmp/gap-scratch/atproto/lexicons/com/atproto/{identity,server,sync}/`, read in full. Reference behaviour was read directly in `/tmp/gap-scratch/atproto/packages/pds/src/` rather than taken from the impl note.

Comparison cells I opened myself: reference `well-known.ts`, `resolveHandle.ts`, `updateHandle.ts`, `signPlcOperation.ts`, `submitPlcOperation.ts`, `requestPlcOperationSignature.ts`, `getRecommendedDidCredentials.ts`, `createAccount.ts`, `account-manager.ts`, `handle/index.ts`, `sequencer/{sequencer,events}.ts`; zds `identity.zig`, `http/router.zig`; tranquil `tranquil-api/src/lib.rs`, `identity/did.rs`, `tranquil-pds/src/handle/mod.rs`; rsky `well_known.rs`, `resolve_handle.rs`, `refresh_identity.rs`, `update_handle.rs`; metalbear `server.c` (`resolve_handle`, `refresh_identity`, `register_identity_documents`, `update_handle`); pegasus `well_known.ml`; arroba `app.py`, `did.py`; dnproto `Pds.cs` route table.

Cells taken from the impl notes without independent re-verification — the weakest in the matrix — are cocoon's `#identity` emission line numbers, cirrus's and alteran's well-known route line numbers, and pegasus's `identity_util.ml` sequence site (grep hit confirmed, surrounding control flow not read). None carries a blocker-grade atproto-crates claim.

Explicitly UNVERIFIED: whether a deployed relay actually rejects the nested `#identity` CBOR body (needs a live subscription; the lexicon mismatch itself is verified); whether the DID-squatting path in finding 4 reproduces end-to-end against a running instance (code path verified line by line, no live request issued); whether `PDS_PLC_ROTATION_KEY_DID_KEY` is set in any shipped deployment manifest, which determines the practical impact of finding 8; and whether `crates/atproto-identity/src/webvh/` can resolve a document rather than only validate syntax — I established only that the PDS never calls it, and since no comparison resolves did:webvh either, it is not a differentiating gap.
