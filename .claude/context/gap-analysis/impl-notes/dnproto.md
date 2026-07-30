# dnproto — implementation notes

Source root: `/tmp/gap-scratch/dnproto/`. **All file:line citations below are relative to that root.**
Canonical lexicons consulted: `/tmp/gap-scratch/atproto/lexicons/com/atproto/**`.
Clone state: single squashed commit `3c84403` (`git log --oneline | wc -l` = 1), so commit-history claims are UNVERIFIED.

---

## 1. Language / stack / build / licence

C# on .NET 10 (`<TargetFramework>net10.0</TargetFramework>`, `src/dnproto.csproj:5`), `ImplicitUsings` and
`Nullable` both enabled (`src/dnproto.csproj:6-7`). The web layer is ASP.NET Core minimal APIs via
`<FrameworkReference Include="Microsoft.AspNetCore.App" />` (`src/dnproto.csproj:11`). Build is plain MSBuild:
one solution with two projects, `src/dnproto.csproj` and `test/dnproto.tests.csproj` (`dnproto.sln:5-8`).

Dependencies are deliberately tiny and centrally pinned (`Directory.Packages.props:7-14`): `Microsoft.Data.Sqlite`
10.0.10, `SQLitePCLRaw.lib.e_sqlite3` 3.53.3, `System.IdentityModel.Tokens.Jwt` 8.19.2, plus xunit.v3 for tests.
There is **no** CBOR library, **no** multiformats library, **no** CAR library, **no** crypto library beyond
`System.Security.Cryptography` — DAG-CBOR, CIDv1, varint, base32, base58btc and MST are all hand-rolled
(`src/repo/DagCborObject.cs`, `src/repo/CidV1.cs`, `src/repo/VarInt.cs`, `src/repo/Base32Encoding.cs`,
`src/repo/Base58BtcEncoding.cs`, `src/mst/Mst.cs`).

Trimming and AOT are explicitly disabled repo-wide (`Directory.Build.props:4-5`).

Licence: MIT, `Copyright (c) threddyrex` (`LICENSE.txt:1-3`).

The single executable is both the CLI and the server: `src/cli/Program.cs:7` calls
`CommandLineInterface.RunMain(args)`, and the PDS is just the `RunPds` command
(`src/cli/commands/RunPds.cs`, invoked by `bash/run_pds.sh:4`).

## 2. Is this actually a PDS? (served vs. called)

Both. It is a CLI/debugging toolset that grew a real, running single-user PDS. The README frames it exactly that
way — "More recently it's become a PDS implementation." (`README.md:8`).

**Served** `com.atproto.*` XRPC methods: **24**, all registered in one route table,
`Pds.MapEndpoints()` at `src/pds/Pds.cs:184-273`. Every one of the 24 dispatches to a concrete handler class
under `src/pds/xrpc/`; none is a `NotImplemented` stub (the only "not implemented" string in the whole tree is
the catch-all fallback, `src/pds/Pds.cs:271`). Two `app.bsky.actor.*` methods are also served
(`src/pds/Pds.cs:199-200`), and everything else under `app.bsky.*` / `chat.bsky.*` is reverse-proxied to an
AppView (`src/pds/Pds.cs:254-262`).

**Called-as-client** `com.atproto.*` methods appear in `src/ws/BlueskyClient.cs` and `src/cli/commands/*`: 22
distinct NSIDs, of which three are *only* ever called and never served — `com.atproto.server.createAccount`
(`src/ws/BlueskyClient.cs:1594`), `com.atproto.server.deleteSession` (`src/cli/commands/DeleteSession.cs:52`),
`com.atproto.sync.requestCrawl` (`src/pds/BackgroundJobs.cs:154`, outbound to relays). Volume-wise the client
side dominates: 68 CLI command classes (`src/cli/commands/*.cs`) and 71 PowerShell wrappers (`powershell/*.ps1`)
versus 33 server handler classes (`src/pds/xrpc/*.cs`). But the server is not a toy: it signs its own commits,
generates a real firehose, and the author runs it in production (`README.md:141`, `bash/deploy_latest.sh`).

## 3. Single-user vs multi-account; deployment

**Strictly single-user, single-repo.** There is no accounts table. The account identity lives in the
key/value `ConfigProperty` table under the keys `UserDid`, `UserHandle`, `UserEmail`, `UserIsActive`,
`UserHashedPassword`, `UserPrivateKeyMultibase`, `UserPublicKeyMultibase`
(`src/pds/db/PdsDb.cs:89-92`; key list at `src/pds/admin/Admin_Config.cs:17-39`). `UserRepo` resolves the DID
from config, not from a request parameter (`src/pds/UserRepo.cs:60-68`). `RepoCommit` is documented as
"Can be only one" (`src/repo/RepoCommit.cs:9`) and `RepoHeaderExists()` asserts `count == 1`
(`src/pds/db/PdsDb.cs:453-456`). A source comment in the proxy is explicit that multi-user is not the model:
"In a multi-user system, you would look up the user's signing key from a database"
(`src/pds/xrpc/AppBsky_Proxy.cs:142-144`).

Deployment: no container, no serverless, no packaged installer. It is `git pull` + `dotnet build` +
`systemctl restart` on a Linux box behind Caddy (`bash/deploy_latest.sh:17-30`, `bash/restart_caddy.sh:4`),
with the systemd unit name and Caddy log path themselves read out of the SQLite config table
(`bash/deploy_latest.sh:3-4`). Note the run script launches the **Debug** build:
`../src/bin/Debug/net10.0/dnproto` (`bash/run_pds.sh:4`). Provisioning is a three-step CLI sequence documented
at `src/pds/Installer.cs:18-25`: `InstallDb` → `InstallConfig` → `InstallRepo`
(`bash/install_db.sh`, `bash/install_config.sh`, `bash/install_repo.sh`). Kestrel binds a scheme/host/port from
config (`src/pds/Pds.cs:122`); TLS is Caddy's job.

## 4. Storage backends

| Data | Engine | Location |
|---|---|---|
| Config / account identity | SQLite table `ConfigProperty(Key PK, Value)` | `src/pds/db/PdsDb.cs:89-92` |
| Repo commit | SQLite `RepoCommit(Version, Cid PK, RootMstNodeCid, Rev, PrevMstNodeCid, Signature BLOB)` | `src/pds/db/PdsDb.cs:559-566` |
| Repo header (CAR root) | SQLite `RepoHeader(RepoCommitCid PK, Version)` | `src/pds/db/PdsDb.cs:440-443` |
| Records | SQLite `RepoRecord(Collection, Rkey, Cid, DagCborObject BLOB, PK(Collection,Rkey))` | `src/pds/db/PdsDb.cs:732-738` |
| Firehose events | SQLite `FirehoseEvent(SequenceNumber PK, CreatedDate, Header_op, Header_t, Header_DagCborObject BLOB, Body_DagCborObject BLOB)` | `src/pds/db/PdsDb.cs:1062-1069` |
| Seq counter | SQLite `SequenceNumber(Seq)` — single row, deleted+reinserted per bump | `src/pds/db/PdsDb.cs:977-979`, `986-995` |
| Blob metadata | SQLite `Blob(Cid PK, ContentType, ContentLength)` | `src/pds/db/PdsDb.cs:217-221` |
| Blob bytes | **Filesystem**, one file per CID at `<datadir>/pds/blobs/<cid>` | `src/pds/blob/BlobDb.cs:43-46`, `:58-63` |
| Preferences, sessions, passkeys, stats | SQLite | `src/pds/db/PdsDb.cs:356`, `1570`, `1903`, `2047`, `2198`, `2433` |

There are **no MST node rows** — the tree is rebuilt in memory from all records on every write and every read
that needs it (`Mst.AssembleTreeFromItems(_db.GetAllRepoRecordMstItems())`, `src/pds/UserRepo.cs:225` and
`:566`, `src/pds/xrpc/ComAtprotoSync_GetRecord.cs:57`). That is O(records) per operation. Schema creation is
all in `Installer.InstallDb` (`src/pds/Installer.cs:75-95`); it is re-runnable (`CREATE TABLE IF NOT EXISTS`)
but there is no migration/versioning mechanism. Write serialisation is a single process-wide semaphore,
`Pds.GLOBAL_PDS_LOCK` (`src/pds/Pds.cs:54`, taken at `src/pds/UserRepo.cs:95` and `:523`).

## 5. Endpoint coverage snapshot (verified against code, not README)

The README has **no** endpoint checklist to disagree with; it only points at the `/src/pds/xrpc/` directory
(`README.md:34`). So the table below is derived purely from `src/pds/Pds.cs`.

### com.atproto.server.*

| NSID | Registered | Handler | Notes |
|---|---|---|---|
| `describeServer` | `src/pds/Pds.cs:190` | `ComAtprotoServer_DescribeServer.cs` | Real. Hardcodes `inviteCodeRequired=true` and `phoneVerificationRequired=true` (`:15-16`) though neither invite nor phone flow exists. |
| `createSession` | `:192` | `ComAtprotoServer_CreateSession.cs` | Real (HS256 JWT + `LegacySession` row). See §6 for two deviations. |
| `refreshSession` | `:193` | `ComAtprotoServer_RefreshSession.cs` | Real (129 lines). |
| `getSession` | `:194` | `ComAtprotoServer_GetSession.cs` | Real; `emailConfirmed` hardcoded `true` (`:35`). |
| `getServiceAuth` | `:195` | `ComAtprotoServer_GetServiceAuth.cs` | Real ES256 minting; clamps `exp` to ≤300s (`:59-62`). |
| `activateAccount` | `:208` | `ComAtprotoServer_ActivateAccount.cs` | Real; emits #account/#identity/#sync. |
| `deactivateAccount` | `:214` | `ComAtprotoServer_DeactivateAccount.cs` | Real; emits #account only. |
| `checkAccountStatus` | `:226` | `ComAtprotoServer_CheckAccountStatus.cs` | **Partial.** Returns only 4 of the 9 lexicon-required fields (missing `repoBlocks`, `indexedRecords`, `privateStateValues`, `expectedBlobs`, `importedBlobs` — see `/tmp/gap-scratch/atproto/lexicons/com/atproto/server/checkAccountStatus.json`). Code admits it: `src/pds/xrpc/ComAtprotoServer_CheckAccountStatus.cs:30-31`. |

Not served: `createAccount`, `deleteSession`, `createAppPassword`, `listAppPasswords`, `revokeAppPassword`,
`createInviteCode(s)`, `updateEmail`, `confirmEmail`, `requestPasswordReset`, `resetPassword`,
`requestAccountDelete`, `deleteAccount`, `reserveSigningKey`.

### com.atproto.repo.*

| NSID | Registered | Notes |
|---|---|---|
| `createRecord` | `src/pds/Pds.cs:202` | Real; delegates to `UserRepo.ApplyWrites`. |
| `putRecord` | `:205` | Real. |
| `deleteRecord` | `:204` | Real. |
| `applyWrites` | `:206` | Real; supports `swapCommit` (`ComAtprotoRepo_ApplyWrites.cs:56-64`). Ignores `swapRecord`. `repo` param is parsed then never compared to `UserDid` (`:34-40`). |
| `getRecord` | `:203` | Real. |
| `listRecords` | `:211` | Real but **never returns `cursor`** in the response body (`ComAtprotoRepo_ListRecords.cs:66-69`), so pagination is one-way only; `repo` param ignored. |
| `describeRepo` | `:210` | Real, but ignores the `repo` param and always answers for the single local user; `handleIsCorrect` hardcoded `true` (`ComAtprotoRepo_DescribeRepo.cs:37`). |
| `uploadBlob` | `:196` | Real. |

Not served: `importRepo`, `listMissingBlobs`.

### com.atproto.sync.*

| NSID | Registered | Notes |
|---|---|---|
| `subscribeRepos` | `src/pds/Pds.cs:207` | Real WebSocket firehose. See §8. |
| `getRepo` | `:201` | Real CAR export. Validates `did` (`ComAtprotoSync_GetRepo.cs:23-26`). **`since` param unsupported** — always full export. |
| `getRecord` | `:212` | Real proof CAR (commit + root-to-leaf MST path + record). **Ignores the required `did` param**; returns 404 JSON instead of a non-existence proof CAR (`ComAtprotoSync_GetRecord.cs:46-49`), contradicting the lexicon description "prove the existence or non-existence" (`/tmp/gap-scratch/atproto/lexicons/com/atproto/sync/getRecord.json`). |
| `listRepos` | `:209` | Real (one repo). Ignores `limit`/`cursor`. |
| `getRepoStatus` | `:213` | **Wrong.** Ignores the required `did` param, returns `PdsDid` (the *service* DID) as `did`, hardcodes `active: true` ignoring the `UserIsActive` flag, and omits `rev` (`ComAtprotoSync_GetRepoStatus.cs:15-19`). |
| `listBlobs` | `:197` | Real cursor paging, but ignores required `did` and optional `since` (`ComAtprotoSync_ListBlobs.cs:21-32`). |
| `getBlob` | `:198` | Real; ignores required `did` (`ComAtprotoSync_GetBlob.cs:21-25`). |

Not served: `getBlocks`, `getLatestCommit`, `getHostStatus`, `listHosts`, `listReposByCollection`,
`notifyOfUpdate`, `requestCrawl`, and the deprecated `getCheckout`/`getHead`.

### com.atproto.identity.*

| NSID | Registered | Notes |
|---|---|---|
| `resolveHandle` | `src/pds/Pds.cs:191` | Real, but **delegates to the public network** rather than answering authoritatively for the hosted handle — `BlueskyClient.ResolveActorInfo(actor, ...)` (`ComAtprotoIdentity_ResolveHandle.cs:29`), which falls back to `https://public.api.bsky.app/xrpc/com.atproto.identity.resolveHandle` (`src/ws/BlueskyClient.cs:355`). |

Not served: `updateHandle`, `resolveDid`, `resolveIdentity`, `refreshIdentity`,
`getRecommendedDidCredentials`, `requestPlcOperationSignature`, `signPlcOperation`, `submitPlcOperation`.

### com.atproto.admin.* / moderation.* / label.*

**Zero endpoints served.** `grep -rni "takedown\|takendown\|moderation\|label" src/` returns only CSS class
names in the admin HTML pages. There is no label store, no `queryLabels`, no `subscribeLabels`, no
`updateSubjectStatus`, and no takedown enforcement anywhere in the read paths.

### Non-XRPC routes

`/` (`:186`), `/favicon.ico` (`:187`), `/hello` (`:188`), `/xrpc/_health` (`:189`),
`/.well-known/did.json` (`:215`), `/.well-known/atproto-did` (`:216`),
`/.well-known/oauth-protected-resource` (`:217`), `/.well-known/oauth-authorization-server` (`:218`),
`/oauth/{jwks,par,authorize,passkeyauthenticationoptions,authenticatepasskey,token}` (`:219-225`),
and 23 `/admin/*` HTML routes (`:227-249`).

## 6. Auth posture

Three auth types, all in `src/pds/xrpc/BaseXrpcCommand.cs` (the file's own doc comment enumerates them at
`:19-36`), selected per request by header sniffing in `UserIsAuthenticated()` (`:60-213`).

**Legacy / session JWT.** `createSession` takes `identifier` + `password` and compares against a single
`UserHashedPassword` config value (`ComAtprotoServer_CreateSession.cs:42-43`). There are **no app passwords** —
one password, full scope. Access/refresh JWTs are **HS256 over a shared secret** (`JwtSecret` config value),
with `scope: com.atproto.access`, 2h lifetime (`src/auth/JwtSecret.cs:41-58`); validation additionally requires
the row to still exist in `LegacySession` (`BaseXrpcCommand.cs:199-206`) and `sub == UserDid`
(`src/auth/JwtSecret.cs:310-318`). Two deviations: (a) a failed login returns **HTTP 200** with null tokens
rather than 401 (`ComAtprotoServer_CreateSession.cs:83-90`); (b) `identifier` is resolved against the public
network, not the local account, so a correct password mints a session for whatever DID the network returns —
harmless only because validation later re-checks `sub == UserDid`.

**OAuth authorization server.** Present and non-trivial, but off by default
(`FeatureEnabled_Oauth` = false, `src/pds/Installer.cs:140`). Implemented: AS + protected-resource metadata
(`src/pds/oauth/Oauth_AuthorizationServer.cs`, `Oauth_ProtectedResource.cs`), JWKS (`Oauth_Jwks.cs`),
PAR (`Oauth_Par.cs`), authorize GET/POST with an HTML login form and optional passkeys
(`Oauth_Authorize_Get.cs`, `Oauth_Authorize_Post.cs`, `Oauth_AuthenticatePasskey.cs`), token with
`authorization_code` + `refresh_token` grants, PKCE **S256 verified** (`Oauth_Token.cs:92-100`,
`:297-305`), and DPoP proof validation with `typ`/`alg`/`jwk`/`jti`/`htm`/`htu` checks plus `cnf.jkt` binding
(`src/auth/JwtSecret.cs:442-540`, binding compared at `BaseXrpcCommand.cs:528-532`).

Gaps, all verified in code:
- **No DPoP nonce.** `grep -rni "nonce" src/` returns nothing — no `DPoP-Nonce` header, no `use_dpop_nonce`
  error. Clients that expect the nonce handshake will not get one.
- **`private_key_jwt` is advertised but not implemented.** `token_endpoint_auth_methods_supported` includes it
  (`Oauth_AuthorizationServer.cs:39`) yet `Oauth_Token.cs` never reads `client_assertion` / `client_assertion_type`.
- **`revocation_endpoint` is advertised but unrouted.** `Oauth_AuthorizationServer.cs:41` publishes
  `/oauth/revoke` and `src/pds/oauth/Oauth_Revoke.cs` exists, but there is no `App.MapPost("/oauth/revoke", ...)`
  in `src/pds/Pds.cs` — the fallback only covers `/xrpc/{**rest}` (`:254`), so the URL 404s.
- **No client-metadata-document resolution.** PAR does not fetch or validate `client_id`; instead
  `redirect_uri` must appear in a hand-maintained `OauthAllowedRedirectUris` config allowlist
  (`Oauth_Par.cs:69-77`). Arbitrary atproto OAuth clients therefore cannot log in without operator action —
  a significant departure from the spec's open client-registration model.
- **Scopes are stored but never enforced.** `result.Scope` is populated (`BaseXrpcCommand.cs:550`,
  `:603`) and no handler ever reads it; `grep` for `.Scope` across `src/pds/xrpc/*.cs` hits only
  `BaseXrpcCommand.cs`. The class comment claiming OAuth is "Restricted by scopes"
  (`BaseXrpcCommand.cs:28`) is not backed by code.

**Service auth — both directions.** *Minting*: `getServiceAuth` signs ES256 with the user's atproto signing key
(`ComAtprotoServer_GetServiceAuth.cs:102-110`), and the AppView proxy mints a fresh per-request token with the
correct `lxm` derived from the path (`AppBsky_Proxy.cs:131-181`). *Verifying*: `ValidateServiceAuthToken`
requires ES256 + `lxm` + DID `iss` (`BaseXrpcCommand.cs:724-778`), checks `aud == PdsDid`, optionally matches
`lxm`, resolves the issuer's DID document, extracts the `#atproto` `publicKeyMultibase` and verifies the
signature (`:815-934`). Only `uploadBlob` opts into it (`ComAtprotoRepo_UploadBlob.cs:19-21`), added because
the author could not post a GIF (`BaseXrpcCommand.cs:32-35`). Caveat: the `lxm` check is skipped when the token
omits `lxm` (`:857` requires *both* to be non-empty).

Commit signing supports P-256 and secp256k1 with low-S normalisation
(`src/auth/KeyPair.cs:32-72`, `src/auth/Signer.cs:412-455`, `NormalizeLowS` at `src/auth/Signer.cs:545-560`).
`Signer.SignToken` for JWTs assumes P-256 for raw-hex keys (`src/auth/Signer.cs:60`).

## 7. Sync 1.1 status

| Requirement | Status | Citation |
|---|---|---|
| `#commit` with `prevData` | **Yes** | `src/pds/UserRepo.cs:330` (JSON) and `:353-357` (re-typed as CBOR tag 42) |
| Per-op `prev` on deletes | **Yes** | `src/pds/UserRepo.cs:213`, re-typed at `:401-422` |
| Per-op `prev` on updates | **No** — only `cid`/`path`/`action` are emitted for create *and* update | `src/pds/UserRepo.cs:166-171` |
| Covering-proof blocks in the commit CAR slice | **Partial** | root-to-leaf path only: `nodesToSend` = `mst.FindNodesForKey(fullKey)` per write (`:229-238`), written root-first (`:291-295`); no sibling/adjacent-leaf blocks are added |
| `#sync` event | **Yes, but only on activate** | `src/pds/Pds.cs:328-341` (`GenerateFrameWithBlocks` with the commit block). Not emitted on resync or handle change |
| `#identity` / `#account` | Activate emits both (`src/pds/Pds.cs:299-320`); deactivate emits `#account` only (`:368-376`) | |
| Reject no-op updates | **No** | a delete of a missing record `break`s without adding an op (`src/pds/UserRepo.cs:181-185`) yet the code still unconditionally re-signs a new commit with a fresh `rev` and emits a `#commit` with an empty `ops` array (`:246-249`, `:315-333`). Content-identical updates are likewise never deduplicated |
| `com.atproto.sync.getHostStatus` | **Not served** | absent from `src/pds/Pds.cs:184-273` |
| `com.atproto.sync.listReposByCollection` | **Not served** | idem |
| `com.atproto.sync.getBlocks` | **Not served** | idem |

Commit format itself is correct v3: `version: 3` (`src/pds/Installer.cs:218`), `prev` explicitly forced to
CBOR null on every commit (`src/repo/RepoCommit.cs:196` sets `PrevMstNodeCid = null`, serialised as simple
value `0xf6` at `:121-128`), signature computed over SHA-256 of the unsigned commit bytes then the CID
recomputed over the signed object (`src/repo/RepoCommit.cs:200-212`).

## 8. Firehose

`com.atproto.sync.subscribeRepos` is a real WebSocket endpoint (`src/pds/xrpc/ComAtprotoSync_SubscribeRepos.cs`).

- **Framing**: header DAG-CBOR bytes concatenated with body DAG-CBOR bytes into one binary WS frame
  (`:97-104`) — correct per the event-stream spec.
- **Event types emitted**: `#commit` (`src/pds/UserRepo.cs:264`), `#account` (`src/pds/Pds.cs:301`, `:370`),
  `#identity` (`src/pds/Pds.cs:315`), `#sync` (`src/pds/Pds.cs:330`). **No `#info` frames and no `op: -1` error
  frames are ever produced** — `Header_op` is hardcoded `1` at every call site.
- **Seq source**: a single-row SQLite counter, read-delete-insert under a C# lock
  (`src/pds/db/PdsDb.cs:986-995`). Not crash-atomic across the delete/insert pair.
- **Cursor resume**: `?cursor=` parsed at `:50-54`; default is "tail from now"
  (`GetMostRecentlyUsedSequenceNumber()`, `:49`).
- **Backfill window**: **12 hours.** `GetFirehoseEventsForSubscribeRepos` filters
  `CreatedDate >= now-12h` (`src/pds/db/PdsDb.cs:1138`, `:1146`, `:1150`). A cursor older than that is silently
  skipped forward with no `#info`/`OutdatedCursor` signal. Retention deletes at 72h
  (`src/pds/db/PdsDb.cs:1193`), run hourly (`src/pds/BackgroundJobs.cs:44`).
- **Throughput ceiling**: the stream loop polls the DB, sends up to `limit = 100` events, then
  `await Task.Delay(1000)` (`:89-108`, limit default at `src/pds/db/PdsDb.cs:1138`). Effective cap ≈100
  events/sec and up to 1s of added latency per event.
- **Slow-consumer handling**: none. No send-queue bound, no backpressure, no disconnect-on-lag. There is a
  dedicated receive loop so relay pings get answered — added after connections timed out at ~3 minutes
  (`:152-156`).

### Byte-format fidelity (the area the author has been bitten in)

The encoder is `DagCborObject.WriteToStream` (`src/repo/DagCborObject.cs:156-297`); the decoder is
`ReadFromStream` (`:49-142`). Findings:

1. **Canonical map ordering is implemented but not byte-exact.** Keys are sorted by UTF-8 byte length then
   `StringComparer.Ordinal` (`:171-173`). Length-first is right; `Ordinal` compares UTF-16 code units, which
   diverges from UTF-8 byte order for keys mixing astral-plane characters with U+E000–U+FFFF. Practically
   unreachable for atproto lexicon keys, but it is not the specified comparison.
2. **Integer encoding is 32-bit only.** `WriteLengthToStream` tops out at additional-info 26 / 4 bytes
   (`:305-336`) and `ReadLengthFromStream` throws on additional-info 27 (`:378-381`). Any int64 is silently
   truncated: `FromRawValue(long)` does `Value = (int)longValue` (`:572-583`) and `FromJsonElement` does
   `FromRawValue((int)longVal)` (`:716-717`). The firehose `seq` is a `long` that flows through
   `JsonObject → FromJsonString` (`src/pds/FirehoseEventGenerator.cs:37-40`), so the stream has a hard,
   silent ceiling at 2^31−1.
3. **CBOR negative integers (major type 1) are unsupported in both directions** — no `case` in the read
   switch (falls to `default: throw`, `:139-141`) and none in the write switch (`:294-296`). Floats are also
   unsupported (`TYPE_SIMPLE_VALUE` accepts only 0x14/0x15/0x16, `:121-137`). Both are correctly excluded by
   the atproto data model, so this is a conservative-strictness point, not a bug — but a hostile or
   non-conforming peer's block will throw rather than error cleanly.
4. **Nested JSON `null` becomes the CBOR *text string* `"null"`.** `GetRawValue` returns the C# string
   `"null"` for a CBOR null (`:445-448` via the `Value = "null"` representation at `:122-125`);
   `FromJsonElement`'s object branch pipes every property through `GetRawValue` (`:742-744`); and
   `FromRawValue(string)` produces `TYPE_TEXT` (`:585-599`). So `{"a": {"b": null}}` round-trips into
   `b: "null"`. This is exactly the class of bug the author patched *at the firehose layer* rather than at the
   codec: `src/pds/UserRepo.cs:385-399` special-cases the delete op's `cid` back into a simple value, with the
   comment that a `"null"` string here "would crash the subscribeRepos connection and retry constantly".
5. **CID encoding is correct on the write path**: tag written as `0xd8 0x2a`, then a byte string of
   `len(cid)+1` with a leading `0x00` multibase prefix (`:222-247`). On the read path the tag byte is read
   without checking that additional-info was 24, the multibase `0x00` is read into an unused
   `int shouldBeZero` and never validated, and the declared byte-string length is discarded rather than
   cross-checked against the parsed CID (`:97-110`). `CidV1.ReadCid` does validate `version == 1` and
   `multicodec ∈ {0x71, 0x55}` (`src/repo/CidV1.cs:57-69`) but does **not** validate the hash function or the
   32-byte digest length, and it reconstructs `AllBytes` assuming each of the four varints is exactly one byte
   (`:74-80`).
6. **Varint reader can hang on truncated input.** `VarInt.ReadVarInt` (`src/repo/VarInt.cs:32-51`) casts
   `Stream.ReadByte()`'s `-1` EOF sentinel to `(byte)0xFF`, whose continuation bit is set, so the `do/while`
   never terminates at end-of-stream. There is also no 9-byte / shift bound. Writer looks correct
   (`:56-69`).
7. **Test coverage does not defend any of this.** `test/repo/DagCborObjectTests.cs` (876 lines) is entirely
   self-round-trip — encode with their writer, decode with their reader, compare the object model. There is no
   golden byte vector from a reference implementation anywhere in `test/` (the only fixture CID is a `$link`
   string in `test/repo/DagCborObjectTests.cs:817`), no canonical-ordering byte assertion, no JSON-null
   round-trip test, and `test/repo/VarIntTests.cs` (92 lines) stops at `int.MaxValue` and never tests
   truncated input.

## 9. did:plc vs did:web

**Account DID**: whatever string an operator types into `UserDid` via the admin config page
(`src/pds/admin/Admin_Config.cs:30`, `:235-237`) or sqlite. There is no DID-creation code in the PDS at all.

- **did:web is the first-class path.** `/.well-known/did.json` serves the *user's* DID document — id `UserDid`,
  `alsoKnownAs: at://{UserHandle}`, a `#atproto` Multikey, and an `#atproto_pds` service entry pointing at
  `PdsHostname` (`src/pds/xrpc/WellKnown_Did.cs:13-50`). The CLI has `GenerateDidWebDoc`
  (`src/cli/commands/GenerateDidWebDoc.cs`) and the project's own docs use `did:web:threddyrex.org`
  as the running example (`docs/handle-resolution.md:143-162`). Because the host serves exactly one
  `did.json`, one host = one did:web account.
- **did:plc is resolve-only and client-side.** `grep -rn "plc.directory" src/` hits only
  `src/ws/BlueskyClient.cs:383` (resolve), `src/cli/commands/GetPlcHistory.cs:63` (audit log) and
  `src/cli/commands/GetPlcExport.cs:93` (directory export). There is **no** PLC genesis-operation creation, no
  rotation-key handling, no operation signing, and no `signPlcOperation`/`submitPlcOperation` endpoint. A
  did:plc account can be *hosted* (set `UserDid` and update the PLC record elsewhere) but not created or
  migrated by this software.

**Service DID**: `PdsDid` is a separate config value (`src/pds/admin/Admin_Config.cs:26`), used as the
`describeServer.did` (`ComAtprotoServer_DescribeServer.cs:18`), the service-auth `aud` check
(`BaseXrpcCommand.cs:850`) and the legacy JWT `aud` (`ComAtprotoServer_CreateSession.cs:54`). Nothing serves a
DID document *for the service DID* — `/.well-known/did.json` is taken by the user's DID — so a `did:web`
service DID equal to `PdsHostname` cannot be resolved correctly from this server.

## 10. Blobs

Bytes go to one file per CID under `<datadir>/pds/blobs/` (`src/pds/blob/BlobDb.cs:43-46`), metadata to the
`Blob` SQLite table (`src/pds/db/PdsDb.cs:217-221`). `uploadBlob` requires auth (legacy, OAuth or service,
`ComAtprotoRepo_UploadBlob.cs:19-21`), computes a raw-codec CIDv1 (`CidV1.ComputeCidForBlobBytes`, multicodec
`0x55`, `src/repo/CidV1.cs:200-230`), and sniffs the content type from magic bytes when the client sends
nothing useful (`:105-209`).

Missing: **no size limit** — the whole body is materialised in memory via
`new byte[contentLength]` from the client-supplied `Content-Length` (`:36-40`); **no MIME allowlist**; **no
temporary/quarantined state** (an uploaded blob is immediately visible via `getBlob`); **no reference
counting and no GC** — nothing ever calls `BlobDb.DeleteBlobBytes` outside `RestoreAccount`
(`src/cli/commands/RestoreAccount.cs`), so blobs orphaned by record deletion persist forever; and **no
`listMissingBlobs`**, so the standard migration handshake cannot complete.

## 11. Moderation / admin / takedown

No `com.atproto.admin.*`, no `com.atproto.moderation.*`, no labels, no takedowns, no subject-status store —
see §5. What exists instead is a password- or passkey-authenticated HTML dashboard at `/admin/*`
(`src/pds/Pds.cs:227-249`) offering: config editing over a 21-key allowlist
(`src/pds/admin/Admin_Config.cs:17-39`), session/passkey listing and deletion, request statistics, and seven
operator actions — `generatekeypair`, `generateuserpassword`, `generateadminpassword`, `installuserrepo`,
`rotatejwtsecret`, `activateaccount`, `deactivateaccount` (`src/pds/admin/Admin_Actions.cs:57-180`). The only
"takedown-shaped" control is deactivating the single account, which sets `UserIsActive=false` and emits
`#account {active:false, status:"deactivated"}` (`src/pds/Pds.cs:353-385`) — and even then `getRepoStatus`
keeps reporting `active: true` (§5) and `getRepo`/`getRecord`/`getBlob` keep serving data, since no read path
consults `UserIsActive`.

## 12. Rate limiting, metrics, health, ops

- **Rate limiting: none.** No ASP.NET rate-limiting middleware is registered in `Pds.InitializePdsForRun`
  (`src/pds/Pds.cs:91-142`) and `grep -rni "ratelimit\|throttl"` over `src/` returns nothing.
- **Metrics**: a homegrown `Statistic(Name, IpAddress, UserAgent, Value, LastUpdatedDate)` counter table
  (`src/pds/db/PdsDb.cs:2433-2441`) with exactly two counter names, `Connect` and `ApplyWrites`
  (`src/pds/Statistics.cs:38`, `:59`), surfaced as HTML at `/admin/stats`. No Prometheus, no OpenTelemetry, no
  structured metrics endpoint. Every handler calls `IncrementStatistics()`, i.e. a SQLite upsert keyed by
  `(name, ip, user-agent)` on **every request** — unbounded row growth from user-agent/IP cardinality, with
  manual pruning buttons in the admin UI (`Admin_DeleteOldStatistics.cs`).
- **Health**: `GET /xrpc/_health` returns `{version}` from `data/pds/code-rev.txt` (written by the deploy
  script) or the literal fallback `"dnproto 0.0.005"` (`src/pds/xrpc/Health.cs:16-36`).
- **Logging**: custom logger with console + rotating file destinations (`src/log/`), log level hot-reloaded
  from the DB every 15s (`src/pds/BackgroundJobs.cs:40`, `:54-71`), retention 10 days
  (`src/pds/Installer.cs:143`).
- **Background jobs**: log level, log cleanup, firehose-event pruning, OAuth-request pruning, `requestCrawl`
  to `bsky.network` every 5 min when enabled, stale admin-session cleanup (`src/pds/BackgroundJobs.cs:37-51`).
- **Ops story**: shell scripts in `bash/` for deploy, restart, log tail, log-level toggling and account
  backup/restore. Backups are `BackupAccount` / `RestoreAccount` CLI commands
  (`src/cli/commands/BackupAccount.cs`, `RestoreAccount.cs`).

## 13. Account migration / import-export

None of the migration XRPC surface is served: no `importRepo`, no `listMissingBlobs`, no
`getRecommendedDidCredentials`, no `signPlcOperation`, no `submitPlcOperation`, no `requestPlcOperationSignature`
(verified absent from `src/pds/Pds.cs:184-273`). `activateAccount` / `deactivateAccount` /
`checkAccountStatus` are served but `checkAccountStatus` is field-incomplete (§5).

Migration is instead an **out-of-band CLI workflow**, explicitly modelled on David Buchanan's adversarial-PDS-
migration write-up (`src/cli/commands/BackupAccount.cs:24-26`): `BackupAccount` pulls prefs + repo CAR + every
blob from the *source* PDS over `getRepo`/`listBlobs`/`getBlob` (`src/ws/BlueskyClient.cs:1185`, `:1404`,
`:1467`), then `RestoreAccount` reads that directory and writes prefs, blobs, records, MST and a freshly signed
commit straight into the local SQLite (`src/cli/commands/RestoreAccount.cs:100-170` onward). An operator
performs the DID-document update by hand.

## 14. Notable spec deviations and unsupported features

The README contains **no** "Status", "Known issues", "Limitations" or "Roadmap" section — `grep -in
"status\|known issue\|limitation\|not support\|experimental"` over `README.md` returns nothing. The closest
thing to a candid statement is the framing at `README.md:5-8`, and the code is generally more honest than the
docs (e.g. `src/pds/xrpc/ComAtprotoServer_CheckAccountStatus.cs:30-31` admits missing response fields).

Consolidated deviations, all code-verified:

1. `sync.getRepoStatus` returns the service DID and a hardcoded `active: true`
   (`ComAtprotoSync_GetRepoStatus.cs:15-19`).
2. `server.checkAccountStatus` omits 5 of 9 lexicon-required fields.
3. `sync.getRecord` / `sync.getBlob` / `sync.listBlobs` / `repo.listRecords` / `repo.describeRepo` ignore
   required `did` / `repo` parameters (single-tenant assumption baked into the wire contract).
4. `sync.getRecord` returns JSON 404 instead of a non-existence proof CAR.
5. `sync.getRepo` has no `since`; `sync.listBlobs` has no `since`; `repo.listRecords` returns no `cursor`.
6. `repo.applyWrites` sets every result's `validationStatus` to the literal `"valid"`
   (`src/pds/UserRepo.cs:159`) — **there is no lexicon validation of any kind**; `$type` is force-overwritten
   with the collection NSID (`src/pds/UserRepo.cs:138`).
7. No `swapRecord` support on `putRecord`/`deleteRecord`/`applyWrites` (only `swapCommit`).
8. `createSession` returns 200 on bad credentials; no app passwords; no 2FA.
9. OAuth: no DPoP nonce; `private_key_jwt` and `revocation_endpoint` advertised but not implemented/routed;
   redirect URIs restricted to an operator allowlist instead of client-metadata resolution; scopes unenforced.
10. Firehose: no `#info` frames, no error frames, 12h backfill vs 72h retention with silent cursor
    fast-forward, ~100 events/sec ceiling, int32 `seq` ceiling.
11. No no-op suppression — every `applyWrites` call produces a new signed commit and a `#commit` frame even
    when nothing changed.
12. Per-op `prev` emitted for deletes only, not updates.
13. Zero moderation/label/admin XRPC surface; `UserIsActive` is not enforced on any read path.
14. AppView proxy buffers upstream responses as `string` (`AppBsky_Proxy.cs:233`) — binary AppView responses
    would be corrupted — and constructs a new `HttpClient` per request (`:125`).
15. No rate limiting anywhere.

## 15. Maturity tier

**single-user.**

It is a genuinely working, genuinely deployed personal PDS — 24 real `com.atproto.*` handlers, a
byte-level-correct-enough hand-written DAG-CBOR/CAR/MST stack, signed v3 commits with `prevData`, a live
`subscribeRepos` firehose that relays actually consume, an OAuth authorization server with PAR/PKCE/DPoP, and
service-auth minting *and* verification — well past hobby-experiment. But the single-account assumption is
structural rather than incidental (identity lives in a key/value config table, `RepoCommit` is documented as
one row, `did` and `repo` request parameters are ignored on seven endpoints), and the operational surface a
"serious" tier would need is absent: no account creation, no migration endpoints, no lexicon validation, no
moderation or takedown enforcement, no rate limiting, and no blob GC.

---

## Confidence & unknowns

- **Not executed.** No `dotnet build` or `dotnet test` was run; all claims are from reading source. The
  JSON-null→`"null"`-text and varint-EOF-hang findings (§8 items 4 and 6) are traced through the code paths
  cited but were **not** confirmed by running the code.
- **Git history unavailable.** The clone has one squashed commit, so "the author has hit subtle firehose bugs"
  is corroborated only by in-source comments (`src/pds/UserRepo.cs:385-399`, `src/repo/DagCborObject.cs:482-492`
  and `:641-652`, `src/pds/xrpc/ComAtprotoSync_SubscribeRepos.cs:152-156`), not by commit messages.
- **Read in full**: `src/pds/Pds.cs`, `src/pds/UserRepo.cs`, `src/pds/Installer.cs`,
  `src/pds/FirehoseEventGenerator.cs`, `src/pds/BackgroundJobs.cs`, `src/repo/DagCborObject.cs`,
  `src/repo/CidV1.cs`, `src/repo/VarInt.cs`, `src/pds/blob/BlobDb.cs`, `src/pds/xrpc/BaseXrpcCommand.cs`, and
  most of `src/pds/xrpc/`.
- **Read only partially**: `src/pds/db/PdsDb.cs` (2616 lines — schemas plus firehose/sequence/blob queries),
  `src/mst/Mst.cs` (`FindNodesForKey` only), `src/ws/BlueskyClient.cs` (grepped, ~1600 lines),
  `src/auth/JwtSecret.cs` / `src/auth/Signer.cs` (key regions), the OAuth `Authorize_*` and passkey handlers
  (grepped for PKCE/client-auth). **`src/repo/RepoMst.cs` was not read — UNVERIFIED: whether MST node
  serialisation applies correct prefix compression and `l`/`e`/`p`/`k`/`v`/`t` field naming.**
- **UNVERIFIED: MST correctness.** `test/mst/MstTests.cs` is only 51 lines. Whether the hand-written MST
  produces byte-identical nodes to the reference implementation for non-trivial trees would need a
  cross-implementation CAR diff — `src/cli/commands/PrintRepoComparison.cs` suggests the author does this
  manually, but no automated test asserts it.
- **UNVERIFIED: covering-proof sufficiency.** §7 records that only the root-to-leaf path is included. Whether
  a relay's sync-1.1 verifier accepts that for deletes and for updates that trigger MST node merges/splits
  would need a live relay test.
- **UNVERIFIED: canonical-ordering divergence in practice.** The `StringComparer.Ordinal` issue
  (`src/repo/DagCborObject.cs:171-173`) is real in theory; I did not construct a record whose keys actually
  trigger it.
- **UNVERIFIED: whether `FeatureEnabled_Oauth` is on in the author's deployment.** The installed default is
  `false` (`src/pds/Installer.cs:140`); `powershell/SetOauthIsEnabled.ps1` exists to flip it.
- `docs/` contains exactly one document, `handle-resolution.md` (237 lines, a clear tutorial on
  handle→DID→DID-document resolution). It describes protocol behaviour, not dnproto's own implementation, so
  it was not usable as a source of implementation claims.
