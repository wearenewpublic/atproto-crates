# HappyView — permissioned-data comparison (proposal 0016)

Source read: local clone at `/tmp/gap-scratch/happyview`, git HEAD
`6035c557e3ff2939eb0923bb1161663106c97223` ("fix: add independent logging for jobs", 2026-07-17),
origin `https://github.com/gamesgamesgamesgamesgames/happyview`.
Conformance oracle: the draft lexicons on the `permissioned-data` branch of `bluesky-social/atproto`
at `/tmp/gap-scratch/lex-0016` (HEAD `3f6c96d`, 2026-07-02) plus the spec digest at
`/tmp/gap-scratch/0016-spec-digest.md`. Public-doc notes at `/tmp/gap-scratch/happyview-web-notes.md`
were treated as claims to be checked, not as evidence; every doc claim below is either confirmed
against source or explicitly flagged as contradicted.

Everything cited as `file:line` was opened. Claims I could not confirm are marked UNVERIFIED.

## (A) What HappyView is, its stack, license, deployment

HappyView is a lexicon-driven AppView server: you upload lexicon schemas and it derives XRPC routes,
storage, and network sync from them (`README.md:3`, `README.md:9-11`). Spaces are a subsystem inside
that AppView, not a separate product, and they sit behind an instance setting —
`feature.spaces_enabled`, with all space endpoints returning 404 `FeatureDisabled` when it is off
(`packages/docs/content/docs/experimental/spaces/index.md`, "Feature flag" section).

The stack is a single Rust binary. `Cargo.toml:1-5` declares `happyview` 0.1.0 on edition 2024 with
`rust-version = "1.96"`, pinned by `rust-toolchain.toml` to 1.96.1. HTTP is axum 0.8
(`Cargo.toml:17`); persistence is sqlx 0.9 over the `Any` driver with both Postgres and SQLite
enabled (`Cargo.toml:43`), which is why every query in the spaces module goes through
`adapt_sql(...)` (for example `src/spaces/db.rs:316-319`). Crypto is `k256` 0.14 and `p256` 0.14
(`Cargo.toml:32,34`) plus `blake3`, `hkdf`, `hmac`, `sha2` (`Cargo.toml:62-64,42`). Scripting is
embedded Lua via `mlua` (`Cargo.toml:53`) and WASM plugins via `wasmtime` (`Cargo.toml:58`). The
dashboard is a Next.js app built in a separate Docker stage (`Dockerfile:1-8`).

License is MIT, "Copyright (c) 2024 Lexicon Community" (`LICENSE.md:1,3`) — permissive, so
atproto-crates can read its constructions freely.

Deployment is self-host-first despite the hosted happyview.dev presence. `Dockerfile:10-25` builds a
release binary, `Dockerfile:26-29` ships it on `debian:bookworm-slim`, and `Dockerfile:33-40` carries
an explicit note that the container runs as root because a previous non-root attempt broke SQLite
volume ownership on Railway-style mounts. `.env.example` defaults `DATABASE_URL` to
`sqlite://data/happyview.db?mode=rwc` with Postgres commented out, and documents Cloudflare Tunnel as
the exposure mechanism. `docker-compose.yml:21-24` is a dev-mode `cargo watch` container. So the
deployment shape is: one process, SQLite by default, optionally Postgres, reachable through a tunnel.

## (B) NSID coverage

Two routers register everything. `src/spaces/routes.rs:209-210` sets `PROTO_NS = "com.atproto"` and
`LEGACY_NS = "dev.happyview"`; `src/spaces/simplespace.rs:86-87` does the same for the management
side. Checked against `/tmp/gap-scratch/lex-0016/`:

| NSID (0016 branch) | HappyView route | Verb match | Shape divergence vs lexicon |
|---|---|---|---|
| `com.atproto.space.getSpace` | `routes.rs:215` GET | yes | output adds a non-lexicon `space` object next to `{uri, config}` (`routes.rs:461-465`; oracle `space/getSpace.json`) |
| `com.atproto.space.listSpaces` | `routes.rs:217` GET | yes | no `type` param (`routes.rs:87-91` vs `space/listSpaces.json`) |
| `com.atproto.space.getRecord` | `routes.rs:221` GET | yes | no `repo` param at all (`routes.rs:113-118`); lexicon requires `repo` |
| `com.atproto.space.listRecords` | `routes.rs:225` GET | yes | `repo` optional (`routes.rs:122-129`); lexicon requires it. No `excludeValues` |
| `com.atproto.space.getLatestCommit` | `routes.rs:229` GET | yes | param named `did`, not `repo` (`routes.rs:27-30`) |
| `com.atproto.space.getRepoState` | `routes.rs:233` GET (alias to same handler) | n/a | not in the 0016 branch at all — HappyView's own back-compat alias |
| `com.atproto.space.getRepo` | `routes.rs:236` GET | yes | param `did` not `repo`; returns `application/vnd.ipld.car` (`routes.rs:1079`) |
| `com.atproto.space.listRepoOps` | `routes.rs:238` GET | yes | `did` not `repo`; `cursor` not `since` (`routes.rs:41-47`, bound at `routes.rs:1113`); output omits the `commit` field the lexicon defines |
| `com.atproto.space.listRepos` | `routes.rs:242` GET | yes | repo entries carry `{did, rev}` only, no `hash` (`src/spaces/db.rs:1022-1024` vs `space/listRepos.json#repo`) |
| `com.atproto.space.getDelegationToken` | `routes.rs:246` GET | yes | output key is `delegationToken` (+`expiresAt`), lexicon says `token` (`routes.rs:955-958`) |
| `com.atproto.space.getSpaceCredential` | `routes.rs:250` POST | yes | input is `{grant}` (`routes.rs:155-157`); lexicon input is `{space, clientAttestation}` with the delegation token in the Authorization header |
| `com.atproto.space.createRecord` | `routes.rs:254` POST | yes | no `repo`/`rkey`/`validate`; no `validationStatus` in output |
| `com.atproto.space.putRecord` | `routes.rs:258` POST | yes | no `repo`/`validate`; no `validationStatus` |
| `com.atproto.space.deleteRecord` | `routes.rs:262` POST | yes | no `repo` |
| `com.atproto.space.applyWrites` | `routes.rs:266` POST | yes | no `repo`/`validate`; adds a non-lexicon `swapCommit` (`routes.rs:176-180`) |
| `com.atproto.space.registerNotify` | `routes.rs:270` POST | yes | input `{space, serviceDid, endpoint}` (`routes.rs:51-55`) vs lexicon `{space, repo, endpoint}`; output `{id}` vs `{expiresAt}` |
| `com.atproto.space.notifyWrite` | `routes.rs:274` POST | yes | **major**: input `{space, did, collection, rkey, cid}` (`routes.rs:59-65`) vs lexicon `{space, repo, rev, hash}`. The spec's notification is contentless; HappyView's carries collection/rkey/CID |
| `com.atproto.space.notifySpaceDeleted` | `routes.rs:278` POST | yes | matches `{space}` |
| `com.atproto.space.getBlob` | `routes.rs:282` GET | yes | no `repo` param (`routes.rs:169-172`); author is looked up from the blob CID (`routes.rs:1178-1180`) |
| `com.atproto.simplespace.createSpace` | `simplespace.rs:93` POST | yes | no `did` input — authority is taken from the session (`simplespace.rs:206-219`); `skey` required though lexicon marks it optional |
| `com.atproto.simplespace.updateSpace` | `simplespace.rs:97` POST | yes | takes `mintPolicy`, not `policy`; adds `displayName`/`description`/`config` |
| `com.atproto.simplespace.deleteSpace` | `simplespace.rs:101` POST | yes | matches |
| `com.atproto.simplespace.addMember` | `simplespace.rs:105` POST | yes | adds `access` and `isDelegation` (`simplespace.rs:59-64`) |
| `com.atproto.simplespace.removeMember` | `simplespace.rs:109` POST | yes | matches |
| `com.atproto.simplespace.listMembers` | `simplespace.rs:113` GET | yes | no `limit`/`cursor`, no cursor in output (`simplespace.rs:281-283`) |
| `com.atproto.simplespace.checkUserAccess` | **not routed** — outbound only | — | called at `src/spaces/auth.rs:137-159` as a **POST with a JSON body** `{space, did, clientId}` reading `granted`; the lexicon defines a **GET query** with params `{space, user, clientId}` returning `authorized`. Three-way break: verb, param name, output key |

Documented extensions, each verified in source:

- **Invites** — `createInvite`/`acceptInvite`/`revokeInvite`/`listInvites` under `dev.happyview.space.*`
  (`routes.rs:286-301`), handlers at `routes.rs:813-903`, service logic `src/spaces/service.rs:404-482`,
  storage `migrations/sqlite/20260429000004_create_space_invites.sql`. Token is 24 random bytes hex,
  stored only as `sha256` hex (`service.rs:414-417`). Confirmed extension: no invite NSID exists in the
  0016 branch.
- **`isDelegation` member flag** — `simplespace.rs:63`, `types.rs:198`, resolved transitively in
  `src/spaces/members.rs:66-78` with `MAX_DELEGATION_DEPTH = 10` (`members.rs:9`) and a `visited` set
  (`members.rs:59-61`). Confirmed extension.
- **`displayName`/`description`** — `types.rs:171-172`, settable at `simplespace.rs:25-26`. Confirmed
  extension.
- **`read_self` access tier** — `types.rs:6-10`, ranked below `read` at `types.rs:40-46`, enforced in
  `src/spaces/scope.rs:24-63`. Confirmed extension.
- **`getConfig`/`updateConfig`** — `simplespace.rs:117,121`, handlers `simplespace.rs:316-360`.
  Confirmed extension: neither NSID exists on the 0016 branch. Note both emit
  `{"$type": "com.atproto.simplespace.defs#spaceConfig", "mintPolicy": ..., "appAccess": ..., "managingApp": ...}`
  (`simplespace.rs:325-330`), but the real `simplespace/defs.json#spaceConfig` requires the key
  `policy`, not `mintPolicy`. HappyView stamps a `$type` on an object that does not validate against
  the def it names.

Legacy `dev.happyview.space.*` aliases for the protocol routes are at `routes.rs:303-343` and for
management at `simplespace.rs:125-148`, including `getMemberGrant` → `get_delegation_token`
(`routes.rs:316-319`).

## (C) Cryptography, in forensic detail

### `src/spaces/lthash.rs` — LtHash

State is `[u16; 1024]` (`lthash.rs:4-9`), i.e. 2048 bytes, with `NUM_LANES = 1024` and
`STATE_BYTES = NUM_LANES * 2` (`lthash.rs:4-5`). Serialization is explicit little-endian per lane
(`lthash.rs:42-50`), and `from_bytes` reads back with `u16::from_le_bytes` (`lthash.rs:52-58`).

Element expansion is BLAKE3 in XOF mode: `Blake3Hasher::new()`, `update(element)`,
`finalize_xof().fill(&mut [0u8; 2048])`, then reinterpreted as 1024 little-endian `u16` lanes
(`lthash.rs:61-73`). `add` is `wrapping_add` per lane (`lthash.rs:24-29`); `remove` is `wrapping_sub`
(`lthash.rs:31-36`) — arithmetic mod 2^16 exactly as the digest describes.

The digest is `Sha256::digest(self.as_bytes())` → `[u8; 32]` (`lthash.rs:38-40`), i.e. sha256 over the
2048-byte state, not over the lanes directly.

Element encoding is `format!("{collection}/{rkey}/{cid}")` as UTF-8 bytes (`lthash.rs:75-77`), asserted
byte-for-byte in `lthash.rs:133-136`. This matches the spec digest's `{collection}/{rkey}/{record_cid}`
and matches atproto-crates byte-for-byte (see §E).

The unit tests cover the algebra properly: order-independence (`lthash.rs:102-116`), add/remove
inverse (`lthash.rs:92-99`), and full mod-2^16 wraparound after 65536 adds (`lthash.rs:148-157`).

**But nothing in the production write path uses it.** `LtHashState` and `record_element` are imported
only by `src/spaces/integration_tests.rs:11`; grep across `src/` finds no other consumer. The
`lthash_state BLOB` column is created at
`migrations/sqlite/20260627000000_proposal_0016_alignment.sql:42`, initialized to 2048 zero bytes at
`src/spaces/db.rs:762,771`, and only ever written by `db::update_repo_state`
(`src/spaces/db.rs:791-813`) — whose sole caller anywhere is a test, `tests/spaces_db.rs:250`.

### `src/spaces/commit.rs` — deniable commit signatures

`SignedCommit` is `{ver: u32, hash: [u8;32], ikm: [u8;32], sig: Vec<u8>, mac: [u8;32], rev: String}`
(`commit.rs:9-16`), matching the lexicon's required set in `space/defs.json` including `ver`.

The context encoding is the TLS 1.3 variable-length-vector form: the literal tag `atproto-space-v1`
with no length prefix, then big-endian `uint16` length prefixes for `space`, `author_did`, `rev`, and
the 32-byte `ikm`, in that order (`commit.rs:18-44`, with the ordering asserted at
`commit.rs:158-184`). The author DID is present, matching `space/defs.json`'s "Signature over ctx
(space, author DID, rev, ikm)".

Signing does implement the spec construction: a fresh 32-byte `ikm` per commit
(`commit.rs:53-54`), a signature over `ctx` and explicitly **not** over the hash — the comment at
`commit.rs:58` says so — and
`mac = HMAC-SHA256(HKDF-SHA256(ikm, ctx), hash)` built as `Hkdf::<Sha256>::new(None, &ikm)` then
`expand(&ctx, &mut [0u8;32])` then HMAC over `hash` (`commit.rs:62-70`). Verification reconstructs
`ctx` from the stored `ikm`, checks `ver == 1` (`commit.rs:88-93`), verifies the signature over `ctx`,
re-derives the key and constant-time-compares the MAC (`commit.rs:95-117`). Test coverage rejects
tampered hash (`commit.rs:241-250`), tampered MAC (`commit.rs:306-317`), wrong author
(`commit.rs:214-223`), wrong space (`commit.rs:252-275`), wrong key, and unknown version.

Two limits. First, the signing type is hardwired to secp256k1: `commit.rs:3` imports only
`k256::ecdsa::{Signature, SigningKey, VerifyingKey}` and `sign_commit` takes `&SigningKey` of that
type (`commit.rs:51`). A P-256 atproto account cannot produce a HappyView commit. Second — and this
is the big one — `sign_commit` has no production caller either: grep finds it only in `commit.rs`
itself and `src/spaces/integration_tests.rs`. Consequently `get_latest_commit` returns
`"commit": null` whenever `repo_state.hash` is NULL (`routes.rs:988-1008`), and `get_repo` returns
404 `"no commit exists for this repo"` (`routes.rs:1041-1044`). The record write paths
(`service.rs:120-152`, `155-192`, `194-227`, and `routes.rs:597-704`) update only
`space.revision` via `db::update_space_revision` and never touch repo state, the LtHash, or the oplog.
The commit and set-hash machinery is a correct, well-tested library that is not wired in.

### `src/spaces/credential.rs` — the two JWTs

Constants at `credential.rs:14-18`: `DEFAULT_CREDENTIAL_TTL_SECS = 7200`,
`DELEGATION_TOKEN_TTL_SECS = 60`, `DELEGATION_TOKEN_TYP = "atproto-space-delegation+jwt"`,
`SPACE_CREDENTIAL_TYP = "atproto-space-credential+jwt"`. Both match the spec digest and the public
glossary.

*Delegation token.* Claims are `{iss, sub, aud, iat, exp, jti}` (`credential.rs:51-58`); header is
`{"alg":"ES256K","typ":"atproto-space-delegation+jwt","kid":"#atproto"}` (`credential.rs:64-68`).
Verification rejects wrong `alg` (`credential.rs:96-98`), wrong `typ` (`credential.rs:100-104`),
expiry (`credential.rs:141-143`), and `aud` mismatch (`credential.rs:145-149`). It accepts either a
raw or low-S-normalized signature by retrying with `normalize_s()` (`credential.rs:111-122`) — a
pragmatic malleability accommodation, but it means a non-canonical high-S signature is accepted.

The critical divergence is the *key*. The spec requires the delegation token to be signed by the
user's account signing key so any space host can verify it against the user's DID document.
HappyView instead derives a secp256k1 scalar from the instance's `TOKEN_ENCRYPTION_KEY`:
`k256::ecdsa::SigningKey::from_slice(encryption_key)` at `routes.rs:926`, with the matching
`VerifyingKey` re-derived from the same secret at `routes.rs:1310-1315`. The `aud` is
`"{space.did}#atproto_space_host"` (`routes.rs:939`), so the shape is right, but only the instance
that minted the token can verify it. The token proves "HappyView says this member asked", not "this
member signed".

*Space credential.* Claims are `{iss, sub, iat, exp, jti}` with no `aud`
(`credential.rs:155-161`) — correct per the spec's "no `aud`, presentable to any repo host". Note
there is also no `client_id` claim, so an attested app identity is not carried into the credential.
Header is `{"alg":"ES256","typ":"atproto-space-credential+jwt","kid":"#atproto_space"}`
(`credential.rs:178-182`); verification checks alg, typ, signature, and expiry
(`credential.rs:209-246`). Signing uses a per-space P-256 keypair generated on first use and stored
AES-encrypted alongside a separate rotation key (`src/spaces/auth.rs:261-317`, generator at
`auth.rs:323-353`, table `migrations/sqlite/20260429000005_create_space_dids.sql`).

Cross-instance verification resolves `claims.iss`'s DID document and looks for a verification method
whose id ends `#atproto_space`, converting `publicKeyMultibase` to a JWK by stripping the P-256
multicodec prefix `0x80 0x24` (`credential.rs:277-306`, `credential.rs:312-345`). This is coherent as
a *consumer* of someone else's credential. As a verifier of its own it does not close: `iss` is set to
`space.authority_did` (`auth.rs:44`), a user DID, while the key that signed is the per-space key from
`happyview_space_dids`; the only `#atproto_space` key HappyView provisions is an
instance-level one (`src/spaces/service.rs:286-295` → `src/verification_methods.rs:206-215`, published
in the instance did:web doc per `src/service_identity.rs:384`). Nothing publishes the per-space public
key under the authority's DID.

*Revocation.* `migrations/sqlite/20260707000000_add_revoked_at_to_space_credentials.sql:1-4` adds a
nullable `revoked_at` to `happyview_space_credentials` (the header comment labels it "M3"). Each mint
records `sha256(token)` hex (`auth.rs:56-57`, `auth.rs:355-385`).
`db::revoke_space_credentials_for_member` (`src/spaces/db.rs:330-348`) stamps `revoked_at` for all of
a member's outstanding credentials, and `service::remove_member` calls it *before* deleting the
membership row (`service.rs:395-397`). Reads consult `is_space_credential_revoked`
(`db.rs:311-326`) via `routes.rs:363-369`, checked in `require_auth_or_credential`
(`routes.rs:386-388`) and again in `service::require_membership` (`service.rs:95-96`).
`tests/spaces_credential_revocation.rs:108-135` exercises it end to end. So revocation is real,
member-scoped, and TTL-independent — a genuine addition over the spec, which relies purely on the
2-hour TTL.

**However, the space credential is not actually accepted as an auth scheme on the `com.atproto.*`
routes.** `src/auth/middleware.rs:299` computes `is_space_route = path.contains("/dev.happyview.space.")`,
and `middleware.rs:316` matches `Some(typ) if typ == "space_credential" && is_space_route`. Two
independent mismatches: the minted `typ` is `atproto-space-credential+jwt` (`credential.rs:18,181`),
never the bare string `space_credential`; and the path test excludes the entire `com.atproto.space.*`
namespace. The public changelog states the `typ` change explicitly
(`packages/docs/content/docs/experimental/spaces/changelog.md`, v2.10, "Space credential `typ` —
changed from `space_credential` to `atproto-space-credential+jwt`"), and `credentials.md` states
"HappyView distinguishes space credentials from other tokens by checking the JWT header's `typ` field
(`atproto-space-credential+jwt`)". The docs describe the intended behavior; the extractor still
tests the old string on the old path. Doc/code disagreement, and the code is the one that runs.

### `src/spaces/client_attestation.rs` — app-identity attestation

The module verifies an `atproto-client-attestation+jwt` (`client_attestation.rs:3`): it checks `typ`
(`:28-32`), requires a `kid` header (`:34-36`), requires `iss == sub` (`:53-55`), checks `aud`
(`:57-59`) and `exp` (`:61-67`), then treats `iss` as a URL, fetches it as OAuth client metadata,
resolves `jwks` inline or via `jwks_uri` (`:70-94`), selects the key whose `kid` matches (`:97-104`),
and verifies an ES256 signature — rejecting every other `alg` (`:107-126`). The verified `client_id`
is the attestation's `iss` (`:128-130`). That is a reasonable implementation of the spec's client
attestation.

It is dead code. `verify_client_attestation` has no caller: grep across `src/` and `tests/` finds only
the `pub mod client_attestation;` declaration at `src/spaces/mod.rs:3`. Consistently,
`getSpaceCredential`'s input struct has only `grant` (`routes.rs:155-157`) with no
`clientAttestation` field, so an attestation cannot even be submitted.

App identity is instead established out-of-band: `routes.rs:1350-1354` maps the caller's
`X-Client-Key` header (required for DPoP auth, `src/auth/middleware.rs:182-186`) through
`resolve_client_id_url` (`routes.rs:413-427`) to the `client_id_url` column of HappyView's own
`happyview_api_clients` table, and that string is what `check_app_access` compares against the
allowlist (`src/spaces/auth.rs:244-259`). The allowlist is therefore enforced against a
HappyView-issued API key, not against a cryptographic proof of app identity — which is exactly what
the spec's `#allowList` variant exists to avoid.

## (D) The seven axes

**1. Space/grant modeling.** A space is `(authority DID, space-type NSID, skey)` rendered as
`at://<did>/space/<type>/<skey>`, parsed by `SpaceUri::parse` in `src/spaces/mod.rs:38-110`, which
requires the literal `space` segment at index 1 (`mod.rs:67-71`) and accepts either 4 segments (a
space) or 7 (a record: `.../<author-did>/<collection>/<rkey>`, `mod.rs:83-100`). Legacy `ats://` URIs
are rewritten on the way in (`mod.rs:41-52`). The skey concept is first-class and stored as its own
column with a `UNIQUE (did, type_nsid, skey)` constraint
(`migrations/sqlite/20260627000000_proposal_0016_alignment.sql:9-10,20`), so an authority holds
arbitrarily many spaces. The root of trust is `authority_did`, distinct from `creator_did`
(`types.rs:166-167`), both set to the creating session's DID at `service.rs:270-272`. There is also a
`did` column distinct from both, so a space's addressing DID can in principle differ from its
authority.

**2. Membership management.** The member list lives in HappyView's own `happyview_space_members`
table (`migrations/sqlite/20260429000001_create_space_members.sql`), mutated only by the space
authority or a HappyView super-admin (`service.rs:32-55`, called from `service::add_member`
`service.rs:318` and `remove_member` `service.rs:394`). There is no set-hash or commit over the member
list — membership is plain rows, resolved on demand by `members::resolve_members`
(`members.rs:17-33`), which walks `isDelegation` entries into other spaces up to depth 10
(`members.rs:9,55-57`) with cycle protection (`members.rs:59-61`) and merges duplicate reachability by
privilege rank, never downgrading (`members.rs:107-115`). Members learn about their membership by
polling — `listSpaces` (`routes.rs:468-500`) and `listMembers` (`simplespace.rs:267-284`); there is no
`notifyMembership` and no enrollment record. Invites are the push-ish alternative
(`routes.rs:813-903`).

**3. Auth/authz enforcement.** Enforcement is at both write and read time and is centralized in
`service::require_membership` (`service.rs:75-118`), which either accepts a verified,
non-revoked space credential whose `sub` equals the space URI (`service.rs:82-107`) or falls through
to a member lookup, additionally requiring `can_write()` for mutations (`service.rs:112-116`). Reads
layer a second check: `SpaceReadAccess::from_space_access` plus `check_read_access`
(`scope.rs:11-45`) restricts a `read_self` member to their own repo, and `check_delegation_token_access`
(`scope.rs:50-63`) blocks `read_self` members from minting delegation tokens at all. Credential types
recognized: DPoP session, signed session cookie, service-auth JWT, and (nominally) space credential
(`src/auth/middleware.rs:274-368`). Failure codes are inconsistent by design: non-membership is 403
(`service.rs:111`), a `read_self` violation is 403 (`scope.rs:39-42`), and a missing record is 404
(`routes.rs:736`) — but `getSpace` on a space with private membership returns **404 "Space not
found"** rather than 403 (`routes.rs:441-448`), deliberately hiding existence. Several of these gates
carry inline notes about previously-missing checks: `listRepos` leaked participant lists ("M2",
`routes.rs:1141-1155`), `notifyWrite`/`notifySpaceDeleted` accepted any caller ("M1",
`routes.rs:1260-1265`, `1287-1291`), and `getSpaceCredential` let a captured delegation token be
redeemed by a third party ("M4", `routes.rs:1331-1341`, regression-tested in
`tests/spaces_credential_mint.rs:128-146`). Read those as evidence the surface has been audited, not
as evidence it was always right.

**4. App-view access control.** Two orthogonal dials, both on the space row. Mint policy is
`member-list | public | managing-app` (`types.rs:59-86`), evaluated in `auth::check_mint_policy`
(`auth.rs:66-108`); note `MemberList` is an explicit no-op there (`auth.rs:75-79`) that trusts the
caller to have checked membership, which `routes.rs:1348` does. `managing-app` calls out to the
managing app's `checkUserAccess`, resolving its `#atproto_pds` service endpoint from the DID document
(`auth.rs:185-242`) — and the code comment at `auth.rs:150-152` admits it sends **no service auth at
all**, only an `X-Authority-Did` header, "relying on the managing app to trust HappyView". App access
is `open | allowList` (`types.rs:94-102`) enforced in `check_app_access` (`auth.rs:244-259`) against
the API-client-derived `client_id_url` as described in §C. There is no trusted-app-view concept beyond
this.

**5. Record read/write paths.** Permissioned records do **not** share a public repo write path and do
not touch a PDS. They are rows in HappyView's own `happyview_space_records` table
(`migrations/sqlite/20260429000002_create_space_records.sql`: `uri` PK, `space_id`, `author_did`,
`collection`, `rkey`, `record` as TEXT JSON, `cid`, `indexed_at`), written by
`db::insert_space_record` / `upsert_space_record` from `service::create_record`
(`service.rs:120-152`) and friends. This is the contrail-shaped choice — storage at the AppView —
not the 0016/atproto-pds shape. Record identity is a **fabricated CID**:
`service::content_cid` is `format!("bafyrei{}", hex::encode(&sha256(serde_json::to_vec(record))[..20]))`
(`service.rs:26-30`). That is not a CID: it is not multibase-decodable, the digest is truncated to 20
bytes, the encoding is hex not base32, and the bytes hashed are `serde_json` output rather than
DAG-CBOR. Any `cid` HappyView emits — in `getRecord`, `listRecords`, `listRepoOps`, or an LtHash
element if the machinery were wired — is incomparable with any real atproto CID. Compounding this,
`car::serialize_repo` re-derives a *different* CID for each record block, using the RAW codec 0x55
over the same `serde_json` bytes (`car.rs:65-67`), so the CAR export's block CIDs do not equal the
stored `cid` values either. The CAR itself is otherwise well-formed: a two-root header
(commit + index, `car.rs:120-129`), a DAG-CBOR index map of `"collection/rkey"` → tag-42 CID link
sorted lexicographically (`car.rs:71-87`), the commit block (`car.rs:90-117`), then record blocks in
sorted order (`car.rs:146-148`). Optimistic concurrency exists via `swapRecord`
(`db::upsert_space_record_with_swap`, `service.rs:184-188`) and `swapCommit`
(`routes.rs:583-593`). Collections can be constrained per space via an `allowedCollections` config
injected from the lexicon registry at creation time (`service.rs:57-73`, `service.rs:252-267`).

**6. Sync/event behavior.** The design is pull-based oplog reconciliation plus best-effort push, and
it is half-built. `listRepoOps` (`routes.rs:1085-1131`) reads `happyview_space_record_oplog`
(`oplog.rs:32-99` metadata-only, `oplog.rs:101-174` with values inlined via a LEFT JOIN against
`happyview_space_records`), and the default is values-inlined with `excludeValues=true` to opt out
(`routes.rs:1106-1128`) — matching the lexicon's default. But `oplog::append_op` (`oplog.rs:5-30`) has
no caller anywhere, so the table is always empty in production and the sync path returns `{"ops": []}`
forever. The response also omits the `commit` field the lexicon defines. Push is
`registerNotify` with a 24-hour TTL (`notifications.rs:7,19-28`) and `notifyWrite` fanning out to
registered endpoints (`notifications.rs:43-76`), fire-and-forget with errors discarded
(`notifications.rs:72`); the payload sends the internal `space_id` UUID rather than the space URI
(`notifications.rs:63-69`), which registered syncers cannot resolve back to a space. And the docs
claim at `packages/docs/content/docs/experimental/spaces/notifications.md:69` — "This is used
internally by HappyView when records change" — is contradicted by the code:
`dispatch_write_notification`'s only caller is the `notifyWrite` HTTP handler itself
(`routes.rs:1267`). Nothing on the write path fires a notification. There is no firehose interaction
for space data at all; the question of keeping permissioned writes off the public firehose does not
arise because they never enter a repo.

**7. Interop with the 0016 direction.** Namespace-wise this is the closest external match that exists:
the same `com.atproto.space.*` / `com.atproto.simplespace.*` split, the same delegation-token →
space-credential exchange, the same `typ` strings, TTLs, and algorithms, the same LtHash parameters
and element encoding, and the same deniable-commit construction including the author DID in `ctx`. At
the wire level, though, an independent 0016 client would fail against it on almost every call: `did`
instead of `repo`, `cursor` instead of `since`, `delegationToken` instead of `token`, `{grant}` in the
body instead of the delegation token in the Authorization header, `mintPolicy` instead of `policy`, a
content-bearing `notifyWrite`, and a `checkUserAccess` callback with the wrong verb, parameter name,
and response key.

## (E) HappyView vs atproto-crates

Compared against `crates/atproto-space` and `crates/atproto-pds/src/space` in this worktree.

**Set hash — equivalent, both correct.** `crates/atproto-space/src/set_hash.rs:30-32` uses the same
`LANES = 1024` / `STATE_BYTES = 2048`; `set_hash.rs:94-104` expands with BLAKE3 XOF into little-endian
`u16` lanes; `set_hash.rs:114-119` wraps on add. Element encoding is identical:
`format!("{collection}/{rkey}/{cid}")` at `set_hash.rs:167-168` versus HappyView's `lthash.rs:75-77`.
Digests are byte-comparable. atproto-crates is slightly ahead on structure — the `SetHash` trait
(`set_hash.rs:39-73`) separates persistable `state_bytes` from the 32-byte `digest`, and the PDS binds
the concrete impl in one place (`crates/atproto-pds/src/realm.rs:24`).

**Commit — atproto-crates is behind on two fields.** HappyView's `ctx` is
`tag || space || author || rev || ikm` (`commit.rs:18-44`); atproto-crates' `encode_ctx` is
`tag || space || rev || ikm` with no author DID (`crates/atproto-space/src/commit.rs:58-64,71-81`).
`space/defs.json` says the signature covers "space, author DID, rev, ikm", so **HappyView matches the
current lexicon and atproto-crates does not** — commits produced by the two will not cross-verify.
Second, HappyView's `SignedCommit` carries `ver` and rejects `ver != 1` (`commit.rs:9-16,88-93`);
atproto-crates' `Commit` has no `ver` field at all (`crates/atproto-space/src/commit.rs:87-102`),
though `space/defs.json` marks it required. Read this alongside the wiring finding below: HappyView
has the correct byte layout in code that no production path calls, while atproto-crates has the wrong
layout in code that runs on every write. Where atproto-crates is ahead: signing goes through
`atproto_identity::key::KeyData` (`crates/atproto-space/src/commit.rs:41`), so P-256 and K-256 accounts
both work, whereas HappyView hardwires secp256k1 (`commit.rs:3,51`).

**Commit wiring — atproto-crates is decisively ahead.** `crates/atproto-pds/src/space/writer.rs:335`
calls `create_commit` inside the actual write path, after folding the ops into the set hash
(`crates/atproto-space/src/space_repo.rs:127-269`) and persisting the new state
(`space_repo.rs:264-269`, `437`). HappyView's equivalent code is never called (§C). This is the single
largest functional gap in HappyView's spaces implementation and the place where atproto-crates has the
clearest lead.

**Addressing — HappyView is ahead.** HappyView migrated to `at://<did>/space/<type>/<skey>` and treats
`ats://` as legacy input (`src/spaces/mod.rs:41-52,112-114`). atproto-crates still parses and emits
only `ats://` (`crates/atproto-space/src/types.rs:13,89,114,187`, round-trip asserted at
`types.rs:397-402`). The spec digest and every lexicon parameter use `format: "at-uri"`, so
atproto-crates' addressing is now off-spec and would need a migration equivalent to HappyView's v2.11.

**Credential tokens — near-parity, atproto-crates slightly ahead on fidelity.** Both define
`atproto-space-delegation+jwt` / `atproto-space-credential+jwt` with 60s / 7200s TTLs and kids
`#atproto` / `#atproto_space` (HappyView `credential.rs:14-18,68,182`; atproto-crates
`crates/atproto-space/src/credential.rs:40-55`). atproto-crates constrains `alg` to ES256/ES256K and
derives it from the key rather than hardcoding (`space_jws_alg`, `credential.rs:150-157`), and its
`SpaceCredential` carries the attested `client_id` (`credential.rs:96-100`) which HappyView's does not
(`credential.rs:155-161`) — and which the 0016 README does not require of either
(`/tmp/gap-scratch/0016-README.md:219-223`, `:233-239`), so this is an atproto-crates extension
rather than a HappyView gap. Crucially, atproto-pds signs the delegation token with the **account's own
signing key**, loaded from `account.signing_key_ref` via `local_signing_key`
(`crates/atproto-pds/src/http/space_auth.rs:74-96`, used at
`crates/atproto-pds/src/http/space_handlers.rs:1451-1452`), which is what the spec requires and what
makes the token verifiable by a third-party space host. HappyView signs with the instance's
`TOKEN_ENCRYPTION_KEY` (`routes.rs:926`), which makes it instance-local.

**Credential revocation — HappyView is ahead, uniquely.** HappyView added `revoked_at` plus
member-scoped revocation on `removeMember` (§C). Grep for `revoke` across `crates/atproto-space/src`
and `crates/atproto-pds/src/space` returns nothing: atproto-crates has no revocation, so a credential
stays valid for its full 2 hours after a member is removed. This is a concrete, low-cost feature worth
copying, and HappyView's implementation (hash the token at mint, stamp `revoked_at`, check on every
credential-authenticated read) is directly portable.

**Client attestation — atproto-crates is ahead.** `crates/atproto-pds/src/space/mint_authz.rs` verifies
`atproto-client-attestation+jwt` (`mint_authz.rs:145-146`), bounds accepted lifetime to five minutes
(`MAX_ATTESTATION_LIFETIME_SECS`, `mint_authz.rs:202-206`), and wires the verified `client_id` into
the `#open` / `#allowList` decision (`app_axis`, `mint_authz.rs:128-143`) and into the minted
credential. HappyView's equivalent module is dead code
and the allowlist is checked against a HappyView API key instead (§C).

**Record identity — atproto-crates is ahead by a wide margin.** atproto-crates computes real CIDs
through `atproto-dasl`; HappyView's `content_cid` is a fabricated `bafyrei`+hex string
(`service.rs:26-30`) that is neither a valid CID nor internally consistent with its own CAR export
(`car.rs:65-67`). Any interop that compares record CIDs — which is the entire basis of the LtHash
element encoding both implementations share — will fail against HappyView.

**Method coverage — divergent, each ahead in places.** HappyView routes `getRepo` (CAR export,
`routes.rs:236`, serializer `car.rs:60-151`) and `getLatestCommit` under its current name
(`routes.rs:229`); atproto-pds has neither — `crates/atproto-pds/src/http/router.rs:325-327` registers
only `getRepoState`, a name that does not exist on the 0016 branch, and there is no `getRepo` route in
`router.rs:286-355`. Conversely atproto-pds uses the lexicon-correct `repo` parameter throughout
(`crates/atproto-pds/src/http/space_handlers.rs:716,766,821,905,984,1136,1269`) where HappyView uses
`did`, and its `notifyWrite` is contentless and service-auth-bound with the JWT `iss` pinned to the
claimed writer (`space_handlers.rs:2083-2110`) where HappyView's carries collection/rkey/cid and gates
only on space-admin identity (`routes.rs:1260-1265`).

**Storage placement — fundamentally divergent, not a gap.** atproto-crates keeps permissioned records
in the owner's PDS per-actor store and explicitly keeps them off the public firehose
(`crates/atproto-pds/src/space/notify.rs:3`, `crates/atproto-pds/src/space/reader.rs:1-24`). HappyView
keeps them in the AppView's database. These are different points in the design space; the 0016
direction is atproto-crates'. Note one consequence in the other direction: atproto-pds' reader
deliberately does not enforce membership at read time for own-PDS OAuth callers
(`reader.rs:12-18`), pushing that check to consumers, whereas HappyView enforces membership on every
single read (`service.rs:75-118`). On read-time authz specifically, HappyView is stricter — but score
that as HappyView being ahead of the *draft*, not as an atproto-crates defect: the reference
implementation on the `permissioned-data` branch behaves the same way as atproto-crates, taking
`repo` verbatim from params into `ctx.actorStore.read(repo, …)` with no membership lookup
(`packages/pds/src/api/com/atproto/space/getRecord.ts`) and skipping the scope check for every
non-OAuth credential (`.../space/util.ts:32-37`). See
[40-permissioned-overview.md](./40-permissioned-overview.md) M7.

**Extensions worth considering.** `read_self` (`scope.rs:24-63`) is a coherent tier that atproto-crates
lacks and that maps cleanly onto a "user can see only their own contributions" product need. Space
delegation via `isDelegation` (`members.rs:66-78`) gives nested groups for free. Neither is in 0016;
both are additive and would not break a conforming client.

## (F) Confidence and unknowns

High confidence, directly verified by reading the cited lines: the NSID routing table, all crypto
constants and constructions, the LtHash and commit implementations, the credential typ/alg/TTL/claim
sets, the revocation mechanism, the storage schema, and every "no production caller" claim (each
established by grepping the whole of `src/` and `tests/`, not by absence of a single reference).

High confidence on the doc/code disagreements, because both sides were opened: the space-credential
`typ` and route-prefix mismatch (`src/auth/middleware.rs:299,316` vs `credential.rs:18` vs
`changelog.md` v2.10 and `credentials.md`), and the "notifications fire on write" claim
(`notifications.md:69` vs the single caller at `routes.rs:1267`).

Medium confidence on intent. I cannot tell whether the unwired LtHash/commit/oplog code is
deliberately staged ahead of a later wiring task or an incomplete migration; the v2.10/v2.11 changelog
entries describe these as shipped features, which suggests the latter, but that is inference.

UNVERIFIED, and what it would take:

- Whether the hosted happyview.dev deployment runs this same code. I read a 2026-07-17 clone; the
  hosted service could be ahead. Would need a version endpoint response or a tagged release to
  confirm.
- Whether the space-credential extractor bug is observable end to end. The mint tests
  (`tests/spaces_credential_mint.rs`) stop at mint and never present the credential back as a Bearer
  token, and `tests/spaces_records.rs` uses cookie auth. Would need to run the suite with a request
  carrying `Authorization: Bearer <minted credential>` against `/xrpc/com.atproto.space.getRecord`.
- Whether the per-space P-256 public key is published anywhere resolvable under the authority DID. I
  found only the instance-level `#atproto_space` method (`src/verification_methods.rs:206-215`,
  `src/service_identity.rs:384`). Would need to fetch a live space authority's DID document.
- Whether the Postgres migrations mirror the SQLite ones exactly. I read the SQLite set in full and
  only spot-checked `migrations/postgres/20260627000000_proposal_0016_alignment.sql` line ranges for
  the repo-state and oplog tables. Would need a full diff of the two directories.
- Whether any Lua binding or plugin writes to the oplog or repo-state tables outside the Rust paths I
  grepped. `src/lua/db_api.rs:30,47` lists both tables (one as raw-SQL-blocked), which suggests they
  are reachable from script code; I did not audit the Lua surface.
