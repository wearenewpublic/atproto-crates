# atproto-space

AT Protocol permissioned-data spaces — protocol primitives.

This crate implements the cryptographic and orchestration primitives from the
[Spaces Design Spec](https://github.com/bluesky-social/atproto/blob/main/docs/superpowers/specs/2026-04-22-permissioned-data-pds-design.md):
SetHash commitments, signed commits with HKDF-derived HMAC + ECDSA + per-commit
random IKM (for deniability), domain-separated record vs member commitments,
and the two-step `MemberGrant` → `SpaceCredential` JWT exchange.

> **Status: experimental**. The Spaces Design Spec is still settling; several
> primitives (notably `SetHash`) are explicitly placeholder until upstream
> picks ECMH or ltHash. The current default is `XorSha256SetHash`.

## Modules

- `set_hash` — `SetHash` trait + `XorSha256SetHash` placeholder.
- `set_hash_ecmh` *(feature `ecmh`)* — `EcmhSetHash` over secp256k1: scalar-mul
  multiset hash with property-tested homomorphic invariants. SEC1-compressed
  digest. Pulls in k256.
- `commit` — `SpaceContext`, `Commit`, `create_commit`, `verify_commit` with
  HKDF + HMAC + ECDSA construction. Domain-separated `Records` vs `Members`
  via `CommitScope`.
- `space_repo` — `SpaceRepo<S, H>` orchestrator over the storage trait surface
  for per-(user, space) record CRUD.
- `space_members` — `SpaceMembers<S, H>` orchestrator (owner-only).
- `credential` — `MemberGrant` and `SpaceCredential` JWT mint/verify.
- `recon` — `Reconciler` / `Sketch` traits + `oplog_catchup` baseline impl.
  RIBLT impl is deferred; the trait surface preserves the call sites for the
  eventual swap.
- `storage` — `SpaceRepoStorage`, `SpaceMembersStorage` traits.
- `types` — `SpaceUri`, `SpaceType`, `SpaceKey` newtypes.
- `errors` — `SpaceError` enum with `error-atproto-space-<domain>-<n>` IDs.

## Cargo features

| Feature | Default | Description |
|---|---|---|
| `ecmh` | | Build the `EcmhSetHash` impl over k256/secp256k1. |

## Benchmarks

Criterion-driven comparison of `XorSha256SetHash` vs `EcmhSetHash` is in
`benches/set_hash.rs`. Run with:

```bash
cargo bench -p atproto-space --features ecmh
```

Three groups: `add_throughput` (1 / 100 / 1000 elements), `add_remove_round_trip`
(single-element flush), and `digest_serialization` (digest + from_digest).

## Quick start

```rust,ignore
use atproto_space::{
    SpaceUri, SpaceType, SpaceKey, SpaceContext, CommitScope,
    XorSha256SetHash, SetHash, create_commit, verify_commit,
};
use atproto_identity::key::{KeyType, generate_key, identify_key};

let private_did = generate_key(KeyType::P256Private)?;
let private_key = identify_key(&private_did)?;

let space = SpaceUri::new(
    "did:plc:owner".to_string(),
    SpaceType::new("app.bsky.group")?,
    SpaceKey::new("default")?,
);

let mut hash = XorSha256SetHash::empty();
hash.add(b"app.bsky.feed.post/3jui:bafy123");

let context = SpaceContext {
    space_did: "did:plc:owner".to_string(),
    space_type: "app.bsky.group".to_string(),
    space_key: "default".to_string(),
    user_did: "did:plc:alice".to_string(),
    scope: CommitScope::Records,
    rev: "3jui7kd2z2y2e".to_string(),
};

let commit = create_commit(&hash, &context, &private_key)?;
// commit.set_hash, commit.rev, commit.ikm, commit.tag, commit.sig

# Ok::<(), anyhow::Error>(())
```

## License

MIT — see [LICENSE](../../LICENSE).
