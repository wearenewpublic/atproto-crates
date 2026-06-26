# atproto-space

AT Protocol permissioned-data spaces — protocol primitives.

This crate implements the cryptographic and orchestration primitives from the
[0016 Permissioned Data draft](https://github.com/bluesky-social/proposals/tree/main/0016-permissioned-data),
which is the authoritative alignment target for this crate: SetHash
commitments, signed commits with HKDF-derived HMAC + ECDSA + per-commit random
IKM (for deniability), and the two-step delegation-token → space-credential JWT
exchange.

> **Status: experimental**. The 0016 Permissioned Data draft is still settling.
> The production `SetHash` is `LtHash`, the lattice hash the spec selects (spec
> § "Commit digest").

## Modules

- `set_hash` — `SetHash` trait + `LtHash` production primitive.
- `commit` — `SpaceContext`, `Commit`, `create_commit`, `verify_commit`. A
  commit signs only the per-commit context (`ctx`) and binds the set-hash
  digest with an HKDF-keyed HMAC, so a leaked commit is deniable (spec
  § "Commit signature", lines 285-316).
- `space_repo` — `SpaceRepo<S, H>` orchestrator over the storage trait surface
  for per-(user, space) record CRUD.
- `space_members` — `SpaceMembers<S, H>` member-list orchestrator backing the
  `simplespace` `member-list` mint policy (the spec carries no member commits).
- `credential` — `DelegationToken` and `SpaceCredential` JWT mint/verify (spec
  § "Access control", lines 136-251).
- `storage` — `SpaceRepoStorage`, `SpaceMembersStorage` traits.
- `types` — `SpaceUri`, `RecordUri`, `SpaceType`, `SpaceKey` newtypes.
- `errors` — `SpaceError` enum with `error-atproto-space-<domain>-<n>` IDs.

## Quick start

```rust,ignore
use atproto_space::{
    SpaceUri, SpaceType, SpaceKey, SpaceContext,
    LtHash, SetHash, create_commit, verify_commit,
};
use atproto_identity::key::{KeyType, generate_key, identify_key};

let private_did = generate_key(KeyType::P256Private)?;
let private_key = identify_key(&private_did)?;

let space = SpaceUri::new(
    "did:plc:owner".to_string(),
    SpaceType::new("app.bsky.group")?,
    SpaceKey::new("default")?,
);

let mut hash = LtHash::empty();
// Each record element is `{collection}/{rkey}/{record_cid}` (spec line 270).
hash.add(b"app.bsky.feed.post/3jui/bafy123");

// The signed context is the space URI + revision (spec lines 292-297); the
// set-hash digest is bound by the commit's MAC, not signed directly.
let context = SpaceContext {
    space: space.to_string(),
    rev: "3jui7kd2z2y2e".to_string(),
};

let commit = create_commit(&hash, &context, &private_key)?;
// commit.hash, commit.ikm, commit.sig, commit.mac, commit.rev

# Ok::<(), anyhow::Error>(())
```

## License

MIT — see [LICENSE](../../LICENSE).
