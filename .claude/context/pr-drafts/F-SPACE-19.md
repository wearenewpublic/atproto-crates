# fix(atproto-space): conform the commit format to the 0016 draft

Closes **F-SPACE-19**, **F-SPACE-04**, **F-SPACE-18**. Milestone M3.1 — first item on the spaces track, and the coupled group the report says *"must land as one change."*

## Three divergences, one change

Nothing this server has ever emitted for spaces interoperates with a conformant peer. Three reasons, and they cannot be split.

### F-SPACE-19 — the `ctx` omitted the author DID

The draft (`0016-README.md:306-310`) builds it as:

```
"atproto-space-v1" || uint16be(len(space))  || space
                  || uint16be(len(author)) || author
                  || uint16be(len(rev))    || rev
                  || uint16be(len(ikm))    || ikm
```

`commit.rs:71-81` emitted `[space, rev, ikm]`. So `sig` and `mac` were computed over different bytes than any peer, in both directions.

The security half matters as much as the interop half: **without the author DID the signature does not bind the author**, so a signature over one author's commit is a signature over any author's commit at the same rev. The draft's domain separation *within* a space was gone.

`lex-0016/space/defs.json` corroborates — `sig` is described as *"Signature over ctx (space, author DID, rev, ikm)"*. HappyView's `build_context` (`spaces/commit.rs:18-44`) does the same four fields.

### F-SPACE-04 — no `ver` on the signed commit

`ver` is **first** in the lexicon's `required` set (`["ver","hash","mac","ikm","sig","rev"]`) and is currently `1`. `Commit` had `{hash, mac, ikm, sig, rev}`. Every emitted commit failed schema validation on a required field before any crypto ran, and there was no version discriminator with which to negotiate a future `ctx` construction.

An unknown `ver` is now refused **before** the MAC is checked. Reporting a version mismatch as a MAC failure sends an implementor looking for a crypto bug that is not there.

### F-SPACE-18 — the URI scheme

`ATS_SCHEME = "ats://"` (`types.rs:13`), hard-required by `SpaceUri::parse`. Every draft lexicon types the space parameter as `at-uri`, and `packages/syntax/src/space-uri.ts:8` gives the canonical form:

```
at://{authorityDid}/space/{spaceType}/{skey}[/{authorDid}/{collection}/{rkey}]
```

A fixed `space` marker sits where a public URI carries a collection NSID. The reference explains why that is unambiguous: a collection always has dots, the marker never does. Space URIs go 3 → 4 segments, record URIs 6 → 7.

**This is why the other two could not ship alone.** `space` is length-prefixed into the `ctx`, so changing the string changes the signed bytes regardless of the other fixes.

`ats://` is still **accepted on input** and normalized — HappyView's `spaces/mod.rs:38-71` is the portable pattern and I followed it. Nothing emits it.

## No migration, and one would not help

The space URI is the **primary key of the `space` table**, with `ON DELETE CASCADE` foreign keys from nine tables and a key prefix in the fjall keyspace. So the strings *could* be rewritten in SQL.

It would not help, and would mislead. `sig` and `mac` on every stored commit were computed over the old `ctx` — old space string, no author. Rewriting the URI produces rows that **look conformant and fail verification**. Commits can only be re-signed, which needs each author's signing key.

Since none of this data was ever interoperable, recreating spaces is the honest path. Recorded in the CHANGELOG in those terms.

## Two hand-rolled copies

`space/writer.rs:226` and `:276` built record URIs with `format!("ats://{}/{}/{}/{}/{}/{}", …)` rather than going through `RecordUri`. So the scheme lived in three places and the change had to be found by grep — and the writer's own test asserted the old prefix, so nothing would have caught it. Both now build through the type, and the module doc says why.

## Tests

12 new or rewritten, **8 verified red** by reverting each of the three halves in turn:

```
commit_ctx_layout_is_a_known_answer ................... FAILED
domain_separation_by_author .......................... FAILED
an_unknown_version_is_refused_before_the_mac_is_checked  FAILED
space_uri_roundtrip .................................. FAILED
space_uri_serde_round_trip ........................... FAILED
record_uri_round_trip ................................ FAILED
a_legacy_space_uri_parses_and_normalizes ............. FAILED
a_legacy_record_uri_parses_and_normalizes ............ FAILED
```

**`commit_ctx_layout_is_a_known_answer` is written as literal bytes**, not by re-running the encoder:

```rust
b"atproto-space-v1", &[0x00,0x02], b"sp", &[0x00,0x02], b"au", …
```

A test that rebuilds the value the way the encoder does agrees with whatever field order the implementation happens to use. That is precisely how the author DID went missing — the old test did exactly that and passed.

`the_space_marker_is_required_on_the_canonical_form` pins the ambiguity the marker exists to prevent: without the check, `at://did/app.bsky.group/default` would parse as a space URI whose "type" is a collection.

## A correction to the `Commit` doc, and to the finding's framing

The doc comment claimed *"wire field order matches the lexicon required set"*. **Field order is not a wire requirement** — JSON objects are unordered and canonical DAG-CBOR sorts keys by length then bytes. My first test asserted the order and failed against `serde_json`'s own sorted map, which is what surfaced it. The test now asserts the field *set* and that there are no extras; the doc says why order is not the property that matters.

## Verification

- `cargo fmt --all -- --check` — clean
- `cargo clippy --workspace --all-targets -- -D warnings` — clean
- `cargo test --workspace` — **2277 passed, 0 failed, 63 ignored** (exit 0)
- `cargo test -p atproto-pds --features fjall` — **745 passed, 0 failed** (exit 0)
- `cargo check --release --bins -F clap,hickory-dns,zeroize,tokio,smtp` — 0 errors

## Blast radius

**Every space created before this release must be recreated.** Its commits carry signatures over the old `ctx` and will never verify.

Every space URI on the wire changes shape. `getRepoState`, `listRepoOps`, `notifyWrite`, the credential `sub`, the admin takedown input and every space read take the new form; the old one is accepted and normalized on the way in.

`SignedCommitDto` gains `ver`, which is additive for readers and required for writers.

## Not fixed here

The other nine M3 items, of which these are the prerequisite. Nearest:

- **F-SPACE-30** (M3.2) — `Box::leak` on `space_handlers.rs:1113`, one line, an availability defect on the hottest authenticated space path.
- **F-SPACE-07** (M3.3) — no read-time membership enforcement, so any authenticated local account reads any other's permissioned records. Inherited from the reference draft; the report says to raise it upstream as well as fix it here.
- **F-SPACE-05** (M3.8) — `hash` is still absent from `notifyWrite` and `listRepos#repo`.

Conformance is claimed against the draft lexicons at **`3f6c96d` (2026-07-02)**, and that date will expire — 0016 is an open WIP.
