# fix(atproto-pds): emit subscribeRepos bodies in the lexicon's shape

Closes **F-FIRE-01** (envelope-shaped bodies) and **F-FIRE-04** (JSON-encoded payloads). Milestone M1.13.

## Why these two together

`com.atproto.sync.subscribeRepos` publishes a **closed union**: a subscriber decodes each frame against `#commit`, `#sync`, `#identity` or `#account` and rejects anything matching none of them. Every frame this server emitted matched none, so no relay could consume the firehose.

Fixing either defect alone leaves the union undecodable — the shape fix produces a body whose links are still text, and the encoding fix produces correctly-typed fields still buried under `payload`.

## What was wrong

**The body was an envelope, not the event.** Frames carried:

```json
{"seq": 42, "repo": "did:plc:…", "time": "…", "payload": {"rev": "…", "data": "…"}}
```

`payload` is not a field the lexicon declares, and none of the eight required `#commit` fields — `rebase`, `tooBig`, `commit`, `rev`, `since`, `blocks`, `ops`, `blobs` — appeared at the level a decoder reads them. A relay parsed the frame header successfully and then could not map the body to any union member.

**Bodies round-tripped through JSON.** The AT Protocol data model has one shape and two encodings; JSON has no link type and no byte-string type, so the two types this union depends on could not survive storage:

- `commit` and each `ops[].cid` arrived as **text** where a decoder expects a CBOR tag-42 link.
- `blocks` is typed `bytes` and could not be represented at all — it was absent from the body entirely.

## What changed

New `crates/atproto-pds/src/sequencer/payload.rs` holds the four body types in the shapes the lexicon declares, stored as DAG-CBOR. `splice_envelope` adds `seq` and `time` — which belong to the delivery rather than the event, and `seq` is not known until the row exists — by decoding to `Ipld`, inserting, and re-encoding. That stays inside the data model, so a link stays a link and `blocks` stays bytes; the frame encoder does no re-encoding beyond the splice.

The JSON encoder is retained for browser-dev subscribers and now renders through `atproto_dasl::atproto_json`, so links and bytes are spelled `{"$link": …}` / `{"$bytes": …}` rather than silently degrading. CBOR remains the default and the wire format.

Corrected along the way, all in the same union:

| Event | Was | Now |
|---|---|---|
| `#commit` | emitted `data` (not a lexicon field) | dropped |
| `#commit` | omitted `since` | required-and-nullable, emitted (`null` on a first commit) |
| `#sync` | emitted `head` (not a lexicon field) and a block *count* | `did` / `blocks` (CARv1) / `rev` only |
| `#account` | always emitted `status`, including `"active"` | optional field, omitted when active |

Note the asymmetry, which is the specification's and not a slip here: `#commit` names the repository `repo`, while `#sync`, `#identity` and `#account` name it `did`.

## Known remaining gap

`blocks` is present, well-typed and **empty** — building the CARv1 slice is F-FIRE-02/F-FIRE-03 (M1.14). Rather than let that read as complete, `blocks_is_present_but_empty_pending_car_slices` pins `blocks == Ipld::Bytes(vec![])` and says in its message that it should be replaced when the slice lands. `blobs` is likewise empty pending F-BLOB-02.

## Tests

Both conformance checks are removed from `KNOWN_FAILURES` in `crates/atproto-pds/tests/interop_firehose.rs`, and the guard actively demanded their removal once the fix landed:

```
check "commit body is flat" now PASSES — F-FIRE-01 appears to be fixed.
  Remove it from KNOWN_FAILURES in this file.
check "commit blocks is a CBOR byte string" now PASSES — F-FIRE-04 appears to be fixed.
  Remove it from KNOWN_FAILURES in this file.
```

Verified red against the unfixed encoder (stash the two source files, keep the tests):

```
REGRESSION: check "commit body is flat" fails and is not in KNOWN_FAILURES:
  missing required lexicon fields ["blobs", "blocks", "commit", "ops", "rebase",
  "rev", "since", "tooBig"]; body carries ["payload", "repo", "seq", "time"]

REGRESSION: check "commit blocks is a CBOR byte string" fails and is not in
  KNOWN_FAILURES: blocks absent from the body entirely
```

Seven new unit tests in `payload.rs` cover required-field presence, links surviving as links, `blocks` as a byte string, `since` present-and-null, the `did`/`repo` asymmetry, and `status` omitted-vs-present.

**The existing unit tests passed throughout** because they asserted the envelope they were handed — `body["payload"]["rev"]`, `payload["head"]`, `payload["blocks"] == 42` — rather than the lexicon. This is the third finding in this series where a test concealed the defect by asserting the implementation instead of the specification. Those four tests now assert the published schema.

## Verification

- `cargo fmt --all -- --check` — clean
- `cargo clippy --workspace --all-targets -- -D warnings` — clean
- `cargo test --workspace` — **2096 passed, 0 failed, 63 ignored**

## Blast radius

`atproto-pds` only. The wire format changes for every firehose subscriber — which is the point, since the previous format was not decodable by any conformant one. Stored outbox rows written before this change are DAG-CBOR-undecodable JSON and will be dropped by `encode_event` with a warn-log rather than crashing the broadcast loop; this is pre-release, so no deployed subscriber is affected.

`SyncEvent`'s `head` and `blocks` fields are retained as caller context and documented as diagnostic only — they are not fields of `#sync`.

## Not fixed here

- **F-FIRE-02 / F-FIRE-03** — real CARv1 slices in `blocks`. Next up (M1.14).
- **F-FIRE-05** — the global stream sequence. `seq` is still per-actor, so it is not globally monotonic across repositories. Separate branch.
- **F-BLOB-02** — walking records for blob refs to populate `blobs`.
