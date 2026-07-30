# fix(repo): read AT Protocol JSON into the data model before encoding records

## What and why

`repo/writer.rs:223,545` handed a `serde_json::Value` straight to the DAG-CBOR encoder. The AT
Protocol data model has one shape and two encodings: DAG-CBOR expresses links and byte strings
directly, while JSON, which has neither, spells them with reserved single-key objects.

| Data model | DAG-CBOR | JSON |
| --- | --- | --- |
| link | tag 42 | `{"$link": "bafy…"}` |
| bytes | byte string | `{"$bytes": "<base64>"}` |

Encoding the JSON verbatim did not store the record it described. It stored a map with a literal
`$link` text key where a link belonged — a CID no other implementation computes, and a body that
fails `blob`-typed validation downstream. Floats passed through too, though the data model has no
floating-point type.

## The fix

New `atproto_dasl::atproto_json` reads the JSON representation into the data model and renders it
back. `Ipld` already serialized a link as tag 42, so the missing piece was the translation, not the
encoding.

## Numbers: the fixtures settled this, not my judgement

`data-model-valid.json` carries a case noted **"float, but integer-like"** whose value is `123.0` —
which must be **accepted** as an integer. `data-model-invalid.json` has `123.456`, which must be
**refused**.

"Reject non-integer numbers" in the finding is exact. Implementing "reject floats", which is what I
would have reached for, fails a valid record. Worth recording as a case where the vendored fixtures
earned their place beyond the headline CIDs.

Malformed sentinels are refused rather than guessed at — a non-string value, a CID that does not
parse, or any extra key alongside the reserved one, all drawn from the invalid fixtures.

## The read path had to change too — not mentioned in the finding

Once writes are correct, records hold tag 42, and `serde_json::Value` cannot represent that.
`getRecord` and `listRecords` failed outright:

```
Deserialization("invalid type: byte array, expected any valid JSON value")
```

They now render through the inverse conversion, so a record reads back in the shape it was written
in. Found by probing the round trip before wiring anything, not by a failing test after the fact.

## A design change to my own earlier work

The M1.1 harness asserted `atproto_dasl::to_vec(&vector.json)` — it assumed the translation would
live inside the generic `to_vec`. I now think that was wrong: `to_vec` is generic over
`T: Serialize`, so making it honour these sentinels means the *serializer* sniffs map keys, silently
changing encoding for any type that happens to have a `$link` field.

The harness now calls `atproto_json::to_vec`. **The expected bytes and CIDs are untouched** — only
which function is asked to produce them. Flagging it because "changed the test to match the code" is
exactly the failure mode to be suspicious of, and this is a design revision rather than a
convenience.

## Testing

| Harness | Before | After |
| --- | --- | --- |
| `data-model-fixtures.json` (bytes + CID) | 1/3 | **3/3**, `KNOWN_FAILURES` empty |
| `data-model-valid.json` | not wired | 5/5 encode |
| `data-model-invalid.json` | not wired | 6/6 encoding cases refused |

The two valid/invalid files were vendored with M1.1 and never consumed; they are harnesses now.

Six invalid cases concern record *structure* rather than encoding — a missing `$type`, a blob with a
string `size` — and are listed by name as excluded, so the gap is visible rather than implied by a
passing test. Those belong to F-REC-05 (M2.23).

Eight unit tests on the conversion, plus an end-to-end test that writes a record with a blob ref
through `createRecord` and reads it back through `getRecord`. That test **pins** the CID rather than
recomputing it, so it cannot pass by agreeing with whatever the writer does. Against the previous
code:

```
left:  bafyreia5fgoyqphlaa5h3wtx7s5kmpds5fmgbmfrsi4inbu77o64fpu3ni
right: bafyreidbmrjqco5tedmdigvwvdaonch4o4esflpgztmz7dqhl36z26hshq
```

Green under the pinned 1.90 toolchain: `cargo fmt --all -- --check`,
`cargo clippy --workspace --all-targets -- -D warnings`, `cargo test --workspace` —
**2077 passed, 0 failed, 63 ignored.**

## Risk and blast radius

**Record CIDs change for any record containing a blob ref or bytes.** Correct, and consistent with
the root CIDs that already moved under the MST work. Records of plain JSON are unaffected — fixture
#0 passed before this change and still does.

`to_vec`'s generic behaviour is unchanged, so nothing else in the workspace shifts.

`serde_json` and `base64` become ordinary dependencies of `atproto-dasl` rather than optional ones.
Both were already dev-dependencies, so no new code enters the tree; the crate's default feature set
grows by two widely-used crates.

A record written before this change decodes fine — it is a valid map, just not the map that was
meant — and will be re-encoded correctly on its next write.

## An adjacent defect, deliberately not fixed here

`crates/atproto-pds/src/space/writer.rs:285` has the **identical** call:
`atproto_dasl::to_vec(&value)` on a record body from the spaces write path. Spaces records
containing blob refs have the same non-interoperable CIDs.

It is a one-line change now that the helper exists, but it is on the permissioned-data track (M3)
and outside this finding's scope, so it is recorded in the progress ledger as a finding candidate
rather than swept in.

## Resolves

`F-REPO-05` (roadmap M1.11).
