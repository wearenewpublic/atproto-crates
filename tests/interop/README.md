# Vendored AT Protocol interop test vectors

Known-answer vectors used as an **external oracle** for the encoding layers of this workspace.

| | |
| --- | --- |
| Upstream | <https://github.com/bluesky-social/atproto-interop-tests> |
| Pinned revision | `056e5741bb330757205d6b16db5266fffcae937b` (2026-07-01) |
| License | Creative Commons Zero 1.0 Universal — see [`LICENSE-CC0`](./LICENSE-CC0) |

CC-0 permits direct copying into other projects without restriction or attribution. The vectors are
vendored rather than added as a submodule so that a plain `cargo test` works from a fresh clone with
no extra setup, and so the revision under test is visible in the diff when it is bumped.

`mst/gen_keys.py` is not vendored; it is a generator for `mst/example_keys.txt`, which is.

## Why these exist

Every encoding test in this workspace prior to these vectors was a **round trip** — encode, decode,
compare. A round trip passes against a wrong encoding, because it only proves the code agrees with
itself. These files are the only thing in the repository that proves the code agrees with the
*protocol*.

## Which harnesses consume which files

| Vectors | Harness |
| --- | --- |
| `mst/key_heights.json`, `mst/common_prefix.json`, `firehose/commit-proof-fixtures.json` | `crates/atproto-repo/tests/interop_mst.rs` |
| `data-model/data-model-fixtures.json`, `data-model/data-model-{valid,invalid}.json` | `crates/atproto-dasl/tests/interop_data_model.rs` |
| `syntax/` (all 24 files) | `crates/atproto-lexicon/tests/interop_syntax.rs` |

The remaining files (`crypto/`, `lexicon/`, `mst/example_keys.txt`)
are vendored for future harnesses and are not yet consumed.

What each of those would take:

- **`lexicon/`** — 68 cases across 9 files, against `crates/atproto-lexicon`'s record validation.
- **`crypto/`** — signature and `did:key` encoding vectors.
- **`mst/example_keys.txt`** — 156 keys. Unlike the rest of the corpus this file carries no expected
  answers: it is tree-building *input*, so consuming it means asserting a resulting tree shape
  against another implementation rather than checking an oracle.

Both lists above are checked by an external conformance harness, which is how the three claims this
section previously got wrong were found: `data-model-{valid,invalid}.json` were described as
unconsumed after the harness that reads them landed, and `mst/example_keys.txt` appeared in neither
list at all. Keep them accurate in the same change as the harness — a map that is right about most
of the corpus is worse than no map, because a reader cannot tell which parts were maintained.

## Known failures

Both harnesses carry a `KNOWN_FAILURES` table naming each vector this workspace does not yet satisfy,
together with the gap-analysis finding that explains why. A listed vector is **required to fail**: if
it starts passing, the harness fails and instructs you to delete the entry. That way the tables
cannot silently rot, and the moment an encoding fix lands the gate tells you which finding it closed.

Do not add an entry to relax a genuine regression. An entry is a statement that a *known, filed*
defect is still open.

## Bumping the pin

```
git clone --depth 1 https://github.com/bluesky-social/atproto-interop-tests /tmp/interop
rsync -a --delete --exclude .git --exclude .gitignore --exclude mst/gen_keys.py \
      /tmp/interop/ tests/interop/
```

Then restore this README, update the pinned revision above, and re-run
`cargo test --workspace`. New vectors that fail are new findings, not licence to extend
`KNOWN_FAILURES`.
