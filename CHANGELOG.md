# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]
### Removed
- `atproto-oauth-aip` — the AIP (Identity Provider) OAuth implementation. No crate in the workspace
  depended on it and nothing in the repository used it.
- `atproto-xrpcs-helloworld` — the example XRPC service, and the `atproto-xrpcs-helloworld` binary
  from the container image. `atproto-xrpcs` remains; its documentation no longer points at an example
  that is not there.
- `walking-club-appview`, `walking-club-cluster-plan.md` and `walking-club-cluster-plan-review.md` —
  an application built on these crates rather than part of them.
- `deploy/` — the Walking Club cluster compose stack, named as such in its own `Makefile` and added
  in the same commit as the AppView it exists to run. Four of its five services were `atproto-pds`,
  so this does cost the repository its only containerized multi-PDS deployment; keeping it would have
  meant maintaining a cluster definition for an application no longer in the tree.

  None of this is reachable from any remaining crate: the workspace builds, clippy is clean, and all
  2637 tests pass with the four directories gone.

### Fixed
- `atproto-oauth`: `repo` scopes written in the query form granted nothing. `collection` is the
  positional parameter — `repo:foo` is shorthand for `repo?collection=foo` — and it is multi-valued,
  so `repo?collection=a&collection=b` names two collections in one scope. The parser read only the
  positional form: the empty string before the `?` became a collection NSID of `""`, and the
  `collection=` parameters were never looked at. A client granted
  `repo?collection=app.example.one&collection=app.example.two` was then refused on every write with
  `InsufficientScope`, naming a collection its token appeared to carry.

  `RepoScope::collection` becomes `RepoScope::collections`, a set — a single field could only ever
  hold the shorthand. Matching, rendering and scope-coverage all read the set; a scope with more than
  one collection renders in the query form, since the shorthand cannot express it, and round-trips
  through that form. Nothing outside `scopes.rs` constructed or read the old field.


### Added
- `atproto-pds`: `PDS_LEXICON_DIR` — resolve lexicon documents from a directory on disk, searched
  after the bundled corpus and before the network.

  For schemas that are real but not reachable from where the server is standing. A PDS writing genesis
  operations to a *local* PLC directory cannot resolve any DID registered in the production one —
  including the DID that publishes an application's own lexicons. The symptom is remote from the
  cause: an `include:` scope silently expands to nothing and every write is refused with
  `InsufficientScope`, long after the resolution that actually failed.

  Each document is keyed by its own `id`, falling back to its path. The bundled corpus derives NSIDs
  from paths because it is generated from a vendored tree whose layout is known; an operator's
  directory is not the server's to arrange, and a document that says what it is should be believed
  over its location. A file naming an NSID the bundle already answers for is reported as shadowed
  rather than silently ignored.

  Read once at startup, like the bundled corpus — editing a file needs a restart, because re-reading
  per request would let two consecutive writes validate against different schemas with nothing in the
  logs to say so. A directory that cannot be read is fatal: a mistyped path would otherwise load
  nothing and leave a server that looks configured and resolves exactly as it did before. A single
  malformed document is warned about and skipped, since one bad comma should not keep the server down.

- `atproto-pds`: the OAuth consent screen prefills its sign-in field from the client's `login_hint`
  when the hint is a valid handle or DID.

  The hint was already captured at PAR and persisted on the authorization request; nothing read it
  back. A client that already knows who is signing in says so, and the holder should not have to
  retype it — they arrived from an application that just asked them for exactly this. Handles are
  normalized (lowercased, `at://` and `@` stripped); DIDs are prefilled as given, across `plc`, `web`
  and `webvh`. Focus moves to the password field when the identifier is filled.

  **The hint is validated, not merely escaped.** It is chosen by the client and lands in an HTML
  attribute on the one page whose job is collecting a password. Escaping stops it being markup;
  validating stops it being *text* — an unvalidated hint renders attacker-chosen prose inside the
  sign-in box, on a page carrying this server's name and styling, and "type your password here to
  continue" is a legal string. A handle or a DID cannot say anything.

  An email is deliberately not prefilled even though the field accepts one: `login_hint` is a handle
  or DID per the AT Protocol OAuth spec, and filling in an address a third-party client supplied puts
  an email this server never disclosed on the screen — a claim about the account rather than a
  convenience.

### Fixed
- `atproto-pds`: space-type declarations now resolve through the shared lexicon resolver chain
  instead of a second, network-only implementation of the same lookup.

  A declaration *is* a lexicon document — `defs.main` with `type: "space"` — but
  `NetworkSpaceDeclarationResolver` walked DNS, PLC and `getRecord` itself. So a space type the
  binary bundles, or one an operator supplies, was invisible to it while resolving fine for every
  other lookup, and on a server whose PLC directory does not hold the authority DID it did not
  resolve at all.

  That had teeth, because `declared_collections` is fail-closed: a bare `space:` grant (one omitting
  `collection`, which defaults to the type's declared collections per spec line 413) expanded to *no*
  write collections, and creating the first record in a new space was refused with
  `InsufficientScope` — several log lines away from the resolution that failed.

  `NetworkSpaceDeclarationResolver` is kept; it is still what the chain's network tier does. What
  changes is that declarations and lexicons now resolve through one chain, in one order, behind one
  cache.

## [0.15.0-rc.2] - 2026-08-07
### Changed
- `atproto-pds`: the account portal is four navigated sections rather than one page —
  **Settings** (`/account`: handle, email, password), **Access** (`/account/sessions`: app passwords,
  OAuth sessions, sign out everywhere), **Repository** (`/account/repository`: the record browser)
  and **Delegation** (`/account/delegation`). Every page carries the same nav, so no section is
  reachable only by knowing its URL, and `Section::ALL` is the single place the four paths and labels
  are written.

  **`/browse/*` is removed, not redirected.** The repository browser moves wholesale under
  `/account/repository`; the old URLs were not load-bearing and a redirect would be a second name for
  every page. Every URL the browser generates now hangs off one `ROOT` constant — it was spelled out
  in a dozen `format!` strings and three breadcrumb trails, and the link-crawl test is what caught the
  ones a move missed. That test now follows every `/account` link on every section, so a section named
  in the nav but mounted at a path nobody routed fails there rather than in a browser.

  **Access lists live credentials only.** Both credential kinds are stateless JWTs, so a session has
  no row to list and nothing needs recording after one ends; an app password's row *is* the standing
  grant and its last-used stamp is the only trace a session leaves. `delete_sessions_for` is unchanged.

  **Delegation is a placeholder that says so.** It states in as many words that nothing is switched on
  and no identity can act as the account. A section about letting other identities act as you is the
  last place to leave a reader unsure — an empty table under a plausible heading reads as a feature
  with no entries.

  The Repository index now lists the account's blobs. The two-backend enumeration that was inline in
  `blob_handlers::list_blobs` — SQLite joins the public-reference check in SQL, fjall filters the page
  after the fact — is extracted to `blob::list_public`, so the portal shows exactly what
  `com.atproto.sync.listBlobs` serves and a permissioned CID has one place to leak from rather than
  two. The returned page carries `scanned` alongside `cids`, which is the only honest way to tell a
  short page that ended the list from a short page whose blobs were permissioned.

### Added
- `atproto-pds`: `com.atproto.space.notifyWrite` carries the repo's commit `hash`, and
  `listRepos#repo` reports it. The lexicon marks `hash` required on `notifyWrite` and says why —
  *"Lets the space host maintain each repo's hash for listRepos"* — and without it a syncer could not
  tell which repos had actually changed without fetching every one. The hash-propagation loop from
  repo host to space host now closes.

  Everything needed was already present and unused: `space_received_op` has always had a `set_hash`
  column that the inbound handler filled with an empty blob, and the writer built the signed commit
  and discarded it.

  `listRepos` reports the hash belonging to the **latest** rev, via a correlated subquery rather than
  a bare column beside `MAX(rev)` — SQLite would give the right row there, but nothing else would, and
  a hash paired with the wrong rev is a wrong answer rather than a missing one.

  **Sent always, optional on receipt.** `notifyWrite` is declared best-effort and this is the only
  implementation that emits a hash at all, so a payload without one is accepted and logged rather than
  rejected — refusing would drop write notifications from every peer running older code. A repo whose
  host reported no hash is listed without one, never with an empty one.

- `atproto-pds`: `com.atproto.space.getRepo` — the whole permissioned repo as a CAR, for full-state
  recovery. This was the only missing recovery path: `listRepoOps` replays *changes* and cannot rebuild
  a repo whose earliest ops have been pruned, and `listRecords` carries no commit and no CID-addressed
  blocks. A syncer past its oplog retention had nowhere to go.

  Layout follows the draft lexicon exactly: two roots (the signed commit, then a DRISL index mapping
  `{collection}/{rkey}` to record CID), the commit block, the index block, then record blocks in
  lexicographic key order. Blobs are excluded and fetched through `space.getBlob`.

  Record blocks are copied verbatim with their stored CIDs rather than re-encoded, so every block
  hashes to the CID the CAR claims and the index, `getRecord` and the commit all agree. The export
  pages through `listRecords` at the lexicon's 100 per page rather than issuing one unbounded query.

- `atproto-pds`: `com.atproto.space.getLatestCommit` — the canonical name for the endpoint this server
  shipped as `getRepoState`. Both now route to the same handler; a conformant client was 404ing on the
  only name it knows. `getRepoState` is kept as an alias rather than removed.

### Security
- `atproto-identity`: `DidBuilder::build` published rotation keys in **private** form. Verification
  methods were converted with `key::to_public` before serialization; rotation keys were formatted
  straight from the `KeyData`, which emits the private multicodec (`P256Private` → `0x1306`) followed
  by the raw 32-byte scalar. Every genesis operation therefore carried the account's PLC rotation
  private key to the directory, and a PLC directory is a public, permanent, append-only log: anyone
  reading the audit log could rotate the DID away from its owner, irreversibly.

  `add_rotation_key` takes the private key deliberately — `build` signs the genesis operation with
  `rotation_keys[0]` — so the public conversion has to happen on the way out, and now does. A key
  whose public form cannot be derived is a hard error rather than a fallback to the value as given,
  because that fallback is exactly how the private key reached the wire.

  **Exposure.** The reference directory rejects these operations: `did:key` parsing there accepts
  only the public multicodecs, so a submission carrying `0x1306` fails validation and is never
  recorded. Any DID created against a directory that validated `did:key` less strictly should be
  treated as compromised and rotated using a key generated after this change.

### Added
- `atproto-lexicon`: `tests/interop_syntax.rs` runs the vendored syntax corpus — **536 cases across 24
  files**, the largest suite in the corpus and the one both reference implementations run — against
  this crate's grammar validators. Every test for those parsers had been written alongside the parser
  it tests, so each encoded the same reading of the grammar the parser did; these vectors are the
  first external oracle they have been held to.

  **505 pass. 31 do not**, and are pinned in `KNOWN_FAILURES` so the disagreement cannot widen and
  cannot be silently closed. They are real disagreements with the network, not corpus quirks:

  | grammar | cases | disagreement |
  |---|---|---|
  | NSID | 6 | domain segments may begin with a digit — `org.4chan.lex.getThing` is refused |
  | CID | 6 | only base32 multibase accepted; base58btc, base64, base16 and base10 are refused |
  | AT-URI | 5 | a trailing slash and an empty path segment are accepted |
  | language | 4 | grandfathered tags (`i-default`) and uppercase private-use (`X-fr-CH`) refused |
  | TID | 2 | first character is not range-checked, so `zzzzzzzzzzzzz` is accepted |
  | URI | 2 | raw and trailing spaces accepted |
  | DID | 2 | an incomplete percent-escape (`did:method:val%`) is accepted |
  | datetime | 2 | `-00:00` accepted, which RFC 3339 reserves for "offset unknown" |

  The AT-URI and NSID entries are the ones with teeth: accepting a trailing slash means two strings
  denote the same record, which breaks equality comparison anywhere it is done; refusing digit-leading
  domain segments refuses names that exist.

### Added
- `atproto-identity`: `tests/interop_crypto.rs` runs the vendored crypto corpus — 12 cases across 3
  files — against this crate's signature verification and `did:key` derivation. **All 12 pass**; no
  defect was found, which is the result rather than an absence of one.

  The negative fixtures are why the file is worth having. `signature-fixtures.json` carries high-S
  and DER-encoded signatures a conforming verifier must *refuse*, and neither is reachable from a
  sign-then-verify test: `sign` normalises, so this crate cannot produce a high-S signature to check
  itself against. Those two classes had no coverage at all.

  Confirmed load-bearing by mutation: switching `validate` to `SignaturePolicy::AnyS` — the policy
  split added in `F-OAUTH-13` — makes the **P-256** high-S vector pass when it must fail. The K-256
  high-S vector stays refused under either policy, because the underlying k256 verifier rejects
  high-S on its own, so the low-S guard is only load-bearing for P-256.

  The `did:key` vectors derive a public `did:key` from private key material, which the crate's own
  tests do not do: they pin `did:key` literals for keys they generate, fixing the string format but
  not the derivation. A wrong multicodec prefix would round-trip cleanly here and be unreadable
  everywhere else.

  One check is implemented rather than ported. The reference cross-checks `publicKeyMultibase`
  against `publicKeyDid` with `expect(uint8arrays.equals(a, b))` and no matcher attached, so it
  passes whatever the comparison returns. It is a real assertion here.

### Added
- `atproto-lexicon`: `tests/interop_lexicon.rs` runs the vendored lexicon corpus — 68 cases across 9
  files — against record validation and schema parsing. **63 pass; 5 are pinned in
  `KNOWN_FAILURES`**, each a real disagreement rather than a corpus quirk.

  | case | disagreement |
  |---|---|
  | `record-data-valid: full` | `$bytes` is base64 **without** padding; decoded with the padded `STANDARD` engine |
  | `record-data-invalid: open union missing $type` | an open-union member with no `$type` is accepted |
  | `lexicon-invalid: defined unknown` | a top-level def of type `unknown` is accepted |
  | `lexicon-invalid: defined ref` | a top-level def of type `ref` is accepted |
  | `lexicon-valid: basic permission-set` | namespace authority enforced at schema-parse time |

  The `$bytes` one has an edge inside the workspace. `atproto-dasl` — which passes the data-model
  corpus — **encodes** `$bytes` with `STANDARD_NO_PAD` and decodes either form. So this crate refuses
  exactly what that one emits, and a record that round-trips through the data model fails lexicon
  validation. Two crates spelling one rule differently, the same shape as the TID first-character
  bug.

  The permission-set case is a design question rather than a defect, and is written up in the test
  that pins it. The Namespace Authority rule is real, but the reference checks nothing of the kind
  when parsing a lexicon document — its `lexPermissionSet` has no namespace logic at all — and the
  document in question is in the corpus's own catalog. Authority is a question about whether a grant
  may be *made*, not about whether a document is well-formed. It is left enforced because nothing
  else in this workspace enforces it: `include:` scopes parse but are never resolved into concrete
  permissions.

### Added
- `atproto-repo`: `mst/example_keys.txt` is now asserted — 156 keys, the last unconsumed file in the
  vendored corpus. **Every vendored vector file now reaches a harness.**

  The file had been described, here and in the corpus README, as carrying no expected answers and
  being tree-building input only. That was wrong: the **second character of each key is its expected
  MST height** — `R2/359107` is height 2 — which is how indigo reads it (`TestExampleKeyHeights`),
  with `HeightForKey("R2/359107") == 2` also asserted literally as a cross-check. The oracle is
  inside the data rather than beside it, which is easy to miss, and was missed.

  It is an order of magnitude more coverage than `key_heights.json`, and drawn across the whole
  height range rather than chosen to illustrate it. Confirmed load-bearing: stubbing `key_height` to
  return 0 fails 130 of the 156.

  `interop_crypto.rs` gains an empty `KNOWN_FAILURES` table. Nothing in Rust reads it — the
  conformance harness parses it out of every `interop_*.rs`, and a harness with no table cannot be
  told apart from one whose table the parser failed on.

### Fixed
- `atproto-lexicon`: a permission set that granted outside its own namespace authority made the
  whole lexicon document unreadable. The rule was right and the layer was wrong.

  An `include:` scope names a permission set rather than listing permissions, so the user consents to
  a name; the Namespace Authority rule is what stops `app.evil.authFull` declaring
  `repo:com.yourbank.records`. The reference enforces it as an `include:` scope is *resolved*
  (`isAllowedPermission` in `@atproto/oauth-scopes`), dropping the offending permissions —
  `lexPermissionSet` itself performs no authority check at all. Enforcing it at parse time meant this
  crate refused documents the reference reads happily, and lost every unrelated definition sharing
  the file.

  `repo` `collection` and `rpc` `lxm` are no longer authority-checked when a permission set is
  parsed. Structural validation is untouched: the NSIDs must still be well formed, non-empty and
  wildcard-free, and `include` and `space` permissions keep their existing constraints.

  The rule itself is preserved as `permission_within_authority`, documented as the security check it
  is. It has no caller: nothing in this workspace resolves `include:` scopes — `Scope::Include`
  grants only itself — so there is currently no path an out-of-authority permission could travel
  down. `atproto-oauth`'s `include_scope_grants_nothing_until_authority_filtering_exists` asserts
  that invariant and will fail the moment resolution is implemented, so the filter cannot be
  forgotten silently.

- `atproto-lexicon`: two record-structure rules from the interop corpus were unenforced — a record
  could be a bare string rather than an object, and `$type` could be the empty string.

  `parse_json` is called for every value at every depth, so it cannot demand that its argument be an
  object: `"blah"` is a perfectly well-formed data-model *value*, and is only ill-formed as a
  *record*. The rule needs a record-level entry point, so there is now `parse_record_json`, which
  requires a top-level object and then delegates. An empty `$type` is refused outright: `$type` names
  the schema a consumer dispatches on, and the empty string names nothing — an object that claims to
  be typed but can never be resolved is worse than one with no `$type` at all, because absence is at
  least detectable.

  Found by asserting the six cases `atproto-dasl`'s `interop_data_model` excludes as
  `NOT_AN_ENCODING_CONCERN`. Four of the six turned out to be enforced already, contradicting that
  exclusion's claim that they were "not implemented yet" — which is the hazard of a rule that is
  implemented but unasserted: it is one refactor away from silently disappearing. All six are now
  covered by `atproto-lexicon`'s `interop_data_model_structure`, whose `ASSERTED_CASES` mirrors the
  exclusion list so the two cannot drift apart unnoticed.

- `atproto-pds`: a space credential could only be verified by the host that minted it, which confined
  every permissioned space to a single PDS — the opposite of what proposal-0016 is for.

  `SpaceReader::authority_public_key` resolved the authority's key with
  `SELECT signing_key_ref FROM account WHERE did = ?` against its **own** account table. A repo host
  serving a member whose space authority lives elsewhere has no such row, so every read was refused:

  ```
  401 invalid space credential: not found: account did:plc:… (signing_key_ref)
  ```

  0016 requires the opposite: a credential is "signed by the space authority's signing key, so **any
  repo host can verify it against the authority's key without contacting the authority**" — the key
  comes from the DID document, the same third party every other atproto signature is checked against.

  Local authorities are still answered from the account table, which is faster and works before a new
  account has propagated. Everyone else is now resolved from their DID document, preferring the
  `#atproto_space` verification method and falling back to `#atproto`, which 0016 allows to coincide.
  A reader with no PLC directory configured says so rather than failing the signature check, since
  that is a deployment problem and not a bad token.

  Found by a second PDS added to the conformance rig. Everything around this already worked — the
  authority verifies a delegation token minted by a host it has never contacted, and the repo host
  auto-registers the authority's `#atproto_space_host` endpoint on the first write — so the identity
  resolution this needed was in use a few lines away.

- `atproto-oauth`: the `space:` OAuth scope syntax was from a superseded draft of proposal-0016, and
  was wrong in two ways — one that made conformant grants unparseable, one that made every bare grant
  far wider than intended.

  **The parameter is `authority`, not `did`.** `authority` was rejected outright as an unknown query
  key, so *every spec-conformant `space:` scope string failed to parse*. `did` is kept as a deprecated
  alias so grants already issued keep working; naming both is refused.

  **`authority` defaults to `self`, not `*`.** A bare `space:com.example.bookmarks` covers only the
  granting user's own spaces of that type; reaching another authority's requires naming it or
  `authority=*`. The default was `SpaceDid::All`, so every bare grant reached **every authority's
  spaces of that type**, and `self` was not representable at all.

  `self` is resolved at match time against the DID the token was issued to. `ScopesSet` carries that
  subject — bound once at construction via `from_scope_string_for`, since the subject belongs to the
  token rather than to each question asked of it — so no call site changed.

  > **This needs attention.** `ScopesSet::from_scope_string` cannot resolve `self`, and a set built
  > that way now matches **no space at all** unless the grant names its authority explicitly. That
  > fails closed, which is the safe direction, but it fails *silently*: an authorization check that
  > should pass will simply return false. Every caller that authorizes a space request must build its
  > set with `from_scope_string_for` or `with_subject`. The PDS's `AuthSubject::scopes()` does; a new
  > caller that forgets will not fail loudly.

  Consequences worth noting. The consent screen now renders a bare grant as "your own" rather than
  "any owner" — the line the user reads before deciding. And the network-wide warning no longer fires
  on `space:*`, which under the corrected default means every space type under the user's *own* DID:
  it now requires `space:*?authority=*`. A warning shown on a narrow grant is one users learn to
  dismiss.

- `atproto-lexicon`: `ref`, `union` and `params` were accepted as top-level definitions. None is a
  definition type — each describes how a field relates to something else, so none says anything
  standing alone: a top-level `ref` is a pointer with nobody holding it, and a `params` is the
  query-string half of an endpoint that is not there.

  The reference lists what a definition may be (`lexUserType`,
  `packages/lexicon/src/types.ts:372-404`) and has no case for any of the three. Checked from the
  other side too: **none of the 396 lexicons in the reference repository** defines one.

  A bad schema costs more than a bad record. One record that should not validate is one record; a
  schema that should not parse is every record validated against it, and the mistake is inherited
  rather than repeated.

  `unknown` is **not** included, though the interop corpus calls a lone `{"type": "unknown"}`
  definition invalid. The reference's `lexUserType` has a case for it, so corpus and reference
  disagree, and that is not this crate's call to settle. It stays pinned in `interop_lexicon.rs` with
  that reasoning.

  Several recursion-limit fixtures defined a top-level `union` or `ref` and so are no longer valid
  documents. They now build their catalogs through `BaseCatalog::add_schema` without document
  validation, which is a truer test than before: `SchemaFile`'s fields are public, so a catalog can
  be assembled from a cache or a peer with no parse step, and the validator's own bounds still have
  to hold. Document validation is the first line of defence and is asserted separately; it was never
  the only one.

- `atproto-lexicon`: a union value with no `$type` was accepted by **structural matching** — each ref
  was tried in order and the first that matched was taken. A union is discriminated: the member names
  the variant it is. The reference refuses a value without `$type` outright, and that holds for open
  unions too, since openness tolerates `$type` values not in `refs`, not the absence of `$type`.

  The fallback was unsound on its own terms. Two variants with compatible shapes are
  indistinguishable that way, so the validator's answer depended on the order `refs` happened to be
  written in, while a consumer — which has no list to walk — could only read `$type`. They could
  reach different conclusions about the same record.

  **This removes a resource-exhaustion surface rather than bounding one.** Candidate enumeration was
  the engine behind every union-driven attack the recursion limits were built for: fan-out (4¹³
  combinations from a 34-byte body, ~25 s before those limits landed), nested backtracking, union
  chains deep enough to trip the depth limit, and the frame- and counter-leak bugs that came from
  unwinding a failed candidate. A union now resolves to at most one ref, so there is nothing to
  enumerate, nothing to backtrack out of, and no failed attempt to unwind.

  Ten tests that bounded that work were replaced by five asserting it cannot start. What is still
  bounded, and still tested: a union naming *itself* through `$type` (cycle detection), plain `ref`
  chains (the depth limit), and large records (the step budget). The absolute step cap test needed a
  larger record to still reach the cap — a four-branch union costs one traversal per element now
  rather than about five.

- `atproto-lexicon` / `atproto-dasl`: a `$bytes` value meant two different things in one workspace.

  `atproto-lexicon` decoded with the padded `STANDARD` engine while `atproto-dasl` emits **unpadded**
  — so a record written through the data model failed lexicon validation. Both also rejected
  non-canonical trailing bits, which the reference accepts: `{"$bytes": "123"}` decodes to two bytes
  in JavaScript and is listed as a **valid** record in the interop corpus.

  There is now one decoder. `atproto_dasl::atproto_json::decode_bytes` is the `$bytes` codec —
  standard alphabet, padding optional, trailing bits tolerated — and `atproto-lexicon` delegates to
  it. Encoding is unchanged and still canonical and unpadded, so nothing this workspace *emits*
  depends on the tolerance; the leniency applies only to what it is willing to *read*, which is where
  a validator stricter than the network does damage.

  Two decoders that had to agree and nothing making them was the actual defect. The padding half was
  caught by the lexicon interop corpus; the trailing-bits half was not caught by either crate's
  corpus, because every `$bytes` value in the data-model vectors happens to be canonical.

- `atproto-lexicon`: the Namespace Authority rule for permission sets had a hole shaped like its
  recursive case. `include` — the spec's "meta" resource, which pulls in another permission set —
  was not a recognised resource at all, so a set referencing another set was refused outright, and
  the rule that should bind it was never written.

  That is the resource the rule most needs. An `include` grant is **transitive**: whatever the
  referenced set contains is inherited. A set naming one under an unrelated authority would inherit
  permissions its own namespace does not cover, and the rule would be gone in one hop. `include` is
  now modelled (`nsid`, plus `aud`) and bound by the same check as `repo` collections, `rpc` methods
  and `space` types.

  Wildcards inside a permission set are now refused *as wildcards*. They were already refused —
  `*` is not a valid NSID — but reported as a malformed NSID, which sends a reader looking for a typo
  instead of at the rule. The spec is explicit: "Wildcards are not supported in permissions within a
  permission set." Partial wildcards (`app.example.*`) are refused too.

  The dispatch no longer falls through on unrecognised resources. `PERMISSION_RESOURCES` is now
  paired with `PERMISSION_RESOURCES_WITHOUT_NSIDS`, and a test asserts every resource is either
  namespace-checked or explicitly listed as naming no NSID. Adding a resource without deciding which
  it is now fails a test rather than silently exempting it.

  **No exceptions were added.** The spec computes authority "without \"siblings\" or special
  namespaces", and its own worked example — now a test, verbatim — needs none. The exemption list is
  three resources that carry no NSID (`blob`, `identity`, `account`), which is a statement about
  their shape, not a carve-out for any name.

- `atproto-lexicon`: `validate_datetime` accepted `-00:00` as a UTC offset and checked the year
  before the offset was applied.

  RFC 3339 §4.3 gives `-00:00` a meaning of its own — "the offset to local time is unknown" — rather
  than making it a spelling of UTC. Both references refuse it by name. `Z` and `+00:00` are
  unaffected.

  The year was read off the `YYYY` field, so `0000-01-01T00:00:00+01:00` passed: a well-formed string
  naming an instant in year -1, which no `YYYY` field can represent. The year is now checked after
  normalization, which also catches the mirror case, `9999-12-31T23:59:00-00:01`.

  Per-field range checks are replaced by an actual parse. They could only ask whether each number was
  individually plausible: `2023-02-30` has a month in 1..=12 and a day in 1..=31 and is not a date.
  It used to validate; it no longer does, along with `2023-04-31` and `2023-02-29`. Leap seconds
  remain valid.

  The lenient flag still widens the accepted *shape* — lowercase `t`/`z`, a space separator, a
  colon-less offset — but no longer skips the calendar. Lenient meant "accepts more forms", and had
  come to mean "checks less", which made the flag a way to write an impossible date into a record.

  Closes the last 2 of the 31 pinned cases. **532 of 536 assert**; the 4 that remain are the CID
  multibase encodings where the two reference implementations disagree with each other.

- `atproto-lexicon`: `validate_did` accepted a DID ending in `%`, so `did:method:val%` validated. A
  `%` introduces a percent-escape, and a trailing one is an escape with nothing to escape. The crate
  already refused a trailing `:` and the `%` half of the same rule was simply missing.

  The regex now carries the reference implementations' final-character class —
  `^did:[a-z]+:[a-zA-Z0-9._:%-]*[a-zA-Z0-9._-]$`, which both spell identically — and the explicit
  check alongside it now names both characters so the refusal says why.

  This is deliberately not a validity check on each escape: `did:method:va%20l` remains valid, and so
  does a malformed interior escape, matching both references. The rule is about the final character.

  Closes 3 of the pinned cases — the same defect reached `at-identifier`, which delegates here.
  530 of 536 now assert.

- `atproto-lexicon`: `validate_uri` accepted raw whitespace, so `https://example.com/path gap` and
  `https://example.com/trailing-whitespace  ` both validated. RFC 3986 has no production admitting a
  raw space — it must be percent-encoded. The scheme-specific part is now `\S+` rather than `.+`.

  Trailing whitespace is the case worth naming: it survives a careless copy-paste and produces a URI
  that looks correct in every log line it appears in.

  The scheme grammar is deliberately left as this crate had it — `[a-zA-Z][a-zA-Z0-9+.-]*`, which is
  RFC 3986 §3.1 — rather than ported from the reference's `\w+`. `\w` is wrong in both directions:
  it admits `_` and a leading digit, which RFC 3986 does not, and refuses `+`, `-` and `.`, which it
  does. Checked against the corpus: the reference's own regex fails three of its vectors,
  `content-type:text/plan` and `microsoft.windows.camera:thing` among them.

  Closes 2 of the pinned cases. 527 of 536 now assert.

- `atproto-record`: `Tid::decode` tested the wrong bit, so it rejected valid TIDs and accepted
  invalid ones that **aliased onto valid ones**.

  Thirteen base32-sortable characters carry 65 bits and a TID is 64, so the first character's high
  bit falls off the top of `value` during decoding. Testing `value & (1 << 63)` therefore tested the
  first character's *second* bit. TIDs beginning `c`-`j` were refused, and TIDs beginning `k`-`r`
  were accepted — the dangerous half, because the discarded bit meant `k222222222222` and
  `2222222222222` decoded to the same `Tid` and both re-encoded to the second. Two distinct record
  keys collapsed into one, silently, and round-tripping did not preserve the string.

  The first character is now checked before it is shifted away.

- `atproto-lexicon`: `validate_tid` never implemented its first-character rule, so `zzzzzzzzzzzzz`
  and `kjzfcijpj2z2a` validated. The rule was in the module's own doc comment, and stated wrongly
  there too — as `[2-b]`, the first *eight* characters, where a TID's first character carries four
  usable bits and so ranges over the first sixteen, `234567abcdefghij`. Both reference
  implementations spell it as one regex:
  `^[234567abcdefghij][234567abcdefghijklmnopqrstuvwxyz]{12}$`.

  Closes 2 of the pinned cases. 525 of 536 now assert.

- `atproto-lexicon`: `validate_language` matched `^[a-zA-Z]{2,3}(-[a-zA-Z0-9]{1,8})*$`, which is not
  the BCP 47 grammar. It was wrong in both directions at once:

  - **Refused valid tags.** Grandfathered irregular tags (RFC 5646 §2.2.8) such as `i-default` and
    `i-navajo` have a one-letter primary subtag and are not produced by any grammar rule — they have
    to be listed. Private-use-only tags (`X-fr-CH`) likewise never match, and the singleton is
    case-insensitive per §2.1.1.
  - **Accepted invalid ones.** Every subtag after the first was `[a-zA-Z0-9]{1,8}`, so subtags were
    interchangeable when the grammar makes them positional: a 4-letter subtag is a script, a 2-letter
    or 3-digit one is a region. Strings no consumer can interpret passed.

  The RFC 5646 `Language-Tag` grammar is now used, ported from the reference, plus the rule that the
  primary subtag is two or three **lowercase** letters. That second rule is what refuses `JA` and the
  bare four-letter run `jaja`, both of which the grammar alone admits — §2.1.1 only *recommends*
  lowercase, and the grammar reserves `[A-Za-z]{4}` for future use.

  A repeated variant subtag (`de-DE-1901-1901`) is deliberately **accepted**: it is well-formed, and
  the reference draws the line in the same place — `isValidLanguage` returns true and only
  `parseLanguageString` returns null. This is the syntax check, so it answers the syntax question.

  Closes 4 of the pinned cases. 523 of 536 now assert.

- `atproto-lexicon`: `validate_cid` refused base58btc CIDs, which **both** reference implementations
  accept. A record carrying a `zdj7…` CID in a `format: cid` string field was rejected on write.

  The cause was a category error rather than a wrong rule: the validator delegated to
  `atproto_dasl::Cid`, which requires base32lower because *the DASL spec* requires it. That is
  correct for a CID used as a DAG-CBOR link and is a different question from what may appear in a
  record's string field. The link constraint had been borrowed for the lexicon check.

  Base32lower and base58btc are now accepted and still fully decoded — multibase, multicodec and
  multihash — and CIDv1 is still required. Base16, base64 and base10 stay refused: the corpus calls
  them valid but the TypeScript lexicon's `CID.parse` refuses them too, so they are contested between
  the references rather than a defect here, and `interop_syntax.rs` now records them as such.

  Closes 2 of the pinned cases. Not 3: `z7x3CtScH765HvShXT` is base58btc and in the corpus's *valid*
  file, but its multihash does not decode — indigo accepts it because indigo's helper does no
  decoding at all. It stays refused, with a test saying why.

### Added
- `atproto-dasl`: `CidVersion` is re-exported alongside `CidCore`, so callers can check a CID's
  version without taking their own dependency on the `cid` crate.

- `atproto-lexicon`: `validate_nsid` refused NSIDs whose domain authority contains a segment
  beginning with a digit — `org.4chan.lex.getThing`, `cn.8.lex.stuff`, and any name under an onion
  address, which is digit-leading by construction. These are ordinary NSIDs for ordinary domains: DNS
  labels may begin with a digit (RFC 1123 §2.1), and only the first segment (the TLD) and the last
  (the name) are further restricted.

  The cause was one regex requiring *every* dot-separated segment to start with a letter, which
  flattened three different rules into one. The validator now follows the reference's own structure
  (`validateNsid`, `packages/syntax/src/nsid.ts:89-122`), checking each rule where it applies: the
  character set over the whole string, length and hyphen placement per segment, no leading digit on
  the first segment only, and letters-and-digits-no-leading-digit-no-hyphen on the name.

  Closes 7 of the 31 cases pinned in `interop_syntax.rs` (six vectors, one of which the corpus lists
  twice). 512 of 536 now assert.

- `atproto-lexicon`: `validate_at_uri` accepted a trailing slash and empty path segments —
  `at://alice/`, `at://alice//`, `at://alice//com.example.thing`. Both make two distinct strings
  denote the same record, so anything comparing, deduping or indexing by AT-URI sees two where there
  is one.

  The empty-segment case was the worse of the two. Segments were validated behind
  `!segments[1].is_empty()` guards, so an empty collection segment did not merely pass — it skipped
  the record key behind it as well, and `at://alice//com.example.thing` validated without the
  collection ever being looked at.

  Also now refused, matching the reference (`aturi_validation.ts:225-245`): a space anywhere in the
  URI, reported as a space rather than as an invalid record key, and a third path segment, which
  `splitn(3, '/')` had silently folded into the record key.

  Closes 5 of the remaining pinned cases in `interop_syntax.rs`.

- `atproto-pds`: a new account had no repository until its first write. `getLatestCommit` answered
  `RepoNotFound` for a valid account, `getRepo` had nothing to export, and the account announcement
  on the firehose could carry neither `#commit` nor `#sync` because there was no commit to name — a
  relay learned the account existed and could not learn where its repository started.

  `createAccount` now creates the genesis commit: an empty, signed commit, announced with `#commit`
  **and** `#sync`. `#sync` matters here specifically — it force-sets repo state without a diff, which
  is what a consumer needs for a repository it has never seen, where `#commit` is a diff against a
  head the consumer is assumed to hold. The reference sequences all four events together in
  `sequenceAccountCreation`, after `actorTxn.repo.createRepo([])`.

  `applyWrites` still refuses an empty batch. The genesis path commits one, so the guard moved rather
  than disappeared — widening the endpoint would have been the easy way to make this work and would
  have turned a client error into a silent no-op.

  Only accounts that land active. A verified inbound migration lands deactivated and receives its
  repository from the CAR import; an empty genesis commit first would give the import a prior commit
  to conflict with.

- `atproto-pds`: fifteen endpoints in `auth_handlers` verified an app-password session and nothing
  else, so a valid OAuth token was answered `expected typ at-pp-access, got at-oauth-access`. Five of
  them should take one, per the reference's per-endpoint `authorize:` callback:

  | endpoint | policy |
  |---|---|
  | `com.atproto.server.getSession` | any OAuth token |
  | `com.atproto.server.checkAccountStatus` | any OAuth token |
  | `com.atproto.server.requestEmailConfirmation` | `account:email?action=manage` |
  | `com.atproto.identity.signPlcOperation` | `identity:*` |
  | `com.atproto.identity.submitPlcOperation` | `identity:*` |

  `getSession` mattered most: it is the first call most clients make after authorizing, so every
  OAuth token appeared broken at the first hop even once the rest of the flow was correct.

  `signPlcOperation` takes `identity:*` rather than `identity:handle` because a PLC operation can
  rewrite rotation keys and verification methods, not only the handle.

  The other ten are **correctly** closed to OAuth — the reference refuses them with
  `ForbiddenError('OAuth credentials are not supported for this endpoint')` rather than by scope, and
  no scope widens into them. Only the message changes: reporting a well-formed OAuth token as a
  malformed session token sent client authors looking for a bug in their JWT.

- `atproto-oauth`: `transition:generic` granted two things it must not. It is the legacy blanket
  scope every client still requests (`scope: 'atproto transition:generic'` in the reference's own
  README), so both were reachable by any client a user had ever authorized.

  **Identity.** `allows_identity_handle` treated the blanket as covering identity, so a
  `transition:generic` token could rotate the account's handle — rewriting its PLC document.
  Confirmed live against a real PDS: the call returned 200. The reference gates `updateHandle` on
  `assertIdentity({attr:'handle'})` and does not override `allowsIdentity` for transitional scopes,
  so the blanket confers nothing there. `identity:handle` or `identity:*` is now required.

  **Chat.** `allows_rpc` returned true for every method under the blanket, including `chat.bsky.*` —
  direct messages. The reference carves chat out explicitly and requires `transition:chat.bsky`,
  which this crate did not model at all. `TransitionScope::ChatBsky` is added and parses
  `transition:chat.bsky`. A request for the `*` wildcard is still satisfied by `generic` alone,
  matching the reference: asking for "whatever this token has" is not a chat request.

  A test asserted both over-grants — `transition_generic_satisfies_every_granular_axis`, reasoning
  that "enforcing the granular axes without honouring it would refuse every one of them". True of
  repo and blob, not of identity or chat. It is replaced by three tests that draw the boundary where
  the reference draws it.

- `atproto-pds`: a DPoP-bound OAuth access token could not be presented correctly. The server issues
  tokens with `token_type: DPoP` and a `cnf.jkt` binding, which RFC 9449 §7.1 requires be sent as
  `Authorization: DPoP <token>` — but every authenticated XRPC read the header with
  `strip_prefix("Bearer ")` and answered `DPoP` with 401 `expected Bearer scheme`. The whole OAuth
  flow worked up to the token and stopped there: no conforming client could spend one.

  The `DPoP` scheme is now accepted, and the scheme must agree with the token's binding in both
  directions — a `cnf.jkt`-bound token presented as `Bearer` is refused even when a valid proof is
  attached (the downgrade the binding exists to prevent, which the server previously accepted), and an
  unbound token presented as `DPoP` is refused too. `bearer_token` stays Bearer-only for credentials
  that are Bearer by definition — service auth, space credentials, delegation grants.

  Found end-to-end: the harness could not exercise this while the authorization-code leg was skipped
  as "needs a human at a consent screen". `POST /oauth/authorize` accepts the same JSON the consent
  page's own script posts, so no browser was required — the skip was an assumption about the endpoint
  rather than a fact about it, and it hid the defect that made every preceding fix unusable.

- `atproto-pds`: the `FutureCursor` refusal on `subscribeRepos` was sent in an `#info`-shaped frame
  rather than an XRPC error frame, so a conforming client could not read it. An error frame carries
  `op = -1`, **no** `t`, and a body of `{error, message}` — the error *name* is what a client switches
  on. The frame sent instead carried `t: "#info"` and spelled the name `name`, which no client looks
  for.

  `encode_info` was the only frame helper available and conflated the two shapes: it emitted the error
  opcode with an `#info` type tag and body. It is now what its name says — an `#info` **message**,
  `op = 1`, which is what `OutdatedCursor` is: the stream continues after it. `FrameType.Message = 1`
  and `FrameType.Error = -1`, and the reference yields `OutdatedCursor` through the ordinary message
  path.

  A new `encode_error` produces the error shape. Two tests pinned the old opcode — one unit, one
  interop constant spelling the header bytes — and asserted the encoder's behaviour rather than the
  wire contract; both now assert `op = 1` for `#info`, with new tests covering the error frame.

- `atproto-repo` / `atproto-pds`: `#commit` frames carried only the blocks a commit wrote, not the
  Sync 1.1 covering proof, so an inductive consumer could not verify them. A consumer checks a frame
  from the previous root and the frame's blocks alone; to check an operation on a key it needs the
  nodes along that key's path, including ones the commit left untouched. Without them `goat firehose
  --verify` — and indigo's relay in strict mode — answer *"partial MST, can't determine insertion
  order"* and reject the frame.

  `Mst::covering_proof(key)` returns those blocks: the union of the descent to the key and the
  descents to its left and right neighbouring subtrees, matching the reference
  (`packages/repo/src/mst/mst.ts:784-849`). The write path collects the proof for every touched key
  from the post-commit tree and unions it with the written blocks before building the CAR, as the
  reference does. `build_commit_car`'s reachability walk still omits anything the consumer already
  holds — the proof adds only what verification needs.

  Written as three loops rather than three recursive calls: each descent is a tail descent, and
  `BlockStorage::get` is an `async fn` in a trait whose future is not automatically `Send`, so boxed
  recursion cannot satisfy the bound axum requires of a handler.

  The six vendored `firehose/commit-proof-fixtures.json` vectors now assert `blocksInProof` rather
  than only the two roots — the assertion those fixtures exist for, and previously unexercised.
  Checking the roots says the tree ends up the right shape; checking the proof says a consumer can
  verify it, and only the second was ever in question.

  Verified live: with 8 records written to a fresh repository, `goat firehose --verify` reports zero
  inversion failures where every frame was previously rejected.

- `atproto-pds`: creating an account emitted no firehose events at all, so a new account was
  invisible to the network until it happened to write a record — and a consumer that indexes identity
  separately never learned its handle. A relay or appview learns an account exists from `#identity`
  and `#account`; the reference sequences both as part of account creation.

  Emitted from `AccountManager::create_account` rather than the `createAccount` handler, because that
  is the choke point every creation path passes through — the XRPC endpoint, account migration, and
  fixtures alike. Announcing from one caller would have left the others silent, and the crate's own
  firehose tests create accounts through the manager.

  Only for accounts that land active. A verified inbound migration lands deactivated deliberately —
  until the DID document points here the repository must not be publicly readable or emit firehose
  events — and `set_account_state` already announces it on activation.

  `#commit` and `#sync`, which the reference also sequences here, are deliberately **not** emitted:
  it creates an empty repository with a genesis commit, whereas this server defers the first commit
  to the first write, so `getLatestCommit` answers `RepoNotFound` until then and there is no commit
  to name. Emitting either would mean inventing one. A genesis commit at signup is separate work.

  Several existing tests read the whole stream and assumed the first row was the commit. They now
  select by event type, which is what each was actually asserting.
- `atproto-pds`: `com.atproto.sync.subscribeRepos` replayed the entire retained history to any
  subscriber that supplied no cursor, and held the socket open on a cursor past the head instead of
  refusing it.

  `read_after(None, ..)` reads from the start of the log, so a cursor-less subscriber was served
  everything. Every reconnect re-read the whole stream and a fresh consumer inherited a backlog it
  had no way to decline; on a busy repository that is unbounded work on each connect. A missing
  cursor now starts at the current head, matching the reference, which leaves its outbox cursor unset
  and streams live events only. An explicit `cursor=0` still backfills — that is how a consumer asks
  for history, and a regression test pins it so the fix cannot be widened into "never replay".

  A cursor greater than the head now answers a `FutureCursor` info frame. The lexicon declares the
  error and the reference PDS raises it; waiting instead leaves a consumer that mangled its cursor
  unable to distinguish "caught up" from "asking for something that does not exist".

- `atproto-identity` / `atproto-oauth`: JWS signature verification rejected the high-S form, so
  roughly half of all DPoP proofs from a conforming OAuth client failed at random with
  `invalid_dpop_proof … invalid signature`. `key::validate` refuses high-S — correctly, because AT
  Protocol signatures are specified as low-S and the malleable twin must not verify — but the same
  function backed JWS verification, where that constraint does not apply. RFC 7515 defines ES256 as
  the raw `r || s` pair and imposes no low-S rule, and WebCrypto (every browser, and Node's
  `crypto.subtle`) does not normalise `s`.

  `validate_with_policy` now takes a `SignaturePolicy`. `validate` keeps `LowSOnly` and every AT
  Protocol caller keeps today's behaviour unchanged; `jwt::verify_with_config` and
  `dpop::verify_dpop_proof` pass `AnyS`.

  Measured against a live PDS before and after: of 14 proofs from a WebCrypto client, 9 carried
  high-S and all 9 were refused beforehand; afterwards all 14 verified. The failure looked
  intermittent, which is what made it hard to attribute — the same client, unchanged, succeeded or
  failed depending only on a bit of the signature.
- `atproto-pds`: the authorization-server metadata omitted
  `client_id_metadata_document_supported`, so no client built on `@atproto/oauth-client` could
  authenticate. AT Protocol has no client pre-registration — a `client_id` *is* the URL its metadata
  document lives at — and the official client resolver throws
  `Authorization server "…" does not support client_id_metadata_document` when the flag is anything
  other than `true`, before issuing any request. The reference provider sets it unconditionally.

  Everything else about the OAuth surface was already correct: PAR required, S256-only PKCE, DPoP
  algorithms advertised, `redirect_uri` validated against the fetched document. One absent boolean
  made all of it unreachable.
- `atproto-pds`: `POST /oauth/par` accepted a `dpop_jkt` parameter that contradicted the DPoP proof
  sent alongside it, storing the parameter unchecked. RFC 9449 §10.1 lets a pushed request bind the
  key either way, and either alone remains fine — the proof is optional on PAR and a bare request is
  still accepted. But `dpop_jkt` is an assertion by whoever sent the request while a proof is a
  demonstration of key possession, so honouring the parameter over a contradicting proof let a caller
  bind the eventual token to a key it does not hold. The reference provider raises
  `InvalidDpopKeyBindingError` for the same case.

  The check is deliberately not a replay guard: consuming the proof's `jti` at PAR would make the
  same proof unusable at the token endpoint moments later.

- `atproto-pds`: a request to an `/xrpc/` path the router does not serve answered a bare HTTP 404 with
  no body at all. XRPC requires every error response to carry `{"error", "message"}`, and the reference
  server maps an unrouted method id to `MethodNotImplementedError` — `ResponseType.MethodNotImplemented`,
  501. A bodiless 404 is indistinguishable from a wrong hostname or an intercepting proxy, so a client
  could not tell "this server does not implement that method" from "this is not a PDS", and a
  conformance harness reads it as no error envelope rather than as a named error.

  The router now installs a fallback that answers 501 `MethodNotImplemented` for any path under
  `/xrpc/` that names a method. It is scoped by testing that prefix inside the fallback rather than by
  adding an `/xrpc/{*rest}` route: the envelope is a claim about which protocol a path speaks and it is
  only true under `/xrpc/`, so `/.well-known/*`, `/oauth/*`, `/metrics` and every other miss keep the
  bare 404 they had — an OAuth client reading a 501 there would conclude the authorization server is
  broken rather than absent. Keeping the routing table untouched also means no existing route can be
  shadowed and the proxy prefixes (`app.bsky.`, `chat.bsky.`, `tools.ozone.`, `com.atproto.label.`)
  still match first, so a method this server forwards is still forwarded rather than declared missing.

  Only a single path segment counts as a method id, because an NSID has no `/` in it. `/xrpc/`,
  `/xrpc//bar` and `/xrpc/a/b/c` name no method and stay bare 404s — the reference route
  `/xrpc/:methodId` reaches no handler for them either, since an express `:param` does not span a
  slash. `/xrpc/foo/` is the one deliberate divergence: express with strict routing off reads it as
  `foo` and would route it, while this server normalizes no trailing slashes anywhere and so leaves
  it a bare 404. Answering 501 there would claim a method id the router never accepted. A routed
  method called with the wrong
  HTTP verb is unchanged — axum decides that while routing and answers 405 without reaching the
  fallback, so a wrong-verb call is not relabelled as unimplemented. The reference server answers that
  case with 400 `InvalidRequest`; aligning it is a separate change and is deliberately not made here.

  **Operational note.** Unrouted `/xrpc/` traffic moves from the 4xx bucket to the 5xx bucket of
  `atproto_pds_http_responses_total`, which labels by raw status code. Endpoint scanning and clients
  calling methods this server does not implement now count as server errors, so a 5xx-rate alert or an
  SLO burn-rate rule may fire on traffic it previously ignored. This is inherent to matching the
  reference server's 501; alerts that need to exclude it should filter on the status label.
- `atproto-identity`: `DidBuilder` derived the `did:plc` identifier by hashing the signed genesis
  operation's **JSON** serialization. did:plc specifies SHA-256 over the **DAG-CBOR** encoding,
  base32-lower, first 24 characters, which is what the reference implementation computes. JSON and
  DAG-CBOR are different byte strings, so every DID this produced disagreed with the one every other
  implementation derives from the same operation, and a directory refused the submission with
  *"Hash of genesis operation does not match DID identifier"*.

  `derive_did` now encodes with `atproto_dasl::to_vec`, the same DAG-CBOR encoder already used to
  produce the bytes that get signed and the operation's CID. The error variant was always
  `DagCborEncodeFailed`, which suggests DAG-CBOR was the intent and JSON the slip.

  Identifiers minted before this change are wrong and cannot be reconciled — the operation that
  produced one hashes to a different DID. Any such DID has to be recreated.
- `atproto-pds`: a request the HTTP layer could not decode never reached the XRPC error envelope.
  `POST /xrpc/com.atproto.server.createAccount` with `{}` answered HTTP 422 and the `text/plain` body
  *"Failed to deserialize the JSON body into the target type: missing field `handle` at line 1
  column 2"* — axum's default `Json` rejection, written before any handler ran. 422 is not one of the
  statuses XRPC defines, and a client that parses `{"error", "message"}` has nothing to report when
  the body is not JSON at all. The same held for every query-string rejection (HTTP 400, plain text)
  and for a body sent without `Content-Type: application/json` (HTTP 415, plain text).

  `XrpcJson` and `XrpcQuery` in `http::extract` now wrap axum's extractors and translate the
  rejection into the envelope: HTTP 400, `error: "InvalidRequest"`, message. Every handler module
  imports them under the axum names, so `Json` and `Query` in a handler signature are the XRPC ones
  and a handler added later inherits the behaviour instead of having to remember it. That covers all
  47 body-extractor sites and all 30 query-extractor sites across the `/xrpc/*` surface and the admin
  API. `XrpcJson` is a response as well as an extractor, and derefs like axum's, so the substitution
  is an import line per module rather than a signature change per handler.

  Every rejection that means *undecodable* becomes 400 `InvalidRequest`; only the wording differs,
  and that is what tells the caller whether to fix its serializer, its payload or its headers. The
  decoder's own explanation is kept — *"missing field `handle` at line 1 column 2"*, and serde's
  field path for a nested failure — since that is what makes the error actionable. What is dropped is
  the Rust type name serde emits when the top level has the wrong shape (`expected struct
  CreateAccountInput` becomes `expected an object`): the name is in no lexicon, a caller cannot look
  it up, and a refactor changes it while the wire contract stands still.

  The one rejection that does not mean *undecodable* keeps its status. axum wraps every request body
  in `http_body_util::Limited` and this server installs no `DefaultBodyLimit`, so the 2 MiB default
  is live on all 47 endpoints: a `com.atproto.repo.applyWrites` batch past it is refused before any
  byte reaches serde. That is HTTP 413, and it stays 413, now with the named error
  `RequestTooLarge` inside the envelope — the sibling of the `BlobTooLarge` and `RepoTooLarge` this
  server already answers 413 with on `uploadBlob` and `importRepo`. Collapsing it into 400 would have
  left a client unable to tell "split the batch" from "fix the encoder".

  Decoding itself is unchanged — these types accept exactly what axum accepted — so no handler's
  semantics move.

  The OAuth endpoints keep their own error vocabulary, since RFC 6749 clients are specified to read
  `invalid_request` rather than `InvalidRequest`. Two of the five (`POST /oauth/token`, `POST
  /oauth/par`) go through `JsonOrForm`, which already answered in that shape and now also strips the
  Rust type name axum's wrapper text carried. The other three — `POST /oauth/authorize`, `POST
  /oauth/revoke` and `GET /oauth/authorize` — still use axum's own `Json`, `Form` and `Query`, and
  still reject with plain text naming a Rust struct. That is unfixed, not fixed.
- `atproto-identity`: genesis operations omitted `prev` instead of sending `prev: null`. did:plc
  declares the field required and nullable, and the reference directory validates operations against
  a strict schema, so a genesis op without the key was rejected before any signature or hash was
  considered — `createAccount` could not mint a DID against a conformant directory.

  `skip_serializing_if = "Option::is_none"` is dropped from `prev` on both `Operation::PlcOperation`
  and `UnsignedOperation::PlcOperation`. The two have to agree: the unsigned form is what gets
  DAG-CBOR encoded and signed, and the signed form is what gets hashed for the DID, so a field that
  appears in one and not the other means the signature covers different bytes than the directory
  verifies. This is why the change is not a JSON cosmetic — it moves the identifier too.

  The tombstone variant is unaffected; its `prev` was never optional.

- `atproto-pds`: `com.atproto.server.createAccount` reported both of its uniqueness conflicts with an
  error a client cannot act on. A duplicate email was never checked before the INSERT, so the `UNIQUE`
  constraint on `account.email` fired and came back as `500 InternalError` — a client mistake reported
  as a server fault, with SQLite's own `(code: 2067) UNIQUE constraint failed` text in the log as the
  only explanation. A duplicate handle returned `403 Forbidden`, a name the lexicon does not declare
  among `InvalidHandle`, `InvalidPassword`, `InvalidInviteCode`, `HandleNotAvailable`,
  `UnsupportedDomain`, `UnresolvableDid` and `IncompatibleDidDoc`; clients switch on the name, so the
  one case with a declared error was the one case that did not produce it.

  The pre-flight check in `AccountManager::create_account` conflated the columns — it selected `did`,
  tested `did OR handle`, and never looked at `email` — so it could not have named the collision even
  where it caught one. It now reads all three columns and reports `AccountAlreadyExists`,
  `HandleNotAvailable` or `EmailNotAvailable` in that precedence: a DID already hosted here subsumes
  the other two, since telling that caller to pick another handle points them at the wrong remedy
  entirely. All three are 400. The handle case maps to `HandleNotAvailable`; the other two map to
  `InvalidRequest`, because `createAccount` declares no error for either and a name absent from the
  lexicon is no more useful to a client than `Forbidden` was.

  The pre-flight is a read followed by a write with nothing holding the gap, so two concurrent signups
  can both pass it and one still reach the INSERT. A unique-constraint violation there is now
  classified by the column that collided rather than becoming a storage fault, matching on the column
  name that SQLite's `UNIQUE constraint failed: account.email` and Postgres's `account_email_key`
  both carry. Anything that is not a uniqueness violation still reports as a backend fault, as does a
  violation naming the email column on a request that carried no email — an inconsistency the caller
  cannot have caused and should not be told to fix.

  **Operators should know that this discloses email registration.** `createAccount` is unauthenticated,
  so anyone who can reach it can now learn whether a given address holds an account here, by submitting
  it and reading *"the email address `<addr>` is already registered"* — where the opaque `500` disclosed
  nothing on the wire. Handles are public (`resolveHandle` answers for them); email addresses are not,
  so this is a real change in what an anonymous caller can observe. It is deliberate: the reference
  `@atproto/pds` returns `Email already taken: <email>` for the same case, so a signup form written
  against upstream expects an actionable conflict here, and refusing to give one — while still failing
  the request — tells the honest user nothing and the prober only that they must try the address twice.
  What remains is rate limiting: `createAccount` is limited per handle and by the global per-client-IP
  tier (`http/rate_limit.rs`, not per email address), which bounds enumeration rather than preventing
  it. An operator who needs this closed has to
  turn signup off or put it behind an invite, which gates the endpoint before the check runs.

  The check now also runs once in the handler **before PLC genesis**. Minting a `did:plc` publishes an
  operation to the directory's append-only log and nothing can withdraw it, so a duplicate signup used
  to strand a fresh identity there before being rejected a moment later. A conflict is reported ahead
  of `PlcUnavailable` too: a PDS with no PLC service configured now answers 400 naming the conflict
  rather than 503, for a request that could not have succeeded either way.

  Not closed: the race that still reaches the INSERT, and any failure after genesis inside
  `create_account`, can still leave a published DID with no account behind it. Closing that means
  minting the DID last, which restructures the handler rather than fixing an error report, and is left
  as follow-up work.

- `atproto-identity`: the PLC directory client built every request URL as `https://{configured}/{did}`,
  so a directory configured with a scheme produced `https://http://127.0.0.1:2582/…` and no directory
  that does not speak HTTPS could be reached at all. `query`, `fetch_audit_log` and `submit` now share
  a `directory_base` helper that keeps an explicit scheme and prepends `https://` only to a bare
  hostname — the convention `crate::url::build_url` has always followed and the PLC client never used.

  This is what makes a local network possible. `atproto-pds` compiles `reqwest` with `rustls-tls`,
  whose roots are the bundled webpki set, so a private CA cannot be trusted and a loopback directory
  cannot be fronted with TLS either; without an addressable `http://` directory there was no way to
  run PLC genesis outside the public internet, and so no way to exercise `createAccount` in a test
  network.

  Production configuration is unchanged: `plc.directory` still resolves to `https://plc.directory`.


  against the lexicon alone could not page the oplog at all. The lexicon calls `since` *"operations
  after this revision"* and declares no separate `cursor` **input** — the `cursor` the response
  carries has nowhere to go except back into `since` — and this server accepted only its own
  composite `"<rev>__<idx>"` token, 400ing on anything else.

  A bare rev is now accepted and resolves to `(rev, 0)`. Emission is unchanged: the composite token
  is still what the response returns, because it is the form that survives a page boundary inside an
  atomic batch.

  `(rev, 0)` rather than "strictly after `rev`" is the point. The two readings differ only for a
  batch larger than one page: `(rev, 0)` re-delivers that batch's remaining ops, which a syncer
  applies idempotently, where the stricter reading drops them silently. That tail-drop is a bug
  latent in the draft itself — HappyView pages by bare rev and has it — so this server reads `since`
  in the way that can only duplicate, never lose. A malformed token is still a 400.

- `atproto-pds`: `com.atproto.repo.getRecord` reported missing records under the error name
  `NotFound`, which no lexicon declares. `getRecord` declares exactly one error and calls it
  `RecordNotFound`, so a client branching on the declared name — the entire reason errors are named
  rather than numbered — matched nothing and fell through to whatever it does with an unrecognised
  400. A record that was deleted, one hidden by a record-level takedown, and a `cid` the record is no
  longer at now all answer `RecordNotFound`. The status was already right and is unchanged: the
  reference implementation raises this as an `InvalidRequestError`, so 400 rather than 404.

  **A repository this server does not host is a different condition and does not get that name.** The
  lexicon has no error for it, and answering `RecordNotFound` would assert the repo is here and the
  record is not. It answers the generic `InvalidRequest` instead — the one name every XRPC client
  understands without consulting a lexicon — which is what the reference PDS returns when it can
  locate neither the account nor an AppView to forward to. The message still names the identifier
  that did not resolve.

  The rename is made at the `getRecord` call sites, not in the shared `PdsError` → XRPC conversion.
  `PdsError::NotFound` is raised from roughly two dozen places across the sync, blob, key, space and
  account paths; renaming it there would have quietly changed endpoints whose lexicons declare a
  different error or declare none, and no test in this crate would have noticed. The new
  `PdsError::RecordNotFound` carries the AT-URI and is raised only on the repo read path.

  One condition moved rather than being renamed: a record indexed against a block the block store
  does not hold used to report as not-found as well. It is now a logged `InternalError`, because a
  `repo_record` row pointing at a block nobody holds is a damaged actor store, and a routine 400
  buries that. An operator seeing it should check whether that DID recently ran
  `com.atproto.repo.importRepo` and repair by re-importing a complete CAR or deleting the orphaned
  rows — `importRepo` is how the state is reachable: inductive verification accepts blocks missing
  from the CAR for every non-genesis commit, and the MST walk that builds the index loads node
  blocks but never record leaves, so a multi-commit CAR that omits record leaves indexes rows whose
  blocks were never stored. Closing that gap in `importRepo` is follow-up work, as is
  `com.atproto.space.getRecord`, which still answers a missing record with 404 `RecordNotFound`
  where this endpoint now answers 400 — one error name under two statuses on the same server.

- `atproto-pds`: six `com.atproto.space.*` / `com.atproto.simplespace.*` wire shapes did not match
  the lexicons they implement.

  - **`spaceConfig`'s policy field is `policy`, not `mintPolicy`.** A conformant client's `policy`
    was silently dropped and the default `member-list` applied in its place — the request looked
    like it worked. Both names are now accepted on input (`policy` wins) and only `policy` is
    emitted, on `getSpace` and `updateSpace` alike. HappyView carries the same divergence, so an
    upstream issue is owed.
  - **`applyWrites` required a `repo` and returned `{results}`.** It took only `{space, writes}` and
    returned the internal commit result (`{rev, setHash, uris, cids}`), a shape the lexicon does not
    describe. It now takes the lexicon's `repo` — which, as on the single-record writes, must name
    the authenticated subject — accepts `validate`, and returns one `$type`-tagged
    `#createResult` / `#updateResult` / `#deleteResult` per write, in request order. The variant
    follows the *action*, not whether a CID came back. `rev` and `setHash` are no longer returned;
    `getLatestCommit` reports them.
  - **`listSpaces` took a `filter` the lexicon does not declare, and never returned a cursor.** It
    now takes `type` and `did`, and emits a cursor when the page is full — a caller with more spaces
    than one page had no way to reach the rest.
  - **`getRecord` returned a URI that does not parse.** It was built with a format string that
    dropped the author segment, so the URI this server reported failed this workspace's own
    `RecordUri::parse`. It is now built through `RecordUri`, and `repo` is required as the lexicon
    declares — there is no implicit form, because a record URI names its author even when that
    author is the caller.
  - **`limit` was unclamped on `listRepoOps`, `listSpaces` and `listMembers`.** One request could
    demand an entire collection in a single page. All four listing endpoints now resolve `limit`
    through one helper carrying each lexicon's own default and ceiling; they are not the same bound.
  - **`SpaceNotFound` answered 400 on most handlers and 404 on three** — `getSpaceCredential`,
    `listRepos` and `registerNotify` — so a client switching on the status saw one condition two
    ways. All are 400 now.

  `getRecord`'s `repo`, `applyWrites`' input and output, `listSpaces`' parameters and the three
  statuses are **breaking wire changes** for clients written against this server rather than against
  the lexicons.

- `atproto-pds`: `com.atproto.space.listRecords` and `listRepoOps` returned no record values, so a
  syncer had to issue one `getRecord` per record with no bulk path — initial backfill was unusable and
  the pull design became quadratic. Both lexicons inline the value **by default**; the in-code comment
  claiming keys-only *"per `com.atproto.space.listRecords#record`"* contradicted the lexicon it named.

  Values are now inlined by default on both endpoints, with `excludeValues` as the opt-out, and
  `listRecords` gains `reverse`.

  `listRepoOps` omits the value in the three cases the lexicon requires: `excludeValues`, deletes, and
  **ops superseded by a later write**. The last is implemented by matching the op's own CID against
  the current record's, so a superseded op finds nothing. Joining on `(collection, rkey)` alone would
  attach the *newer* value to the *older* op, which is worse than omitting it.

  `listRecords` also clamps `limit` to the lexicon's 1–100; `listRepoOps` keeps its own 1–1000. They
  are not the same bound.

  **Responses are substantially larger by default.** That is the fix; `excludeValues` restores the old
  shape for callers that only want keys.

- `atproto-pds`: `com.atproto.space.getSpace` described the space from the **caller's** per-actor store
  rather than the authority's. Two consequences: a member's store acquires a space row with column
  defaults the moment they first write, so a client asking about an `allowList` space was told `open`
  and could not make a correct minting decision; and a member who had never written had no row at all
  and got `SpaceNotFound` for a space they belong to.

  The draft lexicon describes this endpoint as *"served by the space host"*, and the handler's own
  comment already said to read the authority's store. The viewer parameter is gone rather than
  corrected — `getSpace`'s output carries no viewer-dependent field, so the parameter only ever
  selected the wrong store.

  Authorization is unchanged: who may call `getSpace` is decided as before. Only which store answers.

### Changed
- **`atproto-space` / `atproto-pds`: the permissioned-data commit format changed in three coupled
  ways. Spaces created before this release must be recreated.**

  Nothing this server emitted for spaces has ever interoperated with a conformant peer, for three
  reasons that had to be fixed together:

  - **The `ctx` omitted the author DID.** The 0016 draft builds it as
    `"atproto-space-v1" || len+space || len+author || len+rev || len+ikm`; this crate emitted
    `[space, rev, ikm]`. So `sig` and `mac` were computed over different bytes than any peer — and
    the signature did not bind the author, losing the draft's domain separation *within* a space.
  - **The signed commit had no `ver`.** `ver` is first in the lexicon's `required` set and is
    currently `1`. Every emitted commit failed schema validation on a required field before any
    crypto ran, and there was no version discriminator to negotiate a future `ctx` construction with.
  - **The URI scheme was `ats://{did}/{type}/{skey}`.** Every draft lexicon types the space
    parameter as `at-uri`, and the reference form is
    `at://{did}/space/{type}/{skey}[/{author}/{collection}/{rkey}]` — a fixed `space` marker where a
    public URI carries a collection NSID. The two are unambiguous because a collection has dots and
    the marker does not.

  The third change is why the other two could not ship alone: `space` is length-prefixed into the
  `ctx`, so changing the string changes the signed bytes regardless.

  `ats://` is still **accepted on input** and normalized, so a caller holding an old URI gets an
  answer rather than a syntax error. Nothing emits it. A commit carrying an unknown `ver` is refused
  before the MAC is checked, so a version mismatch does not present as a crypto failure.

  **There is no migration, and one would not help.** The space URI is the primary key of the `space`
  table with nine FK-referencing tables, so the strings *could* be rewritten — but `sig` and `mac`
  on every stored commit were computed over the old `ctx`. Rewriting the URI produces rows that look
  conformant and fail verification. Commits can only be re-signed, which needs each author's signing
  key. Since none of this data was ever interoperable, recreating spaces is the honest path.

- `atproto-pds`: **PostgreSQL accounts storage and S3 blob storage are documented as unsupported,
  and configuring either now refuses at boot.**

  Both have complete, feature-gated, tested implementations in the source tree, and neither is
  constructed by the `pds` binary. `PDS_POSTGRES_URL` and `PDS_BLOB_STORE_URL` were declared with
  behavioural documentation and never read — so an operator who configured S3 got per-actor SQLite,
  and one who configured Postgres got the same, with nothing to indicate it. The README advertised
  both as selectable.

  Postgres is further from working than the README implied: 57 of 59 accounts-DB query sites already
  dispatch per dialect, but thirteen production call sites — the OAuth state store, the JTI replay
  guard and rate-limit SQL backend, the GC loop, the notifier, the sequencer, four files of the
  spaces subsystem, and the repository writer's signing-key lookup — take a SQLite-only pool
  accessor that panics on a Postgres pool.

  Both README rows are gone, replaced by an explicit "Unsupported deployment modes" section, and the
  module docs on `blob_s3` and `account::pool` now say so at the top rather than describing a mode
  you cannot select. The code stays: it compiles, it is tested, and deleting it would make wiring it
  later harder than leaving it.

  **A deployment that sets either variable will not boot.** That is the point — it previously
  believed it had a backend it did not have.

### Security
- `atproto-space` / `atproto-pds`: **delegation tokens and space credentials had no clock-skew
  tolerance and no `iat` sanity check, and the SpaceCredential TTL was unbounded.**

  A delegation token lives 60 seconds and is minted by one host and verified by another, so a few
  seconds of drift between two machines rejected a token that was valid when issued. `exp` now
  tolerates 60 seconds either way.

  The other half is the security-relevant one: `iat` was never checked, so an issuer could date a
  token forward and extend its life without bound — the same as having no expiry at all. An `iat`
  further ahead than the tolerance is now refused.

  `PDS_SPACE_CREDENTIAL_TTL_SECONDS` was already range-checked by the CLI, but the library builder
  `with_space_credential_ttl` took any `u64`. A SpaceCredential has no revocation path — removing a
  member does not invalidate one already minted — so the ceiling bounds how long a removed member
  keeps access. Both paths now share one 60s–24h range, and the builder clamps and warns rather than
  accepting a value it will not honour.

- `atproto-pds`: **permissioned blobs were served to anyone holding the CID, with no credential at
  all.** There is no `com.atproto.space.uploadBlob`: permissioned blobs are uploaded through the
  ordinary `com.atproto.repo.uploadBlob` and land in the same `repo_blob` table as public ones.
  `com.atproto.sync.getBlob` fetched by CID with no join and no auth, and `listBlobs` enumerated every
  stored CID.

  This reached further than the cross-account record read below, which at least needs an account on
  the same PDS. CIDs are high-entropy but not secret — they appear in space oplog entries, in
  `listRepoOps` output, in any AppView indexing the space, in logs, and to every member including one
  since removed. A removed member retained permanent access to every blob whose CID they ever saw, and
  deleting the record did not revoke it.

  The public endpoints now serve only blobs a **public** record references — the join across
  `repo_blob_ref` and `repo_record`, which is zds's `getPublicBlob` construction expressed in this
  schema. **An uploaded-but-unreferenced blob is no longer publicly fetchable**, which is a behaviour
  change: nothing should be fetching it before a record names it, and the uploader has the bytes.

- `atproto-pds`: `com.atproto.space.getBlob`'s `space` parameter was decorative. It gated the request
  and was then discarded — the blob was fetched by `(repo, cid)` alone — so a member of one space
  could read a blob referenced only from another space in the same account's store.

  A new `space_blob_ref` table records which space references which blob, maintained on the space
  write path with the same blob-envelope walker the public path uses. `space.getBlob` requires a
  reference in the space it was asked about, and dropping the last referencing record revokes access.

  Both gates are predicates against the per-actor SQLite rather than joins into the fetch, so they
  hold on the fjall profile too, where the bytes are not in a database that knows about records.

- `atproto-pds`: **any authenticated local account could read any other local account's permissioned
  records.** `resolve_record_auth` adopted the caller-supplied `repo` query parameter verbatim — no
  comparison against the authenticated subject, no membership lookup — and recorded the read as
  `OwnPds { account_did: <the caller> }`. `SpaceReader::verify_auth` is a documented no-op for that
  variant, so nothing downstream checked either. Authenticate with an ordinary app password, name the
  victim as `repo`, and `getRecord`, `listRecords` and `getBlob` all served their records.

  The confidentiality property the entire permissioned-data feature exists to provide did not hold
  against anyone on the same PDS.

  Reads are now gated on membership, checked per request: the caller must be a member of the space,
  and the named repo must be one too. Cross-member reads are unaffected — that is what a shared space
  is for — and a removed member loses access on their next request rather than at token expiry.

  The gate is **not** behind the `is_oauth` check that scope enforcement opens with. Scope asks what
  a token was granted; membership asks who the account is. App-password sessions carry no scopes by
  construction and are full-authority, which is precisely how they reached this code.

  Refusals report `SpaceNotFound`: whether a given space holds a given account's records is itself
  the confidential fact, and a non-member should not be able to probe it.

  **Scoped honestly: this is inherited, not an authoring error here.** The reference implementation on
  the `permissioned-data` branch shares all three links — `space/getRecord.ts` destructures `repo`
  straight into `ctx.actorStore.read(repo, …)`, and `space/util.ts:32-37` skips the scope check for
  every non-OAuth credential. It wants an upstream issue as well as this fix.

- `atproto-pds`: every authenticated permissioned-record read leaked the caller's DID string.
  `resolve_record_auth` called `Box::leak(sub.clone().into_boxed_str())` on the hottest authenticated
  path in the spaces surface, so any account with a valid session could drive unbounded process
  memory growth with ordinary reads — `getRecord`, `listRecords`, `getBlob`.

  The cause was a type, not a line. `SpaceReadAuth::OwnPds` declared `account_did: &'a str`, but the
  DID is produced by `subject.sub()` during request authentication — derived, not a slice of the
  request — so no caller could ever supply a borrow that lived long enough. `Box::leak` was the only
  way to satisfy the compiler. The field is now owned.

  The lifetime parameter stays: `SpaceCredential` genuinely borrows the `Authorization` header, and
  removing it would have meant cloning a JWT on every credential read to fix a leak on a different
  variant.

- `atproto-pds`: records were written with no structural checks of any kind. `repo/writer.rs`
  interpolated the record key straight into the MST path and encoded the value without inspecting
  `$type`. Neither failure is recoverable once the commit is signed and sequenced: a key containing
  `/` produces a record whose MST path and its own AT-URI disagree, and a record without `$type`
  cannot be decoded by any consumer.

  Every write now passes three checks first — the collection is a valid NSID, the record key matches
  the record-key grammar (1–512 characters from `[A-Za-z0-9.:_~-]`, never `.` or `..`), and `$type`
  agrees with the collection. The validators already existed in `atproto-lexicon`, which this crate
  has always depended on; nothing called them.

  `$type` is **supplied** from the collection when absent rather than refused, which is what the
  reference does. A record with no `$type` is undecodable, and filling it in is what makes it
  decodable — refusing would only turn away writes the reference accepts. A `$type` that *disagrees*
  with the collection is refused.

  The checks run before the write lock and before anything is encoded, so a refused `applyWrites`
  batch lands none of its ops — as its lexicon requires.

  **Record keys this server previously accepted are now refused.** Existing repositories may already
  contain such records; nothing here rewrites them and reads are unaffected.

- `atproto-pds`: rate limiting reached six call sites out of 104 routes, and every bucket key was
  derived from caller-supplied input — `createSession:{identifier}`, `createAccount:{handle}`,
  `requestPasswordReset:{email}`. A password sprayer varied `identifier` and got a fresh bucket per
  attempt; a signup flood varied `handle`. The limiter did not bound the attack it most resembles a
  defence against. Everything else — all repo writes, all of sync, `subscribeRepos`, the whole
  spaces namespace, `/oauth/par`, `/oauth/authorize`, every admin route — had no limit at all.

  There is now a per-IP limiter over every route, in two tiers: a global budget and a tighter one
  for the endpoints that mint or consume credentials. The existing per-identifier limits stay —
  they bound one account being attacked from many addresses, which a per-IP limit cannot see.

  **`X-Forwarded-For` is ignored by default.** A header any client can set is not an identity, and
  trusting it would hand every caller a private bucket — worse than no limit, because it reads as a
  defence. Set `PDS_TRUSTED_PROXY_HOPS` to the number of proxies you operate and the address is
  taken that many entries from the right of the header; each trusted proxy appends what it saw, so
  counting from the right is what makes the value trustworthy. A chain shorter than configured, or
  an unparseable entry, falls back to the peer address rather than believing it.

  Tunable via `PDS_RATE_LIMIT`, `PDS_RATE_LIMIT_AUTH`, `PDS_RATE_LIMIT_WINDOW_SECS` and
  `PDS_RATE_LIMIT_BYPASS_IPS`. The bypass list matters: without it an operator has to choose between
  limiting attackers and letting their own relay work.

  **Every route is now limited.** Anything doing bulk work from one address — a migration script, a
  test harness, a backfill — will start seeing 429s. The bypass list is the answer.

- `atproto-pds`: `requestPasswordReset` discarded its rate-limit result (`let _ = try_acquire`), so
  the limit was decorative. Reset mail goes to an address the requester does not have to control,
  which made an unbounded endpoint a mail cannon pointed at a third party. It is now fail-closed.

- `atproto-pds`: `PDS_DURABILITY_PROFILE=memory` is refused when `PDS_PRODUCTION=true`. The memory
  backend keeps the OAuth replay guard and every rate-limit bucket in process, so a restart makes
  single-use refresh tokens replayable and hands an attacker mid-flood a fresh budget. The crate's
  own module doc has said so since it was written; nothing checked it.

  **A production deployment on the default profile will not boot until `PDS_DURABILITY_PROFILE=sql`
  is set, or `PDS_VALKEY_URL` is configured.** Same call as refusing the default admin password.

- `atproto-pds`: `com.atproto.admin.updateSubjectStatus` and `getSubjectStatus` spoke a shape that
  appears nowhere in any lexicon. They took and returned `{did, state}`; the lexicon takes
  `{subject, takedown, deactivated}` where `subject` is a union of `com.atproto.admin.defs#repoRef`,
  `com.atproto.repo.strongRef` and `#repoBlobRef`. Not one field name overlapped, so every call from
  Ozone or `pdsadmin` failed to deserialize — this PDS could not be moderated by any canonical tool.

  Both endpoints now speak the union. Account takedown maps onto the existing `takendown` state,
  which the read and write gates already enforce; `deactivated` maps onto `deactivated` and is
  refused on a record or blob subject rather than silently ignored.

  **The old `{did, state}` shape is gone with no alias.** It was not an alternative spelling of
  anything — there is no `state` field in the lexicon — so nothing that spoke the protocol was
  relying on it.

- `atproto-pds`: `signPlcOperation` would sign a key-rotation operation on the strength of an access
  token alone. The lexicon takes a `token` — a code the account receives by email — and the handler
  did not accept the field, let alone check it. `requestPlcOperationSignature`, whose whole job is to
  issue that code, instead returned a service-auth JWT **in its response body**: the second factor was
  handed to whoever already held the first. A stolen two-hour access token was enough to have the PDS
  sign an operation replacing the account's rotation keys, which on an append-only log the PDS cannot
  then undo.

  `requestPlcOperationSignature` now mails a 15-minute one-time code and returns no body, per its
  lexicon. `signPlcOperation` requires it, and consumes it — bound to the account, bound to the flow,
  single-use. A code issued for a password reset does not open this door, and neither does another
  account's code.

  Operators running without SMTP still see the code: the shipped `EmailService` stub logs it, as it
  already does for password resets.

- `atproto-pds`: `updateHandle` performed no validation whatsoever. It took the caller's string,
  wrapped it in `at://`, and put it into a signed PLC operation. Any account could claim any handle —
  `admin.<the-operator's-domain>`, or a domain belonging to someone else entirely — and this server
  would then answer `resolveHandle` for it. A collision with an existing handle surfaced as a 500
  *after* the PLC operation had been submitted, leaving the DID document permanently claiming a handle
  the local database refused to record.

  Handles are now normalized and checked before anything is signed: syntax via the workspace's own
  `atproto_identity::validation` (which the PDS had never called), the upstream disallowed-TLD list,
  uniqueness, and — for a handle under one of this server's domains — length, single-label shape and a
  reserved-name list. A handle outside those domains must resolve back to the claiming DID first,
  which is the only thing that can establish the claim is true.

  **Handles this server previously accepted are now refused.** That is the fix.

- `atproto-pds`: `submitPlcOperation` forwarded whatever it was given. The lexicon describes it as
  *"Validates a PLC operation to ensure that it doesn't violate a service's constraints or get the
  identity into a bad state, then submits it"*, and validation was the one thing it did not do —
  making the reason for routing the operation through the PDS at all moot. A migration client with a
  malformed operation locked itself out of its own identity, permanently, and the server helped.

  Five constraints are now checked before submission: the operation lists this server's rotation key,
  its `atproto_pds` service has the right type and points at this server, its `atproto` verification
  method is this account's signing key, and its first `alsoKnownAs` is this account's handle. PLC is
  append-only, so all of it happens before the POST rather than after.

- `atproto-pds` / `atproto-oauth`: granular OAuth scopes were parsed, stored, and never consulted, so
  every token behaved as a wildcard. The authorization server recorded exactly what the user granted
  — `repo:` with a collection and action, `blob:` with MIME patterns, `rpc:` with method and audience
  — and the resource server had no reference to `scope` anywhere in its write path. `scope=atproto`
  alone could write every collection, upload any MIME type, rotate the handle and proxy arbitrary
  calls on the holder's behalf. The authorization server's decisions were not enforced by the
  resource server.

  `atproto-oauth::scopes` gains the missing `allows_*`/`assert_*` pairs for repo, blob, rpc and
  identity, mirroring the `space:` ones that already existed. A refusal names the minimal scope that
  would have satisfied the request (`InsufficientScope`, with e.g.
  `repo:app.bsky.feed.post?action=create`), so a client can act on it rather than guess.

  Enforced on `createRecord`, `putRecord`, `deleteRecord`, `applyWrites`, `uploadBlob`, the `rpc:`
  proxy path and `updateHandle`. `applyWrites` is checked per operation rather than once for the
  batch: one call can touch several collections with different verbs, and a token scoped to create in
  one collection must not delete in another by riding along.

  **`transition:generic` satisfies all four axes.** It is the legacy full-access migration scope and
  is what most AT Protocol OAuth clients request today; enforcing the granular axes without honouring
  it would refuse every one of them. It is deliberately *not* a wildcard for `space:` — spaces
  post-date it, so nothing was granted it expecting space access.

  App-password sessions are not scope-checked. They carry no scopes by construction and are
  full-authority, which is the rule the existing `space:` assertions already applied.

  **A token granted narrow scopes is now refused where it previously succeeded.** That is the fix,
  but it will surface as breakage in any client that requested less than it actually used.

- `atproto-pds`: anyone could claim any DID. `createAccount` took no request parts at all — it could
  not read a header if it wanted to — and used a caller-supplied `did` verbatim. An attacker got a
  session bound to the victim's identity, had this server answer `describeRepo`, `getRepo` and
  firehose events for it, and permanently denied the victim an inbound migration here. Forged commits
  fail relay signature verification, so the damage was bounded; the lockout was not.

  A caller-supplied DID now requires an inbound service-auth token issued by that DID's **current**
  host: `iss` is the DID being claimed, `aud` is this server, `lxm` is `com.atproto.server.
  createAccount`, and the signature is checked against the `#atproto` key in the DID's own document,
  fetched live. Only whoever controls that identity today can move it here. This is also the first
  canonical endpoint on this server to accept an inbound service-auth token at all — `verify_service_
  auth` previously had two callers, both in Spaces.

  **There is no way to switch this off.** An escape hatch would be set on exactly the deployments
  that most need the check.

  A verified inbound migration now lands **deactivated**, as the canonical sequence requires —
  create → import → `submitPlcOperation` → activate. Landing active meant the repository was
  publicly readable and emitting firehose events before the DID document pointed here, and left
  `activateAccount` with nothing to gate.

  `reserveSigningKey` is session-gated and idempotent. Unauthenticated, it generated a fresh keypair
  on every call and wrote a reservation row for whatever `did` the caller named — unbounded key
  generation and reservation squatting for anyone who could reach it. Worse, the row id was a
  millisecond timestamp, so the first reservation was kept while every subsequent call handed back a
  *different* key: the key returned and the key reserved diverged after the first request. A repeat
  call now returns the key already reserved, and a caller may only reserve against its own DID.

- `atproto-pds`: a takedown did almost nothing. Account state was enforced on two public read paths
  and nowhere else, so a moderation action removed record-level reads while the account's complete
  repository CAR, its raw blocks and every blob stayed anonymously downloadable — and the account
  kept writing, kept refreshing its session, and could restore itself with one unprivileged call.
  Five findings, one sentence.
  - **Reads.** `getRepo`, `getBlocks`, `getBlob`, `listBlobs`, `getLatestCommit` and `describeRepo`
    had no state check at all; the sync and blob files contained no reference to `AccountState` of
    any kind. All nine public read paths now share one gate and answer with the errors their
    lexicons declare — `RepoTakendown`, `RepoSuspended`, `RepoDeactivated` — which were previously
    unreachable on the five endpoints that declare them. `getRecord` and `listRecords` move from a
    generic `403 Forbidden` to the same named errors, so a caller branching on state needs one
    branch rather than one per endpoint.
  - **Writes.** `AccountState::allows_writes` existed with no caller anywhere, and the write guard
    never read account state. A taken-down account kept writing records and publishing firehose
    commits until its refresh token expired — up to 90 days after the moderation action.
  - **Refresh.** Neither `refreshSession` nor the OAuth refresh grant looked at state;
    `refreshSession` already had the account row in hand and read only its `did`. Without this the
    write gate is bounded by a 90-day token rather than by the moderation decision.
  - **Activation.** `activateAccount` called `set_state(Active)` unconditionally, so an admin
    takedown was reversible by its subject. Deactivation stays self-service — it is a pause the user
    chose, and the inbound-migration flow depends on undoing it.
  - **Storage.** Both blob handlers opened the per-actor store before any check, and
    `SqlActorStore::open` runs `create_dir_all` and migrations, so an unauthenticated caller could
    materialise a SQLite file for every DID it cared to invent. The gate now runs first.

  **Deactivated accounts can no longer perform ordinary writes**, which matches `allows_writes` and
  the reference. `importRepo`, `uploadBlob` and `listMissingBlobs` deliberately still work while
  deactivated: inbound migration is prescribed as create → deactivate → import → upload → activate,
  so refusing those would make the ordinary migration path impossible. Moderated states are refused
  there too — a taken-down account must not import a repository either.

  This hides a taken-down account's data; it does not erase it. `deleteAccount` still performs no
  data erasure, so a "deleted" account's repository and blobs remain on disk behind these gates.

- `atproto-pds`: the spaces client-attestation path dereferenced attacker-named URLs with no
  restriction, making the endpoint a request generator pointed wherever a caller liked — a cloud
  metadata service, an internal admin port, a neighbour on the same host. Three fetches, on one
  attacker-controlled input:
  - the attestation's `client_id`, checked only for an `https://` prefix, which stops none of the
    above;
  - the `jwks_uri` from the document that fetch returns, checked not at all;
  - and, from the same `client_id`, the recipient resolver's `.well-known/atproto-did` lookup and
    the DID-document fetch behind it — a pair the finding does not name.

  All three now pass `atproto_identity::validation::validate_service_endpoint`, the same policy the
  OAuth client-metadata path has used since the PAR fixes: HTTPS only, no address literal in any
  form a resolver accepts, no embedded userinfo, no port but 443, and the reserved `.localhost`,
  `.internal`, `.arpa` and `.local` suffixes refused. The recipient resolver falls back to a stub on
  any failure, so a refusal is logged at WARN — otherwise a guarded host and an unreachable one are
  indistinguishable, including to whoever is debugging it.

  **This is a syntactic guard.** It performs no DNS resolution, so it does not defend against
  rebinding, nor against a public name whose A record points at a private address. It is the layer
  this workspace has, not a complete SSRF control.

  Operators running a spaces deployment against client metadata on an IP literal, a non-443 port, or
  a `.localhost` host will find those attestations now refused.

- `atproto-pds`: the single secret guarding every admin verb was comparable by timing, guessable
  without limit, and — in any deployment that had not set `PDS_PRODUCTION=true` — published in this
  repository. Three defects on one door:
  - **Non-constant-time compare.** `admin/handlers.rs` and `admin/dashboard.rs` used `!=` on `&str`,
    which short-circuits at the first differing byte, so rejection time revealed how much of the
    prefix was right. Both now go through one shared `secret_eq`, which MACs each side under a
    per-call key and compares through HMAC's verifier — constant-time in the contents and
    independent of length, so neither the password nor its size leaks.
  - **No rate limit.** An attacker who can guess without limit does not need a side-channel at all.
    Both surfaces now pass through the existing sliding-window limiter before comparing.
  - **A live default password.** `admin-default-CHANGE-ME` is a constant in this crate, and it was
    refused only when `PDS_PRODUCTION=true` — so *forgetting* the flag selected the insecure branch.
    Startup now refuses the sentinel everywhere unless `PDS_ALLOW_DEV_DEFAULTS=true` says the
    deployment is unreachable by anyone else, and that opt-in cannot be combined with
    `PDS_PRODUCTION`.

  **Operators and developers:** a PDS with no `PDS_ADMIN_PASSWORD` set now fails to start. Set a real
  password, or set `PDS_ALLOW_DEV_DEFAULTS=true` for a local instance. This is deliberate — absence
  of configuration used to fail open.

- `atproto-pds`: an uploaded blob could render as a document on this origin — stored XSS against the
  authorization server. `com.atproto.sync.getBlob` set only `Content-Type`, echoing the MIME the
  uploader declared in its request header, which is neither validated nor sniffed. Upload
  `text/html`, get someone to open the blob URL, and the script runs on the origin that also serves
  the OAuth consent screen and its session cookies — which chains straight into account takeover.

  `getBlob` now sends the same three headers `space.getBlob` has always sent: `nosniff`, so a
  browser does not second-guess a benign declared type; `content-disposition: attachment`, so the
  response downloads rather than renders; and `default-src 'none'; sandbox`, so anything rendered
  regardless can do nothing. The MIME is still unvalidated — sniffing it is a separate change — but
  it can no longer be turned into script on this origin.

- `atproto-pds`: password-reset and account-deletion tokens were written to the application log at
  INFO, in the only build that shipped. `EmailService::Disabled::send` logged the full rendered body,
  and that body carries the confirmation URL for password reset, account deletion and email change.
  The stub is meant for development and says so — but the published image always selected it,
  because `smtp` is not a default feature and the Dockerfile did not ask for it. Logs are routinely
  lower-trust than the credential store they were protecting: shipped to aggregators, mounted into
  sidecars, swept up by crash reporters. Anyone who could read one could complete a reset for any
  account on the instance.

  The body is no longer logged. The recipient and subject still are, so an operator can see that a
  send was attempted and to whom. `PDS_EMAIL_LOG_BODIES=true` restores the body for local
  development — at DEBUG, never INFO — and warns at startup, in as many words, that anyone who can
  read the log can take over any account.

  The image now builds with `smtp`, so it can deliver mail at all; `lettre` was already pinned to
  rustls, so no OpenSSL enters the runtime image. When SMTP is unconfigured the service now warns at
  startup rather than noting it at INFO, because an unconfigured mailer means `requestPasswordReset`
  and `requestAccountDelete` return success and send nothing — a failure the caller cannot see.

- `atproto-pds`: closed an authorization-code exfiltration chain ending in full account takeover.
  Three defects composed, and the compromise was invisible to the victim because the `client_id`
  shown on the consent screen was genuine:
  - **`redirect_uri` was never validated.** PAR stored whatever the caller sent and the consent page
    navigated to it, so an authorization code issued for a trusted client could be delivered to an
    attacker's destination. PAR now resolves the client's metadata and requires the requested
    redirect to be one the client published, compared for exact equality per RFC 6749 §3.1.2.3.
  - **The token endpoint required no proof of possession.** A stolen code or a leaked refresh token
    was redeemable by whoever held it. Both grants now require a DPoP proof bound to the token
    endpoint (RFC 9449 §5 — no `ath`, since no access token exists yet), with the proof's `jti`
    recorded against replay.
  - **The caller chose its own `cnf.jkt`.** `token.rs` preferred a request-body `dpop_jkt` over the
    thumbprint pinned at authorization, so an attacker redeeming a stolen code received a token
    DPoP-bound to their own key — DPoP was decorative. The binding now comes from the signed proof
    and nothing else; the `dpop_jkt` request field is gone. When authorization pinned a thumbprint
    the proof must match it, and a refresh token is usable only by the key it is bound to.

  This chain was unexploitable in practice only because of the encoding bug fixed below, which is
  why the two ship together: fixing the encoding alone would have converted an unreachable defect
  into a reachable one.

  Client metadata is fetched from an unauthenticated caller's URL, so both that fetch and any
  `jwks_uri` reached through it are gated by
  `atproto_identity::validation::validate_service_endpoint`, which rejects non-HTTPS schemes,
  address literals in every resolver-accepted form, embedded userinfo, non-443 ports and reserved
  suffixes. The guard is syntactic and does not defend against DNS rebinding.

- `atproto-pds`: service auth could mint an unrestricted cross-service credential. Any authenticated
  account could call `getServiceAuth` with no `lxm` and receive a token scoped to nothing — which
  satisfies every method a receiving service gates by one — for up to ten minutes, with no
  protected-method, privileged-method or takedown gate, and no way to revoke it. The only thing
  keeping that from working against real peers was a wrong `typ` header, which is fixed in the same
  change; fixing the header alone would have made it live. Now:
  - `PROTECTED_METHODS` (16 account-management NSIDs) can never be reached through service auth.
  - `PRIVILEGED_METHODS` — `com.atproto.server.createAccount`, the migration credential, and the
    `chat.bsky.*` namespace — require a privileged session.
  - A taken-down account may mint only `com.atproto.server.createAccount`, so a takedown cannot
    strand an account but cannot be worked around either.
  - Inbound verification requires `lxm` to be present *and* match. Previously it compared only when
    the claim happened to be there.
  - `com.atproto.admin.revokeServiceAuth` now takes effect. It wrote a blacklist row that no
    verifier read, so an operator revoking a leaked token got 200 OK and nothing happened — a
    security control that reads as working is worse than an absent one.

### Added
- `atproto-pds`: `validate` is accepted on `createRecord`, `putRecord` and `applyWrites`, and
  `validationStatus` is returned. (`deleteRecord` declares neither — there is no record to validate.)

  Lexicon schema validation is not implemented, so `validate: true` is **refused by name** with
  `ValidationUnavailable` rather than accepted and ignored. A caller who explicitly asked for
  validation is better served by an error naming the gap than by a success that validated nothing.
  `validate: false` and unset both write. `validationStatus` reports `unknown`, which is the honest
  value while no schema engine is wired — `valid` would claim a check that did not happen.

- `atproto-pds`: record- and blob-level takedown. `updateSubjectStatus`'s two non-account subject
  kinds had no storage behind them, so an operator asked to remove one illegal post or one illegal
  image had no option short of taking down the whole account.

  A taken-down record disappears from `getRecord` and `listRecords`; a taken-down blob is withheld
  from `com.atproto.sync.getBlob`. Both report as not-found rather than forbidden, so a probe cannot
  confirm the content is still stored here. Both lift cleanly, and applying or lifting twice is a
  no-op — moderation actions arrive from queues that retry.

  Takedowns are recorded in the per-actor SQLite on both storage profiles. Records and blobs
  dispatch through `PublicRealmBackend`, so a column on `repo_record` or `repo_blob` would have
  covered the SQLite profile and silently missed fjall.

### Fixed
- `atproto-pds`: no `#identity` event was emitted when a handle changed. `emit_identity_event`
  existed and was called from exactly one place — `refreshIdentity` — so a rename made through
  `updateHandle`, `admin.updateAccountHandle` or `submitPlcOperation` reached no relay and no
  AppView. The new handle worked on this server and nowhere else, with nothing to indicate why.

- `atproto-pds`: `swapCommit` was accepted and never enforced, so concurrent writers clobbered each
  other and both received HTTP 200. `createRecord` declared the field and never read it; `putRecord`,
  `deleteRecord` and `applyWrites` did not accept it at all, though all four lexicons declare it and
  name `InvalidSwap` as the error. Two clients that each read the repo, decided something, and wrote
  would both be told they succeeded, and the second would silently discard the first's work.

  All four now perform a real compare-and-swap. The check happens inside the per-DID write mutex,
  after the prior commit is loaded and before anything is written, so it holds against concurrent
  writers on this server rather than being a check-then-hope. `applyWrites` guards the whole batch,
  as its lexicon requires — "the entire operation will fail".

  A mismatch returns `InvalidSwap` with both the expected and the actual commit, so a client can see
  what it needs to rebase onto rather than only that something went wrong. Omitting `swapCommit`
  writes as before: the guard is opt-in, and a caller that makes no claim has nothing to check.

  `swapRecord`, which was already honoured on standalone `putRecord`/`deleteRecord`, is unchanged.

- `atproto-pds`: `importRepo` wrote no record index, so an imported repository was invisible to every
  record API. It persisted blocks and commit rows and stopped; `getRecord`, `listRecords` and
  `describeRepo` all resolve through `repo_record`, which nothing populated — despite the module doc
  saying the import would index records.

  So the import reported success, the commit chain verified inductively, and the account then
  presented as empty: not-found for every record, an empty page, no collections. Silent data loss at
  the last step of a migration, with every step reporting success.

  The import now walks the head commit's MST and indexes what it holds, then reads each record and
  records the blob references it carries — so `listMissingBlobs` answers the question a migrating
  client asks next, instead of always saying nothing is owed.

  Two limits worth knowing. Records are indexed at the head commit's rev rather than the rev each was
  actually written at; deriving true per-record revs means walking every historical commit's tree and
  diffing, which the reference implementation does not do on import either. And when a CAR omits a
  block its MST names — which is what a diff slice is — the record is still indexed and only its blob
  walk is skipped, because refusing the whole import over one absent block would be a worse failure
  than the one being fixed.

- `atproto-pds`: record→blob reference tracking was implemented, tested, and never invoked. The trait
  method, all three backend implementations and the free functions existed with their own unit tests,
  and nothing in the write path called any of them — despite a doc comment stating the writer did.

  So `listMissingBlobs` answered `{"blobs": []}` forever and `checkAccountStatus.expectedBlobs` stayed
  `0`. A migrating client asked what still needed transferring, was told nothing, and activated an
  account with none of its media — while every step reported success. Blob GC also had no ref-counts
  to consult.

  The write path now walks each record for blob references and maintains the index. The walker
  recurses rather than checking known paths like `embed.images`: blobs appear at arbitrary depth and
  in arrays, and a walker that had to be taught each lexicon would silently miss every one it had not
  been taught — the same outcome as not walking at all. It validates the whole envelope before
  accepting a reference, so a map carrying `$type: "blob"` and nothing else does not produce a row
  with an empty CID that `listMissingBlobs` would then report as missing forever.

  Updates and deletes drop the record's existing references first. Adding without dropping would make
  the counts only ever grow, which is a different wrong answer rather than a fix.

  **`listMissingBlobs` now returns entries on repositories that previously reported none.** That is
  the correction, but anything asserting an empty list will see it as a change.

- `atproto-pds`: the fjall test suite did not compile, so it had not run. Once building, one test was
  failing on a stale assertion — it read `blob.$link` from an `uploadBlob` response, a shape that
  stopped existing when blob refs became the lexicon's typed envelope (`blob.ref.$link`). A second
  assertion in the same file compared two of those absent values and so asserted nothing. Both
  corrected; the fjall profile is green.

- `atproto-pds`: no route sent CORS headers, so no browser client worked. A browser OAuth client runs
  on some other origin; without `Access-Control-Allow-Origin` the browser refuses to hand it the
  response body, so discovery failed before the authorization request was attempted — and had it got
  past that, every XRPC call would have failed the same way.

  `CorsLayer` now covers the whole surface: the four discovery documents, the OAuth endpoints, and
  the XRPC routes. The finding scopes this to discovery and OAuth, but a client that completes the
  token exchange and then cannot call a single method is still blocked, so the fix follows the
  consequence rather than the letter.

  The policy is `Allow-Origin: *` with **no** `Allow-Credentials`. That is safe precisely because
  AT Protocol authenticates with `Authorization` and `DPoP` request headers and never with cookies:
  a browser attaches neither cross-origin unless the calling script sets them, and a script that can
  set them already holds the token — so the wildcard grants a hostile page nothing it could not get
  by calling this server from its own backend. `Allow-Credentials: true` is the switch that would
  change that, by making the browser send ambient credentials and hand over the response; combined
  with a wildcard origin it is also forbidden by the Fetch standard. It is deliberately absent and a
  test fails if it ever appears.

  `dpop-nonce`, `WWW-Authenticate` and `atproto-repo-rev` are exposed, since a client cannot read a
  response header it was not told about and each of those exists to be acted on.

- `atproto-identity`: P-256 and P-384 signatures were not low-S normalized, and verification accepted
  the high-S form. ECDSA signatures are malleable — for every valid `(r, s)` the pair `(r, -s)`
  verifies just as well — and AT Protocol requires the canonical low-S form. `k256` normalizes inside
  its own signing primitive, which is why K-256 account keys were never affected; `p256` and `p384`
  ship an empty `SignPrimitive` impl, so nothing normalized theirs.

  Measured rather than assumed: signing 64 times with a fresh P-256 key produced **27 high-S
  signatures**, a coin flip as predicted. A peer enforcing low-S rejects each of those, so a P-256
  key was failing roughly half its signatures at random, permanently.

  `sign` now normalizes for all three curves, and `validate` refuses a high-S signature outright
  (`error-atproto-identity-key-14`) rather than accepting either form. Accepting both was the second
  half of the problem: anyone holding a valid signature could derive a different byte string that
  also verified, so "the signature over this commit" was not a unique value — which is exactly what
  anything content-addressing or deduplicating a signature relies on.

  This is a published library other projects sign with, so the blast radius was never limited to this
  PDS. **Verification is now stricter**: a high-S signature produced by an older version of this
  crate, or by another implementation that does not normalize, is rejected where it used to pass.

- `atproto-pds`: five admin request/response shapes did not match their lexicons, so a canonical
  client failed against every one of them. Verified against the published schemas rather than
  against the report's summary, which surfaced two things the report does not mention.
  - **`com.atproto.admin.defs#accountView`** requires `did`, `handle` and `indexedAt`, and declares
    no `createdAt`. This server emitted `createdAt` and `state` and omitted `indexedAt`, so a
    validating client rejected every account it described. There is now one `AccountView` used by
    `getAccountInfo`, `getAccountInfos` **and `searchAccounts`** — the last returns `accountView`
    refs too, and had its own separate struct with the same defect, which a fix aimed only at the
    first two would have left in place.
  - **`searchAccounts`** declares `email`, `limit` and `cursor` — and no `q`. It required an
    undeclared `q` and ignored `email`, so a conformant caller got a 400 and an operator's `email=`
    was silently dropped. `limit` now defaults to the declared 50 rather than 25.
  - **`updateAccountEmail`** names the account `account`, typed `at-identifier`. This server read
    `did` — a hard deserialization failure for a canonical request — and accepted only a DID. It now
    reads `account` and resolves a handle as readily as a DID.
  - **`sendEmail`** requires `senderDid` and leaves `subject` optional. This server had no
    `senderDid` at all and required `subject`. Both corrected, and the declared `comment` field is
    accepted; a message with no subject gets a neutral one rather than a rejection.
  - **`disableAccountInvites` / `enableAccountInvites`** are `com.atproto.admin.*`, not
    `com.atproto.server.*`, and name their subject `account`. Moved and renamed; the optional `note`
    is accepted.

  **These are breaking wire changes**, deliberately without aliases: the old spellings were
  unreachable by any conformant client, so nothing standards-compliant regresses. Callers of the old
  shapes must move to the canonical field names and the two relocated routes. The bundled
  `atproto-pds-admin` CLI is updated with them.

- `atproto-pds`: the 16 MiB blob ceiling was dead code — the real limit was axum's 2 MiB default, so
  a typical phone photo failed to upload and inbound migration failed for any non-trivial
  repository. `uploadBlob` and `importRepo` extracted `axum::body::Bytes`, which applies
  `DEFAULT_LIMIT = 2_097_152` unless a body-limit layer says otherwise, and no layer existed. The
  refusal was `text/plain` — `Failed to buffer the request body: length limit exceeded` — not the
  XRPC error shape every other failure on that surface uses, so a client's error handling never saw
  it. `README.md` meanwhile told operators to size their reverse proxy for bodies over 1 GiB while
  the application rejected at 2 MiB.

  Both handlers now take the body and buffer it under a ceiling of their own, so the limit is the
  one the operator configured and an over-sized request is refused as `BlobTooLarge` or
  `RepoTooLarge` with a JSON body. Two knobs, neither feature-gated so both work in the shipped
  image: `PDS_BLOB_UPLOAD_LIMIT` (default 16 MiB) and `PDS_IMPORT_LIMIT` (default 1 GiB, matching
  what the README asks of the proxy). `MAX_BLOB_BYTES` was a `const` no operator could change; it is
  now `DEFAULT_BLOB_UPLOAD_LIMIT_BYTES`, a default, and `put_blob` takes the limit as an argument
  rather than reading a global.

  Per-account blob quotas remain unimplemented.

- `atproto-pds`: the OAuth token binding is no longer optional in the type system. `issue_pair` took
  `Option<String>` and stored an absent thumbprint as an empty string, which came back as
  `cnf.jkt = ""` and matched no proof for the life of the session — a permanent `InvalidDpopProof`
  with no way out. That path stopped being reachable when the token endpoint began requiring a DPoP
  proof of every grant, so the defect is already closed; what remained was a trap, where a future
  caller passing `None` would silently re-create it with no error at the point of the mistake. The
  parameter is now `&str`, `cnf` is unconditional, and `token_type` is the constant `"DPoP"`. No wire
  change — every token this server issues was already DPoP-bound.

- **The release build was broken, so the container could not be built at all.** Seven crates derived
  `Debug` under `#[cfg_attr(any(debug_assertions, test), ...)]`, which makes a public type implement
  the trait in a debug build and not in a release one. `atproto-pds` derives `Debug` on a struct
  holding a `BlobRef`, so `cargo build --release` failed on `atproto_record::lexicon::Blob doesn't
  implement std::fmt::Debug` — the Dockerfile's exact command. Tests, clippy and CI all run the dev
  profile, so nothing ever exercised it.

  `Debug` is now unconditional across all 60 sites in the seven crates. A published type that
  implements a trait only in debug builds is a latent break for every downstream consumer, not just
  this workspace. CI gains a `cargo check --release` step using the Dockerfile's own feature set, so
  an unbuildable image fails the build rather than the release.

- `atproto-pds`: the firehose named records without shipping them. `#commit.blocks` is a required
  `bytes` field the lexicon describes as a CAR rooted at the commit block, and it was zero bytes —
  no CAR was ever built, because `car_export` was reachable only from `getRepo` and `getBlocks`.
  A consumer learned that a record had changed and had to come back over XRPC to learn what it
  said, which makes the stream a notification feed rather than the thing federation runs on.
  `#sync.blocks` had the matching gap: it once carried a block *count*, and since the previous
  release a well-typed empty byte string.

  Both now carry a real CARv1. `RecordingBlockStorage` wraps the storage the MST writes through and
  keeps every block written during the commit, so the diff is captured by construction — the writer
  puts exactly the record blocks and MST nodes the commit creates — rather than re-derived
  afterwards by comparing two trees. Recording alone over-collects, because a multi-operation batch
  rewrites intermediate MST nodes the final root never references, so the recorded set is filtered
  to what the new commit can reach. Blocks the commit did not write are left out even when
  reachable: the consumer already has them, and that is what makes this a diff rather than a
  snapshot. `#sync` carries the commit block alone, which is what a consumer needs to re-anchor.

  **This is not the Sync 1.1 covering proof.** A proof also carries the blocks needed to verify the
  prior state of each touched key, so a consumer can check the operation inductively without
  holding the repository; that is a separate piece of work, and the vendored
  `firehose/commit-proof-fixtures.json` describes that larger block set. Until it lands, consumers
  that verify inductively will still reject these frames. Consumers that trust the PDS can now read
  the records off the stream. `blobs` also remains empty.

- `atproto-pds`: `seq` numbered a repository rather than the stream, so the firehose cursor meant
  nothing. `outbox.seq` was an `AUTOINCREMENT` column inside each per-actor database, which made
  every account's first event `seq = 1` — two repositories were handed the same number, a resuming
  relay could not tell those events apart, and a repository created after a subscriber connected
  restarted at 1 and had its entire history discarded as already-seen. The subscriber loop then
  drained one account's outbox fully before touching the next, so frames left out of order even
  where the numbers happened to differ.

  There is now one ordered event log for the whole server, in the accounts database — which is
  opened under every storage profile, so a single schema serves both the SQLite and fjall
  deployments. `seq` is allocated by the INSERT into that log, which is what makes it monotonic:
  allocation order *is* commit order. Handing out globally-unique numbers over per-actor storage
  would not have been enough, because a subscriber merging those rows can still observe a later
  number before an earlier one commits.

  `subscribeRepos` accordingly tails one log with one cursor. Three limits disappear with the
  per-account bookkeeping: a connection no longer covers at most 1000 accounts, an account created
  after a subscriber connects now appears without reconnecting, and the per-account outbox is no
  longer reopened on every poll tick. `?did=` remains as a filter over the stream and does not
  renumber it, so a filtered subscriber's cursor stays valid against the unfiltered stream.

  One trade is deliberate: a `#commit` is no longer written in the same transaction as the commit
  it describes, because the repository lives in a per-actor store and the log is server-global. The
  event is published only once the commit is durable, so a crash between the two loses an event
  rather than announcing one that never happened — the case `#sync` and `getRepo` re-anchoring
  exist to repair. The reference implementation splits them the same way.

  The per-actor `outbox` table is left in place but is no longer written or read; dropping it is a
  separate change.

- `atproto-pds`: no relay could consume this server's firehose. `com.atproto.sync.subscribeRepos`
  publishes a closed union — a subscriber decodes each frame against `#commit`, `#sync`, `#identity`
  or `#account` and rejects anything matching none of them — and every frame this server emitted
  matched none. Two defects, which is why they ship together:
  - **The body was an envelope, not the event.** Frames carried
    `{seq, repo, time, payload: {…}}`, wrapping the event inside a `payload` field the lexicon does
    not declare, while none of the eight required `#commit` fields (`rebase`, `tooBig`, `commit`,
    `rev`, `since`, `blocks`, `ops`, `blobs`) appeared at the level a decoder reads them. Bodies are
    now the lexicon shape itself, with only `seq` and `time` — which belong to the delivery, not the
    event — spliced in when the frame is built.
  - **Bodies round-tripped through JSON.** JSON has no link type and no byte-string type, so the two
    types this union depends on could not survive storage: `commit` and each `ops[].cid` arrived as
    text where a decoder expects a CBOR tag-42 link, and `blocks` could not be represented at all.
    Bodies are now stored and spliced as DAG-CBOR throughout, so a link stays a link.

  `blocks` is present, well-typed and empty pending the commit path building a CARv1 slice; a test
  pins that so the remaining gap stays visible rather than reading as complete. Also corrected along
  the way: `#sync` was emitting `head` (not a field of the event) and a block *count* where the
  lexicon specifies a CARv1; `#account` emitted `status: "active"` where the field is optional and
  must be omitted for an active account; `#commit` emitted `data` (not a field) and omitted `since`,
  which is required-and-nullable and tells a resuming subscriber where the gap starts.

  The existing unit tests passed throughout because they asserted the envelope they were given —
  `body["payload"]["rev"]` — rather than the lexicon. The new conformance harness checks bodies
  against the published `subscribeRepos` schema.

- `atproto-pds`: AppView proxying was non-functional as routed, so no Bluesky client worked against
  this server. The route `/xrpc/app.bsky.{*nsid}` captures only what follows the literal prefix, so
  `app.bsky.feed.getTimeline` arrived as `feed.getTimeline`. The default-pin test
  `nsid.starts_with("app.bsky.")` could therefore never match — every unheadered call returned 503 —
  and a headered one forwarded to `{appview}/xrpc/feed.getTimeline` with the query string dropped
  entirely. The NSID and query now come from the original request URI.

  The unit tests passed throughout because they called `resolve_target` with a hand-written full
  NSID rather than routing a request. The new tests go through the real router and assert what a
  stand-in upstream actually receives.

### Added
- `atproto-pds`: `app.bsky.actor.getPreferences` and `putPreferences` are served locally. They were
  not implemented at all — the `app.bsky.*` catch-all forwarded them to an AppView that implements
  neither, so every call failed. Muted words, feed preferences and content-label settings were broken
  for every logged-in user, and private state could not migrate in either direction, which is the one
  thing `getPreferences`'s own lexicon says it is for.

  Stored per-actor as the JSON array that arrived. `app.bsky.actor.defs#preferences` is an array of
  open-union objects, and a PDS that parsed them would silently drop every preference type it had not
  been taught — for private state, data loss the user discovers much later. A preference type this
  build has never heard of round-trips intact, and a test pins that.

  `putPreferences` replaces the stored array wholesale. The reference may instead merge by namespace,
  leaving entries outside `app.bsky.*` untouched; that could not be verified here, and a merge rule
  that is subtly wrong discards settings silently, so this does the predictable thing. A client that
  reads, edits and writes back the whole array — the shape the lexicon invites — is unaffected either
  way.

  No scope gate: there is no lexicon-defined OAuth scope for preferences, and inventing one would
  refuse clients for a permission the ecosystem does not define. An authenticated session is
  required.

- `atproto-pds`: `Atproto-Proxy: <did>#<service-id>` now resolves the named DID's document and
  forwards to the service carrying that fragment, instead of refusing every DID except the
  operator-pinned AppView. This is what makes labelers, feed generators, chat and Ozone reachable.
  Endpoints are read through `Document::service_endpoint_validated`, so an attacker-supplied DID
  cannot direct the server at an internal address; resolutions are cached with a five-minute TTL,
  negative results included, so a bad header cannot drive one outbound request per inbound one.
- `atproto-pds`: routes for `chat.bsky.*`, `tools.ozone.*` and `com.atproto.label.*`.
  `com.atproto.label.` specifically rather than `com.atproto.`, which would shadow the many methods
  served locally.
- `atproto-pds` / `atproto-dasl`: records were DAG-CBOR-encoded straight from JSON, so a record
  containing a blob ref hashed to a CID no other implementation computes. The AT Protocol data model
  has one shape and two encodings: DAG-CBOR expresses links and byte strings directly, while JSON
  spells them `{"$link": …}` and `{"$bytes": …}`. Handing a `serde_json::Value` to the encoder stored
  a literal map with a reserved key where a link belonged, and passed floats through even though the
  data model has no floating-point type.

  New `atproto_dasl::atproto_json` reads the JSON representation into the data model and renders it
  back: `$link` becomes a link, `$bytes` a byte string, an integral number an integer whether it was
  written `123` or `123.0`, and a fractional number is refused. Malformed sentinels — a non-string
  value, a bogus CID, an extra key alongside the reserved one — are refused rather than guessed at.
  The record read path renders the inverse, so a record comes back in the shape it went in.

  All three `data-model` interop fixtures now match, up from one. The two vendored-but-unused
  `data-model-valid` and `data-model-invalid` fixture files are now wired as harnesses too.
- `atproto-repo`: the MST write path never built subtrees, so every repository was a single node
  and every root CID was wrong at any realistic size. A key's layer is fixed by its hash — `sha256`,
  leading zero bits, in pairs — and `key_height` computed it correctly and then discarded it
  (`let _target_height = …`). `insert_recursive` never called itself and never set `l` or `t`.
  Keys reach layer ≥ 1 with probability 1/4, so a repository of a dozen records already diverged.

  Insert is now height-aware: a key at the node's layer slots in, splitting any subtree that spans
  its position; a key below descends, creating intermediate layers as needed; a key above splits the
  existing tree and becomes a new root over both halves. Delete recurses, merges the subtrees a
  removed leaf leaves adjacent, and trims layers that no longer hold a key.

  **All six upstream commit-proof vectors now pass, before and after commit** — the first time this
  workspace has produced MST roots a peer can recompute. They were red through the encoding fix in
  0.15.0-rc.2 and stayed red: F-REPO-01 corrected the node bytes and F-REPO-04 the tree shape, and
  neither alone moved a single vector.

  Two read paths changed with it. `get` descended on a height heuristic that only worked when no
  subtree existed; it now follows the structural position. `delete` recurses, where it previously
  ignored `l` and `t` entirely — harmless while nothing built them, silent data loss the moment
  anything did.
- `atproto-repo`: `Mst::delete` silently corrupted neighbouring records. MST entries are
  prefix-compressed against the full key of the preceding entry, so removing one changes the base
  its successor was encoded against. Repairing that needs two steps in order — reconstruct the
  successor's key against the entry being deleted, then re-compress against the entry before that —
  and `delete_recursive` performed only the second, reconstructing against the wrong base. The
  result was not an error: a neighbouring record's key was rewritten in place, and because every
  later entry reconstructs against the rewritten one, the damage ran to the end of the node.

  Measured on a 20-key, four-collection repository, deleting each key in turn from a fresh tree:
  **3 of 20 deletes corrupted the tree**, one of them mangling nine records — `app.bsky.feed.like`
  and `app.bsky.feed.post` entries reappearing as `app.bsky.actorpost/aaaa` and similar. An ordinary
  user deleting one record moved unrelated records to keys that were never inserted, and the result
  was committed and signed.

  `delete_recursive` now derives every full key in the node, removes the deleted one, and rebuilds
  the entry list's compression from the resulting key list. There is no index arithmetic left to get
  backwards, which is how the reference and every port avoid this class entirely.
- `atproto-pds`: `listRecords` emitted a `cursor` on every non-empty page, including the last, and
  serialized it as `null` when there genuinely was none. The lexicon types `cursor` as a plain
  string, so the final iteration of every pagination loop threw in a validating client. A cursor is
  now emitted only when the page was full — a partial page cannot have more behind it — and the key
  is omitted rather than nulled when absent.
- `atproto-repo`: `#repoOp.cid` carried `skip_serializing_if`, dropping the key for deletions where
  the lexicon requires it present-and-null. Now serialized as an explicit `null`. `prev` keeps its
  `skip_serializing_if`, which is not symmetric and not an oversight: the lexicon declares `prev`
  optional — "for creations, field should not be defined" — rather than nullable.
- `atproto-pds`: `applyWrites` results matched no member of the closed output union. Each entry now
  carries a `$type` of `#createResult`, `#updateResult` or `#deleteResult`. Two further corrections
  fall out of the schema: neither create nor update results carry `commit` — that appears once at
  the top level — and `#deleteResult` is an empty object, where results previously carried a `uri`
  the schema does not define.
- `atproto-pds`: `describeRepo` omitted `didDoc`, which the lexicon marks required, so the call
  threw in a validating client and broke the migration handshake. The document is synthesised from
  local state rather than resolved from PLC: `didDoc` being required means a resolver would turn a
  directory outage into a hard failure, for a field whose useful contents — the handle, the signing
  key, the PDS endpoint — this server is itself the authority for.
- `atproto-pds`: service-auth JWTs carried `typ: "at+jwt"`. `@atproto/xrpc-server` throws
  `BadJwtType` for exactly that value, so every token this PDS minted was refused by the Bluesky
  AppView, by Ozone, and by any service built on that library — before the signature was checked.
  All five minters and both verifier constants now emit `"JWT"`, which is what seven of the
  comparison implementations emit and none emits `at+jwt`.
- `atproto-pds`: `getServiceAuth` read `exp` as a lifetime rather than an absolute epoch-seconds
  instant. A client asking for 30 seconds received 600, and a client naming a real timestamp got a
  token lasting until the clamp. `exp` is now absolute, with `BadExpiration` for an instant in the
  past, beyond an hour, or beyond a minute for a token with no `lxm`.
- CI ran an unpinned toolchain, so `cargo clippy` locally and in the spindle were different
  compilers that disagreed about lints. A `clippy::const_is_empty` failure reached `main` after
  passing on a developer machine: `assert!(!BUILD_REV.is_empty())` calls `is_empty()` on a `const`
  filled by `env!`, which the compiler decides, so the assertion can never do work at run time.
  `rust-toolchain.toml` now pins 1.90 — matching the workspace `rust-version` and the Dockerfile's
  builder stage — and the workflow installs it through `rustup` and prints the active version. The
  assertion is replaced by one that reads the build rev back out of the formatted `user_agent()`
  string, which keeps the property under test and cannot be const-folded.
- `atproto-pds`: `com.atproto.repo.uploadBlob` returned `{"$link", "mimeType", "size"}`, an envelope
  matching neither JSON form the AT Protocol data model accepts. The two accepted shapes are the
  typed `{"$type": "blob", "ref": {"$link": …}, "mimeType", "size"}` and the legacy two-key
  `{"cid", "mimeType"}`, both declared strict upstream — and the legacy form is rejected at write
  time regardless. `$link` is a key in neither, and it belongs nested under `ref` as a cid-link
  rather than spliced into the envelope. `@atproto/api` threw on the upload call itself, and a
  client that embedded the returned object produced a record the reference validator rejected, so
  media was broken against every real client.

  The envelope is now `atproto_record::lexicon::TypedBlob`, the workspace's existing representation
  of this shape, rather than a second local definition. Blob storage, ref-tracking rows and the
  `listMissingBlobs` output are unchanged; only the returned envelope moves.
- `atproto-pds`: `/oauth/par` and `/oauth/token` accepted `application/json` only, where RFC 9126 §2
  and RFC 6749 §4.1.3 specify `application/x-www-form-urlencoded` and every standard AT Protocol
  OAuth client sends it. `@atproto/oauth-client-node` and `-browser` received HTTP 415 and could not
  complete a single flow, making an extensively implemented authorization server unreachable.
  `/oauth/revoke` had always used `Form`, which is what showed the inconsistency was unintentional.
  Both endpoints now accept either encoding.

  Two consequences worth noting. Every issued token is now DPoP-bound and `token_type` is `DPoP`
  rather than `Bearer`, which is what the server's own
  `require_dpop_bound_access_tokens: true` metadata has always advertised. And a `client_id` must
  now be resolvable: either an HTTPS URL serving a client metadata document, or a loopback
  identifier of the form `http://localhost[/][?scope=…&redirect_uri=…]`, whose metadata is derived
  from the identifier itself and defaults to `http://127.0.0.1/` and `http://[::1]/`.

- `atproto-repo`: `prevData` was carried inside the signed commit body, making the commit a six-key
  object where the AT Protocol commit schema has five. `prevData` — the prior MST root CID used for
  Sync 1.1 inductive verification — is a `com.atproto.sync.subscribeRepos#commit` **event** field.
  It is per-delivery information, not repository state, and not something the account signs.
  Carrying it in the commit meant the commit CID and the signature still differed from a conformant
  peer's even after the nullable-key fix above: a non-initial commit encoded to 208 bytes and `a6`
  against the canonical 158 and `a5`.

  `Commit::new_unsigned_with_prev_data` and `UnsignedCommit::new_with_prev_data` are removed along
  with the field; use `new_unsigned` / `new`. Subscribers are unaffected — the firehose payload
  already carried `prevData` (`crates/atproto-pds/src/repo/writer.rs`), and the `commit_obj`
  `prev_data_cid` column is unchanged, now populated by walking the commit chain rather than reading
  a self-declared value off the commit.

  **Operational note:** commits written before this change carry the extra key. They still decode —
  the field is ignored — but their signatures no longer verify, because signature checking
  reconstructs the signed bytes from the decoded struct and those bytes no longer include
  `prevData`. In practice this means a CAR previously exported by this server will fail
  signature-verified re-import. Those repositories were already unverifiable by any peer for the
  same reason, so nothing that worked stops working.

- `atproto-repo`: MST nodes and commits omitted map keys the AT Protocol data model requires to be
  present-and-null, so **every MST root CID and every commit CID this workspace produced was
  unrecomputable by any peer** — including for a single-record repository, where tree shape cannot
  differ. `MstNode.l`, `TreeEntry.t` and `Commit.prev`/`UnsignedCommit.prev` are nullable, not
  optional; `skip_serializing_if = "Option::is_none"` dropped the key instead of writing `null`,
  turning the node map from `a2` into `a1`, the entry map from `a4` into `a3`, and the signed commit
  from a five-key object into a four-key one. A single-entry node encoded to 76 bytes against the
  canonical 82. The attribute on `UnsignedCommit.prev` is the one on the signing path, so commit
  signatures were computed over the wrong bytes as well.

  **Operational note:** this changes the bytes every node and commit hashes to. Existing
  repositories get a new MST root CID and a new commit CID on their next write, and the blocks
  written under the old encoding become unreferenced. Reading is unaffected in both directions —
  nodes stored without `l`/`t` still decode, and re-encoding one now yields the canonical form.

  `prevData` inside the signed commit body is a separate divergence and is unchanged here.

  Covered by byte-level known-answer vectors in
  `crates/atproto-repo/tests/known_answer_encoding.rs`, asserted against DAG-CBOR written out from
  the specification rather than against this crate's own output. The pre-existing round-trip tests
  passed throughout.

- `Cargo.lock` was corrupt and no crate in the workspace built from a clean checkout. A bad merge
  concatenated two resolutions of the AWS SDK dependency subtree, leaving 35 duplicate `[[package]]`
  entries and an inconsistent `data-encoding` selection, so `cargo` refused to parse the file at all
  (`package 'aws-config' is specified twice in the lockfile`). Regenerated; 716 package entries
  down to 577. This shipped in `0.15.0-rc.1` because nothing ran a build.
- Removed `crates/atproto-space/benches/set_hash.rs`, which had not compiled since the set-hash
  rewrite: it declares no `[[bench]]` target, has no `criterion` dev-dependency, and imports
  `XorSha256SetHash` (renamed to `LtHash`) from `set_hash_ecmh` (never declared as a module). Its
  presence made `cargo clippy --workspace --all-targets` fail.

### Added
- `atproto-pds`: four discovery endpoints that were never routed.
  - `com.atproto.server.describeServer` — the first call a client makes, and the one account
    migration reads the new PDS's `did` from to learn the `aud` for the service-auth token the old
    PDS must mint. Migration failed at step two without it.
  - `com.atproto.sync.listRepos` — how a relay discovers which accounts this server hosts, with
    `{did, head, rev}` per repo plus `active`/`status`, `limit`/`cursor` pagination, and accounts
    with no commits omitted rather than announced with a head a relay would fail to fetch.
  - `/.well-known/atproto-did` — resolves a handle hosted on this server's own domain to its DID
    from the request `Host`. Without it the PDS could not host handles on its own domain unless an
    operator stood up a separate web server to synthesise the response, which was documented
    nowhere.
  - `/.well-known/did.json` — this server's own `did:web` document, synthesised from
    `PDS_SERVICE_DID`. Peers resolving this PDS for spaces or service auth need it.
- Continuous integration at `.tangled/workflows/ci.yml`, running `cargo fmt --all -- --check`,
  `cargo clippy --workspace --all-targets -- -D warnings` and `cargo test --workspace` on every push
  to `main` and every pull request, with a recursive submodule checkout so the DASL CBOR compliance
  fixtures are actually present. Previously no workflow ran the test suite, and 13 `atproto-dasl`
  compliance cases failed on a missing fixture from a fresh clone.
- Known-answer conformance vectors from `bluesky-social/atproto-interop-tests` (CC-0, pinned at
  `056e574`), vendored at `tests/interop/`, with three harnesses:
  `crates/atproto-repo/tests/interop_mst.rs` (MST key heights, common prefixes, and commit root
  CIDs), `crates/atproto-dasl/tests/interop_data_model.rs` (canonical DAG-CBOR bytes and CIDs), and
  `crates/atproto-pds/tests/interop_firehose.rs` (frame headers against hand-decoded CBOR, the
  `#commit` body against the `subscribeRepos` lexicon, and the first end-to-end WebSocket test of
  the firehose). Every prior encoding test in the workspace was a round trip, which passes just as
  happily against a wrong encoding; these are the first that compare against an external oracle.
  Vectors that do not pass yet are enumerated in each harness's `KNOWN_FAILURES` table with the
  defect that explains them, and are required to keep failing until it is fixed.
- `atproto_repo::mst::common_prefix_len` is now re-exported alongside `compare_keys` and
  `key_height`.

### Removed
- `deploy/well-known/` — three hand-maintained `did.json` files that were never mounted by
  `docker-compose.yml` and are now redundant: each container already sets `PDS_SERVICE_DID` to the
  DID those files described, and the server synthesises the identical document. A static file is a
  second source of truth that can drift from the DID the server actually runs as.

## [0.15.0-rc.1] - 2026-07-27
### Security
- `atproto-lexicon`: bounded `ref`/`union` traversal during data validation. A `union` def that
  referenced itself, or an acyclic chain of ~2500 `union` defs (~105 KB of lexicon JSON), drove
  unbounded recursion on the same `DataValue` and overflowed the stack. A stack overflow aborts the
  whole process with `SIGABRT`, so a single unauthenticated request killed every in-flight request on
  the server; `catch_unwind` cannot catch it. `validate_union` now honours `visited_refs` and
  `ValidateFlags::STRICT_RECURSIVE_VALIDATION` the same way `validate_ref` always did, and
  `ValidationLimits` adds a recursion depth cap (`max_ref_depth`, default 256) plus a total traversal
  step budget (`max_ref_steps` + `max_ref_steps_per_node`). Reported by Lexicon Garden.
- `atproto-lexicon`: bounded the `union` fan-out search. When a value carried no `$type`, every ref
  was tried against the same value and each nested union retried all of its own refs, so a 978-byte
  lexicon plus a 34-byte request body consumed ~25 s of CPU. The step budget above bounds it; the
  same payload now fails in ~39 ms.
- `atproto-dasl`: DRISL decoding no longer panics on a hostile collection header. A 9-byte input
  declaring an array of 2^63 elements reached `Vec::reserve` with the wire-declared count and panicked
  with `capacity overflow` under both `DecodeConfig::default()` and `non_strict()`. Pre-allocation is
  now clamped, a declared count exceeding the remaining input is rejected
  (`DecodeError::CollectionLengthExceedsInput`), and `max_array_elements` / `max_map_entries` default
  to 2^24 instead of `0` (unlimited).
- `atproto-dasl`: CAR block reads no longer allocate from an unvalidated wire length. A 10-byte input
  declaring a 2^63-byte block panicked with `capacity overflow`. `CarBlock::read_from` /
  `from_bytes` and the async block reader now enforce `LimitsConfig::max_block_size` *before*
  allocating and read incrementally via `Vec::try_reserve`. `CarReader::next_block` was affected too:
  it checked `max_block_size` only *after* `read_block` had already allocated, so the documented
  limit provided no protection.
- `atproto-identity`: hardened the SSRF surface around DID and handle hosts. `is_valid_hostname`
  accepted integer, hexadecimal and octal IP forms (`2852039166`, `0xA9FEA9FE`,
  `0250.0376.0250.0376`, and empty-hex labels such as `0x7f.0x.0x.0x1`), all of which resolvers and
  `reqwest` normalize back into addresses like `169.254.169.254` and `127.0.0.1`. Neither
  `did_web_to_url` nor `did_webvh_to_url` validated the host at all before building a URL. Hosts are
  now rejected syntactically and cross-checked against the `url` parser, a shared method-aware
  `did_host()` helper avoids consumers re-deriving host extraction (`did:webvh` places the SCID
  first), and `Document::pds_endpoints()` documents that `serviceEndpoint` is attacker-controlled
  alongside a new validating accessor.
- `atproto-oauth`: `oauth_complete` now requires an expected subject and rejects a `TokenResponse`
  whose `sub` does not match it. Previously `sub` was never bound to the DID the flow began for, so
  an attacker running their own authorization server could return any victim's DID and have the
  relying app mint a session as that victim. JWT verification now requires an `exp` claim, since a
  token omitting it never expired.

### Changed
- **Breaking** `atproto-oauth`: `oauth_complete` takes an additional expected-subject argument.
  Callers must pass the DID the authorization flow started for.
- **Breaking** `atproto-oauth`: `oauth_refresh` keeps its signature, but now binds the returned `sub`
  to the `document` it was called with and rejects a mismatch. A refresh whose authorization server
  returns a different subject now fails where it previously succeeded. Because the signature is
  unchanged, this one does not surface as a compile error.
- **Breaking** `atproto-lexicon`: data validation now bounds `ref`/`union` traversal, so a document
  needing more than `DEFAULT_MAX_REF_DEPTH` (256) nested ref/union hops — or more traversal steps
  than `DEFAULT_MAX_REF_STEPS` (100,000) plus `DEFAULT_MAX_REF_STEPS_PER_NODE` (16) per value node
  allows — is now rejected where it previously validated. Ordinary records, including legitimately
  self-referential ones such as threaded replies, are unaffected. Tune the bounds with
  `ValidationLimits` through the new `validate_record_with_limits` and matching
  `validate_query_params_with_limits` / `validate_procedure_params_with_limits` /
  `validate_procedure_input_with_limits` entry points (and their `_with_schema_and_limits` variants).
- **Breaking** `atproto-identity`: `did_web_to_url` and `did_webvh_to_url` now return an error for
  hosts that are address literals or fall under the reserved suffixes `.local`, `.internal`,
  `.localhost` and `.arpa`. This blocks `metadata.google.internal`, but also rejects
  cluster-internal names such as `pds.svc.cluster.local` and `host.docker.internal` that previously
  produced a URL — deployments publishing a PDS under a cluster-internal name need a routable
  hostname. Bare `localhost` (with or without a port) is unaffected. `did:web` path segments are
  also restricted to `[A-Za-z0-9._-]`, which rejects the percent-encoded segments the DID Core
  `idchar` grammar permits.
- **Breaking** `atproto-dasl`: `CarBlock::read_from` and `CarBlock::from_bytes` are now bounded by
  `LimitsConfig::default()` (1 MB) instead of being unlimited. Use `read_from_with_limits` /
  `from_bytes_with_limits` to widen. Callers going through `CarReader` are unaffected.
- **Breaking** `atproto-dasl`: `DecodeConfig::max_array_elements` and `max_map_entries` default to
  2^24 rather than `0` (unlimited). Because `serde` encodes a plain `Vec<u8>` as a CBOR array, a
  `Vec<u8>` larger than 16 MiB no longer round-trips under the defaults; use `serde_bytes` /
  `Ipld::Bytes`, or `with_unlimited_array_elements()`.

## [0.15.0-alpha.2] - 2026-06-26
### Changed
- Re-aligned permissioned-data Spaces (`atproto-space`, `atproto-pds`) to the published [0016 "Permissioned Data"](https://github.com/bluesky-social/proposals/blob/06d439e6be9004a086f392008e41acddd1a444ff/0016-permissioned-data/README.md) draft, taking the spec as the source of truth over the reference implementation: LtHash set-hash commits, the delegation-token / space-credential JWT shapes, the OAuth `space:` scope grammar, and the `com.atproto.simplespace` mint-policy / `appAccess` / `managingApp` configuration.
- Unified space-declaration resolution across the OAuth consent screen and the `space:` scope gate behind a shared resolver.

### Removed
- Permissioned-data member-sync machinery (`getMemberState` / `getMemberOplog` / `notifyMembership`); member-list management (`addMember` / `removeMember` / `listMembers`) is retained.

## [0.15.0-alpha.1] - 2026-05-09
### Added
- AT Protocol PDS + permissioned-data Spaces (alpha-ready) — new `atproto-pds` and `atproto-space` crates introducing a Personal Data Server implementation and permissioned-data Space primitives (commits, credentials, recon, set hashing, members, repo, storage).
- `atproto-repo`: inductive verification (`src/repo/inductive.rs`) and MST diffing (`src/mst/diff.rs`).

## [0.14.6] - 2026-04-22
### Added
- `atpmcp login <identifier> [password]` subcommand mirroring the atpxrpc login UX. Resolves the identifier, creates a session via `com.atproto.server.createSession`, and upserts the account into the shared `~/.config/atpxrpc/config.json` so credentials are usable by both binaries.

## [0.14.5] - 2026-04-02
### Fixed
- Fixed panproto strategies bypassing `$type` rewriting for nested union types

### Changed
- Updated dependency versions: criterion 0.8, compact_str 0.9, data-encoding 2.10, sha2 0.11, tokio 1.50, unicode-segmentation 1.13, proptest 1.11

## [0.14.4] - 2026-04-02
### Added
- `transmogrify_record` tool to atpmcp MCP server
- `transmogrify_record` function in atproto-lexicon library
- Scenario triggers, parameter examples, and error guidance to atpmcp tool descriptions
- `lenient_optional_format` datetime module and malformed `createdAt` test
- Default values to `alt` and `role` fields in Media type
- Unified `atpdid` CLI tool for DID management (key generate/inspect, resolve, PLC audit/create/update/submit, did:webvh verify/create/update)
- did:webvh v1.0 resolution with full spec compliance
- DiskRepository with `from_car` support

### Changed
- Made lexicon main definition optional per AT Protocol spec
- Moved transmogrify and compatibility into atproto-lexicon library
- Replaced deprecated `plugin-types` CSP directive with `media-src`

## [0.14.3] - 2026-03-12
### Added
- Unknown variant to LocationOrRef and EventLocation enums for calendar events
- `--version` flag to atpmcp CLI

## [0.14.2] - 2026-03-09
### Added
- `atptid` CLI tool for generating and parsing AT Protocol Timestamp Identifiers
- `get_lexicon` tool to atpmcp MCP server for fetching lexicon schema records
- `invoke_xrpc` tool to atpmcp MCP server
- `generate_tid` tool to atpmcp MCP server
- `validate_xrpc` tool to atpmcp MCP server

### Changed
- Updated release workflow and README to include atptid and atpcid binaries

## [0.14.1] - 2026-03-08
### Added
- `atpxrpc` CLI tool for persistent XRPC session management with proxy support
- `--out` argument for atpxrpc proxy and base commands for output control
- `--bytes` and `--manual` proxy flags to atpxrpc CLI
- 5 new tools to atpmcp MCP server

### Changed
- Updated GitHub Actions workflow to build atpxrpc and atpmcp release binaries
- Updated README to reflect full Rust crates workspace

## [0.14.0] - 2026-02-21

## [0.13.0] - 2025-09-21
### Added
- New `atproto-lexicon` crate for AT Protocol lexicon resolution and validation
- `atproto-lexicon-resolve` CLI tool for resolving lexicons via DNS and XRPC
- Comprehensive lexicon reference extraction and recursive resolution capabilities
- Full support for NSID validation and DNS-based lexicon discovery

### Changed
- Updated Rust minimum version requirement to 1.90
- Enhanced error management across atproto-lexicon crate
- Improved project documentation with atproto-lexicon integration

### Improved
- Code formatting and linting across all crates
- Updated README documentation to include atproto-lexicon references

## [0.12.0] - 2025-09-17
### Added
- Unified `Auth` enum for authentication methods in `atproto-client` supporting None, DPoP, and AppPassword authentication
- `com.atproto.server.deleteSession` support in `atproto-client` with AppPassword authentication requirement
- `com.atproto.identity.resolveHandle` support in `atproto-client` for handle resolution
- OAuth client credentials token flow in `atproto-oauth-aip` for service-to-service authentication
- `session_exchange_with_options` function with optional `access_token_type` and `subject` parameters
- Documentation for all Auth enum variants and authentication methods

### Changed
- Updated all XRPC client methods to use the unified `Auth` enum pattern instead of optional DPoP parameters
- Made `refresh_token` field optional in `TokenResponse` structure as not all token responses include refresh tokens
- Refactored `session_exchange` to use `session_exchange_with_options` internally with backward compatibility
- Enhanced error handling with new `InvalidAuthMethod` error variant in client errors

### Fixed
- Removed unused imports and cleaned up code after Auth enum refactoring
- Fixed doctest failures from outdated function signatures
- Resolved compilation errors from type mismatches in error handling

## [0.11.3] - 2025-09-03
### Added
- OAuth scope types, parsing, and utilities for the `atproto-oauth` crate
- Comprehensive support for AT Protocol OAuth 2.0 scope handling

## [0.11.2] - 2025-08-20
### Fixed
- Fixed `atproto-jetstream` consumer to correctly send multiple query parameters for `wantedCollections` and `wantedDids` instead of joining them with commas

## [0.11.1] - 2025-08-20
### Fixed
- Base64 decoding in `atproto-record` now accepts both padded and unpadded base64 strings for better compatibility with various AT Protocol implementations
- Updated `signature::verify` function to only accept `{"$bytes": "..."}` format for signatures

### Added
- Comprehensive unit tests for record signature creation and verification across P-256, P-384, and K-256 curves
- Unit test for deserializing real-world RSVP records with signatures

### Changed
- Made `create` and `verify` functions in the signature module synchronous (removed `async`) as they don't perform async operations

## [0.11.0] - 2025-08-18
### Added
- Document builder functionality for AT Protocol documents
- New `atproto-oauth-service-token` CLI tool for OAuth service token management
- Community lexicon support for extended AT Protocol functionality

### Changed
- Updated record signature and verification to align with current AT Protocol proposal
- Removed `issuedAt` field as required signature field
- Streamlined Debug derive implementations across crates

### Improved
- Removed unused dependencies for smaller build size
- Release preparation and project maintenance

## [0.10.0] - 2025-07-28
### Changed
- Version release 0.10.0 with updated dependencies and stability improvements

## [0.9.7] - 2025-07-13
### Changed
- Updated `list_records` method to support optional DPoP authentication for enhanced security

## [0.9.6] - 2025-07-11
### Improved
- Enhanced DID method validation for did-method-plc and did-method-web
- Updated validation examples and documentation for better clarity

## [0.9.5] - 2025-07-09
### Changed
- Refactored OAuth components to support blind OAuth workflows for enhanced security and privacy

## [0.9.4] - 2025-07-09
### Fixed
- Fixed issue where login_hint was always sent in OAuth initialization

## [0.9.3] - 2025-07-06
### Added
- `delete_record` method to atproto-client for removing AT Protocol records

## [0.9.2] - 2025-06-30
### Added
- Optional `zeroize` feature for secure memory handling of sensitive cryptographic data

## [0.9.1] - 2025-06-29
### Changed
- Updated dependency versions for improved compatibility

## [0.9.0] - 2025-06-29
### Security
- Explicitly forbid unsafe code usage across all crates for enhanced security

### Changed
- Reduced debug information exposure in production builds
- Improved sensitive data handling and reduced exposure
- Cleaned up tracing instrumentation for better performance

### Improved
- Enhanced documentation across all crates and modules

## [0.8.1] - 2025-06-21
### Improved
- Enhanced module documentation across all crates with comprehensive usage examples
- Standardized error handling with consistent naming and unique identifiers
- Updated OAuth AIP crate with detailed API documentation and security considerations
- Improved project documentation and README files across all crates

### Fixed
- Code formatting compliance with rustfmt standards
- Consistent error message formatting and numbering

## [0.8.0] - 2025-06-18
### Added
- OAuth Authorization Initiation Protocol (AIP) crate for AT Protocol OAuth workflows

## [0.7.0] - 2025-06-16
### Added
- DPoP validation support for enhanced security
- Embedded JWKS in OAuth metadata
- P-384 cryptographic curve support and JWK conversion
- App password creation method to atproto-client
- Client authentication binaries for app password and session management

### Changed
- Standardized CLI tools with clap for consistent command-line interfaces
- Enhanced security measures across client tools
- Streamlined documentation structure

### Fixed
- Error cleanup and improved error handling throughout codebase
- Removed unused issuer field from DPoP implementation

## [0.6.0] - 2025-06-08
### Added
- AT Protocol event streaming via atproto-jetstream crate with WebSocket support

## [0.5.0] - 2025-06-05
### Added
- XRPC service helpers and framework crate
- PORT environment variable support for service configuration
- Enhanced DPoP client support for query and procedure methods

### Changed
- Improved tracing and logging throughout the codebase
- Updated Docker configuration to include additional binaries

### Fixed
- Removed hardcoded OAuth metadata field values
- Added missing crate metadata fields

## [0.4.0] - 2025-06-03
### Added
- Initial OAuth client implementation
- Basic AT Protocol identity resolution
- Core DID document handling
- Cryptographic key operations for P-256 curves

[0.15.0-rc.2]: https://tangled.org/ngerakines.me/atproto-crates/tree/v0.15.0-rc.2
[0.15.0-rc.1]: https://tangled.org/ngerakines.me/atproto-crates/tree/v0.15.0-rc.1
[0.15.0-alpha.2]: https://tangled.org/ngerakines.me/atproto-crates/tree/v0.15.0-alpha.2
[0.15.0-alpha.1]: https://tangled.org/ngerakines.me/atproto-crates/tree/v0.15.0-alpha.1
[0.14.6]: https://tangled.org/ngerakines.me/atproto-crates/tree/v0.14.6
[0.14.5]: https://tangled.org/ngerakines.me/atproto-crates/tree/v0.14.5
[0.14.4]: https://tangled.org/ngerakines.me/atproto-crates/tree/v0.14.4
[0.14.3]: https://tangled.org/ngerakines.me/atproto-crates/tree/v0.14.3
[0.14.2]: https://tangled.org/ngerakines.me/atproto-crates/tree/v0.14.2
[0.14.1]: https://tangled.org/ngerakines.me/atproto-crates/tree/v0.14.1
[0.14.0]: https://tangled.org/ngerakines.me/atproto-crates/tree/v0.14.0
[0.13.0]: https://tangled.org/ngerakines.me/atproto-crates/tree/v0.13.0
[0.12.0]: https://tangled.org/ngerakines.me/atproto-crates/tree/v0.12.0
[0.11.3]: https://tangled.org/ngerakines.me/atproto-crates/tree/v0.11.3
[0.11.2]: https://tangled.org/ngerakines.me/atproto-crates/tree/v0.11.2
[0.11.1]: https://tangled.org/ngerakines.me/atproto-crates/tree/v0.11.1
[0.11.0]: https://tangled.org/ngerakines.me/atproto-crates/tree/v0.11.0
[0.10.0]: https://tangled.org/ngerakines.me/atproto-crates/tree/v0.10.0
[0.9.7]: https://tangled.org/ngerakines.me/atproto-crates/tree/v0.9.7
[0.9.6]: https://tangled.org/ngerakines.me/atproto-crates/tree/v0.9.6
[0.9.5]: https://tangled.org/ngerakines.me/atproto-crates/tree/v0.9.5
[0.9.4]: https://tangled.org/ngerakines.me/atproto-crates/tree/v0.9.4
[0.9.3]: https://tangled.org/ngerakines.me/atproto-crates/tree/v0.9.3
[0.9.2]: https://tangled.org/ngerakines.me/atproto-crates/tree/v0.9.2
[0.9.1]: https://tangled.org/ngerakines.me/atproto-crates/tree/v0.9.1
[0.9.0]: https://tangled.org/ngerakines.me/atproto-crates/tree/v0.9.0
[0.8.1]: https://tangled.org/ngerakines.me/atproto-crates/tree/v0.8.1
[0.8.0]: https://tangled.org/ngerakines.me/atproto-crates/tree/v0.8.0
[0.7.0]: https://tangled.org/ngerakines.me/atproto-crates/tree/v0.7.0
[0.6.0]: https://tangled.org/ngerakines.me/atproto-crates/tree/v0.6.0
[0.5.0]: https://tangled.org/ngerakines.me/atproto-crates/tree/v0.5.0
[0.4.0]: https://tangled.org/ngerakines.me/atproto-crates/tree/v0.4.0