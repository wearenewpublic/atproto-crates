# fix(atproto-pds): guard the spaces attestation fetches against SSRF

Closes **F-OAUTH-05**. Milestone M2.11.

## Half of this was already fixed

| Sink the finding names | State |
|---|---|
| PAR `client_id` | **already fixed** — `client_metadata.rs:198` calls `validate_service_endpoint` |
| PAR `jwks_uri` | **already fixed** — `:266`, same guard |
| spaces `client_id` | **was open** — checked only for an `https://` prefix |
| spaces `jwks_uri` | **was open** — not checked at all |

The PAR half was closed by PR #6, which the report predates. Its claim that a grep for SSRF terms "returns zero" no longer holds — it returns four hits, all in `client_metadata.rs`.

**Two corrections.** The guard is `atproto_identity::validation::validate_service_endpoint`, not `crates/atproto-identity/src/host.rs` — there is no `host.rs` in that crate. And:

## There is a third sink the finding does not name

The attested `client_id` also reaches `space/recipient.rs`. `resolve_recipient` derives a host from it and calls `resolve_handle_http`, fetching `https://{attacker-host}/.well-known/atproto-did`, then resolves the DID that returns — which for a `did:web` fetches the attacker's host again.

Same untrusted input, same unguarded client, two further requests. **Fixing only the two named sinks would have left the attestation path exploitable**, which is the whole point of the finding.

## What changed

All three now pass `validate_service_endpoint`: HTTPS only, no address literal in any form a resolver accepts (dotted quad, integer-encoded, bracketed IPv6), no embedded userinfo, no port but 443, and the reserved `.localhost` / `.internal` / `.arpa` / `.local` suffixes refused.

`jwks_uri` needs its own check rather than inheriting `client_id`'s: it comes from the document that first fetch returns, so one hop through a compliant host could otherwise redirect the second anywhere.

The recipient resolver falls back to a stub on any failure, so a refusal is **logged at WARN**. Without that, a guarded host and an unreachable one are indistinguishable — to a later reader, and to the test.

## ⚠️ This is a syntactic guard

It performs no DNS resolution, so it does **not** defend against rebinding, nor against a public name whose A record points at a private address. `validate_service_endpoint`'s own documentation says so.

I am stating it here because "SSRF fixed" is the wrong thing to remember about this change. It closes the syntactic half, which is the layer this workspace has.

## Tests

**`an_unsafe_client_id_is_refused_before_it_is_fetched`** — eight hostile forms through `verify_client_attestation`, asserting each is refused *for its endpoint* and not merely refused. Red before the change, with output that is itself the finding:

```
https://169.254.169.254/cm.json was refused, but not for its endpoint:
aud https://space.example does not target space host did:plc:owner#atproto_space_host
```

The IP literal sailed past the `https://` prefix test and was only stopped later, by an unrelated check.

**`an_unsafe_client_id_host_is_not_dereferenced`** — the resolver returns the same stub whether a host was refused or merely unreachable, so the return value proves nothing. The test asserts on the emitted event instead. Verified red by neutralising the guard:

```
https://169.254.169.254/cm.json was not refused by the endpoint policy — it was
dereferenced and failed on the network instead:
"event crates/atproto-identity/src/resolve.rs:157" ...
```

That `resolve.rs:157` is the request actually going out to `169.254.169.254`.

## Verification

- `cargo fmt --all -- --check` — clean
- `cargo clippy --workspace --all-targets -- -D warnings` — clean
- `cargo test --workspace` — **2136 passed, 0 failed, 63 ignored**
- `cargo check --release --bins -F clap,hickory-dns,zeroize,tokio,smtp` — clean

## Blast radius

`space/mint_authz.rs` and `space/recipient.rs`. A spaces deployment testing against client metadata on an IP literal, a non-443 port, or a `.localhost` host will find those attestations refused — the PAR path has had this constraint since PR #6, the spaces path never has.

## Not fixed here

- **Nineteen other `reqwest::Client` constructions** exist in this crate. Most target operator-configured endpoints (PLC directory, AppView) or DIDs resolved through `atproto-identity`'s own guarded paths, and `proxy_target.rs` was guarded in PR #15. **I have not audited all nineteen**, and would rather say so than imply a clean sweep. A systematic outbound-request audit is worth its own item.
- DNS rebinding, per above. Defending against it needs resolve-then-pin, which is a different piece of work.
