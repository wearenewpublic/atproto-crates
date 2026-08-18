# atproto-space-client

XRPC client for AT Protocol permissioned-data spaces — the 0016 credential
exchange, subscriptions, and space management.

## Why this is a separate crate

`atproto-space` implements the 0016 primitives and states in its own
documentation that it is server-agnostic and has no network dependencies. That
is the right shape for a PDS, which composes with it through storage traits.
A `client` feature would make the guarantee conditional; a sibling crate keeps
it unconditional, and a consumer that wants both writes one more line.

## The credential chain

Reading a space someone else hosts takes three calls to **two** servers:

1. `getDelegationToken` — at the **member's own PDS**. OAuth-gated, and it
   refuses an app-password session: the token asserts that an application is
   acting for this user, which a password session cannot express.
2. `getSpaceCredential` — at the **authority**. The delegation token travels as
   a `Bearer` with a DPoP proof beside it; the credential comes back bound to
   that proof's key.
3. `registerNotify` — at the **authority**. The credential travels under the
   `DPoP` scheme with a proof of possession.

Which call goes to which server is not obvious, which is why `SpaceHosts` names
both rather than taking two `&str` parameters. A single host standing in for
both is a bug that shipped once and was invisible for as long as every space
was the account's own — there the member *is* the authority and the two
strings are equal.

```rust,ignore
use atproto_space_client::{Delivery, SpaceHosts, subscribe_to_space};

let subscription = subscribe_to_space(
    &http,
    SpaceHosts { member_pds: "https://pds.example", authority: "https://authority.example" },
    &dpop_key,
    &access_token,
    &space_uri,
    Delivery::Service("did:web:syncer.example#atproto_space_syncer"),
    None,
).await?;

// Read from the answer, never assumed.
println!("registration expires at {}", subscription.expires_at);
```

## Bound and Grant

Hops 1 and 3 present a token *bound* to the session key: `Authorization: DPoP`,
and the proof carries `ath` over it. Hop 2 presents a *grant*:
`Authorization: Bearer`, and the proof carries **no** `ath` — there is no bound
token to hash, and the proof is there to demonstrate possession of the key the
answer will be bound to.

Getting this backwards produces `401 missing DPoP header` from a server that
was never asked about membership.

## Things worth knowing before you debug something

- **Hop 2 is where a wrong guess is silent for a while.** The proof is verified
  *before* the delegation token, deliberately, so a caller with a bad proof does
  not burn its single-use grant finding out — which also means a missing proof
  answers `InvalidDpopProof` and never reaches the part of the exchange that
  would say anything about membership.
- **The thumbprint is demonstrated, not asserted.** `dpopJkt` used to travel in
  the hop-2 body and was removed: it is a claim anyone holding a delegation
  token can make about a key somebody else controls. The authority takes it
  from the verified proof's own `jwk`.
- **`expiresAt` is read from the answer.** `atproto-pds` takes it from a setting
  clamped to 60 seconds…365 days, so a client assuming 24 hours would silently
  stop receiving deliveries across most of that range.
- **Validate the delivery target before you start.** `subscribe_to_space` does.
  Hops 1 and 2 spend a single-use grant, and finding out at hop 3 that the
  target was never registrable burns it to learn something knowable up front.

## License

MIT
