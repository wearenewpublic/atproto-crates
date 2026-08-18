# atproto-firehose

A `com.atproto.sync.subscribeRepos` consumer: frame decoding, commit
verification, and a reconnecting stream.

## Why this exists

The AT Protocol firehose is a binary WebSocket stream carrying every
repository change on the network. Reading it means decoding a two-object frame
format, deciding which of five event types you are looking at, and — if you
intend to act on what you read — proving that the repository actually signed
it.

Every app view that wants full-fidelity verified events ends up writing that.
This is it, written once.

## Features

- **Two-stage commit decoding.** `ops[].path` lives in the outer payload next
  to `blocks`, so a consumer can decide whether it cares before paying for the
  CAR. On a firehose that is overwhelmingly `app.bsky.feed.post`, this is the
  difference between a consumer that is affordable and one that is not.

- **The five-member union, as it is today.** `#commit`, `#sync`, `#identity`,
  `#account`, `#info`. `#handle`, `#migrate` and `#tombstone` were removed from
  the lexicon, not deprecated in place, and are reported as unknown.

- **Three verification levels.** Trust the relay, check the signature, or
  additionally prove that the tree walks from the root the commit signed and
  that every op describes it truthfully — the last being the half that
  inductive verification alone cannot give you.

- **A cursor that never leads its writes.** The sink says when a write is
  durable; only then does the cursor move. A crash re-processes one commit
  rather than skipping one.

## Installation

```toml
[dependencies]
atproto-firehose = "0.15.0-rc.4"
```

## Usage

```rust,ignore
use atproto_firehose::consumer::{ConsumerConfig, FirehoseConsumer};
use atproto_firehose::verify::VerificationLevel;

let config = ConsumerConfig::new("https://bsky.network")
    .collections(vec!["app.bsky.feed.post".to_string()])
    .verification(VerificationLevel::Full);

let consumer = FirehoseConsumer::new(config, my_sink, my_cursors, my_resolver);
consumer.run(shutdown).await?;
```

Three seams are yours to fill:

- `IngestSink` — where events go, and when they are durable.
- `CursorStore` — where the resume position lives.
- `SigningKeyResolver` — how a repository DID becomes a signing key, and how
  long that answer stays good.

The last one is a trait rather than a concrete resolver because the caching is
the caller's: a firehose consumer resolves the same few thousand DIDs
repeatedly, and the right policy depends on whether the consumer also watches
`#identity`.

## What this crate does not do

- **Backfill.** An `OutdatedCursor` notice tells the sink there is a gap and
  clears the stored cursor. Closing the gap is `com.atproto.sync.getRepo` and
  your own reconciliation.
- **Proposal 0015 framing.** The `xrpc.v1.json` and `xrpc.v1.cbor`
  subprotocols exist and are not negotiated here, so they are never received.
- **Jetstream.** That is a different, simpler, JSON stream — see
  `atproto-jetstream`.

## License

MIT
