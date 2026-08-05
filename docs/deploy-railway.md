# Deploying atproto-pds on Railway

Written against a real deployment: `vesuvius.pyroclastic.cloud`, issuing
handles under `*.dids.lol`, one container, one volume, Mailgun for outbound
mail.

Substitute your own hostnames. Everything else applies as written.

## What you are deploying

One process and one writable volume. Everything durable — the accounts
database, each actor's own SQLite store, blobs, and the key store — lives
under `PDS_DATA_DIRECTORY`. There is no second service to run.

`Dockerfile.pds` at the repository root builds it. The other `Dockerfile`
builds the CLI tools and does **not** build the server; deploying that one and
expecting a PDS is the mistake this note exists to prevent.

---

## 1. Railway service

Point the service at this repository. `railway.toml` names the Dockerfile,
the health check and the replica count, so there is nothing to configure by
hand there.

**Volume.** Attach one, mounted at `/data`. That path is the image's
`PDS_DATA_DIRECTORY` default, so no variable is needed to match them.

**Replicas.** One. `railway.toml` pins this, and it is a correctness setting
rather than a capacity one: SQLite is the durable store, the volume attaches
to a single instance, and two replicas would run against separate copies of
the same repositories — both signing commits into divergent histories under
one DID.

**Port.** Do not set `PDS_PORT`. The image deliberately leaves it unset so the
binary falls back to the platform's `PORT`.

> Check this before the first deploy. Railway's networking panel shows the
> port it routes to — 8080 in this deployment. If Railway does not also inject
> `PORT=8080`, the server binds its own 4800 default, Railway routes to 8080,
> and the health check times out with nothing in the log to explain it. Either
> confirm `PORT` is injected, or set `PORT=8080` explicitly. Setting
> `PDS_PORT` instead would *appear* to work and would defeat the fallback.

---

## 2. Environment

### Identity and handles

```
PDS_SERVICE_DID=did:web:vesuvius.pyroclastic.cloud
PDS_HOSTNAME=vesuvius.pyroclastic.cloud
PDS_SERVICE_HANDLE_DOMAINS=dids.lol
```

`PDS_SERVICE_HANDLE_DOMAINS` may be written with or without a leading dot;
`describeServer` advertises the dotted form either way, which is what clients
concatenate against.

### PLC directory

```
PDS_DID_PLC_URL=https://plc.directory
```

**Every account created against this is permanent and public.** The PLC
directory is an append-only log; a DID created by a stray test cannot be
withdrawn, and its `alsoKnownAs` is visible to anyone. Keep invites required
from the first boot so that nobody — including you, by accident — creates one
before you mean to.

### Secrets

```
PDS_JWT_SECRET=<32+ bytes of randomness>
PDS_ADMIN_PASSWORD=<long random string>
PDS_PRODUCTION=true
PDS_DURABILITY_PROFILE=sql
```

`PDS_JWT_SECRET` must be at least 32 bytes; the server refuses to start
otherwise. `PDS_PRODUCTION=true` additionally refuses sentinel secrets,
`did:web:localhost`, and the in-memory durability profile — it is a guard
against deploying a development configuration by accident.

### Administration by DID

```
PDS_ADMIN_DIDS=did:plc:cbkjy5n7bk3ax2wplmtjofq2
PDS_INVITE_REQUIRED=true
```

The DID above is `@ngerakines.me`. It needs no account on this server. With
it set, that identity can mint invite codes by signing a service-auth token
with the `#atproto` key in its own DID document — see §5.

### Behind Cloudflare

```
PDS_TRUSTED_PROXY_HOPS=1
```

Railway reports "Cloudflare proxy detected" for both domains, which means
every request reaches the server from a Cloudflare address. Left at the
default `0`, the rate limiter uses the TCP peer address, sees one client, and
throttles all of your users as though they were a single caller.

Set to the number of proxies **you** operate. `1` is right for Cloudflare in
front of Railway. Do not inflate it: the client address is taken that many
entries from the right of `X-Forwarded-For`, and a number larger than the real
chain lets a caller forge their own address by prepending entries.

### Mail

```
PDS_EMAIL_SMTP_URL=smtps://postmaster%40mg.pyroclastic.cloud:<key>@smtp.mailgun.org:465
PDS_EMAIL_FROM_ADDRESS=noreply@mg.pyroclastic.cloud
```

`smtps://` on 465 is implicit TLS and unambiguous. Port 587 works too, as
`smtp://…:587?tls=required` — but note that `smtp://` with no `tls` parameter
at all is **plaintext**, and `?tls=none` is not a value lettre accepts.

Percent-encode the username: Mailgun's SMTP login is an email address, and the
`@` in it will otherwise be read as the start of the host.

Both variables must be set. With either missing, the server logs a warning at
boot and every mail-gated flow — password reset, email confirmation, account
deletion — reports success and sends nothing.

---

## 3. DNS

### Railway

| record | name | value |
|---|---|---|
| CNAME | `vesuvius.pyroclastic.cloud` | the target Railway gives you |
| CNAME | `*.dids.lol` | the target Railway gives you |

The wildcard is what makes handle resolution work without a record per
account. A handle resolves either by a DNS TXT record at
`_atproto.<handle>` or by an HTTPS `GET /.well-known/atproto-did` against the
handle's own hostname — and the PDS answers the latter for any `Host` it is
asked about. With `*.dids.lol` routed here, `atproto-com-lexicons.dids.lol`
resolves the moment the account exists, with no DNS change.

### Mailgun

Mailgun will give you its own records for the sending domain. All of them
matter, and for different reasons:

- **TXT (SPF)** and **TXT (DKIM)** — without these your confirmation and
  password-reset mail is spam-filtered, which looks exactly like the server
  failing to send.
- **MX** — only needed if you want to receive at the domain.
- **CNAME (tracking)** — optional.

Verify the domain in Mailgun before relying on it. A domain in Mailgun's
"unverified" state accepts SMTP submissions and delivers nothing.

---

## 4. First boot

```
curl https://vesuvius.pyroclastic.cloud/
```

should answer in plain text with the host, DID and version. Then:

```
curl https://vesuvius.pyroclastic.cloud/xrpc/_health
curl https://vesuvius.pyroclastic.cloud/xrpc/com.atproto.server.describeServer
```

`describeServer` should report `did:web:vesuvius.pyroclastic.cloud`,
`availableUserDomains: [".dids.lol"]` and `inviteCodeRequired: true`. If the
DID is wrong here, stop and fix it before creating anything: it is baked into
every account this server issues.

---

## 5. Minting the first invite

There is no account on the server yet, so there is no session to authenticate
with. That is what `PDS_ADMIN_DIDS` is for.

From a machine holding `@ngerakines.me`'s credentials, ask its PDS for a
service-auth token scoped to this server and this one method:

```
com.atproto.server.getServiceAuth
  aud = did:web:vesuvius.pyroclastic.cloud
  lxm = com.atproto.server.createInviteCode
  exp = <a few minutes out>
```

Then present it here:

```
curl -X POST https://vesuvius.pyroclastic.cloud/xrpc/com.atproto.server.createInviteCode \
  -H 'authorization: Bearer <that token>' \
  -H 'content-type: application/json' \
  -d '{"useCount":1}'
```

The response carries the code. The token proves which identity asked, is good
for one method, and expires in minutes — none of which a shared admin password
can claim.

An administrator with no account here mints a code attributed to nobody. That
is intended.

---

## 6. Creating the identity

Open `https://vesuvius.pyroclastic.cloud/account/signup`.

Fill in the handle (`atproto-com-lexicons`), an email address, a password, and
the invite code from §5.

### Bringing your own keys

Expand **Advanced — bring your own keys**. Both fields are optional and
independent.

Generate them with `goat key generate`, which prints a `did:key:z42t…`
string. The bare multibase form is accepted too.

**Signing key** becomes the account's `#atproto` verification method. This
server signs your commits with it, so it must be a *private* key; a public one
is refused with an error saying so. Leave it empty and one is generated.

**Rotation key** is listed **ahead of** this server's own. PLC gives earlier
rotation keys authority over later ones, so yours outranks the server's: you
can move or recover this identity without its cooperation. Only the public
half is used and it is never stored, so pasting the private key — which is
what `goat` gives you — costs you nothing. The server still adds its own key
after yours, so it can keep operating the account normally.

Keep both keys. The rotation key especially: it is the one thing this server
cannot reproduce for you, and it is what makes the identity yours rather than
the server's.

Afterwards, confirm the document says what you expect:

```
curl https://plc.directory/<did>/data
```

`rotationKeys[0]` should be the public form of the key you supplied, with the
server's after it, and `verificationMethods.atproto` should be the public form
of your signing key.

---

## 7. Signing in to Bluesky

At `bsky.app`, choose to sign in with a custom hosting provider and give
`vesuvius.pyroclastic.cloud`. Sign in with the handle and password.

That flow uses OAuth: the client fetches this server's authorization metadata,
pushes an authorization request, redirects you to `/oauth/authorize` here to
approve, and exchanges the code for a DPoP-bound token. If it fails, the
server's log names the reason — the OAuth surface reports specific errors
rather than a generic refusal.

---

## Operational notes

**Backups.** The volume is the whole of it. A copy of `/data` taken while the
server is stopped is a complete backup. Copying it while the server is running
will usually appear to work and can capture a torn SQLite write — the WAL is
mid-flight. Stop, copy, start.

**Never write to the database from outside the container** while the server is
running. SQLite in WAL mode does not tolerate a second writer arriving through
a different mount; the symptom is `disk I/O error` on unrelated queries.

**Upgrades** are a redeploy. Migrations run at startup and are append-only.
Because there is one replica and one volume, the old container must stop
before the new one starts — `overlapSeconds = 0` in `railway.toml` enforces
that; without it the new container cannot mount the volume and the deploy
fails in a way that reads as a build problem.

**Logs.** `RUST_LOG=info` is a reasonable default.
`RUST_LOG=info,atproto_pds=debug` when something is wrong.
