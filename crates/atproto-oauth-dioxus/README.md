# atproto-oauth-dioxus

Dioxus fullstack integration for AT Protocol OAuth authentication.

This crate wraps the `atproto-oauth` and `atproto-identity` crates into ergonomic Dioxus components, hooks, and server functions, providing a turnkey OAuth PKCE + DPoP flow for Dioxus fullstack apps.

## Quick Start

### 1. Add the dependency

```toml
[dependencies]
atproto-oauth-dioxus = "0.15"

[features]
server = ["atproto-oauth-dioxus/server"]
```

### 2. Define the callback route

```rust
use dioxus::prelude::*;
use atproto_oauth_dioxus::components::AtprotoOAuthCallback;

#[derive(Routable, Clone, PartialEq)]
enum Route {
    #[route("/oauth/callback")]
    AtprotoOAuthCallback {},
    #[route("/")]
    Home {},
}
```

> If you prefer the shorter name `OAuthCallback`, alias the import:
> `use atproto_oauth_dioxus::components::AtprotoOAuthCallback as OAuthCallback;`

### 3. Wrap your app with the provider

```rust
use atproto_oauth_dioxus::components::AtprotoOAuthProvider;
use atproto_oauth_dioxus::config::AtprotoOAuthConfig;

#[component]
fn App() -> Element {
    rsx! {
        AtprotoOAuthProvider {
            config: AtprotoOAuthConfig::new("/oauth/callback"),
            Router::<Route> {}
        }
    }
}
```

### 4. Add login to your page

```rust
use dioxus::prelude::*;
use atproto_oauth_dioxus::hooks::do_atproto_login;

#[component]
fn LoginPage() -> Element {
    let mut handle = use_signal(String::new);
    let auth_url = use_signal(|| None::<String>);
    let error = use_signal(|| None::<String>);
    let is_loading = use_signal(|| false);

    rsx! {
        input {
            placeholder: "you.bsky.social",
            oninput: move |e| handle.set(e.value()),
            disabled: is_loading(),
        }
        button {
            disabled: is_loading() || handle.read().is_empty(),
            onclick: move |_| do_atproto_login(handle(), auth_url, error, is_loading),
            if is_loading() { "Connecting..." } else { "Login with AT Protocol" }
        }
        if let Some(url) = auth_url.read().as_ref() {
            a { href: "{url}", "Continue to Authorization" }
        }
        if let Some(err) = error.read().as_ref() {
            p { "{err}" }
        }
    }
}
```

### 5. Show session state elsewhere

```rust
use dioxus::prelude::*;
use atproto_oauth_dioxus::types::SessionState;
use atproto_oauth_dioxus::hooks::do_atproto_logout;

#[component]
fn UserMenu() -> Element {
    let session = use_context::<Signal<SessionState>>();

    rsx! {
        span { "Logged in as {session.read().handle}" }
        button {
            onclick: move |_| do_atproto_logout(session),
            "Log out"
        }
    }
}
```

## Server Configuration

Set environment variables for production:

| Variable | Purpose |
|----------|---------|
| `OAUTH_KEY_SEED` | 64 hex chars (32 bytes) seed for the P-256 signing key. Restoring the same seed on restart regenerates the identical key. |
| `HOST_DOMAIN` or `RAILWAY_PUBLIC_DOMAIN` | The public hostname used to construct the OAuth `client_id` and `redirect_uri`. |

## Features

| Feature | Description |
|---------|-------------|
| `server` | Enables server-side OAuth logic (DID resolution, PAR, token exchange, session storage). Required for `#[server]` functions. |
| `hickory-dns` | Enables Hickory DNS resolver for handle-to-DID resolution (passthrough to `atproto-identity`). |

## Making Authenticated PDS Calls

After login, server functions can retrieve the active session (including the DPoP key) to make authenticated calls to the user's PDS:

```rust
use atproto_oauth_dioxus::server::get_active_session;
use atproto_oauth::dpop::request_dpop;
use atproto_identity::url::build_url;

pub async fn call_pds(did: &str) -> Result<(), String> {
    let session = get_active_session(did)
        .await
        .ok_or("No active session")?;

    let url = build_url(&session.pds_endpoint, "/xrpc/com.atproto.repo.describeRepo", [("repo", did)])
        .map_err(|e| e.to_string())?
        .to_string();

    let (dpop_token, _, _) = request_dpop(&session.dpop_key, "GET", &url, &session.access_token)
        .map_err(|e| format!("DPoP error: {}", e))?;

    // Make the request with Authorization: DPoP {access_token} and DPoP: {dpop_token}
    // ...
}
```

## How It Works

1. User enters their AT Protocol handle (e.g. `you.bsky.social`)
2. Server resolves the handle to a DID and discovers the user's PDS OAuth endpoints
3. Server initiates a Pushed Authorization Request (PAR) and returns an authorization URL
4. Client redirects the user to their PDS to approve the app
5. PDS redirects back to `/oauth/callback?code=...&state=...`
6. `AtprotoOAuthCallback` component extracts the code and state, calls the server to exchange for tokens
7. Session is persisted to `localStorage` and provided via Dioxus context

## License

MIT (same as the atproto-crates workspace).
