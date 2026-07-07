use dioxus::prelude::*;

use crate::config::AtprotoOAuthConfig;
use crate::types::SessionState;

#[cfg(target_arch = "wasm32")]
use crate::state;

/// Root component that provides AT Protocol OAuth session state to all children.
///
/// Wrap your app's [`Router`] or root element with this component to enable
/// OAuth authentication. It provides a reactive [`SessionState`] via Dioxus
/// context and automatically restores the session from `localStorage` on mount.
///
/// # Example
///
/// ```rust,ignore
/// use atproto_oauth_dioxus::components::AtprotoOAuthProvider;
/// use atproto_oauth_dioxus::config::AtprotoOAuthConfig;
///
/// fn App() -> Element {
///     rsx! {
///         AtprotoOAuthProvider {
///             config: AtprotoOAuthConfig::new("/oauth/callback"),
///             Router::<Route> {}
///         }
///     }
/// }
/// ```
#[component]
pub fn AtprotoOAuthProvider(config: AtprotoOAuthConfig, children: Element) -> Element {
    #[cfg_attr(not(target_arch = "wasm32"), allow(unused_mut, unused_variables))]
    let mut session = use_signal(SessionState::default);
    use_context_provider(|| session);

    let _ = config;

    use_effect(move || {
        #[cfg(target_arch = "wasm32")]
        {
            if !session.read().is_authenticated {
                if let Some(stored) = state::load_session() {
                    session.set(stored);
                }
            }
        }
    });

    rsx! { {children} }
}

/// Component that handles the OAuth callback redirect.
///
/// Mount this at the route matching your configured `redirect_path`
/// (typically `/oauth/callback`). It reads the `code` and `state`
/// query parameters from the URL, calls the `complete_atproto_oauth`
/// server function, updates the session state, and navigates to the
/// home route on success.
///
/// # Example
///
/// ```rust,ignore
/// #[derive(Routable)]
/// enum Route {
///     #[route("/oauth/callback")]
///     OAuthCallback {}, // mounts AtprotoOAuthCallback
///     #[route("/")]
///     Home {},
/// }
/// ```
#[component]
pub fn AtprotoOAuthCallback() -> Element {
    #[cfg_attr(not(target_arch = "wasm32"), allow(unused_mut))]
    let mut status = use_signal(|| "Processing login...".to_string());
    #[cfg_attr(not(target_arch = "wasm32"), allow(unused_mut))]
    let mut done = use_signal(|| false);
    #[cfg_attr(not(target_arch = "wasm32"), allow(unused_mut))]
    let mut err = use_signal(String::new);

    #[cfg_attr(not(target_arch = "wasm32"), allow(unused_mut, unused_variables))]
    let mut session = use_context::<Signal<SessionState>>();

    use_effect(move || {
        #[cfg(target_arch = "wasm32")]
        {
            let params = extract_query_params();
            if let (Some(code), Some(state)) = (params.get("code"), params.get("state")) {
                let code = code.clone();
                let state = state.clone();
                spawn(async move {
                    match crate::server_fns::complete_atproto_oauth(code, state).await {
                        Ok(session_data) => {
                            session.write().did = session_data.did.clone();
                            session.write().handle = session_data.handle.clone();
                            session.write().pds_endpoint = session_data.pds_endpoint.clone();
                            session.write().access_token = session_data.access_token.clone();
                            session.write().is_authenticated = true;

                            state::save_session(&session.read().clone());

                            status.set("Login successful! Redirecting...".to_string());
                            done.set(true);

                            let nav = navigator();
                            nav.push("/");
                        }
                        Err(e) => {
                            err.set(format!("Login failed: {}", e));
                        }
                    }
                });
            } else {
                err.set("Missing code or state parameter in callback URL".to_string());
            }
        }
    });

    if !err.read().is_empty() {
        return rsx! {
            div {
                h1 { "Login Failed" }
                p { "{err}" }
                a { href: "/", "Try Again" }
            }
        };
    }

    rsx! {
        div {
            h1 {
                if done() { "Welcome!" } else { "Logging in..." }
            }
            p { "{status}" }
        }
    }
}

/// Extracts query parameters from the current browser URL.
#[allow(dead_code)]
#[cfg(target_arch = "wasm32")]
fn extract_query_params() -> std::collections::HashMap<String, String> {
    let window = web_sys::window().expect("no window");
    let location = window.location();
    let search = location.search().unwrap_or_default();
    if search.is_empty() {
        return std::collections::HashMap::new();
    }
    let query = search.trim_start_matches('?');
    url::form_urlencoded::parse(query.as_bytes())
        .into_owned()
        .collect()
}

/// Stub for non-WASM targets (SSR).
#[cfg(not(target_arch = "wasm32"))]
#[allow(dead_code)]
fn extract_query_params() -> std::collections::HashMap<String, String> {
    std::collections::HashMap::new()
}
