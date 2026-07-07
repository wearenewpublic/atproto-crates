use dioxus::prelude::*;

use crate::state;
use crate::types::SessionState;

/// Reactive handle for the AT Protocol OAuth authentication state.
///
/// Returned by [`use_atproto_auth`]. All fields are reactive signals
/// that components can read and write. The struct is `Clone + Copy`
/// for ergonomic use in event handlers and async closures.
#[derive(Clone, Copy)]
pub struct AtprotoAuthHandle {
    /// The current session state. Provided via Dioxus context.
    pub session: Signal<SessionState>,
    /// The authorization URL to redirect the user to, if a login is in progress.
    pub authorization_url: Signal<Option<String>>,
    /// An error message, if the last login attempt failed.
    pub error: Signal<Option<String>>,
    /// Whether a login request is currently in progress.
    pub is_loading: Signal<bool>,
}

/// Hook that returns the AT Protocol OAuth reactive state.
///
/// Must be called within a component tree that has an
/// [`AtprotoOAuthProvider`](crate::components::AtprotoOAuthProvider) ancestor.
///
/// # Panics
///
/// Panics if no `Signal<SessionState>` is found in the Dioxus context.
pub fn use_atproto_auth() -> AtprotoAuthHandle {
    let session = use_context::<Signal<SessionState>>();
    let authorization_url = use_signal(|| None::<String>);
    let error = use_signal(|| None::<String>);
    let is_loading = use_signal(|| false);

    AtprotoAuthHandle {
        session,
        authorization_url,
        error,
        is_loading,
    }
}

/// Initiates a login by calling the `init_atproto_oauth` server function.
///
/// Updates the provided signals with the authorization URL on success
/// or an error message on failure.
pub fn do_atproto_login(
    handle: String,
    mut authorization_url: Signal<Option<String>>,
    mut error: Signal<Option<String>>,
    mut is_loading: Signal<bool>,
) {
    if handle.is_empty() {
        return;
    }
    is_loading.set(true);
    error.set(None);
    spawn(async move {
        match crate::server_fns::init_atproto_oauth(handle).await {
            Ok(resp) => {
                authorization_url.set(Some(resp.authorization_url));
                is_loading.set(false);
            }
            Err(e) => {
                error.set(Some(format!("Login failed: {}", e)));
                is_loading.set(false);
            }
        }
    });
}

/// Processes the OAuth callback by calling the `complete_atproto_oauth`
/// server function and updating the session state on success.
pub fn do_atproto_complete_login(
    code: String,
    state: String,
    mut session: Signal<SessionState>,
    mut error: Signal<Option<String>>,
) {
    spawn(async move {
        match crate::server_fns::complete_atproto_oauth(code, state).await {
            Ok(session_data) => {
                session.write().did = session_data.did.clone();
                session.write().handle = session_data.handle.clone();
                session.write().pds_endpoint = session_data.pds_endpoint.clone();
                session.write().access_token = session_data.access_token.clone();
                session.write().is_authenticated = true;

                state::save_session(&session.read().clone());

                error.set(None);
            }
            Err(e) => {
                error.set(Some(format!("Login failed: {}", e)));
            }
        }
    });
}

/// Logs the user out by clearing the session state and localStorage.
pub fn do_atproto_logout(mut session: Signal<SessionState>) {
    state::clear_session();
    session.set(SessionState::default());
}
