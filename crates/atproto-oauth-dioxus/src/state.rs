use crate::types::SessionState;

/// localStorage key for persisting the AT Protocol OAuth session.
#[cfg(target_arch = "wasm32")]
const SESSION_STORAGE_KEY: &str = "atproto-oauth-session";

/// Attempts to load a persisted session from localStorage.
///
/// Returns `None` if no session is stored or if deserialization fails.
#[cfg(target_arch = "wasm32")]
pub fn load_session() -> Option<SessionState> {
    let storage = web_sys::window()?.local_storage().ok()??;
    let json = storage.get_item(SESSION_STORAGE_KEY).ok()??;
    serde_json::from_str(&json).ok()
}

/// Persists the session state to localStorage.
#[cfg(target_arch = "wasm32")]
pub fn save_session(state: &SessionState) {
    if let (Some(storage), Ok(json)) = (
        web_sys::window()
            .and_then(|w| w.local_storage().ok())
            .flatten(),
        serde_json::to_string(state),
    ) {
        let _ = storage.set_item(SESSION_STORAGE_KEY, &json);
    }
}

/// Removes the persisted session from localStorage.
#[cfg(target_arch = "wasm32")]
pub fn clear_session() {
    if let Some(storage) = web_sys::window()
        .and_then(|w| w.local_storage().ok())
        .flatten()
    {
        let _ = storage.remove_item(SESSION_STORAGE_KEY);
    }
}

/// Stub for non-WASM targets (SSR/server rendering).
#[cfg(not(target_arch = "wasm32"))]
pub fn load_session() -> Option<SessionState> {
    None
}

/// Stub for non-WASM targets.
#[cfg(not(target_arch = "wasm32"))]
pub fn save_session(_state: &SessionState) {}

/// Stub for non-WASM targets.
#[cfg(not(target_arch = "wasm32"))]
pub fn clear_session() {}
