/// Configuration for the AT Protocol OAuth Dioxus integration.
///
/// Pass an instance to [`AtprotoOAuthProvider`](crate::components::AtprotoOAuthProvider)
/// to configure the OAuth flow. Server-side values (base URL, signing key seed)
/// are read from environment variables.
#[derive(Debug, Clone, PartialEq)]
pub struct AtprotoOAuthConfig {
    /// The path for the OAuth callback route on the client.
    ///
    /// Must match the route where [`AtprotoOAuthCallback`](crate::components::AtprotoOAuthCallback)
    /// is mounted. Defaults to `/oauth/callback`.
    pub redirect_path: String,

    /// The OAuth scope to request.
    ///
    /// Defaults to `atproto transition:generic`.
    pub scope: String,
}

impl Default for AtprotoOAuthConfig {
    fn default() -> Self {
        Self {
            redirect_path: "/oauth/callback".to_string(),
            scope: "atproto transition:generic".to_string(),
        }
    }
}

impl AtprotoOAuthConfig {
    /// Creates a new configuration with default scope and the given redirect path.
    pub fn new(redirect_path: impl Into<String>) -> Self {
        Self {
            redirect_path: redirect_path.into(),
            scope: "atproto transition:generic".to_string(),
        }
    }

    /// Sets the OAuth scope.
    pub fn with_scope(mut self, scope: impl Into<String>) -> Self {
        self.scope = scope.into();
        self
    }
}
