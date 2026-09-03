Test-only RSA key for the auth-gateway token tests. Never used outside
`cargo test`. Regenerate with `jose.generateKeyPair("RS256")` and keep
`kid: "test-key-1"` — the tests name it.
