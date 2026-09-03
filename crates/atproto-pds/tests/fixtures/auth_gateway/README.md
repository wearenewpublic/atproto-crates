Test-only RSA keys for the auth-gateway token tests. Never used outside
`cargo test`.

- `private.pem` / `jwks.json` — the key pair the tests sign gateway tokens
  with. Regenerate with `jose.generateKeyPair("RS256")` and keep
  `kid: "test-key-1"` — the tests name it.
- `other-private.pem` — an unrelated key, used only to prove a token signed
  with the wrong key (while still naming a real `kid`) is refused as a bad
  signature, not accepted. No public counterpart is published; it never
  appears in `jwks.json`.
