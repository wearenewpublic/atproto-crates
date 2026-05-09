-- — drop two dead-schema tables.
--
-- §2.1 `oauth_session`: superseded by the `oauth_par` / `oauth_code` /
--      `oauth_refresh` triple in `20260505000003_oauth_state.sql`. The
--      original column shape (client_id, dpop_jkt, scope, issued_at,
--      expires_at, refreshed_at) is exactly the rotation-handle shape
--      that `oauth_refresh` now owns. There is no per-XRPC-call session
--      use case for this table — OAuth 2.1 access tokens are stateless
--      bearer JWTs (RFC 6749 §10.3, RFC 9449 §4); validating them via a
--      DB lookup would deviate from spec and double the auth-path floor.
--
-- §2.2 `plc_op_token`: never written. The `requestPlcOperationSignature`
--      handler (PR11) issues a self-signed service-auth JWT directly;
--      revocation can use `service_auth_blacklist` for the matching
--      `lxm=com.atproto.identity.signPlcOperation` JTI.
--
-- Existing rows: there are none — these tables were never written by any
-- production path. Drop is safe; no backfill needed.

DROP INDEX IF EXISTS idx_oauth_session_did;
DROP INDEX IF EXISTS idx_oauth_session_expires;
DROP TABLE IF EXISTS oauth_session;

DROP TABLE IF EXISTS plc_op_token;
