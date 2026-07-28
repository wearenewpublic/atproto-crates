-- The firehose stream: one ordered event log for the whole server.
--
-- Postgres counterpart of the accounts-DB `stream_event` table. See
-- `migrations/accounts/20260728000001_stream_event.sql` for why the log is
-- server-global and why `seq` is allocated by the INSERT rather than ahead of
-- it.
CREATE TABLE stream_event (
    seq              BIGSERIAL PRIMARY KEY,
    did              TEXT NOT NULL,
    event_type       TEXT NOT NULL,
    payload          BYTEA NOT NULL,
    created_at       TEXT NOT NULL
);

CREATE INDEX idx_stream_event_did ON stream_event(did, seq);
