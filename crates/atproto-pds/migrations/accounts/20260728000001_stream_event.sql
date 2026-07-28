-- The firehose stream: one ordered event log for the whole server.
--
-- `seq` in `com.atproto.sync.subscribeRepos` numbers the stream, not a
-- repository. The per-actor `outbox` table cannot express that — its
-- AUTOINCREMENT restarts at 1 in every actor database, so two accounts are
-- both handed seq 1 and a resume cursor is ambiguous.
--
-- This table lives in the accounts DB because that database is server-global
-- and is opened under every storage profile, so one schema serves both SQLite
-- and fjall deployments.
--
-- Allocating `seq` inside the INSERT is what makes the stream monotonic:
-- allocation order is commit order, so a subscriber reading in `seq` order
-- reads in the order events were durably recorded. A counter handed out ahead
-- of the write could be committed out of order.
CREATE TABLE stream_event (
    seq              INTEGER PRIMARY KEY AUTOINCREMENT,
    did              TEXT NOT NULL,
    event_type       TEXT NOT NULL,
    payload          BLOB NOT NULL,
    created_at       TEXT NOT NULL
);

-- Subscribers filtering to one repository still page by seq.
CREATE INDEX idx_stream_event_did ON stream_event(did, seq);
