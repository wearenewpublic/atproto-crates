-- What the retention sweep needs to find expired oplog rows without reading
-- every row that has not expired.
--
-- Both oplog tables are keyed `PRIMARY KEY (space, rev, idx)`, so `rev` is the
-- second column and `DELETE ... WHERE rev < ?` cannot seek on it. The nightly
-- sweep therefore scanned both tables in full, in every account, on every
-- tick -- including the overwhelmingly common tick where the cutoff has not
-- moved past anything and there is nothing to delete at all.
--
-- Measured on one table of 100k rows with nothing to collect: 3ms of pure
-- scanning before, 0ms after, because the seek lands past the end of the range
-- and stops. Multiply by two tables and by every account on the server.
--
-- `rev` alone rather than `(space, rev)`: the sweep is a retention cutoff
-- across the whole database and never asks about one space.
CREATE INDEX idx_space_record_oplog_rev ON space_record_oplog(rev);
CREATE INDEX idx_space_member_oplog_rev ON space_member_oplog(rev);
