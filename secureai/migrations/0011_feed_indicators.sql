-- SecureAI threat-feed indicators (URLhaus + ThreatFox), versioned denylist.
--
-- The reputation stage matches a scan's final host/URL against known-bad
-- indicators loaded from abuse.ch by the hourly cron. Rows are VERSIONED: each
-- refresh writes a new `version`, atomically flips `feed_meta.current_version`,
-- then drops the superseded rows, so a read JOINed through the pointer only ever
-- sees a complete version (never a partial or empty denylist mid-refresh).
--
-- `kind` is 'host' (a lowercased domain) or 'url' (a normalized host+path+query
-- match key); the two value namespaces are disjoint, so the lookup tests `value`
-- alone. `source` ('urlhaus' | 'threatfox') is kept for attribution only, raw
-- feed rows are never exposed or placed in a proof.

CREATE TABLE IF NOT EXISTS feed_indicators (
  version INTEGER NOT NULL,
  kind    TEXT NOT NULL,
  value   TEXT NOT NULL,
  source  TEXT NOT NULL,
  PRIMARY KEY (version, kind, value)
);

-- The match lookup filters by the current version then tests `value` (kind-
-- agnostic), so index (version, value) to keep it O(log n), never a scan.
CREATE INDEX IF NOT EXISTS idx_feed_indicators_version_value
  ON feed_indicators (version, value);

CREATE TABLE IF NOT EXISTS feed_meta (
  id              INTEGER PRIMARY KEY CHECK (id = 1),
  current_version INTEGER,
  updated_at      TEXT
);

-- Single pointer row, seeded once with no live version (NULL) until the first
-- successful refresh flips it.
INSERT INTO feed_meta (id, current_version, updated_at)
  VALUES (1, NULL, NULL) ON CONFLICT (id) DO NOTHING;
