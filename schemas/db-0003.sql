-- Migration 0003: package-family decisions (docs/19 §5.1). A uv/pip launcher whose metadata names a
-- trusted source records its family ("<source prefix>|<tools folder>"); a decision with apply_to
-- 'package_source' covers every executable of that family. SQLite cannot alter a CHECK
-- constraint, so the decisions table is rebuilt; the caller turns foreign keys off around it.
ALTER TABLE executables ADD COLUMN package_family TEXT;
CREATE INDEX ix_executables_family ON executables (package_family) WHERE package_family IS NOT NULL;

CREATE TABLE decisions_0003 (
  id                   INTEGER PRIMARY KEY,
  executable_id        INTEGER NOT NULL REFERENCES executables(id) ON DELETE CASCADE,
  action               TEXT NOT NULL CHECK (action IN ('allow','block','kill')),
  scope                TEXT NOT NULL CHECK (scope IN ('once','1h','24h','forever')),
  apply_to             TEXT NOT NULL CHECK (apply_to IN ('file','publisher','package_source')),
  publisher_thumbprint TEXT,
  publisher_product    TEXT,
  package_family       TEXT,
  expires_at           TEXT,
  by                   TEXT NOT NULL CHECK (by IN ('user','ai','rule')),
  actor                TEXT NOT NULL,
  note                 TEXT,
  created_at           TEXT NOT NULL,
  revoked_at           TEXT,
  CHECK (apply_to <> 'publisher' OR publisher_thumbprint IS NOT NULL),
  CHECK (apply_to <> 'package_source' OR package_family IS NOT NULL)
);
INSERT INTO decisions_0003 (id, executable_id, action, scope, apply_to, publisher_thumbprint,
                            publisher_product, expires_at, by, actor, note, created_at, revoked_at)
  SELECT id, executable_id, action, scope, apply_to, publisher_thumbprint, publisher_product,
         expires_at, by, actor, note, created_at, revoked_at
  FROM decisions;
DROP TABLE decisions;
ALTER TABLE decisions_0003 RENAME TO decisions;
CREATE INDEX ix_decisions_exe ON decisions (executable_id, revoked_at);
CREATE INDEX ix_decisions_publisher ON decisions (publisher_thumbprint) WHERE publisher_thumbprint IS NOT NULL;
CREATE INDEX ix_decisions_family ON decisions (package_family) WHERE package_family IS NOT NULL;

PRAGMA user_version = 3;
