-- Vigil SQLite schema, migration 0001. Applied inside a transaction; sets PRAGMA user_version = 1.
-- Connection-level pragmas (set on every open, not part of the migration):
--   PRAGMA journal_mode = WAL; PRAGMA synchronous = NORMAL; PRAGMA foreign_keys = ON; PRAGMA busy_timeout = 5000;
-- Timestamps are UTC, RFC 3339 text. Booleans are 0/1.

CREATE TABLE meta (
  key   TEXT PRIMARY KEY,
  value TEXT NOT NULL
) WITHOUT ROWID;

CREATE TABLE executables (
  id                INTEGER PRIMARY KEY,
  sha256            TEXT NOT NULL CHECK (length(sha256) = 64),
  path              TEXT NOT NULL,
  signer_thumbprint TEXT,
  publisher         TEXT,
  company           TEXT,
  product           TEXT,
  original_filename TEXT,
  signature_status  TEXT NOT NULL CHECK (signature_status IN
                      ('valid_embedded','valid_catalog','unsigned','invalid','expired','revoked','untrusted_root')),
  first_seen        TEXT NOT NULL,
  last_seen         TEXT NOT NULL
);
CREATE UNIQUE INDEX ux_executables_identity
  ON executables (sha256, lower(path), COALESCE(signer_thumbprint, 'unsigned'));
CREATE INDEX ix_executables_sha256 ON executables (sha256);
CREATE INDEX ix_executables_publisher ON executables (publisher);

CREATE TABLE evaluations (
  id                INTEGER PRIMARY KEY,
  executable_id     INTEGER NOT NULL REFERENCES executables(id) ON DELETE CASCADE,
  score             INTEGER NOT NULL CHECK (score BETWEEN 0 AND 100),
  verdict           TEXT NOT NULL CHECK (verdict IN ('safe','unknown','malicious')),
  hard_rule         TEXT,
  signals_json      TEXT NOT NULL,
  rule_pack_version TEXT NOT NULL,
  source            TEXT NOT NULL CHECK (source IN ('rules','ai','user','cache')),
  evaluated_at      TEXT NOT NULL
);
CREATE INDEX ix_evaluations_exe_time ON evaluations (executable_id, evaluated_at DESC);

CREATE TABLE decisions (
  id                   INTEGER PRIMARY KEY,
  executable_id        INTEGER NOT NULL REFERENCES executables(id) ON DELETE CASCADE,
  action               TEXT NOT NULL CHECK (action IN ('allow','block','kill')),
  scope                TEXT NOT NULL CHECK (scope IN ('once','1h','24h','forever')),
  apply_to             TEXT NOT NULL CHECK (apply_to IN ('file','publisher')),
  publisher_thumbprint TEXT,
  publisher_product    TEXT,
  expires_at           TEXT,
  by                   TEXT NOT NULL CHECK (by IN ('user','ai','rule')),
  actor                TEXT NOT NULL,
  note                 TEXT,
  created_at           TEXT NOT NULL,
  revoked_at           TEXT,
  CHECK (apply_to <> 'publisher' OR publisher_thumbprint IS NOT NULL)
);
CREATE INDEX ix_decisions_exe ON decisions (executable_id, revoked_at);
CREATE INDEX ix_decisions_publisher ON decisions (publisher_thumbprint) WHERE publisher_thumbprint IS NOT NULL;

CREATE TABLE pending (
  id                     INTEGER PRIMARY KEY,
  executable_id          INTEGER NOT NULL REFERENCES executables(id) ON DELETE CASCADE,
  dest_class             TEXT NOT NULL CHECK (dest_class IN ('private','public','loopback')),
  dest_addr              TEXT NOT NULL,
  dest_port              INTEGER NOT NULL CHECK (dest_port BETWEEN 0 AND 65535),
  dns_name               TEXT,
  created_at             TEXT NOT NULL,
  resolved_at            TEXT,
  resolution_decision_id INTEGER REFERENCES decisions(id)
);
CREATE UNIQUE INDEX ux_pending_open
  ON pending (executable_id, dest_class) WHERE resolved_at IS NULL;

CREATE TABLE connections (
  id            INTEGER PRIMARY KEY,
  executable_id INTEGER REFERENCES executables(id) ON DELETE SET NULL,
  pid           INTEGER NOT NULL,
  proto         TEXT NOT NULL CHECK (proto IN ('tcp','udp')),
  direction     TEXT NOT NULL CHECK (direction IN ('outbound','inbound')),
  local_addr    TEXT NOT NULL,
  local_port    INTEGER NOT NULL,
  remote_addr   TEXT,
  remote_port   INTEGER,
  dns_name      TEXT,
  state         TEXT,
  blocked       INTEGER NOT NULL DEFAULT 0 CHECK (blocked IN (0,1)),
  first_seen    TEXT NOT NULL,
  last_seen     TEXT NOT NULL
);
CREATE INDEX ix_connections_exe_time ON connections (executable_id, first_seen DESC);
CREATE INDEX ix_connections_time ON connections (first_seen);

CREATE TABLE block_records (
  id            INTEGER PRIMARY KEY,
  executable_id INTEGER REFERENCES executables(id) ON DELETE SET NULL,
  sha256        TEXT NOT NULL,
  path          TEXT NOT NULL,
  reason        TEXT NOT NULL,
  respawn_kills INTEGER NOT NULL DEFAULT 0,
  created_at    TEXT NOT NULL,
  removed_at    TEXT
);
CREATE INDEX ix_block_records_sha ON block_records (sha256) WHERE removed_at IS NULL;
CREATE INDEX ix_block_records_path ON block_records (lower(path)) WHERE removed_at IS NULL;

CREATE TABLE trust_publishers (
  id          INTEGER PRIMARY KEY,
  subject_org TEXT NOT NULL,
  thumbprint  TEXT NOT NULL,
  source      TEXT NOT NULL CHECK (source IN ('builtin','user')),
  note        TEXT,
  created_at  TEXT NOT NULL,
  removed_at  TEXT,
  UNIQUE (subject_org, thumbprint)
);

CREATE TABLE persistence_items (
  id          INTEGER PRIMARY KEY,
  kind        TEXT NOT NULL CHECK (kind IN ('run_key','service','scheduled_task','startup_folder',
                                            'wmi_subscription','ifeo','appinit','winlogon','shell_ext')),
  location    TEXT NOT NULL,
  image_path  TEXT,
  command     TEXT,
  args_hash   TEXT,
  owner       TEXT,
  status      TEXT NOT NULL DEFAULT 'found' CHECK (status IN ('found','disabled','deleted','restored')),
  risk_note   TEXT,
  first_seen  TEXT NOT NULL,
  updated_at  TEXT NOT NULL,
  UNIQUE (kind, location)
);

CREATE TABLE persistence_backups (
  id          INTEGER PRIMARY KEY,
  item_id     INTEGER NOT NULL REFERENCES persistence_items(id) ON DELETE CASCADE,
  backup_json TEXT NOT NULL,
  created_at  TEXT NOT NULL
);

CREATE TABLE ai_cache (
  cache_key    TEXT PRIMARY KEY,
  opinion_json TEXT NOT NULL,
  model        TEXT NOT NULL,
  created_at   TEXT NOT NULL,
  expires_at   TEXT NOT NULL
) WITHOUT ROWID;
CREATE INDEX ix_ai_cache_expiry ON ai_cache (expires_at);

CREATE TABLE ai_opinions (
  id                  INTEGER PRIMARY KEY,
  executable_id       INTEGER NOT NULL REFERENCES executables(id) ON DELETE CASCADE,
  verdict             TEXT NOT NULL CHECK (verdict IN ('safe','unknown','malicious')),
  confidence          REAL NOT NULL CHECK (confidence BETWEEN 0 AND 1),
  recommended_action  TEXT NOT NULL CHECK (recommended_action IN ('allow','block','ask_user','kill')),
  reasons_json        TEXT NOT NULL,
  indicators_json     TEXT NOT NULL,
  model               TEXT NOT NULL,
  payload_sha256      TEXT NOT NULL,
  applied_decision_id INTEGER REFERENCES decisions(id),
  created_at          TEXT NOT NULL
);
CREATE INDEX ix_ai_opinions_exe ON ai_opinions (executable_id, created_at DESC);

CREATE TABLE settings (
  key   TEXT PRIMARY KEY,
  value BLOB NOT NULL
) WITHOUT ROWID;

CREATE TABLE audit_log (
  seq          INTEGER PRIMARY KEY,
  ts           TEXT NOT NULL,
  actor        TEXT NOT NULL,
  kind         TEXT NOT NULL CHECK (kind IN ('service_start','service_stop','mode_change','verdict','decision',
                 'decision_revoked','kill','respawn_kill','filter_add','filter_remove','panic','ai_decision',
                 'ai_config','rule_change','trust_change','persistence_action','client_connect',
                 'config_change','health','audit_checkpoint')),
  target       TEXT,
  details_json TEXT NOT NULL,
  prev_hash    BLOB NOT NULL CHECK (length(prev_hash) = 32),
  hash         BLOB NOT NULL CHECK (length(hash) = 32)
);
CREATE INDEX ix_audit_time ON audit_log (ts);
CREATE INDEX ix_audit_kind ON audit_log (kind, ts);

-- Audit rows are append-only: block UPDATE and DELETE at the SQL level (purge writes a checkpoint, then uses a
-- dedicated maintenance connection that drops and recreates these triggers inside one transaction).
CREATE TRIGGER trg_audit_no_update BEFORE UPDATE ON audit_log
BEGIN SELECT RAISE(ABORT, 'audit_log is append-only'); END;
CREATE TRIGGER trg_audit_no_delete BEFORE DELETE ON audit_log
BEGIN SELECT RAISE(ABORT, 'audit_log is append-only'); END;

INSERT INTO meta (key, value) VALUES ('schema', '1');

PRAGMA user_version = 1;
