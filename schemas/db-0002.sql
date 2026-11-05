-- Migration 0002: local baselines (docs/18 §2). Learned only from validly signed or user-allowed
-- parents; counts how often a parent image started a child image on this machine.
CREATE TABLE baselines (
  parent_key TEXT NOT NULL,
  child_key  TEXT NOT NULL,
  count      INTEGER NOT NULL DEFAULT 1,
  first_seen TEXT NOT NULL,
  last_seen  TEXT NOT NULL,
  PRIMARY KEY (parent_key, child_key)
);

PRAGMA user_version = 2;
