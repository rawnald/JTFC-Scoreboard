CREATE TABLE IF NOT EXISTS ops (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  op_date TEXT NOT NULL,            -- YYYY-MM-DD
  unit TEXT NOT NULL,               -- e.g. 602nd Bde
  area TEXT NOT NULL,               -- e.g. Region XII
  threat_group TEXT NOT NULL,       -- e.g. BIFF
  surrendered INTEGER DEFAULT 0,
  killed INTEGER DEFAULT 0,
  captured INTEGER DEFAULT 0,
  apprehended INTEGER DEFAULT 0,
  firearms INTEGER DEFAULT 0,
  tolf INTEGER DEFAULT 0,           -- loose firearms turned over
  kia INTEGER DEFAULT 0,
  wia INTEGER DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_ops_date ON ops(op_date);
CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT);
INSERT OR IGNORE INTO settings VALUES ('firearms_target','200');
