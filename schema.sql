CREATE TABLE IF NOT EXISTS ops (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  op_date TEXT NOT NULL,            -- YYYY-MM-DD
  unit TEXT NOT NULL,               -- e.g. 602nd Bde
  area TEXT NOT NULL,               -- e.g. Pikit
  province TEXT,                    -- e.g. Cotabato, Maguindanao del Sur
  threat_category TEXT,             -- Local Terrorist Groups (LTG), Communist Terrorist Group (CTG), PIAGs
  threat_group TEXT NOT NULL,       -- e.g. BIFF-PSRL, GF Musa, MILF
  engagement_type TEXT,             -- Government Initiated (Encounter), Enemy Initiated (Ambush, etc.)
  surrendered INTEGER DEFAULT 0,
  killed INTEGER DEFAULT 0,
  enemy_wounded INTEGER DEFAULT 0,
  captured INTEGER DEFAULT 0,
  apprehended INTEGER DEFAULT 0,
  firearms INTEGER DEFAULT 0,       -- Total firearms gained (sum of all categories)
  fa_captured INTEGER DEFAULT 0,    -- Captured total (CSW + HP + LP)
  fa_confiscated INTEGER DEFAULT 0, -- Confiscated total (CSW + HP + LP)
  fa_surrendered INTEGER DEFAULT 0, -- Surrendered total (CSW + HP + LP)
  fa_recovered INTEGER DEFAULT 0,   -- Recovered total (CSW + HP + LP)
  fa_csw INTEGER DEFAULT 0,         -- Total Crew-Served Weapons (.50 cal, M60, Mortar)
  fa_high_powered INTEGER DEFAULT 0,-- Total High Powered Rifles (M16, M14, AK47)
  fa_low_powered INTEGER DEFAULT 0, -- Total Low Powered Firearms (Pistols, Revolvers, Shotguns)
  tolf INTEGER DEFAULT 0,           -- loose firearms turned over
  kia INTEGER DEFAULT 0,
  wia INTEGER DEFAULT 0,
  war_materiel TEXT,
  remarks TEXT
);
CREATE INDEX IF NOT EXISTS idx_ops_date ON ops(op_date);

CREATE TABLE IF NOT EXISTS sleo (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  op_date TEXT NOT NULL,            -- YYYY-MM-DD
  unit TEXT NOT NULL,               -- e.g. 601st Bde
  area TEXT NOT NULL,               -- e.g. Isulan, Sultan Kudarat
  lead_agency TEXT NOT NULL,        -- e.g. PNP, PDEA, NBI, CIDG
  operation_type TEXT NOT NULL,     -- e.g. Anti-Illegal Drugs, Search Warrant
  target_group TEXT,                -- e.g. Drug Syndicate, Lawless Group
  arrested INTEGER DEFAULT 0,
  killed INTEGER DEFAULT 0,
  enemy_wounded INTEGER DEFAULT 0,
  surrendered INTEGER DEFAULT 0,
  captured INTEGER DEFAULT 0,
  apprehended INTEGER DEFAULT 0,
  firearms_seized INTEGER DEFAULT 0,
  fa_csw INTEGER DEFAULT 0,
  fa_high_powered INTEGER DEFAULT 0,
  fa_low_powered INTEGER DEFAULT 0,
  drugs_grams TEXT,
  drugs_value TEXT,
  contraband_details TEXT,          -- e.g. Shabu, Contraband, Cash
  war_materiel TEXT,
  kia INTEGER DEFAULT 0,
  wia INTEGER DEFAULT 0,
  remarks TEXT
);
CREATE INDEX IF NOT EXISTS idx_sleo_date ON sleo(op_date);

CREATE TABLE IF NOT EXISTS tolf (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  op_date TEXT NOT NULL,            -- YYYY-MM-DD
  unit TEXT NOT NULL,               -- e.g. 602nd Bde
  area TEXT NOT NULL,               -- e.g. Carmen, Cotabato
  source_group TEXT,                -- e.g. Community, Former Combatants, LGU
  firearms_count INTEGER DEFAULT 0, -- Total firearms turned over
  small_arms INTEGER DEFAULT 0,     -- Pistols, revolvers
  light_weapons INTEGER DEFAULT 0,  -- Rifles, shotguns
  crew_served INTEGER DEFAULT 0,    -- Machine guns, mortars
  explosives_count INTEGER DEFAULT 0, -- Grenades, IEDs, mortar rounds
  facilitated_by TEXT,              -- e.g. Municipal Mayor, Barangay Chairman
  remarks TEXT
);
CREATE INDEX IF NOT EXISTS idx_tolf_date ON tolf(op_date);

CREATE TABLE IF NOT EXISTS rido (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  case_date TEXT NOT NULL,          -- YYYY-MM-DD
  unit TEXT NOT NULL,               -- e.g. 603rd Bde
  area TEXT NOT NULL,               -- e.g. Datu Piang, Maguindanao
  parties_involved TEXT NOT NULL,   -- e.g. Family A vs Family B
  status TEXT NOT NULL DEFAULT 'Ongoing Mediation', -- Settled, Ongoing Mediation, Monitored
  casualties_killed INTEGER DEFAULT 0,
  casualties_wounded INTEGER DEFAULT 0,
  firearms_surrendered INTEGER DEFAULT 0,
  mediators TEXT,                   -- e.g. JTFC, LGU, MILF CCCH
  agreement_details TEXT,           -- Summary of resolution/covenant
  remarks TEXT
);
CREATE INDEX IF NOT EXISTS idx_rido_date ON rido(case_date);

CREATE TABLE IF NOT EXISTS hadr (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  op_date TEXT NOT NULL,            -- YYYY-MM-DD
  unit TEXT NOT NULL,               -- e.g. 6th ID / JTFC
  area TEXT NOT NULL,               -- e.g. Cotabato City / Maguindanao
  disaster_type TEXT NOT NULL,      -- Flashflood, Typhoon, Earthquake, Fire
  assisted_families INTEGER DEFAULT 0,
  assisted_individuals INTEGER DEFAULT 0,
  rescued_persons INTEGER DEFAULT 0,
  relief_packs_distributed INTEGER DEFAULT 0,
  personnel_deployed INTEGER DEFAULT 0,
  partner_agencies TEXT,            -- MDRRMO, PDRRMO, DSWD, PRC
  remarks TEXT
);
CREATE INDEX IF NOT EXISTS idx_hadr_date ON hadr(op_date);

CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT);
INSERT OR IGNORE INTO settings VALUES ('firearms_target','200');
