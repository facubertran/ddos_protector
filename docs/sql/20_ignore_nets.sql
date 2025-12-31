CREATE TABLE IF NOT EXISTS default.ignore_nets
(
  cidr String,  -- ej: '8.8.8.8/32' o '142.250.0.0/15'
  direction Enum8('src' = 1, 'dst' = 2, 'both' = 3) DEFAULT 'both',
  label LowCardinality(String) DEFAULT '',
  is_enabled UInt8 DEFAULT 1,
  created_at DateTime DEFAULT now()
)
ENGINE = MergeTree
ORDER BY (is_enabled, direction, cidr);
