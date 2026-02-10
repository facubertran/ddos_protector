CREATE TABLE IF NOT EXISTS default.allow_src_nets
(
  cidr String,                              -- ej: '192.168.0.0/16'
  label LowCardinality(String) DEFAULT '',
  is_enabled UInt8 DEFAULT 1,
  created_at DateTime DEFAULT now()
)
ENGINE = MergeTree
ORDER BY (is_enabled, cidr);
