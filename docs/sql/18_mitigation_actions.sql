CREATE TABLE IF NOT EXISTS default.mitigation_actions
(
  created_at DateTime DEFAULT now(),
  window_start DateTime,
  src_ip IPv4,

  action LowCardinality(String),      -- 'rate_limit', 'block_src', 'quarantine', etc.
  reason LowCardinality(String),      -- attack_type
  score UInt16,

  target_dst_ip IPv4,                 -- opcional (single target)
  target_proto UInt32,                -- opcional
  target_dst_port UInt16,             -- opcional

  status LowCardinality(String) DEFAULT 'pending',  -- pending/applied/failed/ignored
  last_update DateTime DEFAULT now(),
  details String DEFAULT ''
)
ENGINE = MergeTree
PARTITION BY toDate(created_at)
ORDER BY (status, created_at, src_ip);
