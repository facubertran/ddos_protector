CREATE TABLE IF NOT EXISTS default.suspects_1m
(
  window_start DateTime,
  src_ip IPv4,

  -- métricas base
  total_packets UInt64,
  total_bytes UInt64,
  total_flows UInt64,
  pps Float64,
  bps Float64,
  uniq_dst_ips UInt64,
  uniq_dst_ports UInt64,

  -- top destino
  top_dst_ip IPv4,
  top_dst_packets UInt64,
  top_dst_share Float64,
  dst_entropy Float64,

  -- top puerto
  top_proto UInt32,
  top_dst_port UInt16,
  top_port_packets UInt64,
  top_port_share Float64,
  top_port_uniq_dst_ips UInt64,

  -- clasificación + score
  attack_type LowCardinality(String),
  score UInt16,

  inserted_at DateTime DEFAULT now()
)
ENGINE = ReplacingMergeTree(inserted_at)
PARTITION BY toDate(window_start)
ORDER BY (window_start, src_ip);
