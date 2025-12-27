CREATE TABLE IF NOT EXISTS default.flow_port_1m
(
  window_start DateTime,
  src_ip IPv4,
  proto UInt32,
  dst_port UInt16,

  total_bytes_state   AggregateFunction(sum, UInt64),
  total_packets_state AggregateFunction(sum, UInt64),
  total_flows_state   AggregateFunction(count, UInt64),

  uniq_dst_ips_state  AggregateFunction(uniq, IPv4)
)
ENGINE = AggregatingMergeTree
PARTITION BY toDate(window_start)
ORDER BY (window_start, src_ip, proto, dst_port);
