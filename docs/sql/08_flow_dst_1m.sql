CREATE TABLE IF NOT EXISTS default.flow_dst_1m
(
  window_start DateTime,
  src_ip IPv4,
  dst_ip IPv4,

  total_bytes_state   AggregateFunction(sum, UInt64),
  total_packets_state AggregateFunction(sum, UInt64),
  total_flows_state   AggregateFunction(count, UInt64),

  uniq_dst_ports_state AggregateFunction(uniq, UInt16),

  tcp_packets_state  AggregateFunction(sum, UInt64),
  udp_packets_state  AggregateFunction(sum, UInt64),
  icmp_packets_state AggregateFunction(sum, UInt64)
)
ENGINE = AggregatingMergeTree
PARTITION BY toDate(window_start)
ORDER BY (window_start, src_ip, dst_ip);
