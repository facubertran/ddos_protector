CREATE MATERIALIZED VIEW default.mv_flow_dst_1m
TO default.flow_dst_1m
AS
WITH
  if(sampling_rate > 0, sampling_rate, 1) AS s,
  toIPv4(IPv4NumToString(reinterpretAsUInt32(reverse(reinterpretAsString(src_addr))))) AS src_ip_v4,
  toIPv4(IPv4NumToString(reinterpretAsUInt32(reverse(reinterpretAsString(dst_addr))))) AS dst_ip_v4
SELECT
  toStartOfInterval(time_received_ns, INTERVAL 1 MINUTE) AS window_start,
  src_ip_v4 AS src_ip,
  dst_ip_v4 AS dst_ip,

  sumState(toUInt64(bytes)   * toUInt64(s)) AS total_bytes_state,
  sumState(toUInt64(packets) * toUInt64(s)) AS total_packets_state,
  countState()                              AS total_flows_state,

  uniqState(toUInt16(dst_port)) AS uniq_dst_ports_state,

  sumStateIf(toUInt64(packets) * toUInt64(s), proto = 6)  AS tcp_packets_state,
  sumStateIf(toUInt64(packets) * toUInt64(s), proto = 17) AS udp_packets_state,
  sumStateIf(toUInt64(packets) * toUInt64(s), proto = 1)  AS icmp_packets_state
FROM default.flows_raw
WHERE length(reinterpretAsString(src_addr)) >= 4
  AND length(reinterpretAsString(dst_addr)) >= 4
GROUP BY
  window_start, src_ip, dst_ip;