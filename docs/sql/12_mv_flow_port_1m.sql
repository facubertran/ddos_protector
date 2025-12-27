CREATE MATERIALIZED VIEW default.mv_flow_port_1m
TO default.flow_port_1m
AS
WITH
  if(sampling_rate > 0, sampling_rate, 1) AS s,
  toIPv4(IPv4NumToString(reinterpretAsUInt32(reverse(reinterpretAsString(src_addr))))) AS src_ip_v4,
  toIPv4(IPv4NumToString(reinterpretAsUInt32(reverse(reinterpretAsString(dst_addr))))) AS dst_ip_v4
SELECT
  toStartOfInterval(time_received_ns, INTERVAL 1 MINUTE) AS window_start,
  src_ip_v4 AS src_ip,
  proto,
  toUInt16(dst_port) AS dst_port,

  sumState(toUInt64(bytes)   * toUInt64(s)) AS total_bytes_state,
  sumState(toUInt64(packets) * toUInt64(s)) AS total_packets_state,
  countState()                              AS total_flows_state,

  uniqState(dst_ip_v4) AS uniq_dst_ips_state
FROM default.flows_raw
WHERE length(reinterpretAsString(src_addr)) >= 4
  AND length(reinterpretAsString(dst_addr)) >= 4
GROUP BY window_start, src_ip, proto, dst_port;