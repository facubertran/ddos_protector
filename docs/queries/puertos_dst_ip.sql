SELECT
  window_start,
  src_ip,
  dst_ip,
  total_packets,
  total_bytes,
  pps,
  bps,
  uniq_dst_ports
FROM default.v_flow_dst_1m
WHERE window_start >= toStartOfMinute(now()) - INTERVAL 5 MINUTE
  AND src_ip = toIPv4('1.2.3.4')
ORDER BY window_start DESC, total_packets DESC
LIMIT 20
