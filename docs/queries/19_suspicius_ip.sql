SELECT
  window_start,
  src_ip,
  attack_type,
  score,
  pps,
  bps,
  uniq_dst_ips,
  uniq_dst_ports,
  top_dst_ip,
  top_dst_share,
  top_proto,
  top_dst_port,
  top_port_share
FROM default.suspects_1m
WHERE window_start >= toStartOfInterval(now(), INTERVAL 1 MINUTE) - INTERVAL 10 MINUTE
  AND score >= 50
ORDER BY window_start DESC, score DESC
LIMIT 200