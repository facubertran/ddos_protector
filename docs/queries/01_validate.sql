SELECT
  ts_10s,
  src_ip,
  packets,
  bytes,
  packets / 10 AS pps,
  (bytes * 8) / 10 AS bps,
  flows,
  uniq_dst_ips,
  uniq_dst_ports,
  tcp_packets, udp_packets, icmp_packets
FROM default.agg_10s_by_src
ORDER BY ts_10s DESC
LIMIT 50;


-----------

-- Ver lag --
SELECT
  now() AS now,
  max(ts_10s) AS last_bucket,
  dateDiff('second', last_bucket, now()) AS seconds_behind
FROM default.agg_10s_by_src;
