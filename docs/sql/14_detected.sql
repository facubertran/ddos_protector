WITH
  toStartOfInterval(now(), INTERVAL 1 MINUTE) AS now_min,
  now_min - INTERVAL 5 MINUTE AS w_from
SELECT
  m.window_start,
  m.src_ip,

  m.total_packets,
  m.total_bytes,
  m.pps,
  m.bps,
  m.total_flows,
  m.uniq_dst_ips,
  m.uniq_dst_ports,

  d.top_dst_ip,
  d.top_dst_packets,
  round(d.top_dst_share, 3) AS top_dst_share,
  round(d.dst_entropy, 3) AS dst_entropy,

  p.top_proto,
  p.top_dst_port,
  p.top_port_packets,
  round(p.top_port_share, 3) AS top_port_share,
  p.top_port_uniq_dst_ips,

  multiIf(
    m.pps >= 5000 AND d.top_dst_share >= 0.80 AND m.uniq_dst_ips <= 5,  'single_target_flood',
    m.pps >= 3000 AND m.uniq_dst_ips >= 100,                           'spray_many_targets',
    m.pps >= 3000 AND m.uniq_dst_ports >= 100,                         'scan_many_ports',
    m.pps >= 3000 AND p.top_proto = 17 AND p.top_port_share >= 0.70,   'udp_amplification_like',
    'normal_or_low_signal'
  ) AS attack_type
FROM default.v_flow_metrics_1m AS m
LEFT JOIN
(
  SELECT
    window_start,
    src_ip,
    top_dst_ip,
    top_dst_packets,
    top_dst_share,
    if(T > 0, log2(T) - (S / T), 0) AS dst_entropy
  FROM
  (
    SELECT
      window_start,
      src_ip,
      argMax(dst_ip, total_packets) AS top_dst_ip,
      max(total_packets) AS top_dst_packets,
      max(total_packets) / sum(total_packets) AS top_dst_share,
      toFloat64(sum(total_packets)) AS T,
      sum(toFloat64(total_packets) * log2(greatest(toFloat64(total_packets), 1))) AS S
    FROM default.v_flow_dst_1m
    WHERE window_start >= w_from
    GROUP BY window_start, src_ip
  )
) AS d
ON d.window_start = m.window_start AND d.src_ip = m.src_ip
LEFT JOIN
(
  SELECT
    window_start,
    src_ip,
    top_proto,
    top_dst_port,
    top_port_packets,
    top_port_share,
    top_port_uniq_dst_ips
  FROM
  (
    SELECT
      window_start,
      src_ip,
      toUInt32(argMax(proto, total_packets)) AS top_proto,
      argMax(dst_port, total_packets) AS top_dst_port,
      max(total_packets) AS top_port_packets,
      max(total_packets) / sum(total_packets) AS top_port_share,
      argMax(uniq_dst_ips, total_packets) AS top_port_uniq_dst_ips
    FROM default.v_flow_port_1m
    WHERE window_start >= w_from
    GROUP BY window_start, src_ip
  )
) AS p
ON p.window_start = m.window_start AND p.src_ip = m.src_ip
WHERE m.window_start >= w_from
  AND m.pps >= 1000
ORDER BY m.window_start DESC, m.pps DESC
LIMIT 200