CREATE MATERIALIZED VIEW default.mv_suspects_1m
TO default.suspects_1m
AS
SELECT
  m.window_start AS window_start,
  m.src_ip       AS src_ip,

  toUInt64(m.total_packets) AS total_packets,
  toUInt64(m.total_bytes)   AS total_bytes,
  toUInt64(m.total_flows)   AS total_flows,
  toFloat64(m.pps)          AS pps,
  toFloat64(m.bps)          AS bps,
  toUInt64(m.uniq_dst_ips)  AS uniq_dst_ips,
  toUInt64(m.uniq_dst_ports) AS uniq_dst_ports,

  ifNull(d.top_dst_ip, toIPv4('0.0.0.0')) AS top_dst_ip,
  ifNull(d.top_dst_packets, toUInt64(0))  AS top_dst_packets,
  ifNull(d.top_dst_share, toFloat64(0))   AS top_dst_share,
  ifNull(d.dst_entropy, toFloat64(0))     AS dst_entropy,

  ifNull(p.top_proto, toUInt32(0))             AS top_proto,
  ifNull(p.top_dst_port, toUInt16(0))          AS top_dst_port,
  ifNull(p.top_port_packets, toUInt64(0))      AS top_port_packets,
  ifNull(p.top_port_share, toFloat64(0))       AS top_port_share,
  ifNull(p.top_port_uniq_dst_ips, toUInt64(0)) AS top_port_uniq_dst_ips,

  multiIf(
    m.pps >= 1000 AND ifNull(d.top_dst_share, 0) >= 0.80 AND m.uniq_dst_ips <= 5, 'single_target_flood',
    m.pps >= 1000 AND m.uniq_dst_ips >= 100,                                      'spray_many_targets',
    m.pps >= 1000 AND m.uniq_dst_ports >= 100,                                    'scan_many_ports',
    m.pps >= 1000 AND ifNull(p.top_proto, 0) = 17 AND ifNull(p.top_port_share, 0) >= 0.70, 'udp_amplification_like',
    'normal_or_low_signal'
  ) AS attack_type,

  toUInt16(greatest(0, least(100,
      toInt32(m.pps / 200) +
      toInt32(m.uniq_dst_ips / 20) +
      toInt32(m.uniq_dst_ports / 20) +
      toInt32(ifNull(d.top_dst_share, 0) * 40) +
      toInt32(ifNull(p.top_port_share, 0) * 20)
  ))) AS score

FROM default.flow_metrics_1m AS ins
ANY INNER JOIN default.v_flow_metrics_1m AS m
  ON m.window_start = ins.window_start AND m.src_ip = ins.src_ip
LEFT JOIN
(
  SELECT
    window_start,
    src_ip,
    argMax(dst_ip, total_packets) AS top_dst_ip,
    max(total_packets) AS top_dst_packets,
    max(total_packets) / sum(total_packets) AS top_dst_share,
    if(
      sum(toFloat64(total_packets)) > 0,
      log2(sum(toFloat64(total_packets))) -
        (sum(toFloat64(total_packets) * log2(greatest(toFloat64(total_packets), 1.0)))
         / sum(toFloat64(total_packets))),
      0
    ) AS dst_entropy
  FROM default.v_flow_dst_1m
  GROUP BY window_start, src_ip
) AS d
ON d.window_start = m.window_start AND d.src_ip = m.src_ip
LEFT JOIN
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
  GROUP BY window_start, src_ip
) AS p
ON p.window_start = m.window_start AND p.src_ip = m.src_ip
WHERE m.pps >= 1000;