CREATE OR REPLACE VIEW default.v_top_src_pps AS
SELECT
  m.window_start AS window_start,
  m.src_ip       AS src_ip,
  m.pps          AS pps,
  m.bps          AS bps,
  m.total_packets AS total_packets,
  m.total_bytes   AS total_bytes,
  m.total_flows   AS total_flows
FROM default.v_flow_metrics_1m AS m
WHERE
  -- ✅ solo IPs de redes controladas (allow_src_nets)
  arrayExists(
    x -> isIPAddressInRange(toString(m.src_ip), x),
    (SELECT groupArray(cidr) FROM default.allow_src_nets WHERE is_enabled = 1)
  )

  -- 🚫 ignorar por red/IP origen
  AND NOT arrayExists(
    x -> isIPAddressInRange(toString(m.src_ip), x),
    (SELECT groupArray(cidr) FROM default.ignore_nets WHERE is_enabled = 1 AND direction IN ('src', 'both'))
  )
ORDER BY m.pps DESC
LIMIT 100;
