CREATE OR REPLACE VIEW default.v_actions_candidates AS
SELECT
  c.window_start      AS window_start,
  c.src_ip            AS src_ip,
  c.reason            AS reason,
  c.score             AS score,
  c.action            AS action,
  c.target_dst_ip     AS target_dst_ip,
  c.target_proto      AS target_proto,
  c.target_dst_port   AS target_dst_port
FROM
(
  SELECT
    s.window_start AS window_start,
    s.src_ip AS src_ip,
    s.attack_type AS reason,
    s.score AS score,

    multiIf(
      s.attack_type = 'single_target_flood' AND s.score >= 60, 'rate_limit',
      s.attack_type = 'udp_amplification_like' AND s.score >= 60, 'block_udp_port',
      s.attack_type IN ('spray_many_targets','scan_many_ports') AND s.score >= 70, 'quarantine',
      'ignore'
    ) AS action,

    s.top_dst_ip   AS target_dst_ip,
    s.top_proto    AS target_proto,
    s.top_dst_port AS target_dst_port
  FROM
  (
    SELECT
      window_start,
      src_ip,
      argMax(attack_type, inserted_at) AS attack_type,
      argMax(score, inserted_at) AS score,
      argMax(top_dst_ip, inserted_at) AS top_dst_ip,
      argMax(top_proto, inserted_at) AS top_proto,
      argMax(top_dst_port, inserted_at) AS top_dst_port
    FROM default.suspects_1m
    WHERE inserted_at >= now() - INTERVAL 15 MINUTE
    GROUP BY window_start, src_ip
  ) AS s
  WHERE s.score >= 50
) AS c
WHERE c.action != 'ignore'

  -- ✅ solo redes controladas
  AND arrayExists(
    x -> isIPAddressInRange(toString(c.src_ip), x),
    (SELECT groupArray(cidr) FROM default.allow_src_nets WHERE is_enabled = 1)
  )

  -- 🚫 ignorar por red/IP origen
  AND NOT arrayExists(
    x -> isIPAddressInRange(toString(c.src_ip), x),
    (SELECT groupArray(cidr) FROM default.ignore_nets WHERE is_enabled = 1 AND direction IN ('src', 'both'))
  )

  -- 🚫 ignorar por red/IP destino
  AND NOT arrayExists(
    x -> isIPAddressInRange(toString(c.target_dst_ip), x),
    (SELECT groupArray(cidr) FROM default.ignore_nets WHERE is_enabled = 1 AND direction IN ('dst', 'both'))
  )

  -- cooldown
  AND toString(c.src_ip) NOT IN (
    SELECT toString(src_ip)
    FROM default.mitigation_actions
    WHERE created_at >= now() - INTERVAL 1 HOUR
      AND status IN ('pending','applied','mitigated')
  );
