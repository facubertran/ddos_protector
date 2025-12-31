CREATE OR REPLACE VIEW default.v_actions_candidates AS
WITH now() AS t_now
SELECT *
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
    WHERE inserted_at >= t_now - INTERVAL 15 MINUTE
    GROUP BY window_start, src_ip
  ) AS s
  WHERE s.score >= 50
) AS c
WHERE c.action != 'ignore'

  -- ✅ solo redes controladas
  AND EXISTS
  (
    SELECT 1
    FROM default.allow_src_nets n
    WHERE n.is_enabled = 1
      AND isIPAddressInRange(toString(c.src_ip), n.cidr)
  )

  -- 🚫 ignorar por red/IP origen (CIDR, /32 válido)
  AND NOT EXISTS
  (
    SELECT 1
    FROM default.ignore_nets i
    WHERE i.is_enabled = 1
      AND i.direction IN ('src', 'both')
      AND isIPAddressInRange(toString(c.src_ip), i.cidr)
  )

  -- 🚫 ignorar por red/IP destino (target)
  AND NOT EXISTS
  (
    SELECT 1
    FROM default.ignore_nets i
    WHERE i.is_enabled = 1
      AND i.direction IN ('dst', 'both')
      AND isIPAddressInRange(toString(c.target_dst_ip), i.cidr)
  )

  -- cooldown
  AND NOT EXISTS
  (
    SELECT 1
    FROM default.mitigation_actions a
    WHERE a.src_ip = c.src_ip
      AND a.created_at >= t_now - INTERVAL 10 MINUTE
      AND a.status IN ('pending','applied')
  );
