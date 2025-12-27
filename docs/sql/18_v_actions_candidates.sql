CREATE OR REPLACE VIEW default.v_actions_candidates AS
WITH now() AS t_now
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
  -- dedupe: último por (window_start, src_ip)
  SELECT
    window_start,
    src_ip,
    argMax(attack_type, inserted_at) AS attack_type,
    argMax(score, inserted_at) AS score,
    argMax(pps, inserted_at) AS pps,
    argMax(bps, inserted_at) AS bps,
    argMax(uniq_dst_ips, inserted_at) AS uniq_dst_ips,
    argMax(uniq_dst_ports, inserted_at) AS uniq_dst_ports,
    argMax(top_dst_ip, inserted_at) AS top_dst_ip,
    argMax(top_dst_share, inserted_at) AS top_dst_share,
    argMax(top_proto, inserted_at) AS top_proto,
    argMax(top_dst_port, inserted_at) AS top_dst_port,
    argMax(top_port_share, inserted_at) AS top_port_share
  FROM default.suspects_1m
  WHERE inserted_at >= t_now - INTERVAL 15 MINUTE
  GROUP BY window_start, src_ip
) AS s
WHERE s.score >= 50
  AND multiIf(
        s.attack_type = 'single_target_flood' AND s.score >= 60, 'block_src_ip',
        s.attack_type = 'udp_amplification_like' AND s.score >= 60, 'block_src_ip',
        s.attack_type IN ('spray_many_targets','scan_many_ports') AND s.score >= 70, 'quarantine',
        'ignore'
      ) != 'ignore'
  AND NOT EXISTS
  (
    SELECT 1
    FROM default.mitigation_actions AS a
    WHERE a.src_ip = s.src_ip
      AND a.created_at >= t_now - INTERVAL 10 MINUTE
      AND a.status IN ('pending','applied')
  );
