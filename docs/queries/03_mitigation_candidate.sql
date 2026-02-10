SELECT 
    window_start,
    src_ip,
    reason,
    score,
    action,
    target_dst_ip,
    target_proto,
    target_dst_port
FROM default.v_actions_candidates
ORDER BY window_start DESC, score DESC
LIMIT 200