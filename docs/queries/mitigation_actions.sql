SELECT 
    created_at,
    window_start,
    src_ip,
    action,
    reason,
    score,
    target_dst_ip,
    target_proto,
    target_dst_port,
    status,
    last_update,
    details
FROM  default.mitigation_actions 
LIMIT 200