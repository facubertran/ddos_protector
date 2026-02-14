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


---
SELECT *
FROM default.mitigation_actions
WHERE created_at >= now() - INTERVAL 1 HOUR
  AND status IN ('applied', 'mitigated')
ORDER BY created_at DESC