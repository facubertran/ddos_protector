ALTER TABLE default.flow_dst_1m
MODIFY TTL window_start + INTERVAL 90 DAY DELETE;
