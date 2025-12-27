ALTER TABLE default.flow_metrics_10s
MODIFY TTL window_start + INTERVAL 30 DAY DELETE;

ALTER TABLE default.flow_metrics_1m
MODIFY TTL window_start + INTERVAL 180 DAY DELETE;
