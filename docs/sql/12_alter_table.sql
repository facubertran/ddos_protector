ALTER TABLE default.flow_port_1m
MODIFY TTL window_start + INTERVAL 1 DAY DELETE;
