ALTER TABLE default.suspects_1m
MODIFY TTL window_start + INTERVAL 30 DAY DELETE;
