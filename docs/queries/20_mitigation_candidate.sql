SELECT *
FROM default.v_actions_candidates
ORDER BY window_start DESC, score DESC
LIMIT 200