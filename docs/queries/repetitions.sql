SELECT count() as repetitions, src_ip
FROM   default.mitigation_actions 
GROUP BY src_ip
ORDER BY repetitions DESC
LIMIT 200