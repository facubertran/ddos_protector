CREATE MATERIALIZED VIEW default.mv_flow_metrics_1m
TO default.flow_metrics_1m
AS
SELECT
  toStartOfInterval(window_start, INTERVAL 1 MINUTE) AS window_start,
  src_ip,

  sumMergeState(total_bytes_state)   AS total_bytes_state,
  sumMergeState(total_packets_state) AS total_packets_state,
  countMergeState(total_flows_state) AS total_flows_state,

  uniqMergeState(uniq_dst_ips_state)   AS uniq_dst_ips_state,
  uniqMergeState(uniq_dst_ports_state) AS uniq_dst_ports_state,

  sumMergeState(tcp_packets_state)  AS tcp_packets_state,
  sumMergeState(udp_packets_state)  AS udp_packets_state,
  sumMergeState(icmp_packets_state) AS icmp_packets_state
FROM default.flow_metrics_10s
GROUP BY window_start, src_ip;
