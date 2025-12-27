CREATE OR REPLACE VIEW default.v_flow_metrics_1m AS
SELECT
  window_start,
  src_ip,

  sumMerge(total_bytes_state)   AS total_bytes,
  sumMerge(total_packets_state) AS total_packets,
  countMerge(total_flows_state) AS total_flows,

  uniqMerge(uniq_dst_ips_state)   AS uniq_dst_ips,
  uniqMerge(uniq_dst_ports_state) AS uniq_dst_ports,

  sumMerge(tcp_packets_state)  AS tcp_packets,
  sumMerge(udp_packets_state)  AS udp_packets,
  sumMerge(icmp_packets_state) AS icmp_packets,

  (sumMerge(total_packets_state) / 60) AS pps,
  ((sumMerge(total_bytes_state) * 8) / 60) AS bps
FROM default.flow_metrics_1m
GROUP BY window_start, src_ip;
