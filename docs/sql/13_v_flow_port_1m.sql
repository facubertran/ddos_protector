CREATE OR REPLACE VIEW default.v_flow_port_1m AS
SELECT
  window_start,
  src_ip,
  proto,
  dst_port,

  sumMerge(total_bytes_state)   AS total_bytes,
  sumMerge(total_packets_state) AS total_packets,
  countMerge(total_flows_state) AS total_flows,
  uniqMerge(uniq_dst_ips_state) AS uniq_dst_ips
FROM default.flow_port_1m
GROUP BY window_start, src_ip, proto, dst_port;
