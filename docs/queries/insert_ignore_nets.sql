-- una sola IP:
INSERT INTO default.ignore_nets (cidr, direction, label)
VALUES ('192.168.99.2/32', 'src', 'lab host');

-- rango destino (CDN / AS):
INSERT INTO default.ignore_nets (cidr, direction, label)
VALUES ('142.250.0.0/15', 'dst', 'google cdn'),
('172.217.192.0/24', 'dst', 'google cdn'),
('108.177.123.0/24', 'dst', 'google cdn'),
('181.13.0.0/16', 'dst', 'telecom cdn'),
('34.95.240.0/20', 'dst', 'google cdn'),
('172.217.28.0/24', 'dst', 'google cdn'),
('64.233.160.0/19', 'dst', 'google cdn'),
('34.151.240.0/20', 'dst', 'google cdn'),
('181.30.0.0/16', 'dst', 'telecom cdn'),
('45.191.194.40/29', 'src', 'SensaCEM'),
('151.101.216.0/22', 'dst', 'Fastly CDN'),
('181.15.0.0/16', 'dst', 'telecom cdn'),