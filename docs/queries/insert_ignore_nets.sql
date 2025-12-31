-- una sola IP:
INSERT INTO default.ignore_nets (cidr, direction, label)
VALUES ('192.168.99.2/32', 'src', 'lab host');

-- rango destino (CDN / AS):
INSERT INTO default.ignore_nets (cidr, direction, label)
VALUES ('142.251.128.0/24', 'dst', 'google cdn');
