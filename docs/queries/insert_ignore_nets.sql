-- una sola IP:
INSERT INTO default.ignore_nets (cidr, direction, label)
VALUES ('192.168.99.2/32', 'src', 'lab host');

-- rango destino (CDN / AS):
INSERT INTO default.ignore_nets (cidr, direction, label)
VALUES ('142.250.0.0/15', 'dst', 'google cdn');
