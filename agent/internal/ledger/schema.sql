CREATE TABLE IF NOT EXISTS connections (
	id          INTEGER PRIMARY KEY AUTOINCREMENT,
	ts          TEXT NOT NULL,
	last_seen   TEXT NOT NULL DEFAULT '',
	events      INTEGER NOT NULL DEFAULT 1,
	pid         INTEGER NOT NULL,
	image       TEXT NOT NULL,
	remote_ip   TEXT NOT NULL,
	remote_port INTEGER NOT NULL,
	proto       TEXT NOT NULL,
	domain      TEXT,
	verdict     TEXT NOT NULL DEFAULT 'clean',
	inbound     INTEGER NOT NULL DEFAULT 0,
	asn         INTEGER NOT NULL DEFAULT 0,
	as_org      TEXT,
	country     TEXT,
	story       TEXT,
	bytes_sent  INTEGER NOT NULL DEFAULT 0,
	bytes_recv  INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_conn_ts ON connections(ts);
CREATE INDEX IF NOT EXISTS idx_conn_image_domain ON connections(image, domain);
-- Dedupe lookup: the kernel reports network activity per packet, so many
-- events collapse onto one logical connection row.
CREATE INDEX IF NOT EXISTS idx_conn_flow ON connections(image, remote_ip, remote_port, proto, last_seen);
CREATE INDEX IF NOT EXISTS idx_conn_flow_pid ON connections(pid, remote_ip, remote_port, proto, last_seen);
