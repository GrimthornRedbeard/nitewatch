CREATE TABLE IF NOT EXISTS connections (
	id          INTEGER PRIMARY KEY AUTOINCREMENT,
	ts          TEXT NOT NULL,
	pid         INTEGER NOT NULL,
	image       TEXT NOT NULL,
	remote_ip   TEXT NOT NULL,
	remote_port INTEGER NOT NULL,
	proto       TEXT NOT NULL,
	domain      TEXT,
	verdict     TEXT NOT NULL DEFAULT 'clean'
);
CREATE INDEX IF NOT EXISTS idx_conn_ts ON connections(ts);
CREATE INDEX IF NOT EXISTS idx_conn_image_domain ON connections(image, domain);
