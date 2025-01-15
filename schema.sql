CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL UNIQUE,
    password TEXT NOT NULL,
    user_group TEXT NOT NULL,
    last_login TEXT,
    last_ip TEXT
);

CREATE TABLE IF NOT EXISTS ip_cameras (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    description TEXT,
    local_ip TEXT NOT NULL,
    network_mask INTEGER NOT NULL,
    service_port INTEGER NOT NULL,
    camera_group TEXT NOT NULL,
    internal_iface TEXT NOT NULL,
    external_iface TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS external_access (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    camera_id INTEGER NOT NULL,
    external_ip TEXT NOT NULL,
    access_port INTEGER NOT NULL,
    FOREIGN KEY (camera_id) REFERENCES ip_cameras(id)
);
