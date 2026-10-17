CREATE TABLE users (
    id INTEGER PRIMARY KEY,
    login_key TEXT UNIQUE NOT NULL,
    email TEXT,
    display_name TEXT,
    pg_role_name TEXT UNIQUE,
    disabled_at TEXT CHECK (disabled_at IS NULL OR disabled_at GLOB
        '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z'),
    last_oidc_sub TEXT,
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
        CHECK (created_at GLOB
        '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z')
);

CREATE TABLE activations (
    id INTEGER PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users(id),
    reason TEXT NOT NULL,
    activated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
        CHECK (activated_at GLOB
        '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z'),
    expires_at TEXT NOT NULL CHECK (expires_at GLOB
        '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z'),
    client_ip TEXT,
    user_agent TEXT,
    revoked_at TEXT CHECK (revoked_at IS NULL OR revoked_at GLOB
        '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z'),
    revoked_by INTEGER REFERENCES users(id)
);
CREATE INDEX activations_user_id ON activations(user_id);

CREATE TRIGGER activations_no_delete BEFORE DELETE ON activations
BEGIN
    SELECT RAISE(ABORT, 'activations cannot be deleted');
END;

CREATE TRIGGER activations_revoke_only BEFORE UPDATE ON activations
WHEN NOT (
    OLD.revoked_at IS NULL AND OLD.revoked_by IS NULL
    AND NEW.revoked_at IS NOT NULL AND NEW.revoked_by IS NOT NULL
    AND NEW.id IS OLD.id AND NEW.user_id IS OLD.user_id
    AND NEW.reason IS OLD.reason AND NEW.activated_at IS OLD.activated_at
    AND NEW.expires_at IS OLD.expires_at AND NEW.client_ip IS OLD.client_ip
    AND NEW.user_agent IS OLD.user_agent
)
BEGIN
    SELECT RAISE(ABORT, 'activations may only be revoked once');
END;

CREATE TABLE groups (
    id INTEGER PRIMARY KEY,
    name TEXT UNIQUE NOT NULL CHECK (
        length(name) BETWEEN 1 AND 41
        AND substr(name, 1, 1) GLOB '[a-z]'
        AND name NOT GLOB '*[^a-z0-9_]*'
    ),
    description TEXT,
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
        CHECK (created_at GLOB
        '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z')
);
CREATE TRIGGER groups_immutable_name BEFORE UPDATE OF name ON groups
WHEN NEW.name IS NOT OLD.name
BEGIN
    SELECT RAISE(ABORT, 'group names are immutable');
END;
-- Rejects any insert whose id or name already exists, so REPLACE cannot rename or
-- overwrite a row. Side effect: INSERT OR IGNORE and ON CONFLICT DO NOTHING/UPDATE also
-- raise here; idempotent writers must check for the row first.
CREATE TRIGGER groups_no_replace BEFORE INSERT ON groups
WHEN EXISTS (SELECT 1 FROM groups WHERE id = NEW.id OR name = NEW.name)
BEGIN
    SELECT RAISE(ABORT, 'groups cannot be replaced');
END;

CREATE TABLE connections (
    id INTEGER PRIMARY KEY,
    name TEXT UNIQUE NOT NULL CHECK (
        length(name) BETWEEN 1 AND 41
        AND substr(name, 1, 1) GLOB '[a-z]'
        AND name NOT GLOB '*[^a-z0-9_-]*'
    ),
    host TEXT NOT NULL,
    port INTEGER NOT NULL DEFAULT 5432 CHECK (port BETWEEN 1 AND 65535),
    dbname TEXT NOT NULL,
    sslmode TEXT NOT NULL DEFAULT 'require',
    admin_secret_ref TEXT NOT NULL,
    owner_role TEXT NOT NULL,
    default_privilege_owners TEXT NOT NULL DEFAULT '[]'
        CHECK (json_valid(default_privilege_owners)
            AND json_type(default_privilege_owners) = 'array')
);
CREATE TRIGGER connections_immutable_name BEFORE UPDATE OF name ON connections
WHEN NEW.name IS NOT OLD.name
BEGIN
    SELECT RAISE(ABORT, 'connection names are immutable');
END;
-- Rejects any insert whose id or name already exists, so REPLACE cannot rename or
-- overwrite a row. Side effect: INSERT OR IGNORE and ON CONFLICT DO NOTHING/UPDATE also
-- raise here; idempotent writers must check for the row first.
CREATE TRIGGER connections_no_replace BEFORE INSERT ON connections
WHEN EXISTS (SELECT 1 FROM connections WHERE id = NEW.id OR name = NEW.name)
BEGIN
    SELECT RAISE(ABORT, 'connections cannot be replaced');
END;

CREATE TABLE sessions (
    id INTEGER PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users(id),
    activation_id INTEGER NOT NULL REFERENCES activations(id),
    connection_id INTEGER NOT NULL REFERENCES connections(id),
    started_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
        CHECK (started_at GLOB
        '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z'),
    valid_until TEXT NOT NULL CHECK (valid_until GLOB
        '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z'),
    last_seen_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
        CHECK (last_seen_at GLOB
        '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z'),
    ended_at TEXT CHECK (ended_at IS NULL OR ended_at GLOB
        '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z'),
    end_reason TEXT
);
CREATE INDEX sessions_user_id ON sessions(user_id);
CREATE INDEX sessions_activation_id ON sessions(activation_id);
CREATE INDEX sessions_connection_id ON sessions(connection_id);

CREATE TABLE row_policies (
    id INTEGER PRIMARY KEY,
    connection_id INTEGER NOT NULL REFERENCES connections(id),
    schema_name TEXT NOT NULL,
    table_name TEXT NOT NULL,
    column_name TEXT NOT NULL,
    enabled_by INTEGER NOT NULL REFERENCES users(id),
    enabled_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
        CHECK (enabled_at GLOB
        '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z'),
    UNIQUE(connection_id, schema_name, table_name)
);

CREATE TABLE sync_state (
    consumer TEXT PRIMARY KEY NOT NULL,
    fga_store_id TEXT,
    continuation_token TEXT,
    last_applied_at TEXT CHECK (last_applied_at IS NULL OR last_applied_at GLOB
        '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z'),
    last_error TEXT,
    fail_count INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE audit_log (
    id INTEGER PRIMARY KEY,
    ts TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
        CHECK (ts GLOB
        '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z'),
    kind TEXT NOT NULL CHECK (kind IN ('query', 'export', 'login', 'logout', 'admin', 'sync')),
    user_id INTEGER REFERENCES users(id),
    activation_id INTEGER REFERENCES activations(id),
    session_id INTEGER REFERENCES sessions(id),
    pg_role TEXT,
    connection_id INTEGER REFERENCES connections(id),
    sql_text TEXT,
    rows INTEGER,
    duration_ms REAL,
    error TEXT,
    detail TEXT CHECK (detail IS NULL OR json_valid(detail))
);
CREATE INDEX audit_log_ts ON audit_log(ts);
CREATE INDEX audit_log_user_id ON audit_log(user_id);
CREATE INDEX audit_log_activation_id ON audit_log(activation_id);
CREATE INDEX audit_log_session_id ON audit_log(session_id);
CREATE INDEX audit_log_connection_id ON audit_log(connection_id);

CREATE TRIGGER audit_log_no_update BEFORE UPDATE ON audit_log
BEGIN
    SELECT RAISE(ABORT, 'audit_log is append-only');
END;
CREATE TRIGGER audit_log_no_delete BEFORE DELETE ON audit_log
BEGIN
    SELECT RAISE(ABORT, 'audit_log is append-only');
END;
