-- Accounts bind to one OIDC subject (B1). The ALTER is required because users
-- was created by 001; the partial unique index still allows unbound rows.
ALTER TABLE users ADD COLUMN oidc_sub TEXT;
CREATE UNIQUE INDEX users_oidc_sub ON users(oidc_sub) WHERE oidc_sub IS NOT NULL;

CREATE TABLE web_sessions (
    token_hash TEXT PRIMARY KEY NOT NULL CHECK (
        length(token_hash) = 64
        AND token_hash NOT GLOB '*[^0-9a-f]*'
    ),
    user_id INTEGER NOT NULL REFERENCES users(id),
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
        CHECK (created_at GLOB
        '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z'),
    last_seen_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
        CHECK (last_seen_at GLOB
        '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z'),
    expires_at TEXT NOT NULL CHECK (expires_at GLOB
        '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z'),
    ended_at TEXT CHECK (ended_at IS NULL OR ended_at GLOB
        '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z'),
    end_reason TEXT CHECK (
        (ended_at IS NULL AND end_reason IS NULL)
        OR (
            ended_at IS NOT NULL
            AND end_reason IS NOT NULL
            AND end_reason IN ('logout', 'idle', 'expired', 'user_disabled')
        )
    ),
    client_ip TEXT,
    user_agent TEXT,
    oidc_sid TEXT
);
CREATE INDEX web_sessions_user_id ON web_sessions(user_id);
CREATE INDEX web_sessions_expires_at ON web_sessions(expires_at);

CREATE TABLE oidc_login_states (
    state TEXT PRIMARY KEY NOT NULL,
    nonce TEXT NOT NULL,
    code_verifier TEXT NOT NULL,
    return_to TEXT NOT NULL,
    browser_hash TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
        CHECK (created_at GLOB
        '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z'),
    expires_at TEXT NOT NULL CHECK (expires_at GLOB
        '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z')
);
CREATE INDEX oidc_login_states_expires_at ON oidc_login_states(expires_at);
