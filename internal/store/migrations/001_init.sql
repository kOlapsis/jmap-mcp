CREATE TABLE users (
    id         TEXT PRIMARY KEY,
    issuer     TEXT NOT NULL,
    subject    TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    UNIQUE (issuer, subject)
);

CREATE TABLE hosts (
    issuer       TEXT NOT NULL,
    kind         TEXT NOT NULL,
    metadata     TEXT NOT NULL,
    registration BLOB NOT NULL,
    updated_at   INTEGER NOT NULL,
    PRIMARY KEY (issuer, kind)
);

CREATE TABLE accounts (
    id          TEXT PRIMARY KEY,
    user_id     TEXT NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    email       TEXT NOT NULL,
    issuer      TEXT NOT NULL,
    session_url TEXT NOT NULL,
    token       BLOB NOT NULL,
    is_default  INTEGER NOT NULL DEFAULT 0,
    created_at  INTEGER NOT NULL,
    updated_at  INTEGER NOT NULL,
    UNIQUE (user_id, email)
);

CREATE TABLE mcp_clients (
    client_id   TEXT PRIMARY KEY,
    secret_hash TEXT NOT NULL DEFAULT '',
    metadata    TEXT NOT NULL,
    created_at  INTEGER NOT NULL
);

CREATE TABLE auth_requests (
    id         TEXT PRIMARY KEY,
    data       BLOB NOT NULL,
    expires_at INTEGER NOT NULL
);

CREATE TABLE auth_codes (
    code_hash  TEXT PRIMARY KEY,
    user_id    TEXT NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    data       TEXT NOT NULL,
    expires_at INTEGER NOT NULL
);

CREATE TABLE tokens (
    token_hash TEXT PRIMARY KEY,
    kind       TEXT NOT NULL,
    user_id    TEXT NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    client_id  TEXT NOT NULL,
    resource   TEXT NOT NULL,
    scope      TEXT NOT NULL,
    family     TEXT NOT NULL,
    expires_at INTEGER NOT NULL
);

CREATE INDEX tokens_family ON tokens (family);
CREATE INDEX tokens_expiry ON tokens (expires_at);
