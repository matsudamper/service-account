CREATE TABLE users
(
    user_id             INTEGER PRIMARY KEY AUTOINCREMENT,
    username            TEXT    NOT NULL UNIQUE,
    passkey_user_handle TEXT    NOT NULL UNIQUE,
    created_at          INTEGER NOT NULL
);

CREATE TABLE user_passwords
(
    user_id            INTEGER PRIMARY KEY REFERENCES users (user_id) ON DELETE CASCADE,
    password_hash_type TEXT    NOT NULL,
    password_hash      TEXT    NOT NULL,
    updated_at         INTEGER NOT NULL
);

CREATE TABLE passkeys
(
    credential_id            TEXT PRIMARY KEY,
    user_id                  INTEGER NOT NULL REFERENCES users (user_id) ON DELETE CASCADE,
    rp_id                    TEXT    NOT NULL,
    attested_credential_data BLOB    NOT NULL,
    sign_count               INTEGER NOT NULL,
    name                     TEXT    NOT NULL,
    created_at               INTEGER NOT NULL,
    last_used_at             INTEGER
);
CREATE INDEX passkeys_user_id ON passkeys (user_id);

CREATE TABLE passkey_challenges
(
    challenge  TEXT PRIMARY KEY,
    purpose    TEXT    NOT NULL,
    client_id  TEXT    NOT NULL,
    user_id    INTEGER,
    expires_at INTEGER NOT NULL
);
CREATE INDEX passkey_challenges_expires_at ON passkey_challenges (expires_at);

CREATE TABLE login_failures
(
    client_ip     TEXT    NOT NULL,
    username      TEXT    NOT NULL,
    failure_count INTEGER NOT NULL,
    expires_at    INTEGER NOT NULL,
    PRIMARY KEY (client_ip, username)
);
CREATE INDEX login_failures_expires_at ON login_failures (expires_at);
