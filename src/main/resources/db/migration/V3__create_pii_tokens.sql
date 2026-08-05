-- V3__create_pii_tokens.sql
-- Stores encrypted PII (phone, email). The plaintext never leaves this table unencrypted.
-- Encryption key is passed at query time from the application (env var PII_ENCRYPTION_KEY).

CREATE TYPE pii_type AS ENUM ('PHONE', 'EMAIL');

CREATE TABLE pii_tokens (
    id              UUID        PRIMARY KEY DEFAULT uuid_generate_v4(),
    pii_type        pii_type    NOT NULL,
    encrypted_value BYTEA       NOT NULL,   -- pgp_sym_encrypt output
    value_hash      CHAR(64)    NOT NULL,   -- SHA-256 of plaintext for lookup (no key needed)
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Lookup by hash (e.g. "does this phone already exist?")
CREATE UNIQUE INDEX uq_pii_value_hash ON pii_tokens (value_hash);

-- Now add the FK constraints to users (table exists from V1)
ALTER TABLE users
    ADD CONSTRAINT fk_users_phone_token
        FOREIGN KEY (phone_token_id) REFERENCES pii_tokens(id) ON DELETE SET NULL;

ALTER TABLE users
    ADD CONSTRAINT fk_users_email_token
        FOREIGN KEY (email_token_id) REFERENCES pii_tokens(id) ON DELETE SET NULL;
