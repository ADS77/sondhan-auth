-- V2__create_otp_codes.sql

CREATE TYPE otp_purpose AS ENUM ('LOGIN', 'REGISTER', 'PASSWORD_RESET');

CREATE TABLE otp_codes (
    id          UUID        PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id     UUID        NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    code_hash   CHAR(64)    NOT NULL,        -- SHA-256 hex, never plaintext
    purpose     otp_purpose NOT NULL,
    expires_at  TIMESTAMPTZ NOT NULL,
    used_at     TIMESTAMPTZ,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Only one active (unused, non-expired) OTP per user+purpose at a time
CREATE UNIQUE INDEX uq_otp_active
ON otp_codes(user_id, purpose)
WHERE used_at IS NULL;
