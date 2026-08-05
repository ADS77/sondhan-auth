-- ============================================================================
-- V4__create_audit_schema.sql
--
-- Creates:
--   - audit_event enum
--   - audit_logs parent partitioned table
--   - grants
-- ============================================================================

CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM pg_type
        WHERE typname = 'audit_event'
    ) THEN
CREATE TYPE audit_event AS ENUM (
            'REGISTER',
            'LOGIN',
            'LOGOUT',
            'OTP_SENT',
            'OTP_FAILED',
            'OTP_VERIFIED',
            'REFRESH_TOKEN_ROTATED',
            'REFRESH_REUSE_ATTACK',
            'ACCOUNT_LOCKED',
            'ROLE_CHANGED',
            'TOKEN_REVOKED',
            'ACCOUNT_DEACTIVATED'
        );
END IF;
END $$;

CREATE TABLE audit_logs
(
    id          UUID            NOT NULL DEFAULT uuid_generate_v4(),
    user_id     UUID,
    event       audit_event     NOT NULL,
    ip_address  VARCHAR(45),
    user_agent  TEXT,
    metadata    JSONB,
    created_at  TIMESTAMPTZ     NOT NULL DEFAULT now(),

    PRIMARY KEY(id, created_at)
)
    PARTITION BY RANGE(created_at);

DO $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM pg_roles WHERE rolname = 'sondhan_app'
    ) THEN

        GRANT SELECT, INSERT ON audit_logs TO sondhan_app;

END IF;
END $$;