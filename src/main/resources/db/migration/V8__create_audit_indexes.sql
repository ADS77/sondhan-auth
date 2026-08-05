-- ============================================================================
-- V8__create_audit_indexes.sql
-- ============================================================================

CREATE INDEX idx_audit_logs_user_id
ON audit_logs(user_id);

CREATE INDEX idx_audit_logs_created_at
ON audit_logs(created_at DESC);

CREATE INDEX idx_audit_logs_event
ON audit_logs(event);

CREATE INDEX idx_audit_logs_user_created
ON audit_logs(user_id, created_at DESC);