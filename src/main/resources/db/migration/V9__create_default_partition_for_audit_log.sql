-- ============================================================================
-- V9__create_default_partition.sql
-- ============================================================================

CREATE TABLE audit_logs_default
    PARTITION OF audit_logs
    DEFAULT;