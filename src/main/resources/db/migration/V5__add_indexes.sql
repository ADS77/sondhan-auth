-- V5__add_indexes.sql

-- users: look up by phone token for login flow
CREATE INDEX idx_users_phone_token ON users (phone_token_id);

-- users: look up locked accounts quickly
CREATE INDEX idx_users_locked_until ON users (locked_until) WHERE locked_until IS NOT NULL;

-- otp_codes: look up by user + purpose for verification
CREATE INDEX idx_otp_user_purpose ON otp_codes (user_id, purpose);

-- otp_codes: clean-up job can efficiently find expired codes
CREATE INDEX idx_otp_expires_at ON otp_codes (expires_at);

-- pii_tokens: type filter
CREATE INDEX idx_pii_type ON pii_tokens (pii_type);
