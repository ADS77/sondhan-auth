package com.sondhan.auth.exception;

/**
 * All domain-level error codes used in API error responses.
 */
public enum ErrorCode {
    INVALID_OTP,
    OTP_EXPIRED,
    OTP_SEND_FAILED,
    USER_NOT_FOUND,
    USER_ALREADY_EXISTS,
    TOKEN_EXPIRED,
    TOKEN_INVALID,
    RATE_LIMITED,
    ACCOUNT_LOCKED,
    ACCOUNT_NOT_VERIFIED,
    UNAUTHORIZED,
    REFRESH_REUSE_ATTACK,
    INVALID_REQUEST,
    INVALID_EMAIL
}
