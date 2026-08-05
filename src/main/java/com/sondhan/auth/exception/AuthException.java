package com.sondhan.auth.exception;

/**
 * Thrown for all domain-level auth failures. Carries an {@link ErrorCode} for the response.
 */
public class AuthException extends RuntimeException {

    private final ErrorCode errorCode;

    public AuthException(ErrorCode errorCode, String message) {
        super(message);
        this.errorCode = errorCode;
    }

    public ErrorCode getErrorCode() {
        return errorCode;
    }
}
