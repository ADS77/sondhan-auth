package com.sondhan.auth.exception;

import com.sondhan.auth.dto.response.ErrorResponse;
import jakarta.servlet.http.HttpServletRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.slf4j.MDC;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.validation.FieldError;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

import java.time.Instant;
import java.util.stream.Collectors;

/**
 * Maps all exceptions to the standard error envelope.
 * Stack traces are NEVER returned to the client.
 *
 * <p>Error response format:
 * <pre>
 * {
 *   "status": 400,
 *   "error": "INVALID_OTP",
 *   "message": "OTP is incorrect or expired",
 *   "timestamp": "2026-05-11T10:00:00Z",
 *   "request_id": "uuid"
 * }
 * </pre>
 */
@RestControllerAdvice
public class GlobalExceptionHandler {

    private static final Logger log = LoggerFactory.getLogger(GlobalExceptionHandler.class);

    @ExceptionHandler(AuthException.class)
    public ResponseEntity<ErrorResponse> handleAuthException(
            AuthException ex, HttpServletRequest request) {
        HttpStatus status = mapErrorCodeToStatus(ex.getErrorCode());
        log.warn("AuthException [{}]: {}", ex.getErrorCode(), ex.getMessage());
        return ResponseEntity.status(status)
                .body(buildError(status.value(), ex.getErrorCode().name(), ex.getMessage()));
    }

    @ExceptionHandler(MethodArgumentNotValidException.class)
    public ResponseEntity<ErrorResponse> handleValidation(
            MethodArgumentNotValidException ex) {
        String message = ex.getBindingResult().getFieldErrors().stream()
                .map(FieldError::getDefaultMessage)
                .collect(Collectors.joining("; "));
        return ResponseEntity.badRequest()
                .body(buildError(400, "INVALID_REQUEST", message));
    }

    @ExceptionHandler(AccessDeniedException.class)
    public ResponseEntity<ErrorResponse> handleAccessDenied(AccessDeniedException ex) {
        log.warn("Access denied: {}", ex.getMessage());
        return ResponseEntity.status(HttpStatus.FORBIDDEN)
                .body(buildError(403, "UNAUTHORIZED", "You do not have permission to access this resource"));
    }

    @ExceptionHandler(Exception.class)
    public ResponseEntity<ErrorResponse> handleGeneric(Exception ex) throws Exception {
        if (ex instanceof org.springframework.web.servlet.resource.NoResourceFoundException) {
            throw ex;
        }
        log.error("Unhandled exception", ex);
        return ResponseEntity.internalServerError()
                .body(buildError(500, "INTERNAL_ERROR", "An unexpected error occurred"));
    }

    private ErrorResponse buildError(int status, String error, String message) {
        String requestId = MDC.get("request_id");
        return new ErrorResponse(status, error, message, Instant.now(), requestId);
    }

    private HttpStatus mapErrorCodeToStatus(ErrorCode code) {
        return switch (code) {
            case USER_NOT_FOUND -> HttpStatus.NOT_FOUND;
            case USER_ALREADY_EXISTS -> HttpStatus.CONFLICT;
            case UNAUTHORIZED, REFRESH_REUSE_ATTACK -> HttpStatus.UNAUTHORIZED;
            case RATE_LIMITED -> HttpStatus.TOO_MANY_REQUESTS;
            case ACCOUNT_LOCKED, ACCOUNT_NOT_VERIFIED -> HttpStatus.FORBIDDEN;
            case TOKEN_EXPIRED, TOKEN_INVALID -> HttpStatus.UNAUTHORIZED;
            default -> HttpStatus.BAD_REQUEST;
        };
    }
}
