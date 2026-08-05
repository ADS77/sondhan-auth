package com.sondhan.auth.dto.response;

import com.fasterxml.jackson.annotation.JsonProperty;

import java.time.Instant;

public record ErrorResponse(
        int status,
        String error,
        String message,
        Instant timestamp,
        @JsonProperty("request_id") String requestId) {
}
