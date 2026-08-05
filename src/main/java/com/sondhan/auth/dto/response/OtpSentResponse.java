package com.sondhan.auth.dto.response;

import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.UUID;

public record OtpSentResponse(
        @JsonProperty("user_id")
        UUID userId,
        String message,
        @JsonProperty("otp_expires_in_seconds")
        int otpExpiresInSeconds)  {
}
