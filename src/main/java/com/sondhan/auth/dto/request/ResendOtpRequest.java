package com.sondhan.auth.dto.request;

import com.fasterxml.jackson.annotation.JsonProperty;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Pattern;

import java.util.UUID;

public record ResendOtpRequest(
        @NotNull(message = "user_id is required")
        @JsonProperty("user_id")
        UUID userId,

        @NotBlank(message = "purpose is required")
        @Pattern(
                regexp = "^(LOGIN|REGISTER|PASSWORD_RESET)$",
                message = "purpose must be LOGIN, REGISTER, or PASSWORD_RESET")
        String purpose) {
}
