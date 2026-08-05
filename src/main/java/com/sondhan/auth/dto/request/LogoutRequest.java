package com.sondhan.auth.dto.request;

import com.fasterxml.jackson.annotation.JsonProperty;
import jakarta.validation.constraints.NotBlank;

public record LogoutRequest(
        @NotBlank(message = "refresh_token is required")
        @JsonProperty("refresh_token")
        String refreshToken)  {
}
