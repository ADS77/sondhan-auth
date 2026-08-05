package com.sondhan.auth.dto.response;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.sondhan.auth.dto.AuthDtos;

import java.util.List;
import java.util.UUID;

public record TokenResponse(
        @JsonProperty("access_token") String accessToken,
        @JsonProperty("refresh_token") String refreshToken,
        @JsonProperty("token_type") String tokenType,
        @JsonProperty("expires_in") int expiresIn,
        UserSummary user)  {
    public static TokenResponse of(
            String accessToken, String refreshToken, UUID userId, List<String> roles) {
        return new TokenResponse(
                accessToken, refreshToken, "Bearer", 900, new UserSummary(userId, roles));
    }
}
