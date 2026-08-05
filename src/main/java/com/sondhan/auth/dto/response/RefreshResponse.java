package com.sondhan.auth.dto.response;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.sondhan.auth.dto.AuthDtos;

public record RefreshResponse(

        @JsonProperty("access_token") String accessToken,
        @JsonProperty("refresh_token") String refreshToken,
        @JsonProperty("expires_in") int expiresIn) {

    public static RefreshResponse of(String accessToken, String refreshToken) {
        return new RefreshResponse(accessToken, refreshToken, 900);
    }
}
