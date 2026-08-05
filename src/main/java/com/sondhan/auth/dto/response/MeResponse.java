package com.sondhan.auth.dto.response;

import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.List;
import java.util.UUID;

public record MeResponse(
        UUID id,
        @JsonProperty("blood_group") String bloodGroup,
        List<String> roles,
        @JsonProperty("is_verified") boolean verified)  {
}
