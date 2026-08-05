package com.sondhan.auth.dto;

import com.fasterxml.jackson.annotation.JsonProperty;
import java.time.Instant;
import java.util.List;
import java.util.UUID;

/**
 * JSON payload stored in Redis under key {@code refresh:{uuid}}.
 * Schema is frozen — downstream rotation logic depends on these field names.
 */
public record RefreshTokenData(
    @JsonProperty("userId") UUID userId,
    @JsonProperty("roles") List<String> roles,
    @JsonProperty("issuedAt") Instant issuedAt,
    @JsonProperty("deviceId") String deviceId,
    @JsonProperty("familyId") UUID familyId) {

  /** Create a new token data record for a freshly issued refresh token. */
  public static RefreshTokenData issue(
      UUID userId, List<String> roles, String deviceId, UUID familyId) {
    return new RefreshTokenData(userId, roles, Instant.now(), deviceId, familyId);
  }

  /** Rotate — carry forward same family, update issuedAt and deviceId. */
  public RefreshTokenData rotate(String newDeviceId) {
    return new RefreshTokenData(userId, roles, Instant.now(), newDeviceId, familyId);
  }
}
