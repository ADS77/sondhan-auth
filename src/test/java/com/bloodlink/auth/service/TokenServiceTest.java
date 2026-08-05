package com.sondhan.auth.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import com.sondhan.auth.dto.RefreshTokenData;
import com.sondhan.auth.exception.AuthException;
import com.sondhan.auth.exception.ErrorCode;
import com.sondhan.auth.security.JwtTokenProvider;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.data.redis.core.ValueOperations;

import java.util.List;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class TokenServiceTest {

  private final UUID testUserId = UUID.randomUUID();
  private final List<String> testRoles = List.of("DONOR");
  @Mock
  private RedisTemplate<String, Object> redisTemplate;
  @Mock
  private ValueOperations<String, Object> valueOps;
  @Mock
  private JwtTokenProvider jwtTokenProvider;
  private TokenService tokenService;

  @BeforeEach
  void setUp() {
    ObjectMapper mapper = new ObjectMapper().registerModule(new JavaTimeModule());
    tokenService = new TokenService(redisTemplate, jwtTokenProvider, mapper);
    when(redisTemplate.opsForValue()).thenReturn(valueOps);
  }

  @Test
  void isDenied_givenDeniedJti_thenReturnsTrue() {
    when(redisTemplate.hasKey("deny:some-jti")).thenReturn(Boolean.TRUE);
    assertThat(tokenService.isDenied("some-jti")).isTrue();
  }

  @Test
  void isDenied_givenNonDeniedJti_thenReturnsFalse() {
    when(redisTemplate.hasKey("deny:some-jti")).thenReturn(Boolean.FALSE);
    assertThat(tokenService.isDenied("some-jti")).isFalse();
  }

  @Test
  void issueRefreshToken_givenValidArgs_thenStoresInRedisAndReturnsUuidString() {
    UUID familyId = UUID.randomUUID();
    when(valueOps.increment(anyString())).thenReturn(1L);

    String token = tokenService.issueRefreshToken(testUserId, testRoles, "device-1", familyId);

    assertThat(token).isNotBlank();
    // Verify UUID format
    assertThat(UUID.fromString(token)).isNotNull();
    verify(valueOps).set(eq("refresh:" + token), anyString(), eq(30L), any());
  }

  @Test
  void rotateRefreshToken_givenConsumedToken_thenThrowsRefreshReuseAttack() {
    String oldToken = UUID.randomUUID().toString();
    UUID familyId = UUID.randomUUID();
    RefreshTokenData data = RefreshTokenData.issue(testUserId, testRoles, "device", familyId);

    ObjectMapper mapper = new ObjectMapper().registerModule(new JavaTimeModule());
    try {
      String json = mapper.writeValueAsString(data);
      when(valueOps.get("refresh:" + oldToken)).thenReturn(json);
      // Simulate atomic delete returning false (token already consumed)
      when(redisTemplate.delete("refresh:" + oldToken)).thenReturn(Boolean.FALSE);
      when(redisTemplate.keys("refresh:*")).thenReturn(java.util.Set.of());
    } catch (Exception e) {
      throw new RuntimeException(e);
    }

    assertThatThrownBy(() -> tokenService.rotateRefreshToken(oldToken, "device"))
            .isInstanceOf(AuthException.class)
            .satisfies(ex -> assertThat(((AuthException) ex).getErrorCode())
                    .isEqualTo(ErrorCode.REFRESH_REUSE_ATTACK));
  }

  @Test
  void rotateRefreshToken_givenAbsentToken_thenThrowsTokenInvalid() {
    String oldToken = UUID.randomUUID().toString();
    when(valueOps.get("refresh:" + oldToken)).thenReturn(null);

    assertThatThrownBy(() -> tokenService.rotateRefreshToken(oldToken, "device"))
            .isInstanceOf(AuthException.class)
            .satisfies(ex -> assertThat(((AuthException) ex).getErrorCode())
                    .isEqualTo(ErrorCode.TOKEN_INVALID));
  }
}
