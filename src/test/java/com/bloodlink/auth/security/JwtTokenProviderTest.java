package com.sondhan.auth.security;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.List;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class JwtTokenProviderTest {

  private static JwtTokenProvider provider;

  @BeforeAll
  static void setUpKeyPair() throws Exception {
    KeyPairGenerator gen = KeyPairGenerator.getInstance("RSA");
    gen.initialize(2048);
    var pair = gen.generateKeyPair();
    provider = new JwtTokenProvider(
            (RSAPrivateKey) pair.getPrivate(),
            (RSAPublicKey) pair.getPublic());
  }

  @Test
  void issueAccessToken_givenUserAndRoles_thenProducesValidJwt() {
    UUID userId = UUID.randomUUID();
    String token = provider.issueAccessToken(userId, List.of("DONOR"));

    assertThat(token).isNotBlank();
    Claims claims = provider.parseAndValidate(token);
    assertThat(claims.getSubject()).isEqualTo(userId.toString());
    assertThat(claims.getIssuer()).isEqualTo("bloodlink-auth");
    assertThat(claims.get("roles", List.class)).containsExactly("DONOR");
  }

  @Test
  void issueAccessToken_givenMultipleRoles_thenAllRolesEmbedded() {
    UUID userId = UUID.randomUUID();
    String token = provider.issueAccessToken(userId, List.of("DONOR", "ORG_ADMIN"));

    Claims claims = provider.parseAndValidate(token);
    assertThat(claims.get("roles", List.class)).containsExactlyInAnyOrder("DONOR", "ORG_ADMIN");
  }

  @Test
  void issueAccessToken_givenCalls_thenEachTokenHasUniqueJti() {
    UUID userId = UUID.randomUUID();
    String token1 = provider.issueAccessToken(userId, List.of("DONOR"));
    String token2 = provider.issueAccessToken(userId, List.of("DONOR"));

    Claims claims1 = provider.parseAndValidate(token1);
    Claims claims2 = provider.parseAndValidate(token2);
    assertThat(claims1.getId()).isNotEqualTo(claims2.getId());
  }

  @Test
  void parseAndValidate_givenTamperedToken_thenThrowsJwtException() {
    UUID userId = UUID.randomUUID();
    String token = provider.issueAccessToken(userId, List.of("DONOR"));

    // Tamper with the signature segment
    String[] parts = token.split("\\.");
    String tampered = parts[0] + "." + parts[1] + ".invalidsignature";

    assertThatThrownBy(() -> provider.parseAndValidate(tampered))
            .isInstanceOf(JwtException.class);
  }

  @Test
  void parseAndValidate_givenGarbageString_thenThrowsJwtException() {
    assertThatThrownBy(() -> provider.parseAndValidate("not.a.jwt"))
            .isInstanceOf(JwtException.class);
  }

  @Test
  void extractJti_givenValidToken_thenReturnsJti() {
    String token = provider.issueAccessToken(UUID.randomUUID(), List.of("DONOR"));
    String jti = provider.extractJti(token);
    assertThat(jti).isNotBlank();
    // JTI should be a valid UUID
    assertThat(UUID.fromString(jti)).isNotNull();
  }

  @Test
  void extractJti_givenInvalidToken_thenReturnsNull() {
    assertThat(provider.extractJti("garbage")).isNull();
  }

  @Test
  void remainingTtlSeconds_givenFreshToken_thenReturnsCloseToFifteenMinutes() {
    String token = provider.issueAccessToken(UUID.randomUUID(), List.of("DONOR"));
    Claims claims = provider.parseAndValidate(token);
    long ttl = provider.remainingTtlSeconds(claims);
    // Allow ±5s for test execution time
    assertThat(ttl).isBetween(895L, 900L);
  }

  @Test
  void getPublicKey_thenReturnsRsaPublicKey() {
    assertThat(provider.getPublicKey()).isNotNull();
    assertThat(provider.getPublicKey().getAlgorithm()).isEqualTo("RSA");
  }
}
