package com.sondhan.auth.security;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.time.Instant;
import java.util.Date;
import java.util.List;
import java.util.UUID;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

/**
 * Issues and validates RS256-signed JWTs.
 * Private key signs; public key is shared via /auth/.well-known/jwks.json.
 */
@Component
public class JwtTokenProvider {

  private static final Logger log = LoggerFactory.getLogger(JwtTokenProvider.class);
  private static final String ISSUER = "sondhan-auth";
  private static final String CLAIM_ROLES = "roles";
  private static final long ACCESS_TOKEN_TTL_SECONDS = 900L; // 15 minutes

  private final RSAPrivateKey privateKey;
  private final RSAPublicKey publicKey;

  public JwtTokenProvider(RSAPrivateKey privateKey, RSAPublicKey publicKey) {
    this.privateKey = privateKey;
    this.publicKey = publicKey;
  }

  /**
   * Issues a signed RS256 access token.
   *
   * @param userId the subject (user UUID)
   * @param roles  list of role names to embed in the token
   * @return signed JWT string
   */
  public String issueAccessToken(UUID userId, List<String> roles) {
    Instant now = Instant.now();
    Instant exp = now.plusSeconds(ACCESS_TOKEN_TTL_SECONDS);

    return Jwts.builder()
        .subject(userId.toString())
        .id(UUID.randomUUID().toString())
        .issuer(ISSUER)
        .issuedAt(Date.from(now))
        .expiration(Date.from(exp))
        .claim(CLAIM_ROLES, roles)
        .signWith(privateKey)
        .compact();
  }

  /**
   * Parses and validates a JWT. Throws {@link JwtException} on any failure.
   *
   * @param token raw JWT string (without "Bearer " prefix)
   * @return validated {@link Claims}
   */
  public Claims parseAndValidate(String token) {
    return Jwts.parser()
        .verifyWith(publicKey)
        .build()
        .parseSignedClaims(token)
        .getPayload();
  }

  /**
   * Extracts the JTI (JWT ID) without throwing — returns null on parse failure.
   * Used in the deny-list check where we want a graceful fallback.
   */
  public String extractJti(String token) {
    try {
      return parseAndValidate(token).getId();
    } catch (JwtException | IllegalArgumentException e) {
      log.debug("Could not extract JTI from token: {}", e.getMessage());
      return null;
    }
  }

  /**
   * Returns the remaining lifetime of a token in seconds, or 0 if already expired.
   * Used to set the deny-list TTL on logout.
   */
  public long remainingTtlSeconds(Claims claims) {
    long expEpoch = claims.getExpiration().toInstant().getEpochSecond();
    long remaining = expEpoch - Instant.now().getEpochSecond();
    return Math.max(0L, remaining);
  }

  public RSAPublicKey getPublicKey() {
    return publicKey;
  }

  public long getAccessTokenTtlSeconds() {
    return ACCESS_TOKEN_TTL_SECONDS;
  }
}
