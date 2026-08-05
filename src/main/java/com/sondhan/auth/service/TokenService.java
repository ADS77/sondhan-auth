package com.sondhan.auth.service;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.sondhan.auth.dto.RefreshTokenData;
import com.sondhan.auth.exception.AuthException;
import com.sondhan.auth.exception.ErrorCode;
import com.sondhan.auth.security.JwtTokenProvider;
import io.jsonwebtoken.Claims;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Service;

import java.time.Duration;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.TimeUnit;

/**
 * Manages the Redis token store:
 * <ul>
 *   <li>Refresh token issuance, rotation, reuse detection, revocation</li>
 *   <li>Access token deny-list (logout / revoke)</li>
 *   <li>Session counting</li>
 * </ul>
 *
 * <p>Redis key schema (frozen):
 * <pre>
 *   refresh:{uuid}            TTL 30d
 *   deny:{jti}                TTL = token remaining life
 *   otp:{user_uuid}:{purpose} TTL 5min
 *   session:count:{user_uuid} TTL 24h
 * </pre>
 */
@Service
public class TokenService {

    private static final Logger log = LoggerFactory.getLogger(TokenService.class);

    private static final long REFRESH_TTL_DAYS = 30L;
    private static final long SESSION_TTL_HOURS = 24L;

    private static final String PREFIX_REFRESH = "refresh:";
    private static final String PREFIX_DENY = "deny:";
    private static final String PREFIX_SESSION = "session:count:";

    private final RedisTemplate<String, Object> redisTemplate;
    private final JwtTokenProvider jwtTokenProvider;
    private final ObjectMapper objectMapper;

    public TokenService(
            RedisTemplate<String, Object> redisTemplate,
            JwtTokenProvider jwtTokenProvider,
            ObjectMapper objectMapper) {
        this.redisTemplate = redisTemplate;
        this.jwtTokenProvider = jwtTokenProvider;
        this.objectMapper = objectMapper;
    }

    // ─── Access token helpers ────────────────────────────────────────────────

    /**
     * Issues a new signed access token.
     */
    public String issueAccessToken(UUID userId, List<String> roles) {
        return jwtTokenProvider.issueAccessToken(userId, roles);
    }

    /**
     * Adds a JTI to the deny-list with TTL equal to the token's remaining lifetime.
     * After this, the token is rejected by {@link com.sondhan.auth.security.JwtAuthFilter}.
     */
    public void denyAccessToken(String rawToken) {
        try {
            Claims claims = jwtTokenProvider.parseAndValidate(rawToken);
            String jti = claims.getId();
            long ttl = jwtTokenProvider.remainingTtlSeconds(claims);
            if (ttl > 0) {
                redisTemplate.opsForValue()
                        .set(PREFIX_DENY + jti, "1", Duration.ofSeconds(ttl));
                log.debug("Access token JTI {} added to deny-list, TTL {}s", jti, ttl);
            }
        } catch (Exception e) {
            log.warn("Could not deny access token: {}", e.getMessage());
        }
    }

    /**
     * Returns true if the given JTI is on the deny-list.
     */
    public boolean isDenied(String jti) {
        return Boolean.TRUE.equals(redisTemplate.hasKey(PREFIX_DENY + jti));
    }

    // ─── Refresh token ───────────────────────────────────────────────────────

    /**
     * Issues a new opaque refresh token and stores its payload in Redis.
     *
     * @param userId   the user this token belongs to
     * @param roles    roles to embed (carried forward on rotation)
     * @param deviceId hashed User-Agent or device fingerprint
     * @param familyId token family for reuse detection; pass a new UUID for fresh issuance
     * @return the opaque refresh token UUID string
     */
    public String issueRefreshToken(
            UUID userId, List<String> roles, String deviceId, UUID familyId) {
        String tokenId = UUID.randomUUID().toString();
        RefreshTokenData data = RefreshTokenData.issue(userId, roles, deviceId, familyId);
        storeRefreshToken(tokenId, data);
        incrementSessionCount(userId);
        return tokenId;
    }

    /**
     * Rotates a refresh token atomically:
     * <ol>
     *   <li>Looks up the old token</li>
     *   <li>Detects reuse (token already consumed = attack)</li>
     *   <li>Deletes the old key</li>
     *   <li>Issues a new token with the same family ID</li>
     * </ol>
     *
     * @param oldTokenId the presented opaque refresh token
     * @param deviceId   current device identifier
     * @return pair of [new access token, new refresh token]
     * @throws AuthException REFRESH_REUSE_ATTACK if the token was already rotated
     * @throws AuthException TOKEN_INVALID if the token does not exist
     */
    public RotationResult rotateRefreshToken(String oldTokenId, String deviceId) {
        String key = PREFIX_REFRESH + oldTokenId;
        RefreshTokenData data = loadRefreshTokenData(key);

        // Delete the old token atomically — if delete returns false, concurrent rotation happened
        Boolean deleted = redisTemplate.delete(key);
        if (!Boolean.TRUE.equals(deleted)) {
            // Token was already consumed → reuse attack; revoke entire family
            log.warn("Refresh token reuse detected for family {}", data.familyId());
            revokeFamily(data.familyId());
            throw new AuthException(ErrorCode.REFRESH_REUSE_ATTACK,
                    "Refresh token reuse detected — all sessions revoked");
        }

        String newAccessToken = issueAccessToken(data.userId(), data.roles());
        String newRefreshToken = issueRefreshToken(
                data.userId(), data.roles(), deviceId, data.familyId());

        log.debug("Refresh token rotated for user {}", data.userId());
        return new RotationResult(newAccessToken, newRefreshToken, data.userId(), data.roles());
    }

    /**
     * Revokes a specific refresh token (called on logout).
     * Decrements the session counter so it stays accurate.
     */
    public void revokeRefreshToken(String tokenId) {
        String key = PREFIX_REFRESH + tokenId;
        try {
            RefreshTokenData data = loadRefreshTokenData(key);
            redisTemplate.delete(key);
            decrementSessionCount(data.userId());
        } catch (AuthException e) {
            // Token already expired or missing — safe to ignore
            redisTemplate.delete(key);
        }
        log.debug("Refresh token {} revoked", tokenId);
    }

    /**
     * Loads and deserializes the refresh token data. Throws if absent.
     */
    public RefreshTokenData loadRefreshTokenData(String key) {
        Object raw = redisTemplate.opsForValue().get(key);
        if (raw == null) {
            throw new AuthException(ErrorCode.TOKEN_INVALID, "Refresh token not found or expired");
        }
        try {
            String json = raw instanceof String s ? s : objectMapper.writeValueAsString(raw);
            return objectMapper.readValue(json, RefreshTokenData.class);
        } catch (JsonProcessingException e) {
            throw new AuthException(ErrorCode.TOKEN_INVALID, "Malformed refresh token data");
        }
    }

    // ─── Session counting ────────────────────────────────────────────────────

    private void incrementSessionCount(UUID userId) {
        String key = PREFIX_SESSION + userId;
        redisTemplate.opsForValue().increment(key);
        redisTemplate.expire(key, SESSION_TTL_HOURS, TimeUnit.HOURS);
    }

    private void decrementSessionCount(UUID userId) {
        String key = PREFIX_SESSION + userId;
        Long current = redisTemplate.opsForValue().decrement(key);
        // Never let the counter go negative
        if (current != null && current < 0) {
            redisTemplate.opsForValue().set(key, "0", SESSION_TTL_HOURS, TimeUnit.HOURS);
        }
    }

    public long getSessionCount(UUID userId) {
        Object val = redisTemplate.opsForValue().get(PREFIX_SESSION + userId);
        if (val == null) {
            return 0L;
        }
        return Long.parseLong(val.toString());
    }

    // ─── Internal helpers ────────────────────────────────────────────────────

    private void storeRefreshToken(String tokenId, RefreshTokenData data) {
        try {
            String json = objectMapper.writeValueAsString(data);
            redisTemplate.opsForValue()
                    .set(PREFIX_REFRESH + tokenId, json, REFRESH_TTL_DAYS, TimeUnit.DAYS);
            log.info("== RefreshToken stored in redis ==");
        } catch (JsonProcessingException e) {
            throw new IllegalStateException("Failed to serialize refresh token data", e);
        }
    }

    /**
     * Revokes all tokens belonging to a family by scanning for matching familyId.
     * In practice families are small (few devices per user) so a scan is acceptable.
     * A dedicated family:→token index could be added if needed.
     */
    private void revokeFamily(UUID familyId) {
        // Scan for all refresh: keys and remove those matching the familyId
        var keys = redisTemplate.keys(PREFIX_REFRESH + "*");
        if (keys == null || keys.isEmpty()) {
            return;
        }
        for (String key : keys) {
            try {
                RefreshTokenData data = loadRefreshTokenData(key);
                if (familyId.equals(data.familyId())) {
                    redisTemplate.delete(key);
                }
            } catch (Exception e) {
                log.debug("Skipping key {} during family revocation: {}", key, e.getMessage());
            }
        }
    }

    /**
     * Result of a successful refresh token rotation.
     */
    public record RotationResult(
            String accessToken,
            String refreshToken,
            UUID userId,
            List<String> roles) {
    }
}
