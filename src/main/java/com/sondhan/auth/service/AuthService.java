package com.sondhan.auth.service;

import com.sondhan.auth.domain.AuditEvent;
import com.sondhan.auth.domain.OtpPurpose;
import com.sondhan.auth.domain.User;
import com.sondhan.auth.dto.request.RegisterRequest;
import com.sondhan.auth.dto.response.MeResponse;
import com.sondhan.auth.dto.response.OtpSentResponse;
import com.sondhan.auth.dto.response.RefreshResponse;
import com.sondhan.auth.dto.response.TokenResponse;
import com.sondhan.auth.exception.AuthException;
import com.sondhan.auth.exception.ErrorCode;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.UUID;
import java.util.stream.Collectors;

/**
 * Orchestrates the high-level auth flows:
 * register → OTP → verify, login → OTP → verify, refresh, logout, /me.
 */
@Service
public class AuthService {

  private static final Logger log = LoggerFactory.getLogger(AuthService.class);

  private final UserService userService;
  private final OtpService otpService;
  private final TokenService tokenService;
  private final AuditService auditService;

  public AuthService(
          UserService userService,
          OtpService otpService,
          TokenService tokenService,
          AuditService auditService) {
    this.userService = userService;
    this.otpService = otpService;
    this.tokenService = tokenService;
    this.auditService = auditService;
  }

  // ─── Register ────────────────────────────────────────────────────────────

  @Transactional
  public OtpSentResponse register(RegisterRequest registerRequest, String ipAddress, String userAgent) {

    User user = userService.registerNewUser(
            registerRequest.email(),
            registerRequest.phone(),
            registerRequest.firstName(),
            registerRequest.lastName(),
            registerRequest.bloodGroup());
    String decryptedPhone = userService.decryptPhone(user);
    String decryptedEmail = userService.decryptEmail(user);
    int ttl = otpService.generateAndSend(user, decryptedEmail, decryptedPhone, OtpPurpose.REGISTER);
    if (ttl > 0) {
      auditService.log(AuditEvent.REGISTER, user.getId(), ipAddress, userAgent);
      auditService.log(AuditEvent.OTP_SENT, user.getId(), ipAddress, userAgent,
              "{\"purpose\":\"REGISTER\"}");
      return new OtpSentResponse(user.getId(), "OTP sent", ttl);
    } else {
      return new OtpSentResponse(user.getId(), "Failed to send OTP", ttl);
    }
  }

  // ─── Login ───────────────────────────────────────────────────────────────

  @Transactional
  public OtpSentResponse login(String phone, String ipAddress, String userAgent) {
    User user = userService.findByPhone(phone);

    if (!user.isVerified()) {
      throw new AuthException(ErrorCode.ACCOUNT_NOT_VERIFIED,
              "Account not verified. Please complete registration first.");
    }
    if (!user.isActive()) {
      throw new AuthException(ErrorCode.UNAUTHORIZED, "Account is deactivated.");
    }

    String decryptedPhone = userService.decryptPhone(user);
    String decryptedEmail = userService.decryptEmail(user);
    int ttl = otpService.generateAndSend(user, decryptedEmail, decryptedPhone, OtpPurpose.LOGIN);
    if (ttl > 0) {
      auditService.log(AuditEvent.REGISTER, user.getId(), ipAddress, userAgent);
      auditService.log(AuditEvent.OTP_SENT, user.getId(), ipAddress, userAgent,
              "{\"purpose\":\"LOGIN\"}");
      return new OtpSentResponse(user.getId(), "OTP sent", ttl);
    } else {
      return new OtpSentResponse(user.getId(), "Failed to send OTP", ttl);
    }
  }

  // ─── Verify OTP ──────────────────────────────────────────────────────────

  @Transactional
  public TokenResponse verifyOtp(
          UUID userId, String rawOtp, String purposeStr,
          String ipAddress, String userAgent, String deviceId) {

    OtpPurpose purpose = parsePurpose(purposeStr);
    User user = userService.findById(userId);

    try {
      otpService.verify(user, rawOtp, purpose);
    } catch (AuthException e) {
      userService.save(user);  // persist failed attempt counter / lockout
      auditService.log(AuditEvent.OTP_FAILED, userId, ipAddress, userAgent,
              "{\"purpose\":\"" + purposeStr + "\"}");
      throw e;
    }

    if (purpose == OtpPurpose.REGISTER) {
      user = userService.markVerified(user);
    }

    userService.save(user);  // persist resetFailedOtpAttempts

    List<String> roles = extractRoleNames(user);
    String accessToken = tokenService.issueAccessToken(user.getId(), roles);
    String refreshToken = tokenService.issueRefreshToken(
            user.getId(), roles, deviceId, UUID.randomUUID());

    auditService.log(AuditEvent.OTP_VERIFIED, user.getId(), ipAddress, userAgent,
            "{\"purpose\":\"" + purposeStr + "\"}");

    return TokenResponse.of(accessToken, refreshToken, user.getId(), roles);
  }

  // ─── Refresh ─────────────────────────────────────────────────────────────

  public RefreshResponse refresh(String refreshToken, String deviceId,
                                 String ipAddress, String userAgent) {
    try {
      TokenService.RotationResult result = tokenService.rotateRefreshToken(refreshToken, deviceId);
      auditService.log(AuditEvent.REFRESH_TOKEN_ROTATED, result.userId(), ipAddress, userAgent);
      return RefreshResponse.of(result.accessToken(), result.refreshToken());
    } catch (AuthException e) {
      if (e.getErrorCode() == ErrorCode.REFRESH_REUSE_ATTACK) {
        auditService.log(AuditEvent.REFRESH_REUSE_ATTACK, null, ipAddress, userAgent,
                "{\"token\":\"" + refreshToken.substring(0, 8) + "...\"}");
      }
      throw e;
    }
  }

  // ─── Logout ──────────────────────────────────────────────────────────────

  public void logout(String rawAccessToken, String refreshToken,
                     UUID userId, String ipAddress, String userAgent) {
    tokenService.denyAccessToken(rawAccessToken);
    tokenService.revokeRefreshToken(refreshToken);
    auditService.log(AuditEvent.LOGOUT, userId, ipAddress, userAgent);
    log.info("User {} logged out", userId);
  }

  // ─── /me ─────────────────────────────────────────────────────────────────

  @Transactional(readOnly = true)
  public MeResponse getMe(UUID userId) {
    User user = userService.findById(userId);
    return new MeResponse(
            user.getId(),
            user.getBloodGroup(),
            extractRoleNames(user),
            user.isVerified());
  }

  // ─── Helpers ─────────────────────────────────────────────────────────────

  private List<String> extractRoleNames(User user) {
    return user.getRoles().stream()
            .map(r -> r.getName())
            .collect(Collectors.toList());
  }

  private OtpPurpose parsePurpose(String purposeStr) {
    try {
      return OtpPurpose.valueOf(purposeStr.toUpperCase());
    } catch (IllegalArgumentException e) {
      throw new AuthException(ErrorCode.INVALID_REQUEST,
              "Invalid OTP purpose: " + purposeStr);
    }
  }
}
