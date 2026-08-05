package com.sondhan.auth.service;

import com.sondhan.auth.domain.OtpCode;
import com.sondhan.auth.domain.OtpPurpose;
import com.sondhan.auth.domain.User;
import com.sondhan.auth.exception.AuthException;
import com.sondhan.auth.exception.ErrorCode;
import com.sondhan.auth.repository.OtpRepository;
import com.sondhan.auth.service.notification.NotificationManager;
import com.sondhan.auth.util.HashUtil;
import com.sondhan.auth.util.MailUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.security.SecureRandom;
import java.time.Duration;
import java.time.Instant;
import java.util.concurrent.TimeUnit;

/**
 * Generates, sends, and verifies 6-digit OTPs.
 *
 * <p>Security properties:
 * <ul>
 *   <li>OTP is generated via {@link SecureRandom}</li>
 *   <li>Only the SHA-256 hash is stored in the DB</li>
 *   <li>Rate limit: max 3 OTP requests per phone per hour (Redis key otp:rl:{phone})</li>
 *   <li>Lockout: max 5 failed attempts per user before 15-min lockout</li>
 * </ul>
 */
@Service
public class OtpService {

  private static final Logger log = LoggerFactory.getLogger(OtpService.class);

  private static final int OTP_LENGTH = 6;
  private static final int OTP_TTL_SECONDS = 300;           // 5 minutes
  private static final int MAX_OTP_REQUESTS_PER_HOUR = 3;
  private static final int MAX_FAILED_ATTEMPTS = 5;
  private static final long LOCKOUT_MINUTES = 15L;

  private static final String PREFIX_OTP_RATE_LIMIT = "otp:rl:";
  // Frozen Redis key — otp:{user_uuid}:{purpose} TTL 5min
  private static final String PREFIX_OTP_STATE = "otp:";

  private final OtpRepository otpRepository;
  private final RedisTemplate<String, Object> redisTemplate;
  private final NotificationManager notificationManager;

  private final String twilioFromNumber = "01859910447";
  private final boolean twilioEnabled = false;
  private final SecureRandom secureRandom = new SecureRandom();


  public OtpService(OtpRepository otpRepository,
                    RedisTemplate<String, Object> redisTemplate,
                    NotificationManager notificationManager) {
    this.otpRepository = otpRepository;
    this.redisTemplate = redisTemplate;
    this.notificationManager = notificationManager;
  }

  /**
   * Generates an OTP, persists the hash, and sends the code via Twilio SMS.
   *
   * @param user        the target user
   * @param phoneNumber E.164 phone number (decrypted for this call only)
   * @param purpose     LOGIN, REGISTER, or PASSWORD_RESET
   * @return OTP expiry in seconds (always {@value #OTP_TTL_SECONDS})
   */
  @Transactional
  public int generateAndSend(User user, String email, String phoneNumber, OtpPurpose purpose) {
    enforceRateLimit(phoneNumber);
    enforceRateLimit(email);

    // Invalidate any previously active OTP for this user+purpose
    otpRepository.invalidatePreviousOtps(user, purpose, Instant.now());

    String plainOtp = generateSixDigitOtp();
    String codeHash = HashUtil.sha256Hex(plainOtp);
    Instant expiresAt = Instant.now().plusSeconds(OTP_TTL_SECONDS);

    otpRepository.save(new OtpCode(user, codeHash, purpose, expiresAt));

    // Write the frozen Redis key otp:{user_uuid}:{purpose} — TTL 5 min
    // This key signals to downstream services that an OTP is in-flight for this user+purpose
    String otpStateKey = PREFIX_OTP_STATE + user.getId() + ":" + purpose.name();
    redisTemplate.opsForValue().set(otpStateKey, "1", OTP_TTL_SECONDS, TimeUnit.SECONDS);

    if (MailUtil.isValidEmail(email)) {
      try {
        if (!notificationManager.notifyByMail(user, email, plainOtp)) {
          log.error("Failed to send otp by mail, userId : {}", user.getId());
          return 0;
        }
      } catch (Exception e) {
        throw new AuthException(ErrorCode.OTP_SEND_FAILED, "Failed to send otp via email, " + e.getMessage());
      }
    } else {
      log.error("Invalid Email : {}", email);
      throw new AuthException(ErrorCode.INVALID_EMAIL, "Email is not valid");
    }

    //TO-DO : config twillo sms gateway
    //sendSms(phoneNumber, plainOtp);

    log.info("OTP sent to user {},  purpose {}", user.getId(), purpose);
    return OTP_TTL_SECONDS;
  }

  /**
   * Verifies an OTP for a given user and purpose.
   * Increments failed-attempt counter and applies lockout on threshold breach.
   *
   * @param user    the user attempting verification
   * @param rawOtp  the 6-digit code submitted by the client
   * @param purpose the OTP purpose
   * @throws AuthException ACCOUNT_LOCKED if the user is currently locked out
   * @throws AuthException OTP_EXPIRED if the OTP has passed its TTL
   * @throws AuthException INVALID_OTP if the hash does not match
   */
  @Transactional
  public void verify(User user, String rawOtp, OtpPurpose purpose) {
    if (user.isLocked()) {
      throw new AuthException(ErrorCode.ACCOUNT_LOCKED,
              "Account is locked. Try again after " + user.getLockedUntil());
    }

    OtpCode otpCode = otpRepository
            .findActiveOtp(user, purpose, Instant.now())
            .orElseThrow(() -> new AuthException(ErrorCode.OTP_EXPIRED,
                    "No active OTP found. Please request a new one."));

    if (otpCode.isExpired()) {
      throw new AuthException(ErrorCode.OTP_EXPIRED, "OTP has expired");
    }

    String submittedHash = HashUtil.sha256Hex(rawOtp);
    if (!submittedHash.equals(otpCode.getCodeHash())) {
      handleFailedAttempt(user);
      throw new AuthException(ErrorCode.INVALID_OTP, "OTP is incorrect or expired");
    }

    // Success — mark used, clear Redis tracking key, reset counter
    otpCode.markUsed();
    otpRepository.save(otpCode);
    user.resetFailedOtpAttempts();
    String otpStateKey = PREFIX_OTP_STATE + user.getId() + ":" + purpose.name();
    redisTemplate.delete(otpStateKey);
    log.info("OTP verified for user {} purpose {}", user.getId(), purpose);
  }

  // ─── Internal helpers ────────────────────────────────────────────────────

  private void enforceRateLimit(String rlKey) {
    String key = PREFIX_OTP_RATE_LIMIT + HashUtil.sha256Hex(rlKey);
    Long count = redisTemplate.opsForValue().increment(key);
    if (count != null && count == 1L) {
      redisTemplate.expire(key, 1, TimeUnit.HOURS);
    }
    if (count != null && count > MAX_OTP_REQUESTS_PER_HOUR) {
      throw new AuthException(ErrorCode.RATE_LIMITED,
              "Too many OTP requests. Please try again later.");
    }
  }

  private void handleFailedAttempt(User user) {
    user.incrementFailedOtpAttempts();
    if (user.getFailedOtpAttempts() >= MAX_FAILED_ATTEMPTS) {
      user.lockUntil(Instant.now().plus(Duration.ofMinutes(LOCKOUT_MINUTES)));
      log.warn("User {} locked out after {} failed OTP attempts",
              user.getId(), MAX_FAILED_ATTEMPTS);
    }
  }

  private String generateSixDigitOtp() {
    int code = 100_000 + secureRandom.nextInt(900_000);
    return String.valueOf(code);
  }

  private void sendSms(String toNumber, String otp) {
    if (!twilioEnabled) {
      log.info("Twilio disabled — OTP for {} would be: {}", toNumber, otp);
      return;
    }
    try {
 /*     Message.creator(
              new PhoneNumber(toNumber),
              new PhoneNumber(twilioFromNumber),
              "Your Sondhan verification code is: " + otp + ". Valid for 5 minutes.")
          .create();*/
    } catch (Exception e) {
      log.error("Failed to send SMS to {}: {}", toNumber, e.getMessage());
      throw new AuthException(ErrorCode.OTP_SEND_FAILED, "Could not send OTP. Please retry.");
    }
  }
}
