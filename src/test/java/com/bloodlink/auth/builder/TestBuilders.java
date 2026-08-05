package com.sondhan.auth.builder;

import com.sondhan.auth.domain.*;
import com.sondhan.auth.util.HashUtil;

import java.time.Instant;

/**
 * Test data builders — never hardcode raw values in tests; use these instead.
 */
public final class TestBuilders {

  private TestBuilders() {
  }

  // ─── User ────────────────────────────────────────────────────────────────

  public static UserBuilder aUser() {
    return new UserBuilder();
  }

  public static OtpCodeBuilder anOtp() {
    return new OtpCodeBuilder();
  }

  // ─── OtpCode ─────────────────────────────────────────────────────────────

  public static AuditLog anAuditLog(AuditEvent auditEvent) {
    return AuditLog.builder(auditEvent)
            .ipAddress("127.0.0.1")
            .userAgent("TestAgent/1.0")
            .build();
  }

  public static class UserBuilder {

    private String firstName = "Rahim";
    private String lastName = "Uddin";
    private String bloodGroup = "O+";
    private boolean verified = false;
    private boolean active = true;

    public UserBuilder firstName(String firstName) {
      this.firstName = firstName;
      return this;
    }

    public UserBuilder lastName(String lastName) {
      this.lastName = lastName;
      return this;
    }

    public UserBuilder bloodGroup(String bloodGroup) {
      this.bloodGroup = bloodGroup;
      return this;
    }

    public UserBuilder verified(boolean verified) {
      this.verified = verified;
      return this;
    }

    public UserBuilder active(boolean active) {
      this.active = active;
      return this;
    }

    public User build() {
      User user = User.newDonor(firstName, lastName, bloodGroup);
      if (verified) {
        user.markVerified();
      }
      return user;
    }
  }

  // ─── AuditLog ────────────────────────────────────────────────────────────

  public static class OtpCodeBuilder {

    private User user;
    private String plainOtp = "123456";
    private OtpPurpose purpose = OtpPurpose.LOGIN;
    private Instant expiresAt = Instant.now().plusSeconds(300);

    public OtpCodeBuilder user(User user) {
      this.user = user;
      return this;
    }

    public OtpCodeBuilder plainOtp(String plainOtp) {
      this.plainOtp = plainOtp;
      return this;
    }

    public OtpCodeBuilder purpose(OtpPurpose purpose) {
      this.purpose = purpose;
      return this;
    }

    public OtpCodeBuilder expiredAlready() {
      this.expiresAt = Instant.now().minusSeconds(1);
      return this;
    }

    public OtpCode build() {
      return new OtpCode(user, HashUtil.sha256Hex(plainOtp), purpose, expiresAt);
    }

    public String getPlainOtp() {
      return plainOtp;
    }
  }
}
