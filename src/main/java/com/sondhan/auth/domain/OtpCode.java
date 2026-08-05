package com.sondhan.auth.domain;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.FetchType;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.ManyToOne;
import jakarta.persistence.Table;
import org.hibernate.annotations.JdbcTypeCode;
import org.hibernate.type.SqlTypes;

import java.time.Instant;
import java.util.UUID;

/** OTP record. The code_hash stores SHA-256 of the plaintext OTP — never the digits. */
@Entity
@Table(name = "otp_codes")
public class OtpCode {

  @Enumerated(EnumType.STRING)
  @JdbcTypeCode(SqlTypes.NAMED_ENUM)
  @Column(name = "purpose", columnDefinition = "otp_purpose")
  private OtpPurpose purpose;

  @Id
  @GeneratedValue(strategy = GenerationType.UUID)
  @Column(nullable = false, updatable = false)
  private UUID id;

  @ManyToOne(fetch = FetchType.LAZY, optional = false)
  @JoinColumn(name = "user_id", nullable = false, updatable = false)
  private User user;

  @Column(name = "code_hash", nullable = false, length = 64, columnDefinition = "CHAR(64)")
  private String codeHash;

  @Column(name = "expires_at", nullable = false, updatable = false)
  private Instant expiresAt;

  @Column(name = "used_at")
  private Instant usedAt;

  @Column(name = "created_at", nullable = false, updatable = false)
  private Instant createdAt;

  protected OtpCode() {}

  public OtpCode(User user, String codeHash, OtpPurpose purpose, Instant expiresAt) {
    this.user = user;
    this.codeHash = codeHash;
    this.purpose = purpose;
    this.expiresAt = expiresAt;
    this.createdAt = Instant.now();
  }

  public boolean isExpired() {
    return Instant.now().isAfter(expiresAt);
  }

  public boolean isUsed() {
    return usedAt != null;
  }

  public void markUsed() {
    this.usedAt = Instant.now();
  }

  public UUID getId() {
    return id;
  }

  public User getUser() {
    return user;
  }

  public String getCodeHash() {
    return codeHash;
  }

  public OtpPurpose getPurpose() {
    return purpose;
  }

  public Instant getExpiresAt() {
    return expiresAt;
  }

  public Instant getUsedAt() {
    return usedAt;
  }

  public Instant getCreatedAt() {
    return createdAt;
  }
}
