package com.sondhan.auth.domain;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.FetchType;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.JoinTable;
import jakarta.persistence.ManyToMany;
import jakarta.persistence.ManyToOne;
import jakarta.persistence.PrePersist;
import jakarta.persistence.PreUpdate;
import jakarta.persistence.Table;
import java.time.Instant;
import java.util.HashSet;
import java.util.Set;
import java.util.UUID;

/**
 * Core user identity. Raw PII (phone, email) is NEVER stored here.
 * References are held as FK pointers to pii_tokens.
 */
@Entity
@Table(name = "users")
public class User {

  @Id
  @GeneratedValue(strategy = GenerationType.UUID)
  @Column(nullable = false, updatable = false)
  private UUID id;

  /** FK to the PiiToken that holds the encrypted phone number. */
  @ManyToOne(fetch = FetchType.LAZY)
  @JoinColumn(name = "phone_token_id")
  private PiiToken phoneToken;

  /** FK to the PiiToken that holds the encrypted email (optional). */
  @ManyToOne(fetch = FetchType.LAZY)
  @JoinColumn(name = "email_token_id")
  private PiiToken emailToken;

  @Column(name = "first_name", nullable = false, length = 100)
  private String firstName;

  @Column(name = "last_name", nullable = false, length = 100)
  private String lastName;

  @Column(name = "blood_group", nullable = false, length = 5)
  private String bloodGroup;

  @Column(name = "is_verified", nullable = false)
  private boolean verified;

  @Column(name = "is_active", nullable = false)
  private boolean active;

  @Column(name = "failed_otp_attempts", nullable = false)
  private int failedOtpAttempts;

  @Column(name = "locked_until")
  private Instant lockedUntil;

  @Column(nullable = false, updatable = false)
  private Instant createdAt;

  @Column(nullable = false)
  private Instant updatedAt;

  @ManyToMany(fetch = FetchType.EAGER)
  @JoinTable(
      name = "user_roles",
      joinColumns = @JoinColumn(name = "user_id"),
      inverseJoinColumns = @JoinColumn(name = "role_id"))
  private Set<Role> roles = new HashSet<>();

  protected User() {}

  /** Factory — use instead of constructor to keep invariants clear. */
  public static User newDonor(String firstName, String lastName, String bloodGroup) {
    User user = new User();
    user.firstName = firstName;
    user.lastName = lastName;
    user.bloodGroup = bloodGroup;
    user.verified = false;
    user.active = true;
    user.failedOtpAttempts = 0;
    return user;
  }

  @PrePersist
  void onCreate() {
    createdAt = Instant.now();
    updatedAt = createdAt;
  }

  @PreUpdate
  void onUpdate() {
    updatedAt = Instant.now();
  }

  // --- Behaviour ---

  public void incrementFailedOtpAttempts() {
    this.failedOtpAttempts++;
  }

  public void resetFailedOtpAttempts() {
    this.failedOtpAttempts = 0;
  }

  public void lockUntil(Instant until) {
    this.lockedUntil = until;
  }

  public boolean isLocked() {
    return lockedUntil != null && Instant.now().isBefore(lockedUntil);
  }

  public void markVerified() {
    this.verified = true;
  }

  public void addRole(Role role) {
    this.roles.add(role);
  }

  // --- Accessors ---

  public UUID getId() {
    return id;
  }

  public PiiToken getPhoneToken() {
    return phoneToken;
  }

  public void setPhoneToken(PiiToken phoneToken) {
    this.phoneToken = phoneToken;
  }

  public PiiToken getEmailToken() {
    return emailToken;
  }

  public void setEmailToken(PiiToken emailToken) {
    this.emailToken = emailToken;
  }

  public String getFirstName() {
    return firstName;
  }

  public String getLastName() {
    return lastName;
  }

  public String getBloodGroup() {
    return bloodGroup;
  }

  public boolean isVerified() {
    return verified;
  }

  public boolean isActive() {
    return active;
  }

  public int getFailedOtpAttempts() {
    return failedOtpAttempts;
  }

  public Instant getLockedUntil() {
    return lockedUntil;
  }

  public Set<Role> getRoles() {
    return roles;
  }

  public Instant getCreatedAt() {
    return createdAt;
  }

  public Instant getUpdatedAt() {
    return updatedAt;
  }
}
