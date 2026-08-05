package com.sondhan.auth.domain;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import java.time.Instant;
import java.util.UUID;

/**
 * Stores pgcrypto-encrypted PII (phone or email). Raw plaintext never persisted elsewhere.
 * The encrypted_value column is written/read via native queries that pass the encryption key
 * from the environment — JPA never sees the plaintext.
 */
@Entity
@Table(name = "pii_tokens")
public class PiiToken {

  public enum PiiType {
    PHONE,
    EMAIL
  }

  @Id
  @GeneratedValue(strategy = GenerationType.UUID)
  @Column(nullable = false, updatable = false)
  private UUID id;

  @Enumerated(EnumType.STRING)
  @Column(name = "pii_type", nullable = false, updatable = false)
  private PiiType piiType;

  /** SHA-256 hex of the plaintext — used for existence checks without decryption. */
  @Column(name = "value_hash", nullable = false, unique = true, updatable = false, length = 64)
  private String valueHash;

  /** pgp_sym_encrypt output stored as byte array. */
  @Column(name = "encrypted_value", nullable = false)
  private byte[] encryptedValue;

  @Column(nullable = false, updatable = false)
  private Instant createdAt;

  protected PiiToken() {}

  public PiiToken(PiiType piiType, String valueHash, byte[] encryptedValue) {
    this.piiType = piiType;
    this.valueHash = valueHash;
    this.encryptedValue = encryptedValue;
    this.createdAt = Instant.now();
  }

  public UUID getId() {
    return id;
  }

  public PiiType getPiiType() {
    return piiType;
  }

  public String getValueHash() {
    return valueHash;
  }

  public byte[] getEncryptedValue() {
    return encryptedValue;
  }

  public Instant getCreatedAt() {
    return createdAt;
  }
}
