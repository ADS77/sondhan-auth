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
import org.hibernate.annotations.JdbcTypeCode;
import org.hibernate.type.SqlTypes;

/**
 * Append-only audit log. The DB role has no DELETE — see V4 migration.
 * Never call delete/update on this entity from application code.
 */
@Entity
@Table(name = "audit_logs")
public class AuditLog {

  @Id
  @GeneratedValue(strategy = GenerationType.UUID)
  @Column(nullable = false, updatable = false)
  private UUID id;

  @Column(name = "user_id")
  private UUID userId;

  @Enumerated(EnumType.STRING)
  @JdbcTypeCode(SqlTypes.NAMED_ENUM)
  @Column(name = "event", columnDefinition = "audit_event")
  private AuditEvent auditEvent;

  @Column(name = "ip_address", length = 45)
  private String ipAddress;

  @Column(name = "user_agent")
  private String userAgent;

  @JdbcTypeCode(SqlTypes.JSON)
  @Column(columnDefinition = "jsonb")
  private String metadata;

  @Column(name = "created_at", nullable = false, updatable = false)
  private Instant createdAt;

  protected AuditLog() {}

  private AuditLog(Builder builder) {
    this.userId = builder.userId;
    this.auditEvent = builder.auditEvent;
    this.ipAddress = builder.ipAddress;
    this.userAgent = builder.userAgent;
    this.metadata = builder.metadata;
    this.createdAt = Instant.now();
  }

  public static Builder builder(AuditEvent auditEvent) {
    return new Builder(auditEvent);
  }

  public UUID getId() {
    return id;
  }

  public UUID getUserId() {
    return userId;
  }

  public AuditEvent getEvent() {
    return auditEvent;
  }

  public String getIpAddress() {
    return ipAddress;
  }

  public String getUserAgent() {
    return userAgent;
  }

  public String getMetadata() {
    return metadata;
  }

  public Instant getCreatedAt() {
    return createdAt;
  }

  /** Fluent builder for AuditLog. */
  public static final class Builder {

    private final AuditEvent auditEvent;
    private UUID userId;
    private String ipAddress;
    private String userAgent;
    private String metadata;

    private Builder(AuditEvent auditEvent) {
      this.auditEvent = auditEvent;
    }

    public Builder userId(UUID userId) {
      this.userId = userId;
      return this;
    }

    public Builder ipAddress(String ipAddress) {
      this.ipAddress = ipAddress;
      return this;
    }

    public Builder userAgent(String userAgent) {
      this.userAgent = userAgent;
      return this;
    }

    public Builder metadata(String metadata) {
      this.metadata = metadata;
      return this;
    }

    public AuditLog build() {
      return new AuditLog(this);
    }
  }
}
