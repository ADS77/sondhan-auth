package com.sondhan.auth.service;

import com.sondhan.auth.domain.AuditEvent;
import com.sondhan.auth.domain.AuditLog;
import com.sondhan.auth.repository.AuditLogRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

import java.util.UUID;

/**
 * Writes entries to the append-only audit_logs table.
 * Writes are async and run in their own transaction so a failure here
 * never rolls back the main business transaction.
 */
@Service
public class AuditService {

  private static final Logger log = LoggerFactory.getLogger(AuditService.class);

  private final AuditLogRepository auditLogRepository;

  public AuditService(AuditLogRepository auditLogRepository) {
    this.auditLogRepository = auditLogRepository;
  }

  @Async
  @Transactional(propagation = Propagation.REQUIRES_NEW)
  public void log(
          AuditEvent auditEvent,
          UUID userId,
          String ipAddress,
          String userAgent,
          String metadata) {
    try {
      AuditLog entry = AuditLog.builder(auditEvent)
              .userId(userId)
              .ipAddress(ipAddress)
              .userAgent(userAgent)
              .metadata(metadata)
              .build();
      auditLogRepository.save(entry);
    } catch (Exception e) {
      // Audit failures must never surface to the caller
      log.error("Failed to write audit log entry for event {}: {}", auditEvent, e.getMessage());
    }
  }

  /**
   * Convenience overload without metadata.
   */
  @Async
  @Transactional(propagation = Propagation.REQUIRES_NEW)
  public void log(AuditEvent auditEvent, UUID userId, String ipAddress, String userAgent) {
    log(auditEvent, userId, ipAddress, userAgent, null);
  }
}
