package com.sondhan.auth.repository;

import com.sondhan.auth.domain.AuditEvent;
import com.sondhan.auth.domain.AuditLog;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.time.Instant;
import java.util.List;
import java.util.UUID;

@Repository
public interface AuditLogRepository extends JpaRepository<AuditLog, UUID> {

    List<AuditLog> findByUserIdOrderByCreatedAtDesc(UUID userId);

    List<AuditLog> findByUserIdAndAuditEventOrderByCreatedAtDesc(UUID userId, AuditEvent auditEvent);

    List<AuditLog> findByUserIdAndCreatedAtAfterOrderByCreatedAtDesc(
            UUID userId, Instant after);
}
