package com.sondhan.auth.schedular;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

import java.sql.SQLException;

@Component
@Slf4j
@RequiredArgsConstructor
public class AuditLogPartitionScheduler {
    private final JdbcTemplate jdbcTemplate;

    @Scheduled(cron = "0 0 3 * * *")
    public void triggerAuditLogPartition() throws SQLException {
        log.info("=== Audit log partition scheduler starts===");
        jdbcTemplate.execute("CALL ensure_future_partitions(4)");
        log.info("=== Audit log partition created successfully by scheduler ===");

        log.info("=== Deleting audit log partition older than 5 months ===");
        jdbcTemplate.execute("CALL drop_old_partitions(5)");

        log.info("=== Audit log partition maintenance completed ===");

    }
}
