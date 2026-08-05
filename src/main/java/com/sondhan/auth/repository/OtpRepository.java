package com.sondhan.auth.repository;

import com.sondhan.auth.domain.OtpCode;
import com.sondhan.auth.domain.OtpPurpose;
import com.sondhan.auth.domain.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.time.Instant;
import java.util.Optional;
import java.util.UUID;

@Repository
public interface OtpRepository extends JpaRepository<OtpCode, UUID> {

    /**
     * Find the latest active (unused, non-expired) OTP for a user+purpose.
     */
    @Query(
            """
                    SELECT o FROM OtpCode o
                    WHERE o.user = :user
                      AND o.purpose = :purpose
                      AND o.usedAt IS NULL
                      AND o.expiresAt > :now
                    ORDER BY o.createdAt DESC
                    """)
    Optional<OtpCode> findActiveOtp(
            @Param("user") User user,
            @Param("purpose") OtpPurpose purpose,
            @Param("now") Instant now);

    /**
     * Invalidate all unused OTPs for a user+purpose before issuing a new one.
     */
    @Modifying
    @Query(
            """
                    UPDATE OtpCode o SET o.usedAt = :now
                    WHERE o.user = :user
                      AND o.purpose = :purpose
                      AND o.usedAt IS NULL
                    """)
    void invalidatePreviousOtps(
            @Param("user") User user,
            @Param("purpose") OtpPurpose purpose,
            @Param("now") Instant now);
}
