package com.sondhan.auth.repository;

import com.sondhan.auth.domain.PiiToken;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.Optional;
import java.util.UUID;

@Repository
public interface PiiTokenRepository extends JpaRepository<PiiToken, UUID> {

    Optional<PiiToken> findByValueHash(String valueHash);

    boolean existsByValueHash(String valueHash);

    /**
     * Insert a new PII token using pgcrypto symmetric encryption.
     * The encryption key is supplied at runtime — never stored in code.
     */
    @Query(
            value =
                    """
                            INSERT INTO pii_tokens (id, pii_type, value_hash, encrypted_value, created_at)
                            VALUES (
                              uuid_generate_v4(),
                              CAST(:piiType AS pii_type),
                              :valueHash,
                              pgp_sym_encrypt(:plaintext, :encryptionKey),
                              NOW()
                            )
                            RETURNING id, pii_type, value_hash, encrypted_value, created_at
                            """,
            nativeQuery = true)
    PiiToken insertEncrypted(
            @Param("piiType") String piiType,
            @Param("valueHash") String valueHash,
            @Param("plaintext") String plaintext,
            @Param("encryptionKey") String encryptionKey);

    /**
     * Decrypt and return the plaintext PII value for a given token ID.
     * Only called when the plaintext is strictly needed (e.g. sending OTP via Twilio).
     */
    @Query(
            value =
                    """
                            SELECT pgp_sym_decrypt(encrypted_value, :encryptionKey)
                            FROM pii_tokens
                            WHERE id = :id
                            """,
            nativeQuery = true)
    Optional<String> decryptValue(
            @Param("id") UUID id, @Param("encryptionKey") String encryptionKey);
}
