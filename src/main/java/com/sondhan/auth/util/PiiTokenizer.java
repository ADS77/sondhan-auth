package com.sondhan.auth.util;

import com.sondhan.auth.domain.PiiToken;
import com.sondhan.auth.repository.PiiTokenRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

import java.util.Optional;
import java.util.UUID;

/**
 * Handles encryption and decryption of PII (phone, email) via pgcrypto.
 * The encryption key is never stored in code — it comes from the environment.
 */
@Component
public class PiiTokenizer {

    private static final Logger log = LoggerFactory.getLogger(PiiTokenizer.class);

    private final PiiTokenRepository piiTokenRepository;
    private final String encryptionKey;

    public PiiTokenizer(
            PiiTokenRepository piiTokenRepository,
            @Value("${app.pii.encryption-key}") String encryptionKey) {
        this.piiTokenRepository = piiTokenRepository;
        this.encryptionKey = encryptionKey;
    }

    /**
     * Finds an existing PiiToken by SHA-256 hash, or creates and persists a new one.
     *
     * @param plaintext the raw phone/email value
     * @param type      PHONE or EMAIL
     * @return the persisted PiiToken (existing or newly created)
     */
    @Transactional
    public PiiToken findOrCreate(String plaintext, PiiToken.PiiType type) {
        String hash = HashUtil.sha256Hex(plaintext);
        return piiTokenRepository.findByValueHash(hash)
                .orElseGet(() -> {
                    log.debug("Creating new PII token of type {}", type);
                    return piiTokenRepository.insertEncrypted(
                            type.name(), hash, plaintext, encryptionKey);
                });
    }

    /**
     * Looks up a PiiToken by the SHA-256 hash of the plaintext.
     * Used to check if a phone number already exists without decrypting.
     */
    public Optional<PiiToken> findByPlaintext(String plaintext) {
        String hash = HashUtil.sha256Hex(plaintext);
        return piiTokenRepository.findByValueHash(hash);
    }

    /**
     * Decrypts and returns the plaintext PII value for a token.
     * Call this ONLY when the plaintext is strictly needed (e.g. sending an SMS).
     */
    public Optional<String> decrypt(UUID tokenId) {
        return piiTokenRepository.decryptValue(tokenId, encryptionKey);
    }

    /**
     * Returns true if a PII value (by hash) already exists in the token table.
     */
    public boolean exists(String plaintext) {
        return piiTokenRepository.existsByValueHash(HashUtil.sha256Hex(plaintext));
    }
}
