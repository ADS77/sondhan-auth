package com.sondhan.auth.service;

import com.sondhan.auth.domain.PiiToken.PiiType;
import com.sondhan.auth.domain.Role;
import com.sondhan.auth.domain.User;
import com.sondhan.auth.exception.AuthException;
import com.sondhan.auth.exception.ErrorCode;
import com.sondhan.auth.repository.RoleRepository;
import com.sondhan.auth.repository.UserRepository;
import com.sondhan.auth.util.PiiTokenizer;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Optional;
import java.util.UUID;

/**
 * Handles user creation, lookup, and role assignment.
 */
@Service
public class UserService {

    private static final Logger log = LoggerFactory.getLogger(UserService.class);
    private static final String DEFAULT_ROLE = "DONOR";

    private final UserRepository userRepository;
    private final RoleRepository roleRepository;
    private final PiiTokenizer piiTokenizer;

    public UserService(
            UserRepository userRepository,
            RoleRepository roleRepository,
            PiiTokenizer piiTokenizer) {
        this.userRepository = userRepository;
        this.roleRepository = roleRepository;
        this.piiTokenizer = piiTokenizer;
    }

    /**
     * Creates a new unverified user with the DONOR role.
     * The phone number is encrypted in pii_tokens; the users row holds only the FK.
     *
     * @throws AuthException USER_ALREADY_EXISTS if the phone number is already registered
     */
    @Transactional
    public User registerNewUser(String email, String phone, String firstName, String lastName, String bloodGroup) {

        if (piiTokenizer.exists(email)) {
            // Check if already in users table
            piiTokenizer.findByPlaintext(email).ifPresent(token -> {
                if (userRepository.existsByEmailToken(token)) {
                    throw new AuthException(ErrorCode.USER_ALREADY_EXISTS,
                            "A user with this email already exists");
                }
            });
        }
        if (piiTokenizer.exists(phone)) {
            // Check if already in users table
            piiTokenizer.findByPlaintext(phone).ifPresent(token -> {
                if (userRepository.existsByPhoneToken(token)) {
                    throw new AuthException(ErrorCode.USER_ALREADY_EXISTS,
                            "A user with this phone number already exists");
                }
            });
        }

        var phoneToken = piiTokenizer.findOrCreate(phone, PiiType.PHONE);
        var emailToken = piiTokenizer.findOrCreate(email, PiiType.EMAIL);
        Role donorRole = roleRepository.findByName(DEFAULT_ROLE)
                .orElseThrow(() -> new IllegalStateException("DONOR role not seeded"));

        User user = User.newDonor(firstName, lastName, bloodGroup);
        user.setEmailToken(emailToken);
        user.setPhoneToken(phoneToken);
        user.addRole(donorRole);

        User saved = userRepository.save(user);
        log.info("Registered new user {}", saved.getId());
        return saved;
    }

    /**
     * Looks up a user by phone number.
     *
     * @throws AuthException USER_NOT_FOUND if no user is registered with this phone
     */
    @Transactional(readOnly = true)
    public User findByPhone(String phone) {
        return piiTokenizer.findByPlaintext(phone)
                .flatMap(token -> userRepository.findByPhoneToken(token))
                .orElseThrow(() ->
                        new AuthException(ErrorCode.USER_NOT_FOUND,
                                "No account found for this phone number"));
    }

    /**
     * Finds a user by UUID or throws USER_NOT_FOUND.
     */
    @Transactional(readOnly = true)
    public User findById(UUID userId) {
        return userRepository.findById(userId)
                .orElseThrow(() ->
                        new AuthException(ErrorCode.USER_NOT_FOUND, "User not found"));
    }

    /**
     * Decrypts and returns the phone number for a user.
     * Call sparingly — only when the plaintext is strictly needed (e.g. Twilio send).
     */
    @Transactional(readOnly = true)
    public String decryptPhone(User user) {
        if (user.getPhoneToken() == null) {
            throw new IllegalStateException("User has no phone token");
        }
        return piiTokenizer.decrypt(user.getPhoneToken().getId())
                .orElseThrow(() ->
                        new IllegalStateException("Could not decrypt phone for user " + user.getId()));
    }

    @Transactional(readOnly = true)
    public String decryptEmail(User user) {
        if (user.getPhoneToken() == null) {
            throw new IllegalStateException("User has no email token");
        }
        return piiTokenizer.decrypt(user.getEmailToken().getId())
                .orElseThrow(() ->
                        new IllegalStateException("Could not decrypt email for user " + user.getId()));
    }

    /**
     * Marks the user as verified and saves.
     */
    @Transactional
    public User markVerified(User user) {
        user.markVerified();
        return userRepository.save(user);
    }

    /**
     * Saves a user (e.g. after failed OTP attempt counter update).
     */
    @Transactional
    public User save(User user) {
        return userRepository.save(user);
    }

    /**
     * Returns the optional plaintext phone for a user.
     */
    public Optional<String> decryptPhoneOptional(User user) {
        if (user.getPhoneToken() == null) {
            return Optional.empty();
        }
        return piiTokenizer.decrypt(user.getPhoneToken().getId());
    }
}
