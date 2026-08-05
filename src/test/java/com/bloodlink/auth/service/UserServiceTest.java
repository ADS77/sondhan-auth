package com.sondhan.auth.service;

import com.sondhan.auth.builder.TestBuilders;
import com.sondhan.auth.domain.PiiToken;
import com.sondhan.auth.domain.PiiToken.PiiType;
import com.sondhan.auth.domain.Role;
import com.sondhan.auth.domain.User;
import com.sondhan.auth.exception.AuthException;
import com.sondhan.auth.exception.ErrorCode;
import com.sondhan.auth.repository.RoleRepository;
import com.sondhan.auth.repository.UserRepository;
import com.sondhan.auth.util.HashUtil;
import com.sondhan.auth.util.PiiTokenizer;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.Optional;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class UserServiceTest {

    private static final String PHONE = "+8801711000099";
    private static final String EMAIL = "aunkurdas1111@gmail.com";
    @Mock
    private UserRepository userRepository;
    @Mock
    private RoleRepository roleRepository;
    @Mock
    private PiiTokenizer piiTokenizer;
    @InjectMocks
    private UserService userService;
    private PiiToken fakePiiToken;
    private Role donorRole;

    @BeforeEach
    void setUp() {
        fakePiiToken = new PiiToken(PiiType.PHONE, HashUtil.sha256Hex(PHONE), new byte[]{1, 2, 3});
        donorRole = new Role("DONOR");
    }

    @Test
    void registerNewUser_givenNewPhone_thenCreatesUserWithDonorRole() {
        when(piiTokenizer.exists(PHONE)).thenReturn(false);
        when(piiTokenizer.findOrCreate(eq(PHONE), eq(PiiType.PHONE))).thenReturn(fakePiiToken);
        when(roleRepository.findByName("DONOR")).thenReturn(Optional.of(donorRole));
        when(userRepository.save(any(User.class))).thenAnswer(inv -> inv.getArgument(0));

        User result = userService.registerNewUser(EMAIL, PHONE, "Rahim", "Uddin", "O+");

        assertThat(result.getFirstName()).isEqualTo("Rahim");
        assertThat(result.getBloodGroup()).isEqualTo("O+");
        assertThat(result.isVerified()).isFalse();
        assertThat(result.getRoles()).anyMatch(r -> r.getName().equals("DONOR"));
        verify(userRepository).save(any(User.class));
    }

    @Test
    void registerNewUser_givenExistingPhone_thenThrowsUserAlreadyExists() {
        when(piiTokenizer.exists(PHONE)).thenReturn(true);
        when(piiTokenizer.findByPlaintext(PHONE)).thenReturn(Optional.of(fakePiiToken));
        when(userRepository.existsByPhoneToken(fakePiiToken)).thenReturn(true);

        assertThatThrownBy(() ->
                userService.registerNewUser(EMAIL, PHONE, "Rahim", "Uddin", "O+"))
                .isInstanceOf(AuthException.class)
                .satisfies(ex -> assertThat(((AuthException) ex).getErrorCode())
                        .isEqualTo(ErrorCode.USER_ALREADY_EXISTS));

        verify(userRepository, never()).save(any());
    }

    @Test
    void findByPhone_givenRegisteredPhone_thenReturnsUser() {
        User user = TestBuilders.aUser().build();
        when(piiTokenizer.findByPlaintext(PHONE)).thenReturn(Optional.of(fakePiiToken));
        when(userRepository.findByPhoneToken(fakePiiToken)).thenReturn(Optional.of(user));

        User result = userService.findByPhone(PHONE);

        assertThat(result).isEqualTo(user);
    }

    @Test
    void findByPhone_givenUnregisteredPhone_thenThrowsUserNotFound() {
        when(piiTokenizer.findByPlaintext(PHONE)).thenReturn(Optional.empty());

        assertThatThrownBy(() -> userService.findByPhone(PHONE))
                .isInstanceOf(AuthException.class)
                .satisfies(ex -> assertThat(((AuthException) ex).getErrorCode())
                        .isEqualTo(ErrorCode.USER_NOT_FOUND));
    }

    @Test
    void findById_givenValidId_thenReturnsUser() {
        UUID id = UUID.randomUUID();
        User user = TestBuilders.aUser().build();
        when(userRepository.findById(id)).thenReturn(Optional.of(user));

        assertThat(userService.findById(id)).isEqualTo(user);
    }

    @Test
    void findById_givenUnknownId_thenThrowsUserNotFound() {
        UUID id = UUID.randomUUID();
        when(userRepository.findById(id)).thenReturn(Optional.empty());

        assertThatThrownBy(() -> userService.findById(id))
                .isInstanceOf(AuthException.class)
                .satisfies(ex -> assertThat(((AuthException) ex).getErrorCode())
                        .isEqualTo(ErrorCode.USER_NOT_FOUND));
    }

    @Test
    void markVerified_givenUnverifiedUser_thenSetsVerifiedTrue() {
        User user = TestBuilders.aUser().verified(false).build();
        when(userRepository.save(any())).thenAnswer(inv -> inv.getArgument(0));

        User result = userService.markVerified(user);

        assertThat(result.isVerified()).isTrue();
        verify(userRepository).save(user);
    }

    @Test
    void decryptPhone_givenUserWithPhoneToken_thenDelegatesToPiiTokenizer() {
        User user = TestBuilders.aUser().build();
        user.setPhoneToken(fakePiiToken);
        when(piiTokenizer.decrypt(fakePiiToken.getId())).thenReturn(Optional.of(PHONE));

        String result = userService.decryptPhone(user);

        assertThat(result).isEqualTo(PHONE);
    }

    @Test
    void decryptPhone_givenUserWithNoPhoneToken_thenThrowsIllegalState() {
        User user = TestBuilders.aUser().build(); // phoneToken is null

        assertThatThrownBy(() -> userService.decryptPhone(user))
                .isInstanceOf(IllegalStateException.class);
    }
}
