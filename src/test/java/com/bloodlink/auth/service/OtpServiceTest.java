package com.sondhan.auth.service;

import com.sondhan.auth.builder.TestBuilders;
import com.sondhan.auth.domain.OtpCode;
import com.sondhan.auth.domain.OtpPurpose;
import com.sondhan.auth.domain.User;
import com.sondhan.auth.exception.AuthException;
import com.sondhan.auth.exception.ErrorCode;
import com.sondhan.auth.repository.OtpRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.data.redis.core.ValueOperations;
import org.springframework.test.util.ReflectionTestUtils;

import java.time.Instant;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class OtpServiceTest {

    @Mock
    private OtpRepository otpRepository;

    @Mock
    private RedisTemplate<String, Object> redisTemplate;

    @Mock
    private ValueOperations<String, Object> valueOps;

    @InjectMocks
    private OtpService otpService;

    private User testUser;

    @BeforeEach
    void setUp() {
        testUser = TestBuilders.aUser().verified(true).build();
        ReflectionTestUtils.setField(otpService, "twilioFromNumber", "+15005550006");
        ReflectionTestUtils.setField(otpService, "twilioEnabled", false);
        when(redisTemplate.opsForValue()).thenReturn(valueOps);
    }

    @Test
    void generateAndSend_givenValidUser_thenSavesHashedOtpAndReturnsCorrectTtl() {
        when(valueOps.increment(anyString())).thenReturn(1L);
        when(otpRepository.save(any())).thenAnswer(inv -> inv.getArgument(0));

        int ttl = otpService.generateAndSend(testUser, "abc@gmail.com", "+8801711000000", OtpPurpose.LOGIN);

        assertThat(ttl).isEqualTo(300);
        verify(otpRepository).save(any(OtpCode.class));
        verify(otpRepository).invalidatePreviousOtps(eq(testUser), eq(OtpPurpose.LOGIN), any());
    }

    @Test
    void generateAndSend_givenRateLimitExceeded_thenThrowsRateLimited() {
        when(valueOps.increment(anyString())).thenReturn(4L); // > max 3

        assertThatThrownBy(() ->
                otpService.generateAndSend(testUser, "abc@gmail.com", "+8801711000000", OtpPurpose.LOGIN))
                .isInstanceOf(AuthException.class)
                .satisfies(ex -> assertThat(((AuthException) ex).getErrorCode())
                        .isEqualTo(ErrorCode.RATE_LIMITED));

        verify(otpRepository, never()).save(any());
    }

    @Test
    void verify_givenCorrectOtp_thenMarksUsedAndResetsCounter() {
        String plainOtp = "654321";
        OtpCode otpCode = TestBuilders.anOtp()
                .user(testUser)
                .plainOtp(plainOtp)
                .purpose(OtpPurpose.LOGIN)
                .build();

        when(otpRepository.findActiveOtp(eq(testUser), eq(OtpPurpose.LOGIN), any()))
                .thenReturn(Optional.of(otpCode));
        when(otpRepository.save(any())).thenAnswer(inv -> inv.getArgument(0));

        otpService.verify(testUser, plainOtp, OtpPurpose.LOGIN);

        assertThat(otpCode.isUsed()).isTrue();
        assertThat(testUser.getFailedOtpAttempts()).isZero();
    }

    @Test
    void verify_givenWrongOtp_thenThrowsInvalidOtpAndIncrementsCounter() {
        OtpCode otpCode = TestBuilders.anOtp()
                .user(testUser)
                .plainOtp("999999")
                .purpose(OtpPurpose.LOGIN)
                .build();

        when(otpRepository.findActiveOtp(any(), any(), any()))
                .thenReturn(Optional.of(otpCode));

        assertThatThrownBy(() -> otpService.verify(testUser, "111111", OtpPurpose.LOGIN))
                .isInstanceOf(AuthException.class)
                .satisfies(ex -> assertThat(((AuthException) ex).getErrorCode())
                        .isEqualTo(ErrorCode.INVALID_OTP));

        assertThat(testUser.getFailedOtpAttempts()).isEqualTo(1);
    }

    @Test
    void verify_givenNoActiveOtp_thenThrowsOtpExpired() {
        when(otpRepository.findActiveOtp(any(), any(), any())).thenReturn(Optional.empty());

        assertThatThrownBy(() -> otpService.verify(testUser, "123456", OtpPurpose.LOGIN))
                .isInstanceOf(AuthException.class)
                .satisfies(ex -> assertThat(((AuthException) ex).getErrorCode())
                        .isEqualTo(ErrorCode.OTP_EXPIRED));
    }

    @Test
    void verify_givenLockedUser_thenThrowsAccountLocked() {
        testUser.lockUntil(Instant.now().plusSeconds(300));

        assertThatThrownBy(() -> otpService.verify(testUser, "123456", OtpPurpose.LOGIN))
                .isInstanceOf(AuthException.class)
                .satisfies(ex -> assertThat(((AuthException) ex).getErrorCode())
                        .isEqualTo(ErrorCode.ACCOUNT_LOCKED));

        verify(otpRepository, never()).findActiveOtp(any(), any(), any());
    }

    @Test
    void verify_givenFiveConsecutiveFailures_thenLocksUser() {
        OtpCode otpCode = TestBuilders.anOtp().user(testUser).plainOtp("000000").build();
        when(otpRepository.findActiveOtp(any(), any(), any()))
                .thenReturn(Optional.of(otpCode));

        for (int i = 0; i < 5; i++) {
            try {
                otpService.verify(testUser, "111111", OtpPurpose.LOGIN);
            } catch (AuthException ignored) {
                // expected
            }
        }

        assertThat(testUser.isLocked()).isTrue();
        assertThat(testUser.getLockedUntil()).isAfter(Instant.now());
    }
}
