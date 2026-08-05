package com.sondhan.auth.service;

import com.sondhan.auth.builder.TestBuilders;
import com.sondhan.auth.domain.AuditEvent;
import com.sondhan.auth.domain.OtpPurpose;
import com.sondhan.auth.domain.Role;
import com.sondhan.auth.domain.User;
import com.sondhan.auth.dto.request.RegisterRequest;
import com.sondhan.auth.dto.response.MeResponse;
import com.sondhan.auth.dto.response.OtpSentResponse;
import com.sondhan.auth.dto.response.RefreshResponse;
import com.sondhan.auth.dto.response.TokenResponse;
import com.sondhan.auth.exception.AuthException;
import com.sondhan.auth.exception.ErrorCode;
import com.sondhan.auth.service.TokenService.RotationResult;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.List;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class AuthServiceTest {

    private static final String IP = "127.0.0.1";
    private static final String UA = "TestAgent/1.0";
    private static final String DEVICE = "device-abc";
    private final UUID userId = UUID.randomUUID();
    @Mock
    private UserService userService;
    @Mock
    private OtpService otpService;
    @Mock
    private TokenService tokenService;
    @Mock
    private AuditService auditService;
    @InjectMocks
    private AuthService authService;
    private User verifiedUser;
    private User unverifiedUser;

    @BeforeEach
    void setUp() {
        verifiedUser = TestBuilders.aUser().verified(true).build();
        Role donorRole = new Role("DONOR");
        verifiedUser.addRole(donorRole);

        unverifiedUser = TestBuilders.aUser().verified(false).build();
    }

    // ── register ──────────────────────────────────────────────────────────────

    @Test
    void register_givenValidInput_thenCreatesUserAndSendsOtp() {
        when(userService.registerNewUser(anyString(), anyString(), anyString(), anyString(), anyString()))
                .thenReturn(verifiedUser);
        when(userService.decryptPhone(verifiedUser)).thenReturn("+8801711000001");
        when(otpService.generateAndSend(any(), anyString(), anyString(), eq(OtpPurpose.REGISTER))).thenReturn(300);
        RegisterRequest request = new RegisterRequest("+8801711000001", "rahim@gmail.com", "Rahim", "Uddin", "O+");

        OtpSentResponse response = authService.register(request, IP, UA);

        assertThat(response.message()).isEqualTo("OTP sent");
        assertThat(response.otpExpiresInSeconds()).isEqualTo(300);
        verify(auditService).log(eq(AuditEvent.REGISTER), any(), eq(IP), eq(UA));
        verify(auditService).log(eq(AuditEvent.OTP_SENT), any(), eq(IP), eq(UA), anyString());
    }

    // ── login ─────────────────────────────────────────────────────────────────

    @Test
    void login_givenVerifiedUser_thenSendsOtp() {
        when(userService.findByPhone(anyString())).thenReturn(verifiedUser);
        when(userService.decryptPhone(verifiedUser)).thenReturn("+8801711000001");
        when(otpService.generateAndSend(any(), anyString(), anyString(), eq(OtpPurpose.LOGIN))).thenReturn(300);

        OtpSentResponse response = authService.login("+8801711000001", IP, UA);

        assertThat(response.message()).isEqualTo("OTP sent");
    }

    @Test
    void login_givenUnverifiedUser_thenThrowsAccountNotVerified() {
        when(userService.findByPhone(anyString())).thenReturn(unverifiedUser);

        assertThatThrownBy(() -> authService.login("+8801711000001", IP, UA))
                .isInstanceOf(AuthException.class)
                .satisfies(ex -> assertThat(((AuthException) ex).getErrorCode())
                        .isEqualTo(ErrorCode.ACCOUNT_NOT_VERIFIED));

        verify(otpService, never()).generateAndSend(any(), anyString(), any(), any());
    }

    // ── verifyOtp ─────────────────────────────────────────────────────────────

    @Test
    void verifyOtp_givenCorrectOtpForRegister_thenMarksVerifiedAndReturnsTokens() {
        when(userService.findById(any())).thenReturn(unverifiedUser);
        when(userService.markVerified(unverifiedUser)).thenReturn(verifiedUser);
        when(userService.save(any())).thenReturn(verifiedUser);
        when(tokenService.issueAccessToken(any(), any())).thenReturn("access.token.here");
        when(tokenService.issueRefreshToken(any(), any(), any(), any())).thenReturn("refresh-uuid");

        TokenResponse response = authService.verifyOtp(
                userId, "123456", "REGISTER", IP, UA, DEVICE);

        verify(userService).markVerified(unverifiedUser);
        assertThat(response.accessToken()).isEqualTo("access.token.here");
        assertThat(response.refreshToken()).isEqualTo("refresh-uuid");
        assertThat(response.tokenType()).isEqualTo("Bearer");
        assertThat(response.expiresIn()).isEqualTo(900);
    }

    @Test
    void verifyOtp_givenOtpFailure_thenSavesUserAndRethrows() {
        when(userService.findById(any())).thenReturn(verifiedUser);
        doThrow(new AuthException(ErrorCode.INVALID_OTP, "wrong"))
                .when(otpService).verify(any(), anyString(), any());

        assertThatThrownBy(() -> authService.verifyOtp(userId, "000000", "LOGIN", IP, UA, DEVICE))
                .isInstanceOf(AuthException.class)
                .satisfies(ex -> assertThat(((AuthException) ex).getErrorCode())
                        .isEqualTo(ErrorCode.INVALID_OTP));

        verify(userService).save(verifiedUser); // counter persisted
        verify(auditService).log(eq(AuditEvent.OTP_FAILED), eq(userId), eq(IP), eq(UA), anyString());
    }

    @Test
    void verifyOtp_givenInvalidPurposeString_thenThrowsInvalidRequest() {
        when(userService.findById(any())).thenReturn(verifiedUser);

        assertThatThrownBy(() ->
                authService.verifyOtp(userId, "123456", "UNKNOWN_PURPOSE", IP, UA, DEVICE))
                .isInstanceOf(AuthException.class)
                .satisfies(ex -> assertThat(((AuthException) ex).getErrorCode())
                        .isEqualTo(ErrorCode.INVALID_REQUEST));
    }

    // ── refresh ───────────────────────────────────────────────────────────────

    @Test
    void refresh_givenValidToken_thenReturnsNewTokenPair() {
        RotationResult rotation = new RotationResult(
                "new.access.token", "new-refresh-uuid", userId, List.of("DONOR"));
        when(tokenService.rotateRefreshToken(anyString(), anyString())).thenReturn(rotation);

        RefreshResponse response = authService.refresh("old-refresh-uuid", DEVICE, IP, UA);

        assertThat(response.accessToken()).isEqualTo("new.access.token");
        assertThat(response.refreshToken()).isEqualTo("new-refresh-uuid");
        assertThat(response.expiresIn()).isEqualTo(900);
        verify(auditService).log(eq(AuditEvent.REFRESH_TOKEN_ROTATED), eq(userId), eq(IP), eq(UA));
    }

    @Test
    void refresh_givenReuseAttack_thenAuditsAndRethrows() {
        doThrow(new AuthException(ErrorCode.REFRESH_REUSE_ATTACK, "reuse"))
                .when(tokenService).rotateRefreshToken(anyString(), anyString());

        assertThatThrownBy(() -> authService.refresh("reused-token", DEVICE, IP, UA))
                .isInstanceOf(AuthException.class)
                .satisfies(ex -> assertThat(((AuthException) ex).getErrorCode())
                        .isEqualTo(ErrorCode.REFRESH_REUSE_ATTACK));

        verify(auditService).log(eq(AuditEvent.REFRESH_REUSE_ATTACK), eq(null), eq(IP), eq(UA), anyString());
    }

    // ── logout ────────────────────────────────────────────────────────────────

    @Test
    void logout_givenValidTokens_thenDeniesAccessAndRevokesRefresh() {
        authService.logout("raw.access.token", "refresh-uuid", userId, IP, UA);

        verify(tokenService).denyAccessToken("raw.access.token");
        verify(tokenService).revokeRefreshToken("refresh-uuid");
        verify(auditService).log(eq(AuditEvent.LOGOUT), eq(userId), eq(IP), eq(UA));
    }

    // ── getMe ─────────────────────────────────────────────────────────────────

    @Test
    void getMe_givenAuthenticatedUser_thenReturnsMeResponse() {
        when(userService.findById(userId)).thenReturn(verifiedUser);

        MeResponse me = authService.getMe(userId);

        assertThat(me.id()).isEqualTo(verifiedUser.getId());
        assertThat(me.bloodGroup()).isEqualTo("O+");
        assertThat(me.verified()).isTrue();
        assertThat(me.roles()).containsExactly("DONOR");
    }
}
