package com.sondhan.auth.controller;

import com.sondhan.auth.dto.request.*;
import com.sondhan.auth.dto.response.*;
import com.sondhan.auth.service.AuthService;
import com.sondhan.auth.util.HashUtil;
import com.sondhan.auth.util.IpExtractor;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.util.StringUtils;
import org.springframework.web.bind.annotation.*;

import java.util.UUID;

/**
 * Primary auth controller — register, login, verify-otp, refresh, logout, /me.
 */
@RestController
@RequestMapping("auth/v1")
@Tag(name = "Authentication", description = "OTP-based phone authentication endpoints")
public class AuthController {

  private final AuthService authService;

  public AuthController(AuthService authService) {
    this.authService = authService;
  }

  @Operation(summary = "Register a new user",
          description = "Creates an account and sends a 6-digit OTP via SMS")
  @ApiResponses({
          @io.swagger.v3.oas.annotations.responses.ApiResponse(
                  responseCode = "201", description = "User created, OTP sent"),
          @io.swagger.v3.oas.annotations.responses.ApiResponse(
                  responseCode = "409", description = "Phone number already registered"),
          @io.swagger.v3.oas.annotations.responses.ApiResponse(
                  responseCode = "429", description = "Too many OTP requests")
  })
  @PostMapping("/register")
  public ResponseEntity<ApiResponse<OtpSentResponse>> register(
          @Valid @RequestBody RegisterRequest request,
          HttpServletRequest httpRequest) {

    OtpSentResponse data = authService.register(request,
            IpExtractor.extract(httpRequest),
            httpRequest.getHeader("User-Agent"));

    return ResponseEntity.status(HttpStatus.CREATED).body(ApiResponse.of(data));
  }

  @Operation(summary = "Login with phone number",
          description = "Sends a 6-digit OTP to the registered phone number")
  @ApiResponses({
          @io.swagger.v3.oas.annotations.responses.ApiResponse(
                  responseCode = "200", description = "OTP sent"),
          @io.swagger.v3.oas.annotations.responses.ApiResponse(
                  responseCode = "404", description = "Phone not registered"),
          @io.swagger.v3.oas.annotations.responses.ApiResponse(
                  responseCode = "403", description = "Account locked or not verified"),
          @io.swagger.v3.oas.annotations.responses.ApiResponse(
                  responseCode = "429", description = "Too many OTP requests")
  })
  @PostMapping("/login")
  public ResponseEntity<ApiResponse<OtpSentResponse>> login(
          @Valid @RequestBody LoginRequest request,
          HttpServletRequest httpRequest) {

    OtpSentResponse data = authService.login(
            request.phone(),
            IpExtractor.extract(httpRequest),
            httpRequest.getHeader("User-Agent"));

    return ResponseEntity.ok(ApiResponse.of(data));
  }

  @Operation(summary = "Verify OTP and receive tokens",
          description = "Verifies the OTP and returns access + refresh tokens on success")
  @ApiResponses({
          @io.swagger.v3.oas.annotations.responses.ApiResponse(
                  responseCode = "200", description = "OTP verified, tokens issued"),
          @io.swagger.v3.oas.annotations.responses.ApiResponse(
                  responseCode = "400", description = "Invalid OTP"),
          @io.swagger.v3.oas.annotations.responses.ApiResponse(
                  responseCode = "403", description = "Account locked")
  })
  @PostMapping("/verify-otp")
  public ResponseEntity<ApiResponse<TokenResponse>> verifyOtp(
          @Valid @RequestBody VerifyOtpRequest request,
          HttpServletRequest httpRequest) {

    TokenResponse data = authService.verifyOtp(
            request.userId(),
            request.otp(),
            request.purpose(),
            IpExtractor.extract(httpRequest),
            httpRequest.getHeader("User-Agent"),
            buildDeviceId(httpRequest));

    return ResponseEntity.ok(ApiResponse.of(data));
  }

  @Operation(summary = "Refresh access token",
          description = "Rotates the refresh token and issues a new access token")
  @ApiResponses({
          @io.swagger.v3.oas.annotations.responses.ApiResponse(
                  responseCode = "200", description = "Tokens rotated"),
          @io.swagger.v3.oas.annotations.responses.ApiResponse(
                  responseCode = "401", description = "Invalid, expired, or reused refresh token")
  })
  @PostMapping("/refresh")
  public ResponseEntity<ApiResponse<RefreshResponse>> refresh(
          @Valid @RequestBody RefreshRequest request,
          HttpServletRequest httpRequest) {

    RefreshResponse data = authService.refresh(
            request.refreshToken(),
            buildDeviceId(httpRequest),
            IpExtractor.extract(httpRequest),
            httpRequest.getHeader("User-Agent"));

    return ResponseEntity.ok(ApiResponse.of(data));
  }

  @Operation(summary = "Logout",
          description = "Revokes the refresh token and deny-lists the access token")
  @ApiResponses({
          @io.swagger.v3.oas.annotations.responses.ApiResponse(
                  responseCode = "200", description = "Logged out"),
          @io.swagger.v3.oas.annotations.responses.ApiResponse(
                  responseCode = "401", description = "Not authenticated")
  })
  @PostMapping("/logout")
  public ResponseEntity<ApiResponse<MessageResponse>> logout(
          @Valid @RequestBody LogoutRequest request,
          @AuthenticationPrincipal UserDetails userDetails,
          HttpServletRequest httpRequest) {

    UUID userId = UUID.fromString(userDetails.getUsername());
    authService.logout(
            extractRawToken(httpRequest),
            request.refreshToken(),
            userId,
            IpExtractor.extract(httpRequest),
            httpRequest.getHeader("User-Agent"));

    return ResponseEntity.ok(ApiResponse.of(new MessageResponse("Logged out")));
  }

  @Operation(summary = "Get current user profile")
  @ApiResponses({
          @io.swagger.v3.oas.annotations.responses.ApiResponse(
                  responseCode = "200", description = "User profile returned"),
          @io.swagger.v3.oas.annotations.responses.ApiResponse(
                  responseCode = "401", description = "Not authenticated")
  })
  @GetMapping("/me")
  public ResponseEntity<ApiResponse<MeResponse>> me(
          @AuthenticationPrincipal UserDetails userDetails) {
    UUID userId = UUID.fromString(userDetails.getUsername());
    return ResponseEntity.ok(ApiResponse.of(authService.getMe(userId)));
  }

  // ─── Internal helpers ────────────────────────────────────────────────────

  private String extractRawToken(HttpServletRequest request) {
    String header = request.getHeader("Authorization");
    if (StringUtils.hasText(header) && header.startsWith("Bearer ")) {
      return header.substring(7);
    }
    return "";
  }

  private String buildDeviceId(HttpServletRequest request) {
    String ua = request.getHeader("User-Agent");
    return StringUtils.hasText(ua)
            ? HashUtil.sha256Hex(ua).substring(0, 16)
            : "unknown";
  }
}
