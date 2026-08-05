package com.sondhan.auth.controller;

import com.sondhan.auth.domain.AuditEvent;
import com.sondhan.auth.domain.OtpPurpose;
import com.sondhan.auth.domain.User;
import com.sondhan.auth.dto.request.ResendOtpRequest;
import com.sondhan.auth.dto.response.ApiResponse;
import com.sondhan.auth.dto.response.MessageResponse;
import com.sondhan.auth.service.AuditService;
import com.sondhan.auth.service.OtpService;
import com.sondhan.auth.service.UserService;
import com.sondhan.auth.util.IpExtractor;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * Handles OTP lifecycle operations: resend for a given user and purpose.
 * Kept separate from {@link AuthController} to isolate OTP concerns.
 */
@RestController
@RequestMapping("/auth/v1/otp")
@Tag(name = "OTP", description = "OTP resend and management operations")
public class OtpController {

    private final OtpService otpService;
    private final UserService userService;
    private final AuditService auditService;

    public OtpController(
            OtpService otpService,
            UserService userService,
            AuditService auditService) {
        this.otpService = otpService;
        this.userService = userService;
        this.auditService = auditService;
    }


    @Operation(
            summary = "Resend OTP",
            description = "Invalidates any active OTP for the user and sends a new one via SMS. "
                    + "Subject to the same rate limit (max 3 per phone per hour) as initial OTP requests.")
    @ApiResponses({
            @io.swagger.v3.oas.annotations.responses.ApiResponse(
                    responseCode = "200", description = "New OTP sent"),
            @io.swagger.v3.oas.annotations.responses.ApiResponse(
                    responseCode = "404", description = "User not found"),
            @io.swagger.v3.oas.annotations.responses.ApiResponse(
                    responseCode = "403", description = "Account locked"),
            @io.swagger.v3.oas.annotations.responses.ApiResponse(
                    responseCode = "429", description = "Rate limit exceeded")
    })
    @PostMapping("/resend")
    public ResponseEntity<ApiResponse<MessageResponse>> resend(
            @Valid @RequestBody ResendOtpRequest request,
            HttpServletRequest httpRequest) {

        User user = userService.findById(request.userId());
        String phone = userService.decryptPhone(user);
        String email = userService.decryptEmail(user);
        OtpPurpose purpose = OtpPurpose.valueOf(request.purpose());

        otpService.generateAndSend(user, email, phone, purpose);

        auditService.log(
                AuditEvent.OTP_SENT,
                user.getId(),
                IpExtractor.extract(httpRequest),
                httpRequest.getHeader("User-Agent"),
                "{\"purpose\":\"" + request.purpose() + "\",\"resend\":true}");

        return ResponseEntity.ok(ApiResponse.of(new MessageResponse("OTP resent successfully")));
    }
}
