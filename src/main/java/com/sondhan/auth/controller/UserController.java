package com.sondhan.auth.controller;

import com.sondhan.auth.domain.AuditEvent;
import com.sondhan.auth.domain.Role;
import com.sondhan.auth.domain.User;
import com.sondhan.auth.dto.response.ApiResponse;
import com.sondhan.auth.dto.response.MeResponse;
import com.sondhan.auth.dto.response.MessageResponse;
import com.sondhan.auth.exception.AuthException;
import com.sondhan.auth.exception.ErrorCode;
import com.sondhan.auth.repository.RoleRepository;
import com.sondhan.auth.repository.UserRepository;
import com.sondhan.auth.service.AuditService;
import com.sondhan.auth.service.UserService;
import com.sondhan.auth.util.IpExtractor;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.UUID;
import java.util.stream.Collectors;

/**
 * Admin-level user management: role assignment, deactivation, user lookup.
 * All endpoints require {@code ROLE_SYSTEM_ADMIN} or {@code ROLE_ORG_ADMIN} as noted.
 */
@RestController
@RequestMapping("/auth/v1/users")
@Tag(name = "User Management", description = "Admin operations for user and role management")
public class UserController {

    private final UserService userService;
    private final UserRepository userRepository;
    private final RoleRepository roleRepository;
    private final AuditService auditService;

    public UserController(
            UserService userService,
            UserRepository userRepository,
            RoleRepository roleRepository,
            AuditService auditService) {
        this.userService = userService;
        this.userRepository = userRepository;
        this.roleRepository = roleRepository;
        this.auditService = auditService;
    }

    @Operation(summary = "Get user by ID",
            description = "Returns the profile of any user. Requires SYSTEM_ADMIN or ORG_ADMIN.")
    @ApiResponses({
            @io.swagger.v3.oas.annotations.responses.ApiResponse(
                    responseCode = "200", description = "User profile returned"),
            @io.swagger.v3.oas.annotations.responses.ApiResponse(
                    responseCode = "403", description = "Insufficient role"),
            @io.swagger.v3.oas.annotations.responses.ApiResponse(
                    responseCode = "404", description = "User not found")
    })
    @GetMapping("/{userId}")
    @PreAuthorize("hasAnyRole('SYSTEM_ADMIN', 'ORG_ADMIN')")
    public ResponseEntity<ApiResponse<MeResponse>> getUserById(@PathVariable UUID userId) {
        User user = userService.findById(userId);
        List<String> roles = user.getRoles().stream()
                .map(Role::getName)
                .collect(Collectors.toList());
        return ResponseEntity.ok(ApiResponse.of(
                new MeResponse(user.getId(), user.getBloodGroup(), roles, user.isVerified())));
    }

    @Operation(summary = "Assign a role to a user",
            description = "Adds the specified role to the user. Requires SYSTEM_ADMIN.")
    @ApiResponses({
            @io.swagger.v3.oas.annotations.responses.ApiResponse(
                    responseCode = "200", description = "Role assigned"),
            @io.swagger.v3.oas.annotations.responses.ApiResponse(
                    responseCode = "400", description = "Invalid role"),
            @io.swagger.v3.oas.annotations.responses.ApiResponse(
                    responseCode = "403", description = "Insufficient role"),
            @io.swagger.v3.oas.annotations.responses.ApiResponse(
                    responseCode = "404", description = "User or role not found")
    })
    @PostMapping("/{userId}/roles")
    @PreAuthorize("hasRole('SYSTEM_ADMIN')")
    @Transactional
    public ResponseEntity<ApiResponse<MessageResponse>> assignRole(
            @PathVariable UUID userId,
            @Valid @RequestBody AssignRoleRequest request,
            @AuthenticationPrincipal UserDetails actor,
            HttpServletRequest httpRequest) {

        User user = userService.findById(userId);
        Role role = roleRepository.findByName(request.role())
                .orElseThrow(() -> new AuthException(ErrorCode.INVALID_REQUEST,
                        "Role not found: " + request.role()));

        user.addRole(role);
        userRepository.save(user);

        auditService.log(
                AuditEvent.ROLE_CHANGED,
                userId,
                IpExtractor.extract(httpRequest),
                httpRequest.getHeader("User-Agent"),
                String.format("{\"role\":\"%s\",\"action\":\"ASSIGN\",\"actor\":\"%s\"}",
                        request.role(), actor.getUsername()));

        return ResponseEntity.ok(ApiResponse.of(
                new MessageResponse("Role " + request.role() + " assigned to user " + userId)));
    }

    @Operation(summary = "Revoke a role from a user",
            description = "Removes the specified role from the user. Requires SYSTEM_ADMIN.")
    @ApiResponses({
            @io.swagger.v3.oas.annotations.responses.ApiResponse(
                    responseCode = "200", description = "Role revoked"),
            @io.swagger.v3.oas.annotations.responses.ApiResponse(
                    responseCode = "403", description = "Insufficient role"),
            @io.swagger.v3.oas.annotations.responses.ApiResponse(
                    responseCode = "404", description = "User not found")
    })
    @PostMapping("/{userId}/roles/revoke")
    @PreAuthorize("hasRole('SYSTEM_ADMIN')")
    @Transactional
    public ResponseEntity<ApiResponse<MessageResponse>> revokeRole(
            @PathVariable UUID userId,
            @Valid @RequestBody AssignRoleRequest request,
            @AuthenticationPrincipal UserDetails actor,
            HttpServletRequest httpRequest) {

        User user = userService.findById(userId);
        user.getRoles().removeIf(r -> r.getName().equals(request.role()));
        userRepository.save(user);

        auditService.log(
                AuditEvent.ROLE_CHANGED,
                userId,
                IpExtractor.extract(httpRequest),
                httpRequest.getHeader("User-Agent"),
                String.format("{\"role\":\"%s\",\"action\":\"REVOKE\",\"actor\":\"%s\"}",
                        request.role(), actor.getUsername()));

        return ResponseEntity.ok(ApiResponse.of(
                new MessageResponse("Role " + request.role() + " revoked from user " + userId)));
    }

    @Operation(summary = "Deactivate a user account",
            description = "Sets is_active=false for the user. Requires SYSTEM_ADMIN.")
    @ApiResponses({
            @io.swagger.v3.oas.annotations.responses.ApiResponse(
                    responseCode = "200", description = "Account deactivated"),
            @io.swagger.v3.oas.annotations.responses.ApiResponse(
                    responseCode = "403", description = "Insufficient role"),
            @io.swagger.v3.oas.annotations.responses.ApiResponse(
                    responseCode = "404", description = "User not found")
    })
    @PostMapping("/{userId}/deactivate")
    @PreAuthorize("hasRole('SYSTEM_ADMIN')")
    @Transactional
    public ResponseEntity<ApiResponse<MessageResponse>> deactivate(
            @PathVariable UUID userId,
            @AuthenticationPrincipal UserDetails actor,
            HttpServletRequest httpRequest) {

        userService.findById(userId); // validates user exists — throws 404 if not
        userRepository.deactivateUser(userId);

        auditService.log(
                AuditEvent.ACCOUNT_DEACTIVATED,
                userId,
                IpExtractor.extract(httpRequest),
                httpRequest.getHeader("User-Agent"),
                String.format("{\"action\":\"DEACTIVATE\",\"actor\":\"%s\"}", actor.getUsername()));

        return ResponseEntity.ok(ApiResponse.of(
                new MessageResponse("User " + userId + " deactivated")));
    }

    /**
     * Request body for role assignment or revocation.
     */
    public record AssignRoleRequest(
            @NotBlank(message = "role is required")
            @Pattern(
                    regexp = "^(DONOR|SEEKER|ORG_ADMIN|SYSTEM_ADMIN)$",
                    message = "role must be one of: DONOR, SEEKER, ORG_ADMIN, SYSTEM_ADMIN")
            String role) {
    }
}
