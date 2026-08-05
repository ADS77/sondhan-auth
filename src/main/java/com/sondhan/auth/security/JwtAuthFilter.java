package com.sondhan.auth.security;

import com.sondhan.auth.service.TokenService;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.slf4j.MDC;
import org.springframework.lang.NonNull;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

/**
 * Intercepts every request, extracts the Bearer JWT, validates it (signature + expiry),
 * checks the deny-list in Redis, and populates the SecurityContext.
 *
 * <p>MDC is populated with request_id and user_id for structured logging.
 */
@Component
public class JwtAuthFilter extends OncePerRequestFilter {

  private static final Logger log = LoggerFactory.getLogger(JwtAuthFilter.class);
  private static final String BEARER_PREFIX = "Bearer ";
  private static final String MDC_REQUEST_ID = "request_id";
  private static final String MDC_USER_ID = "user_id";
  private static final String HEADER_REQUEST_ID = "X-Request-ID";

  private final JwtTokenProvider jwtTokenProvider;
  private final CustomUserDetailsService userDetailsService;
  private final TokenService tokenService;

  public JwtAuthFilter(
      JwtTokenProvider jwtTokenProvider,
      CustomUserDetailsService userDetailsService,
      TokenService tokenService) {
    this.jwtTokenProvider = jwtTokenProvider;
    this.userDetailsService = userDetailsService;
    this.tokenService = tokenService;
  }

  @Override
  protected void doFilterInternal(
      @NonNull HttpServletRequest request,
      @NonNull HttpServletResponse response,
      @NonNull FilterChain filterChain) throws ServletException, IOException {

    // Propagate or generate X-Request-ID for MDC tracing
    String requestId = request.getHeader(HEADER_REQUEST_ID);
    if (!StringUtils.hasText(requestId)) {
      requestId = java.util.UUID.randomUUID().toString();
    }
    MDC.put(MDC_REQUEST_ID, requestId);
    response.setHeader(HEADER_REQUEST_ID, requestId);

    try {
      String token = extractBearerToken(request);
      if (token != null && SecurityContextHolder.getContext().getAuthentication() == null) {
        authenticateWithToken(token, request);
      }
      filterChain.doFilter(request, response);
    } finally {
      MDC.remove(MDC_REQUEST_ID);
      MDC.remove(MDC_USER_ID);
    }
  }

  private void authenticateWithToken(String token, HttpServletRequest request) {
    try {
      Claims claims = jwtTokenProvider.parseAndValidate(token);
      String jti = claims.getId();
      String userId = claims.getSubject();

      // Check deny-list (logout / revocation)
      if (tokenService.isDenied(jti)) {
        log.debug("Token JTI {} is on the deny-list", jti);
        return;
      }

      UserDetails userDetails = userDetailsService.loadUserByUsername(userId);
      if (!userDetails.isEnabled() || !userDetails.isAccountNonLocked()) {
        log.debug("User account {} is locked", userId);
        return;
      }

      MDC.put(MDC_USER_ID, userId);

      UsernamePasswordAuthenticationToken auth =
          new UsernamePasswordAuthenticationToken(
              userDetails, null, userDetails.getAuthorities());
      auth.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
      SecurityContextHolder.getContext().setAuthentication(auth);

    } catch (JwtException e) {
      log.debug("JWT validation failed: {}", e.getMessage());
    } catch (Exception e) {
      log.warn("Unexpected error during JWT auth: {}", e.getMessage());
    }
  }

  private String extractBearerToken(HttpServletRequest request) {
    String header = request.getHeader("Authorization");
    if (StringUtils.hasText(header) && header.startsWith(BEARER_PREFIX)) {
      return header.substring(BEARER_PREFIX.length());
    }
    return null;
  }
}
