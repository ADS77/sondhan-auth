package com.sondhan.auth.security;

import com.sondhan.auth.service.TokenService;
import jakarta.servlet.FilterChain;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;

import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.List;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class JwtAuthFilterTest {

  @Mock
  private CustomUserDetailsService userDetailsService;

  @Mock
  private TokenService tokenService;

  @Mock
  private FilterChain filterChain;

  private JwtAuthFilter filter;
  private JwtTokenProvider provider;
  private UUID userId;

  @BeforeEach
  void setUp() throws Exception {
    KeyPairGenerator gen = KeyPairGenerator.getInstance("RSA");
    gen.initialize(2048);
    var pair = gen.generateKeyPair();
    provider = new JwtTokenProvider(
            (RSAPrivateKey) pair.getPrivate(),
            (RSAPublicKey) pair.getPublic());

    filter = new JwtAuthFilter(provider, userDetailsService, tokenService);
    userId = UUID.randomUUID();
    SecurityContextHolder.clearContext();
  }

  @Test
  void doFilterInternal_givenValidToken_thenPopulatesSecurityContext() throws Exception {
    String token = provider.issueAccessToken(userId, List.of("DONOR"));
    UserDetails userDetails = User.withUsername(userId.toString())
            .password("").roles("DONOR").build();

    when(tokenService.isDenied(anyString())).thenReturn(false);
    when(userDetailsService.loadUserByUsername(userId.toString())).thenReturn(userDetails);

    MockHttpServletRequest request = new MockHttpServletRequest();
    request.addHeader("Authorization", "Bearer " + token);
    MockHttpServletResponse response = new MockHttpServletResponse();

    filter.doFilterInternal(request, response, filterChain);

    assertThat(SecurityContextHolder.getContext().getAuthentication()).isNotNull();
    assertThat(SecurityContextHolder.getContext().getAuthentication().getName())
            .isEqualTo(userId.toString());
    verify(filterChain).doFilter(request, response);
  }

  @Test
  void doFilterInternal_givenDeniedToken_thenDoesNotPopulateSecurityContext() throws Exception {
    String token = provider.issueAccessToken(userId, List.of("DONOR"));
    when(tokenService.isDenied(anyString())).thenReturn(true);

    MockHttpServletRequest request = new MockHttpServletRequest();
    request.addHeader("Authorization", "Bearer " + token);
    MockHttpServletResponse response = new MockHttpServletResponse();

    filter.doFilterInternal(request, response, filterChain);

    assertThat(SecurityContextHolder.getContext().getAuthentication()).isNull();
    verify(userDetailsService, never()).loadUserByUsername(any());
    verify(filterChain).doFilter(request, response); // chain still continues
  }

  @Test
  void doFilterInternal_givenNoAuthHeader_thenSkipsAuthAndContinuesChain() throws Exception {
    MockHttpServletRequest request = new MockHttpServletRequest();
    MockHttpServletResponse response = new MockHttpServletResponse();

    filter.doFilterInternal(request, response, filterChain);

    assertThat(SecurityContextHolder.getContext().getAuthentication()).isNull();
    verify(tokenService, never()).isDenied(any());
    verify(filterChain).doFilter(request, response);
  }

  @Test
  void doFilterInternal_givenTamperedToken_thenSkipsAuthGracefully() throws Exception {
    MockHttpServletRequest request = new MockHttpServletRequest();
    request.addHeader("Authorization", "Bearer header.payload.badsignature");
    MockHttpServletResponse response = new MockHttpServletResponse();

    filter.doFilterInternal(request, response, filterChain);

    assertThat(SecurityContextHolder.getContext().getAuthentication()).isNull();
    verify(filterChain).doFilter(request, response); // chain must still proceed
  }

  @Test
  void doFilterInternal_givenNoRequestId_thenGeneratesOneAndSetsResponseHeader() throws Exception {
    MockHttpServletRequest request = new MockHttpServletRequest();
    MockHttpServletResponse response = new MockHttpServletResponse();

    filter.doFilterInternal(request, response, filterChain);

    assertThat(response.getHeader("X-Request-ID")).isNotBlank();
  }

  @Test
  void doFilterInternal_givenExistingRequestId_thenPropagatesIt() throws Exception {
    MockHttpServletRequest request = new MockHttpServletRequest();
    request.addHeader("X-Request-ID", "my-trace-id-123");
    MockHttpServletResponse response = new MockHttpServletResponse();

    filter.doFilterInternal(request, response, filterChain);

    assertThat(response.getHeader("X-Request-ID")).isEqualTo("my-trace-id-123");
  }
}
