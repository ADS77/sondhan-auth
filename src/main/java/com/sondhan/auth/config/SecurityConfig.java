package com.sondhan.auth.config;

import com.sondhan.auth.security.JwtAuthFilter;
import java.util.List;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityCustomizer;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

/**
 * Spring Security 6 configuration.
 *
 * <ul>
 *   <li>Stateless JWT — no session, no CSRF</li>
 *   <li>CORS restricted to known origins from config</li>
 *   <li>Public endpoints: /auth/v1/register, /auth/v1/login, /auth/v1/verify-otp,
 *       /auth/v1/refresh, /auth/.well-known/**, /auth/docs/**, /actuator/health</li>
 *   <li>All other endpoints require a valid Bearer token</li>
 * </ul>
 */
@Configuration
@EnableWebSecurity
@EnableMethodSecurity
public class SecurityConfig {

  private static final String[] PUBLIC_ENDPOINTS = {
          "/auth/v1/register",
          "/auth/v1/login",
          "/auth/v1/verify-otp",
          "/auth/v1/refresh",

          "/v3/api-docs/**",
          "/swagger-ui/**",
          "/swagger-ui.html",

          "/auth/docs",
          "/auth/docs/**",
          "/auth/swagger-ui/**",

          "/auth/.well-known/**",
          "/actuator/health"
  };

  private final JwtAuthFilter jwtAuthFilter;
  private final CorsProperties corsProperties;

  public SecurityConfig(JwtAuthFilter jwtAuthFilter, CorsProperties corsProperties) {
    this.jwtAuthFilter = jwtAuthFilter;
    this.corsProperties = corsProperties;
  }

  @Bean
  public WebSecurityCustomizer webSecurityCustomizer() {
    return web -> web.ignoring()
            .requestMatchers(
                    "/swagger-ui/**",
                    "/v3/api-docs/**",
                    "/swagger-ui.html",
                    "/auth/docs",
                    "/auth/docs/**");
  }

  @Bean
  public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
    http
        .csrf(AbstractHttpConfigurer::disable)
        .cors(cors -> cors.configurationSource(corsConfigurationSource()))
        .sessionManagement(session ->
            session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
        .authorizeHttpRequests(auth -> auth
            .requestMatchers(PUBLIC_ENDPOINTS).permitAll()
            .anyRequest().authenticated())
        .addFilterBefore(jwtAuthFilter, UsernamePasswordAuthenticationFilter.class);

    return http.build();
  }

  @Bean
  public CorsConfigurationSource corsConfigurationSource() {
    CorsConfiguration config = new CorsConfiguration();
    config.setAllowedOrigins(corsProperties.getAllowedOrigins());
    config.setAllowedMethods(List.of("GET", "POST", "PUT", "DELETE", "OPTIONS"));
    config.setAllowedHeaders(List.of("*"));
    config.setAllowCredentials(true);
    config.setMaxAge(3600L);

    UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
    source.registerCorsConfiguration("/**", config);
    return source;
  }
}
