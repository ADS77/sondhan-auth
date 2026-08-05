package com.sondhan.auth.security;

import com.sondhan.auth.domain.User;
import com.sondhan.auth.repository.UserRepository;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.UUID;
import java.util.stream.Collectors;

/**
 * Loads a {@link UserDetails} by user UUID (the JWT "sub" claim).
 * Spring Security uses this during filter-chain authentication.
 */
@Service
public class CustomUserDetailsService implements UserDetailsService {

  private final UserRepository userRepository;

  public CustomUserDetailsService(UserRepository userRepository) {
    this.userRepository = userRepository;
  }

  @Override
  @Transactional(readOnly = true)
  public UserDetails loadUserByUsername(String userId) throws UsernameNotFoundException {
    User user = userRepository
        .findById(UUID.fromString(userId))
        .orElseThrow(() ->
            new UsernameNotFoundException("User not found: " + userId));

    var authorities = user.getRoles().stream()
        .map(role -> new SimpleGrantedAuthority("ROLE_" + role.getName()))
        .collect(Collectors.toSet());

    return org.springframework.security.core.userdetails.User.builder()
        .username(user.getId().toString())
        .password("")                        // no password — OTP-only auth
        .authorities(authorities)
        .accountLocked(user.isLocked())
        .disabled(!user.isActive())
        .build();
  }
}
