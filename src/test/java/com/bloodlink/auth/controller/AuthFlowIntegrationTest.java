package com.sondhan.auth.controller;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.redis.testcontainers.RedisContainer;
import com.sondhan.auth.domain.OtpPurpose;
import com.sondhan.auth.domain.User;
import com.sondhan.auth.repository.OtpRepository;
import com.sondhan.auth.repository.UserRepository;
import com.sondhan.auth.util.HashUtil;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

import java.time.Instant;
import java.util.Map;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@AutoConfigureMockMvc
@Testcontainers
@ActiveProfiles("test")
class AuthFlowIntegrationTest {

  @Container
  static PostgreSQLContainer<?> postgres =
          new PostgreSQLContainer<>("postgres:16-alpine")
                  .withDatabaseName("sondhan_auth_test2")
                  .withUsername("sondhan_app")
                  .withPassword("test_password");

  @Container
  static RedisContainer redis = new RedisContainer("redis:7-alpine");
  @Autowired
  private MockMvc mockMvc;
  @Autowired
  private ObjectMapper objectMapper;
  @Autowired
  private UserRepository userRepository;
  @Autowired
  private OtpRepository otpRepository;

  @DynamicPropertySource
  static void overrideProperties(DynamicPropertyRegistry registry) {
    registry.add("spring.datasource.url", postgres::getJdbcUrl);
    registry.add("spring.datasource.username", postgres::getUsername);
    registry.add("spring.datasource.password", postgres::getPassword);
    registry.add("spring.data.redis.host", redis::getHost);
    registry.add("spring.data.redis.port", () -> redis.getMappedPort(6379));
    registry.add("spring.data.redis.password", () -> "");
  }

  @BeforeEach
  void cleanUp() {
    otpRepository.deleteAll();
    userRepository.deleteAll();
  }

  // ─── Helpers ─────────────────────────────────────────────────────────────

  /**
   * Registers a user then completes OTP verify, returning the $.data token node.
   */
  private JsonNode registerAndVerify(String phone) throws Exception {
    var registerBody = Map.of(
            "phone", phone,
            "first_name", "Test",
            "last_name", "User",
            "blood_group", "O+");

    String registerResponse = mockMvc.perform(post("/auth/v1/register")
            .contentType(MediaType.APPLICATION_JSON)
            .content(objectMapper.writeValueAsString(registerBody)))
            .andExpect(status().isCreated())
            .andReturn().getResponse().getContentAsString();

    String userId = objectMapper.readTree(registerResponse).get("data").get("user_id").asText();
    return verifyWithInjectedOtp(userId, OtpPurpose.REGISTER);
  }

  /**
   * Injects a known OTP into the DB and calls /verify-otp, returning the $.data token node.
   */
  private JsonNode verifyWithInjectedOtp(String userId, OtpPurpose purpose) throws Exception {
    User user = userRepository.findById(UUID.fromString(userId)).orElseThrow();

    otpRepository.findActiveOtp(user, purpose, Instant.now()).ifPresent(otp -> {
      otp.markUsed();
      otpRepository.save(otp);
    });

    String knownOtp = "777777";
    otpRepository.save(new com.sondhan.auth.domain.OtpCode(
            user,
            HashUtil.sha256Hex(knownOtp),
            purpose,
            Instant.now().plusSeconds(300)));

    var verifyBody = Map.of(
            "user_id", userId,
            "otp", knownOtp,
            "purpose", purpose.name());

    String verifyResponse = mockMvc.perform(post("/auth/v1/verify-otp")
            .contentType(MediaType.APPLICATION_JSON)
            .content(objectMapper.writeValueAsString(verifyBody)))
            .andExpect(status().isOk())
            .andReturn().getResponse().getContentAsString();

    return objectMapper.readTree(verifyResponse).get("data");
  }

  // ─── JWKS ────────────────────────────────────────────────────────────────

  @Test
  void jwks_givenPublicEndpoint_thenReturnsJwkSet() throws Exception {
    mockMvc.perform(get("/auth/.well-known/jwks.json"))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.data.keys").isArray())
            .andExpect(jsonPath("$.data.keys[0].kty").value("RSA"))
            .andExpect(jsonPath("$.data.keys[0].use").value("sig"))
            .andExpect(jsonPath("$.data.keys[0].alg").value("RS256"))
            .andExpect(jsonPath("$.data.keys[0].n").isNotEmpty())
            .andExpect(jsonPath("$.data.keys[0].e").isNotEmpty());
  }

  @Test
  void jwks_givenNoAuth_thenStill200() throws Exception {
    mockMvc.perform(get("/auth/.well-known/jwks.json"))
            .andExpect(status().isOk());
  }

  // ─── /me ─────────────────────────────────────────────────────────────────

  @Test
  void me_givenValidAccessToken_thenReturnsUserProfile() throws Exception {
    JsonNode tokens = registerAndVerify("+8801711001001");
    String accessToken = tokens.get("access_token").asText();
    String userId = tokens.get("user").get("id").asText();

    mockMvc.perform(get("/auth/v1/me")
            .header("Authorization", "Bearer " + accessToken))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.data.id").value(userId))
            .andExpect(jsonPath("$.data.blood_group").value("O+"))
            .andExpect(jsonPath("$.data.is_verified").value(true))
            .andExpect(jsonPath("$.data.roles").isArray());
  }

  @Test
  void me_givenNoToken_thenReturns401() throws Exception {
    mockMvc.perform(get("/auth/v1/me"))
            .andExpect(status().isUnauthorized());
  }

  @Test
  void me_givenInvalidToken_thenReturns401() throws Exception {
    mockMvc.perform(get("/auth/v1/me")
            .header("Authorization", "Bearer not.a.valid.jwt"))
            .andExpect(status().isUnauthorized());
  }

  // ─── refresh ─────────────────────────────────────────────────────────────

  @Test
  void refresh_givenValidRefreshToken_thenReturnsNewTokenPair() throws Exception {
    JsonNode tokens = registerAndVerify("+8801711001002");
    String oldRefreshToken = tokens.get("refresh_token").asText();

    MvcResult result = mockMvc.perform(post("/auth/v1/refresh")
            .contentType(MediaType.APPLICATION_JSON)
            .content(objectMapper.writeValueAsString(
                    Map.of("refresh_token", oldRefreshToken))))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.data.access_token").isNotEmpty())
            .andExpect(jsonPath("$.data.refresh_token").isNotEmpty())
            .andExpect(jsonPath("$.data.expires_in").value(900))
            .andReturn();

    JsonNode newData = objectMapper.readTree(
            result.getResponse().getContentAsString()).get("data");
    assertThat(newData.get("refresh_token").asText()).isNotEqualTo(oldRefreshToken);
  }

  @Test
  void refresh_givenAbsentRefreshToken_thenReturns401() throws Exception {
    mockMvc.perform(post("/auth/v1/refresh")
            .contentType(MediaType.APPLICATION_JSON)
            .content(objectMapper.writeValueAsString(
                    Map.of("refresh_token", UUID.randomUUID().toString()))))
            .andExpect(status().isUnauthorized())
            .andExpect(jsonPath("$.error").value("TOKEN_INVALID"));
  }

  @Test
  void refresh_givenRotatedTokenPresentedAgain_thenReturns401WithReuseAttack() throws Exception {
    JsonNode tokens = registerAndVerify("+8801711001003");
    String oldRefreshToken = tokens.get("refresh_token").asText();

    // First rotation — consumes old token
    mockMvc.perform(post("/auth/v1/refresh")
            .contentType(MediaType.APPLICATION_JSON)
            .content(objectMapper.writeValueAsString(
                    Map.of("refresh_token", oldRefreshToken))))
            .andExpect(status().isOk());

    // Replay already-rotated token — must be rejected as reuse attack
    mockMvc.perform(post("/auth/v1/refresh")
            .contentType(MediaType.APPLICATION_JSON)
            .content(objectMapper.writeValueAsString(
                    Map.of("refresh_token", oldRefreshToken))))
            .andExpect(status().isUnauthorized())
            .andExpect(jsonPath("$.error").value("REFRESH_REUSE_ATTACK"));
  }

  // ─── logout ──────────────────────────────────────────────────────────────

  @Test
  void logout_givenValidTokens_thenDeniesSubsequentAccessToken() throws Exception {
    JsonNode tokens = registerAndVerify("+8801711001004");
    String accessToken = tokens.get("access_token").asText();
    String refreshToken = tokens.get("refresh_token").asText();

    mockMvc.perform(post("/auth/v1/logout")
            .header("Authorization", "Bearer " + accessToken)
            .contentType(MediaType.APPLICATION_JSON)
            .content(objectMapper.writeValueAsString(
                    Map.of("refresh_token", refreshToken))))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.data.message").value("Logged out"));

    // Same access token must now be denied
    mockMvc.perform(get("/auth/v1/me")
            .header("Authorization", "Bearer " + accessToken))
            .andExpect(status().isUnauthorized());
  }

  @Test
  void logout_givenNoToken_thenReturns401() throws Exception {
    mockMvc.perform(post("/auth/v1/logout")
            .contentType(MediaType.APPLICATION_JSON)
            .content(objectMapper.writeValueAsString(
                    Map.of("refresh_token", UUID.randomUUID().toString()))))
            .andExpect(status().isUnauthorized());
  }

  // ─── Full flow smoke test ─────────────────────────────────────────────────

  @Test
  void fullAuthFlow_registerVerifyRefreshLogout_succeeds() throws Exception {
    var registerBody = Map.of(
            "phone", "+8801711001005",
            "first_name", "Full",
            "last_name", "Flow",
            "blood_group", "AB-");

    String registerResponse = mockMvc.perform(post("/auth/v1/register")
            .contentType(MediaType.APPLICATION_JSON)
            .content(objectMapper.writeValueAsString(registerBody)))
            .andExpect(status().isCreated())
            .andReturn().getResponse().getContentAsString();

    String userId = objectMapper.readTree(registerResponse).get("data").get("user_id").asText();

    JsonNode tokens = verifyWithInjectedOtp(userId, OtpPurpose.REGISTER);
    String accessToken = tokens.get("access_token").asText();
    String refreshToken = tokens.get("refresh_token").asText();

    // /me works
    mockMvc.perform(get("/auth/v1/me")
            .header("Authorization", "Bearer " + accessToken))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.data.id").value(userId));

    // Refresh
    String refreshResponse = mockMvc.perform(post("/auth/v1/refresh")
            .contentType(MediaType.APPLICATION_JSON)
            .content(objectMapper.writeValueAsString(
                    Map.of("refresh_token", refreshToken))))
            .andExpect(status().isOk())
            .andReturn().getResponse().getContentAsString();

    JsonNode newTokens = objectMapper.readTree(refreshResponse).get("data");
    String newAccessToken = newTokens.get("access_token").asText();
    String newRefreshToken = newTokens.get("refresh_token").asText();

    // Logout
    mockMvc.perform(post("/auth/v1/logout")
            .header("Authorization", "Bearer " + newAccessToken)
            .contentType(MediaType.APPLICATION_JSON)
            .content(objectMapper.writeValueAsString(
                    Map.of("refresh_token", newRefreshToken))))
            .andExpect(status().isOk());

    // Post-logout /me is denied
    mockMvc.perform(get("/auth/v1/me")
            .header("Authorization", "Bearer " + newAccessToken))
            .andExpect(status().isUnauthorized());
  }
}
