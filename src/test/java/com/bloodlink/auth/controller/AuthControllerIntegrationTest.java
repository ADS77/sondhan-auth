package com.sondhan.auth.controller;

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
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

import java.util.Map;
import java.util.UUID;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@AutoConfigureMockMvc
@Testcontainers
@ActiveProfiles("test")
class AuthControllerIntegrationTest {

  @Container
  static PostgreSQLContainer<?> postgres =
          new PostgreSQLContainer<>("postgres:16-alpine")
                  .withDatabaseName("sondhan_auth_test")
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

  // All responses now have shape: { "data": { ... } }

  @Test
  void register_givenValidRequest_thenReturns201AndUserId() throws Exception {
    var body = Map.of(
            "phone", "+8801711000001",
            "first_name", "Rahim",
            "last_name", "Uddin",
            "blood_group", "O+");

    mockMvc.perform(post("/auth/v1/register")
            .contentType(MediaType.APPLICATION_JSON)
            .content(objectMapper.writeValueAsString(body)))
            .andExpect(status().isCreated())
            .andExpect(jsonPath("$.data.user_id").isNotEmpty())
            .andExpect(jsonPath("$.data.message").value("OTP sent"))
            .andExpect(jsonPath("$.data.otp_expires_in_seconds").value(300));
  }

  @Test
  void register_givenDuplicatePhone_thenReturns409() throws Exception {
    var body = Map.of(
            "phone", "+8801711000002",
            "first_name", "Karim",
            "last_name", "Hossain",
            "blood_group", "A+");

    mockMvc.perform(post("/auth/v1/register")
            .contentType(MediaType.APPLICATION_JSON)
            .content(objectMapper.writeValueAsString(body)))
            .andExpect(status().isCreated());

    mockMvc.perform(post("/auth/v1/register")
            .contentType(MediaType.APPLICATION_JSON)
            .content(objectMapper.writeValueAsString(body)))
            .andExpect(status().isConflict())
            .andExpect(jsonPath("$.error").value("USER_ALREADY_EXISTS"));
  }

  @Test
  void register_givenInvalidPhone_thenReturns400() throws Exception {
    var body = Map.of(
            "phone", "01711000003",
            "first_name", "Test",
            "last_name", "User",
            "blood_group", "B+");

    mockMvc.perform(post("/auth/v1/register")
            .contentType(MediaType.APPLICATION_JSON)
            .content(objectMapper.writeValueAsString(body)))
            .andExpect(status().isBadRequest())
            .andExpect(jsonPath("$.error").value("INVALID_REQUEST"));
  }

  @Test
  void verifyOtp_givenCorrectOtp_thenReturnsTokens() throws Exception {
    var registerBody = Map.of(
            "phone", "+8801711000004",
            "first_name", "Fatima",
            "last_name", "Begum",
            "blood_group", "AB+");

    String registerResponse = mockMvc.perform(post("/auth/v1/register")
            .contentType(MediaType.APPLICATION_JSON)
            .content(objectMapper.writeValueAsString(registerBody)))
            .andExpect(status().isCreated())
            .andReturn().getResponse().getContentAsString();

    String userId = objectMapper.readTree(registerResponse).get("data").get("user_id").asText();

    User user = userRepository.findById(UUID.fromString(userId)).orElseThrow();
    var otpCode = otpRepository
            .findActiveOtp(user, OtpPurpose.REGISTER, java.time.Instant.now())
            .orElseThrow();
    otpCode.markUsed();
    otpRepository.save(otpCode);

    String knownOtp = "888888";
    otpRepository.save(new com.sondhan.auth.domain.OtpCode(
            user,
            HashUtil.sha256Hex(knownOtp),
            OtpPurpose.REGISTER,
            java.time.Instant.now().plusSeconds(300)));

    var verifyBody = Map.of(
            "user_id", userId,
            "otp", knownOtp,
            "purpose", "REGISTER");

    mockMvc.perform(post("/auth/v1/verify-otp")
            .contentType(MediaType.APPLICATION_JSON)
            .content(objectMapper.writeValueAsString(verifyBody)))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.data.access_token").isNotEmpty())
            .andExpect(jsonPath("$.data.refresh_token").isNotEmpty())
            .andExpect(jsonPath("$.data.token_type").value("Bearer"))
            .andExpect(jsonPath("$.data.expires_in").value(900))
            .andExpect(jsonPath("$.data.user.id").value(userId));
  }

  @Test
  void login_givenUnregisteredPhone_thenReturns404() throws Exception {
    var body = Map.of("phone", "+8801799999999");

    mockMvc.perform(post("/auth/v1/login")
            .contentType(MediaType.APPLICATION_JSON)
            .content(objectMapper.writeValueAsString(body)))
            .andExpect(status().isNotFound())
            .andExpect(jsonPath("$.error").value("USER_NOT_FOUND"));
  }

  @Test
  void verifyOtp_givenWrongOtp_thenReturns400() throws Exception {
    var registerBody = Map.of(
            "phone", "+8801711000005",
            "first_name", "Omar",
            "last_name", "Faruk",
            "blood_group", "B-");

    String registerResponse = mockMvc.perform(post("/auth/v1/register")
            .contentType(MediaType.APPLICATION_JSON)
            .content(objectMapper.writeValueAsString(registerBody)))
            .andReturn().getResponse().getContentAsString();

    String userId = objectMapper.readTree(registerResponse).get("data").get("user_id").asText();

    var verifyBody = Map.of(
            "user_id", userId,
            "otp", "000000",
            "purpose", "REGISTER");

    mockMvc.perform(post("/auth/v1/verify-otp")
            .contentType(MediaType.APPLICATION_JSON)
            .content(objectMapper.writeValueAsString(verifyBody)))
            .andExpect(status().isBadRequest())
            .andExpect(jsonPath("$.error").value("INVALID_OTP"));
  }
}
