package com.sondhan.auth.security;

import com.sondhan.auth.util.HashUtil;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class HashUtilTest {

  @Test
  void sha256Hex_givenKnownInput_thenReturnsExpectedHash() {
    // SHA-256("123456") is a well-known value
    String result = HashUtil.sha256Hex("123456");
    assertThat(result)
            .hasSize(64)
            .isEqualTo("8d969eef6ecad3c29a3a629280e686cf0c3f5d5a86aff3ca12020c923adc6c92");
  }

  @Test
  void sha256Hex_givenSameInput_thenAlwaysReturnsSameHash() {
    String hash1 = HashUtil.sha256Hex("test-phone-+8801711000000");
    String hash2 = HashUtil.sha256Hex("test-phone-+8801711000000");
    assertThat(hash1).isEqualTo(hash2);
  }

  @Test
  void sha256Hex_givenDifferentInputs_thenReturnsDifferentHashes() {
    assertThat(HashUtil.sha256Hex("aaa")).isNotEqualTo(HashUtil.sha256Hex("bbb"));
  }

  @Test
  void sha256Hex_givenInput_thenResultIsLowercase() {
    String result = HashUtil.sha256Hex("Hello");
    assertThat(result).isEqualTo(result.toLowerCase());
  }
}
