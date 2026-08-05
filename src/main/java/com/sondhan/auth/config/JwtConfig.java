package com.sondhan.auth.config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.io.Resource;

import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

/**
 * Loads the RSA-2048 key pair from base64-encoded PKCS8 values.
 * Keys must be set via environment variables or Vault — never hardcoded.
 *
 * <p>Expected application-secrets.yml (loaded from env):
 * <pre>
 * app:
 *   jwt:
 *     private-key: <base64-encoded PKCS8 private key>
 *     public-key:  <base64-encoded X.509 public key>
 * </pre>
 */
@Configuration
public class JwtConfig {

  @Value("${jwt.private-key-path}")
  private Resource privateKeyResource;

  @Value("${jwt.public-key-path}")
  private Resource publicKeyResource;

  @Bean
  public RSAPrivateKey rsaPrivateKey() throws Exception {
    String pem = new String(privateKeyResource.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
    pem = pem.replace("-----BEGIN PRIVATE KEY-----", "")
            .replace("-----END PRIVATE KEY-----", "")
            .replaceAll("\\s+", "");
    byte[] decoded = Base64.getDecoder().decode(pem);
    return (RSAPrivateKey) KeyFactory.getInstance("RSA")
            .generatePrivate(new PKCS8EncodedKeySpec(decoded));
  }

  @Bean
  public RSAPublicKey rsaPublicKey() throws Exception {
    String pem = new String(publicKeyResource.getInputStream().readAllBytes(), StandardCharsets.UTF_8);

    pem = pem.replace("-----BEGIN PUBLIC KEY-----", "")
            .replace("-----END PUBLIC KEY-----", "")
            .replaceAll("\\s+", "");

    byte[] decoded = Base64.getDecoder().decode(pem);

    return (RSAPublicKey) KeyFactory.getInstance("RSA")
            .generatePublic(new X509EncodedKeySpec(decoded));
  }
}
