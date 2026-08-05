package com.sondhan.auth.controller;

import com.sondhan.auth.dto.response.ApiResponse;
import com.sondhan.auth.security.JwtTokenProvider;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import org.springframework.http.CacheControl;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.math.BigInteger;
import java.security.interfaces.RSAPublicKey;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.concurrent.TimeUnit;

/**
 * Exposes the RSA public key in JWK Set format.
 * Other microservices poll this endpoint to verify access tokens.
 * This endpoint is public — no authentication required.
 */
@RestController
@RequestMapping("/auth/.well-known")
@Tag(name = "JWKS", description = "Public key endpoint for token verification")
public class JwksController {

    private final JwtTokenProvider jwtTokenProvider;

    public JwksController(JwtTokenProvider jwtTokenProvider) {
        this.jwtTokenProvider = jwtTokenProvider;
    }

    @Operation(
            summary = "JSON Web Key Set",
            description = "Returns the RSA public key in JWK Set format for RS256 token verification")
    //@ApiResponse(responseCode = "200", description = "JWK Set returned")
    @GetMapping("/jwks.json")
    public ResponseEntity<ApiResponse<Map<String, Object>>> jwks() {
        RSAPublicKey publicKey = jwtTokenProvider.getPublicKey();

        Map<String, Object> jwk = Map.of(
                "kty", "RSA",
                "use", "sig",
                "alg", "RS256",
                "n", base64UrlEncode(publicKey.getModulus()),
                "e", base64UrlEncode(publicKey.getPublicExponent()));

        Map<String, Object> jwkSet = Map.of("keys", List.of(jwk));

        return ResponseEntity.ok()
                .cacheControl(CacheControl.maxAge(1, TimeUnit.HOURS))
                .body(ApiResponse.of(jwkSet));
    }

    private String base64UrlEncode(BigInteger value) {
        byte[] bytes = value.toByteArray();
        // Remove leading zero byte that BigInteger may prepend for sign
        if (bytes[0] == 0) {
            byte[] trimmed = new byte[bytes.length - 1];
            System.arraycopy(bytes, 1, trimmed, 0, trimmed.length);
            bytes = trimmed;
        }
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }
}
