package com.iam.authn.controller;

import com.iam.crypto.service.KeyManagementService;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jwt.SignedJWT;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RestController;

import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

@RestController
public class UserInfoController {

    private final KeyManagementService keyManagementService;

    public UserInfoController(KeyManagementService keyManagementService) {
        this.keyManagementService = keyManagementService;
    }

    @GetMapping(value = "/oauth2/userinfo", produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<Map<String, Object>> getUserInfo(
            @RequestHeader(name = HttpHeaders.AUTHORIZATION, required = false) String authHeader) {

        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .header(HttpHeaders.WWW_AUTHENTICATE, "Bearer error=\"invalid_token\"")
                    .body(Map.of("error", "invalid_token", "error_description", "Missing or invalid Bearer token"));
        }

        String token = authHeader.substring(7);

        try {
            SignedJWT signedJWT = SignedJWT.parse(token);

            boolean verified = signedJWT.verify(new RSASSAVerifier(keyManagementService.getRsaKey().toRSAPublicKey()));
            if (!verified) {
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                        .header(HttpHeaders.WWW_AUTHENTICATE, "Bearer error=\"invalid_token\"")
                        .body(Map.of("error", "invalid_token", "error_description", "Token signature verification failed"));
            }

            Date expirationTime = signedJWT.getJWTClaimsSet().getExpirationTime();
            if (expirationTime == null || expirationTime.before(new Date())) {
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                        .header(HttpHeaders.WWW_AUTHENTICATE, "Bearer error=\"invalid_token\"")
                        .body(Map.of("error", "invalid_token", "error_description", "Token has expired"));
            }

            String subject = signedJWT.getJWTClaimsSet().getSubject();
            Object scopeClaim = signedJWT.getJWTClaimsSet().getClaim("scope");
            List<String> scopes = scopeClaim instanceof List ? (List<String>) scopeClaim : List.of();

            if (!scopes.contains("openid")) {
                return ResponseEntity.status(HttpStatus.FORBIDDEN)
                        .body(Map.of("error", "insufficient_scope", "error_description", "The request requires the 'openid' scope"));
            }

            Map<String, Object> userInfo = new HashMap<>();
            userInfo.put("sub", subject);

            if (scopes.contains("profile")) {
                userInfo.put("name", "User " + subject);
            }

            if (scopes.contains("email")) {
                userInfo.put("email", subject + "@example.com");
            }

            return ResponseEntity.ok(userInfo);

        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .header(HttpHeaders.WWW_AUTHENTICATE, "Bearer error=\"invalid_token\"")
                    .body(Map.of("error", "invalid_token", "error_description", "Malformed or invalid token"));
        }
    }
}