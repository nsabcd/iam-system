package com.iam.authn.controller;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;
import java.util.Map;

@RestController
public class OidcDiscoveryController {
    private final String issuerUri;

    public OidcDiscoveryController(@Value("${iam.issuer-uri:http://localhost:8080}") String issuerUri) {
        this.issuerUri = issuerUri;
    }

    @GetMapping(value = "/.well-known/openid-configuration", produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<Map<String, Object>> getOpenIdConfiguration() {
        Map<String, Object> configuration = Map.ofEntries(
                Map.entry("issuer", issuerUri),
                Map.entry("authorization_endpoint", issuerUri + "/oauth2/authorize"),
                Map.entry("token_endpoint", issuerUri + "/oauth2/token"),
                Map.entry("userinfo_endpoint", issuerUri + "/oauth2/userinfo"),
                Map.entry("jwks_uri", issuerUri + "/.well-known/jwks.json"),
                Map.entry("response_types_supported", List.of("code")),
                Map.entry("subject_types_supported", List.of("public")),
                Map.entry("id_token_signing_alg_values_supported", List.of("RS256")),
                Map.entry("scopes_supported", List.of("openid", "profile", "email")),
                Map.entry("token_endpoint_auth_methods_supported", List.of("client_secret_basic", "client_secret_post")),
                Map.entry("grant_types_supported", List.of("authorization_code", "client_credentials", "refresh_token")),
                Map.entry("claims_supported", List.of("sub", "iss", "aud", "exp", "iat", "auth_time", "name", "email"))
        );

        return ResponseEntity.ok(configuration);
    }
}
