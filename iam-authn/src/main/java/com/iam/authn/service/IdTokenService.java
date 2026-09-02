package com.iam.authn.service;

import com.iam.crypto.service.KeyManagementService;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.Date;
import java.util.List;

@Service
public class IdTokenService {
    private final KeyManagementService keyManagementService;
    private final String issuerUri;

    public IdTokenService(KeyManagementService keyManagementService,
                          @Value("${iam.issuer-uri:http://localhost:8080}") String issuerUri) {
        this.keyManagementService = keyManagementService;
        this.issuerUri = issuerUri;
    }

    public String generateIdToken(String subject, String clientId, String nonce, List<String> scopes, long expirationSeconds) {
        try {
            Instant now = Instant.now();
            Instant expiration = now.plusSeconds(expirationSeconds);

            JWTClaimsSet.Builder claimsBuilder = new JWTClaimsSet.Builder()
                    .issuer(issuerUri)
                    .subject(subject)
                    .audience(clientId)
                    .issueTime(Date.from(now))
                    .expirationTime(Date.from(expiration))
                    .claim("auth_time", now.getEpochSecond());

            if (nonce != null && !nonce.isBlank()) {
                claimsBuilder.claim("nonce", nonce);
            }

            if (scopes.contains("profile")) {
                claimsBuilder.claim("name", "User " + subject); // Replace with actual user attribute lookup
            }

            if (scopes.contains("email")) {
                claimsBuilder.claim("email", subject + "@example.com"); // Replace with actual user attribute lookup
            }

            JWTClaimsSet claimsSet = claimsBuilder.build();

            JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.RS256)
                    .keyID(keyManagementService.getKeyId().toString())
                    .build();

            SignedJWT signedJWT = new SignedJWT(header, claimsSet);

            JWSSigner signer = new RSASSASigner(keyManagementService.getRsaKey().toRSAPrivateKey());
            signedJWT.sign(signer);

            return signedJWT.serialize();
        } catch (Exception e) {
            throw new RuntimeException("Failed to generate OIDC ID Token", e);
        }
    }
}
