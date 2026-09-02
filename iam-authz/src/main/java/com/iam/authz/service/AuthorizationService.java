package com.iam.authz.service;

import com.iam.crypto.service.KeyManagementService;
import com.iam.directory.service.AccessRevocationService;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.proc.BadJOSEException;
import com.nimbusds.jose.proc.JWSVerificationKeySelector;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.jwt.proc.DefaultJWTProcessor;
import org.springframework.stereotype.Service;

import java.text.ParseException;
import java.util.HashMap;
import java.util.Map;

@Service
public class AuthorizationService {

    private final KeyManagementService keyManagementService;
    private final AccessRevocationService accessRevocationService;

    public AuthorizationService(KeyManagementService keyManagementService,
                                AccessRevocationService accessRevocationService) {
        this.keyManagementService = keyManagementService;
        this.accessRevocationService = accessRevocationService;
    }

    public Map<String, Object> introspectToken(String token) {
        Map<String, Object> result = new HashMap<>();
        try {
            if (accessRevocationService.isRevoked(token)) {
                result.put("active", false);
                result.put("error", "Token has been revoked");
                return result;
            }

            SignedJWT signedJWT = SignedJWT.parse(token);
            RSAKey publicRsaKey = keyManagementService.getRsaKey().toPublicJWK();
            ImmutableJWKSet<SecurityContext> jwkSet = new ImmutableJWKSet<>(new JWKSet(publicRsaKey));
            DefaultJWTProcessor<SecurityContext> jwtProcessor = new DefaultJWTProcessor<>();
            jwtProcessor.setJWSKeySelector(new JWSVerificationKeySelector<>(JWSAlgorithm.RS256, jwkSet));
            JWTClaimsSet claims = jwtProcessor.process(signedJWT, null);

            result.put("active", true);
            result.put("sub", claims.getSubject());
            result.put("username", claims.getClaim("username"));
            result.put("email", claims.getClaim("email"));
            result.put("exp", claims.getExpirationTime());

        } catch (ParseException | BadJOSEException | JOSEException e) {
            result.put("active", false);
            result.put("error", e.getMessage());
        }
        return result;
    }

    public void revokeToken(String token) {
        accessRevocationService.revokeAccessToken(token);
    }
}