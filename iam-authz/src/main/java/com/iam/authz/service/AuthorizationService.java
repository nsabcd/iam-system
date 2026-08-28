package com.iam.authz.service;

import com.iam.crypto.service.KeyManagementService;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.proc.BadJOSEException;
import com.nimbusds.jose.proc.JWSVerificationKeySelector;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.proc.BadJWTException;
import com.nimbusds.jwt.proc.DefaultJWTProcessor;
import org.springframework.stereotype.Service;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jwt.SignedJWT;

import java.security.GeneralSecurityException;
import java.text.ParseException;
import java.util.HashMap;
import java.util.Map;

@Service
public class AuthorizationService {
    private final KeyManagementService keyManagementService;

    public AuthorizationService(KeyManagementService keyManagementService) {
        this.keyManagementService = keyManagementService;
    }

    public Map<String, Object> introspectToken(String token){
        Map<String, Object> result = new HashMap<>();
        try{
            SignedJWT signedJWT = SignedJWT.parse(token);
            RSAKey publicRsakKey = keyManagementService.getRsaKey().toPublicJWK();
            ImmutableJWKSet<SecurityContext> jwkSet = new ImmutableJWKSet<>(new JWKSet(publicRsakKey));
            DefaultJWTProcessor<SecurityContext> jwtProcessor = new DefaultJWTProcessor<>();
            jwtProcessor.setJWSKeySelector(new JWSVerificationKeySelector<>(JWSAlgorithm.RS256, jwkSet));
            JWTClaimsSet claims = jwtProcessor.process(signedJWT, null);
            result.put("active", true);
            result.put("sub", claims.getSubject());
            result.put("username", claims.getClaim("username"));
            result.put("email", claims.getClaim("email"));
            result.put("exp", claims.getExpirationTime());

        }catch (ParseException | BadJOSEException | JOSEException e){
            result.put("active", false);
            result.put("error", e.getMessage());
        }
        return result;
    }
}
