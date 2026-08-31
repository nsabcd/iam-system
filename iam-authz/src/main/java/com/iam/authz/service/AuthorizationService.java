package com.iam.authz.service;

import com.iam.crypto.service.KeyManagementService;
import com.iam.directory.model.RevokedTokenEntity;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.proc.BadJOSEException;
import com.nimbusds.jose.proc.JWSVerificationKeySelector;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.proc.DefaultJWTProcessor;
import org.springframework.stereotype.Service;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jwt.SignedJWT;
import java.text.ParseException;
import java.util.HashMap;
import java.util.Map;
import com.iam.directory.repository.RevokedTokenRepository;


@Service
public class AuthorizationService {
    private final KeyManagementService keyManagementService;
    private final RevokedTokenRepository revokedTokenRepository;

    public AuthorizationService(KeyManagementService keyManagementService, RevokedTokenRepository revokedTokenRepository) {
        this.keyManagementService = keyManagementService;
        this.revokedTokenRepository=revokedTokenRepository;
    }

    public Map<String, Object> introspectToken(String token){
        Map<String, Object> result = new HashMap<>();
        try{
            if (revokedTokenRepository.existsByTokenSignature(token)) {
                result.put("active", false);
                result.put("error", "Token has been revoked");
                return result;
            }

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
    public void revokeToken(String token){
        try{
            SignedJWT signedJWT = SignedJWT.parse(token);
            JWTClaimsSet claims = signedJWT.getJWTClaimsSet();
            RevokedTokenEntity revoked = new RevokedTokenEntity();
            revoked.setTokenSignature(token);
            revoked.setExpiresAt(claims.getExpirationTime().toInstant());
            revokedTokenRepository.save(revoked);
        } catch (Exception e) {
            throw new IllegalArgumentException("Invalid token format for revocation", e);
        }
    }
}
