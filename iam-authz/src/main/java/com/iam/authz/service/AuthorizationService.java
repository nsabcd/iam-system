package com.iam.authz.service;

import com.iam.crypto.service.KeyManagementService;
import com.iam.directory.model.RevokedTokenEntity;
import com.iam.security.service.TokenBlacklistService;
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
import java.time.Duration;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import com.iam.directory.repository.RevokedTokenRepository;
import java.time.Instant;


@Service
public class AuthorizationService {
    private final KeyManagementService keyManagementService;
    private final RevokedTokenRepository revokedTokenRepository;
    private final TokenBlacklistService tokenBlacklistService;

    public AuthorizationService(KeyManagementService keyManagementService,
                                RevokedTokenRepository revokedTokenRepository,
                                TokenBlacklistService tokenBlacklistService) {
        this.keyManagementService = keyManagementService;
        this.revokedTokenRepository=revokedTokenRepository;
        this.tokenBlacklistService=tokenBlacklistService;
    }

    public Map<String, Object> introspectToken(String token){
        Map<String, Object> result = new HashMap<>();
        try{
            if (tokenBlacklistService.isBlacklisted(token) || revokedTokenRepository.existsByTokenSignature(token)) {
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
            Date expirationTime = claims.getExpirationTime();

            Instant now = Instant.now();
            Instant expiresAt = expirationTime != null ? expirationTime.toInstant() : now.plusSeconds(3600);

            // Calculate precise remaining lifetime for Redis TTL auto-eviction
            Duration ttl = Duration.between(now, expiresAt);
            if (ttl.isNegative() || ttl.isZero()) {
                ttl = Duration.ofSeconds(60);
            }

            // 1. Store in Redis blacklist for high-throughput distributed verification
            tokenBlacklistService.blacklistToken(token, ttl);

            RevokedTokenEntity revoked = new RevokedTokenEntity();
            revoked.setTokenSignature(token);
            revoked.setExpiresAt(claims.getExpirationTime().toInstant());
            revokedTokenRepository.save(revoked);
        } catch (Exception e) {
            throw new IllegalArgumentException("Invalid token format for revocation", e);
        }
    }
}
