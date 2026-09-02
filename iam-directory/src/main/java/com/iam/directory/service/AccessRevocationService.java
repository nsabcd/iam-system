package com.iam.directory.service;

import com.iam.directory.model.RevokedTokenEntity;
import com.iam.directory.repository.RevokedTokenRepository;
import com.iam.directory.service.TokenBlacklistService;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Duration;
import java.time.Instant;
import java.util.Date;

@Service
public class AccessRevocationService {

    private final RevokedTokenRepository revokedTokenRepository;
    private final TokenBlacklistService tokenBlacklistService;

    public AccessRevocationService(RevokedTokenRepository revokedTokenRepository,
                                   TokenBlacklistService tokenBlacklistService) {
        this.revokedTokenRepository = revokedTokenRepository;
        this.tokenBlacklistService = tokenBlacklistService;
    }

    @Transactional(readOnly = true)
    public boolean isRevoked(String token) {
        if (token == null || token.isBlank()) {
            return false;
        }
        // 1. Fast path: Redis check
        if (tokenBlacklistService.isBlacklisted(token)) {
            return true;
        }
        // 2. Fallback path: Database check
        return revokedTokenRepository.existsByTokenSignature(token);
    }

    @Transactional
    public void revokeAccessToken(String rawAccessToken) {
        if (rawAccessToken == null || rawAccessToken.isBlank()) {
            return;
        }

        try {
            SignedJWT signedJWT = SignedJWT.parse(rawAccessToken);
            JWTClaimsSet claims = signedJWT.getJWTClaimsSet();
            Date expirationTime = claims.getExpirationTime();

            Instant now = Instant.now();
            Instant expiresAt = expirationTime != null ? expirationTime.toInstant() : now.plusSeconds(3600);

            // Calculate TTL for Redis eviction
            Duration ttl = Duration.between(now, expiresAt);
            if (ttl.isNegative() || ttl.isZero()) {
                ttl = Duration.ofSeconds(60);
            }

            // Write-through: Both Redis and Database
            tokenBlacklistService.blacklistToken(rawAccessToken, ttl);

            RevokedTokenEntity revoked = new RevokedTokenEntity();
            revoked.setTokenSignature(rawAccessToken);
            revoked.setExpiresAt(expiresAt);
            revokedTokenRepository.save(revoked);

        } catch (Exception e) {
            // Ignore malformed or unparseable tokens during cleanup
        }
    }
}