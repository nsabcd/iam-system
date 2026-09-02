package com.iam.directory.service;

import com.iam.directory.model.RefreshTokenEntity;
import com.iam.directory.repository.RefreshTokenRepository;


import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.nio.charset.StandardCharsets;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Base64;
import java.util.Optional;
import java.security.MessageDigest;

@Service
public class RefreshTokenService {
    private static final long REFRESH_TOKEN_VALIDITY_DAYS = 365;

    private final RefreshTokenRepository refreshTokenRepository;
    private final SecureRandom secureRandom = new SecureRandom();

    public RefreshTokenService(RefreshTokenRepository refreshTokenRepository) {
        this.refreshTokenRepository = refreshTokenRepository;
    }

    public record IssuedRefreshToken(String rawToken, RefreshTokenEntity entity) {}

    @Transactional
    public IssuedRefreshToken createRefreshToken(String username, String familyId) {
        String rawRefreshToken = generateSecureTokenString();
        String tokenHash = hashToken(rawRefreshToken);

        RefreshTokenEntity entity = new RefreshTokenEntity();
        entity.setTokenHash(tokenHash);
        entity.setUsername(username);
        entity.setFamilyId(familyId != null ? familyId : generateSecureTokenString());
        entity.setRevoked(false);
        entity.setExpiresAt(Instant.now().plus(REFRESH_TOKEN_VALIDITY_DAYS, ChronoUnit.DAYS));

        refreshTokenRepository.save(entity);
        return new IssuedRefreshToken(rawRefreshToken, entity);
    }

    @Transactional
    public IssuedRefreshToken rotateToken(String rawRefreshToken) {
        String incomingHash = hashToken(rawRefreshToken);
        RefreshTokenEntity existingToken = refreshTokenRepository.findByTokenHash(incomingHash)
                .orElseThrow(() -> new IllegalArgumentException("Invalid Refresh Token"));

        // Reuse detection logic
        if (existingToken.isRevoked() || existingToken.getExpiresAt().isBefore(Instant.now())) {
            refreshTokenRepository.deleteByFamilyId(existingToken.getFamilyId());
            throw new SecurityException("Refresh token reuse detected. Revoking token family for security.");
        }

        // Revoke current token
        existingToken.setRevoked(true);
        refreshTokenRepository.save(existingToken);

        // Issue new token preserving the family chain
        return createRefreshToken(existingToken.getUsername(), existingToken.getFamilyId());
    }

    @Transactional
    public void revokeTokenAndFamily(String rawRefreshToken) {
        if (rawRefreshToken == null || rawRefreshToken.isBlank()) {
            return;
        }
        String tokenHash = hashToken(rawRefreshToken);
        Optional<RefreshTokenEntity> tokenOpt = refreshTokenRepository.findByTokenHash(tokenHash);
        if (tokenOpt.isPresent()) {
            RefreshTokenEntity tokenEntity = tokenOpt.get();
            tokenEntity.setRevoked(true);
            refreshTokenRepository.save(tokenEntity);
            if (tokenEntity.getFamilyId() != null) {
                refreshTokenRepository.deleteByFamilyId(tokenEntity.getFamilyId());
            }
        }
    }

    public String hashToken(String rawToken) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] encodedhash = digest.digest(rawToken.getBytes(StandardCharsets.UTF_8));
            return Base64.getEncoder().encodeToString(encodedhash);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("SHA-256 algorithm not found for token hashing", e);
        }
    }

    private String generateSecureTokenString() {
        byte[] randomBytes = new byte[64];
        secureRandom.nextBytes(randomBytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(randomBytes);
    }

}
