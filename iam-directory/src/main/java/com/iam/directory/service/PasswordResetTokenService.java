package com.iam.directory.service;

import com.iam.directory.model.PasswordResetTokenEntity;
import com.iam.directory.repository.PasswordResetTokenRepository;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.UUID;

@Service
public class PasswordResetTokenService {
    private final PasswordResetTokenRepository repository;

    public PasswordResetTokenService(PasswordResetTokenRepository repository) {
        this.repository = repository;
    }

    @Transactional
    public String createTokenForUser(String username) {
        repository.deleteByUsername(username); // Clean up existing active tokens

        String rawToken = UUID.randomUUID().toString();
        PasswordResetTokenEntity entity = new PasswordResetTokenEntity();
        entity.setToken(rawToken);
        entity.setUsername(username);
        entity.setExpiresAt(Instant.now().plus(15, ChronoUnit.MINUTES));
        entity.setUsed(false);

        repository.save(entity);
        return rawToken;
    }

    @Transactional
    public String validateAndConsumeToken(String token) {
        PasswordResetTokenEntity tokenEntity = repository.findByToken(token)
                .orElseThrow(() -> new IllegalArgumentException("Invalid or expired password reset token"));

        if (tokenEntity.isUsed() || tokenEntity.getExpiresAt().isBefore(Instant.now())) {
            throw new IllegalStateException("Password reset token is expired or has already been used");
        }

        tokenEntity.setUsed(true);
        repository.save(tokenEntity);
        return tokenEntity.getUsername();
    }
}
