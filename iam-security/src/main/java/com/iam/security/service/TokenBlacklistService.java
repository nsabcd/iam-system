package com.iam.security.service;

import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Service;

import java.time.Duration;

@Service
public class TokenBlacklistService {
    private final StringRedisTemplate redisTemplate;
    private static final String BLACKLIST_PREFIX = "blacklist:token:";

    public TokenBlacklistService(StringRedisTemplate redisTemplate) {
        this.redisTemplate = redisTemplate;
    }

    public void blacklistToken(String tokenSignature, Duration ttl) {
        redisTemplate.opsForValue().set(BLACKLIST_PREFIX + tokenSignature, "revoked", ttl);
    }

    public boolean isBlacklisted(String tokenSignature) {
        return Boolean.TRUE.equals(redisTemplate.hasKey(BLACKLIST_PREFIX + tokenSignature));
    }
}
