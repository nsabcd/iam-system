package com.iam.authn.dto;

import java.time.Instant;
import java.util.UUID;

public record UserResponse(
        UUID id,
        String username,
        String email,
        boolean active,
        Instant createdAt
) {
}