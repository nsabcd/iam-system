package com.iam.authz.dto;

import jakarta.validation.constraints.NotBlank;

public record RevokeRequest(
        @NotBlank(message = "Token is required")
        String token
) {
}
