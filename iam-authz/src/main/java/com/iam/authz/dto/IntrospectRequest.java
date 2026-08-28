package com.iam.authz.dto;

import jakarta.validation.constraints.NotBlank;

public record IntrospectRequest(
        @NotBlank
        String token
) {
}
