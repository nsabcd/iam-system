package com.iam.authn.dto;

import jakarta.validation.constraints.NotBlank;

public record LoginRequest (
        @NotBlank(message = "User name is required")
        String userName,

        @NotBlank(message = "Password is required")
        String password
) {
}
