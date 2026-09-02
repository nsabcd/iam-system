package com.iam.authn.dto;

public record LogoutRequest(
        String refreshToken
) {
}