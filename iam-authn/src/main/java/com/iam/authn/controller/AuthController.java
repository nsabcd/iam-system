package com.iam.authn.controller;

import com.iam.authn.dto.*;
import com.iam.authn.service.AuthenticationService;
import com.iam.authn.service.OAuth2Service;
import com.iam.common.dto.ApiResponse;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

@RestController
@RequestMapping("/auth")
public class AuthController {
    private final AuthenticationService authenticationService;
    private final OAuth2Service oauth2Service;

    public AuthController(AuthenticationService authenticationService,
                          OAuth2Service oauth2Service) {
        this.authenticationService = authenticationService;
        this.oauth2Service=oauth2Service;
    }

    @PostMapping("/login")
    public ResponseEntity<ApiResponse<String>> login(@Valid @RequestBody LoginRequest request){
        String token = authenticationService.authenticateAndGenerateToken(request.userName(), request.password());
        return ResponseEntity.ok(ApiResponse.success(token, "Authentication successful"));
    }

    @PostMapping("/register")
    public ResponseEntity<ApiResponse<UserResponse>> register(@Valid @RequestBody RegisterRequest request){
        UserResponse response = authenticationService.registerUser(request);
        return ResponseEntity.status(HttpStatus.CREATED)
                .body(ApiResponse.success(response, "User registered successfully"));

    }

    @PostMapping("password/forgot")
    public ResponseEntity<ApiResponse<Map<String, String>>> forgotPassword(@Valid @RequestBody ForgotPasswordRequest request){
        String resetToken = authenticationService.initiatePasswordReset(request.email());
        Map<String, String> data = Map.of("reset_token", resetToken);
        return ResponseEntity.ok(ApiResponse.success(data, "Password recovery token generated and dispatched"));
    }

    @PostMapping("/password/reset")
    public ResponseEntity<ApiResponse<Void>> resetPassword(@Valid @RequestBody ResetPasswordRequest request) {
        authenticationService.resetPassword(request.token(), request.newPassword());
        return ResponseEntity.ok(ApiResponse.success(null, "Password reset successfully"));
    }

    @PostMapping("/refresh")
    public ResponseEntity<ApiResponse<Map<String, Object>>> refreshToken(@Valid @RequestBody RefreshTokenRequest request) {
        Map<String, Object> tokenResponse = oauth2Service.rotateRefreshToken(request.refreshToken());
        return ResponseEntity.ok(ApiResponse.success(tokenResponse, "Access token refreshed successfully"));
    }

    @PostMapping("/logout")
    public ResponseEntity<ApiResponse<Void>> logout(HttpServletRequest request,
                                                    @RequestBody(required = false) LogoutRequest logoutRequest) {
        String authHeader = request.getHeader(HttpHeaders.AUTHORIZATION);
        String refreshToken = logoutRequest != null ? logoutRequest.refreshToken() : null;

        authenticationService.logout(authHeader, refreshToken);
        return ResponseEntity.ok(ApiResponse.success(null, "Logout successful"));
    }
}
