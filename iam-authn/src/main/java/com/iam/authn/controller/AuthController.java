package com.iam.authn.controller;

import com.iam.authn.dto.LoginRequest;
import com.iam.authn.service.AuthenticationService;
import com.iam.common.dto.ApiResponse;
import jakarta.validation.Valid;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/auth")
public class AuthController {
    private final AuthenticationService authenticationService;

    public AuthController(AuthenticationService authenticationService) {
        this.authenticationService = authenticationService;
    }

    @PostMapping("/login")
    public ResponseEntity<ApiResponse<String>> login(@Valid @RequestBody LoginRequest request){
        String token = authenticationService.authenticateAndGenerateToken(request.userName(), request.password());
        return ResponseEntity.ok(ApiResponse.success(token, "Authentication successful"));
    }
}
