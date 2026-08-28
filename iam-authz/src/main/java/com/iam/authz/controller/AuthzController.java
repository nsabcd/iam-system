package com.iam.authz.controller;

import com.iam.authz.dto.IntrospectRequest;
import com.iam.authz.service.AuthorizationService;
import com.iam.common.dto.ApiResponse;
import jakarta.validation.Valid;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

@RestController
@RequestMapping("/authz")
public class AuthzController {
    private final AuthorizationService authorizationService;

    public AuthzController(AuthorizationService authorizationService) {
        this.authorizationService = authorizationService;
    }

    @PostMapping("/introspect")
    public ResponseEntity<ApiResponse<Map<String, Object>>> introspect(@Valid @RequestBody IntrospectRequest request){
        Map<String, Object> details = authorizationService.introspectToken(request.token());
        return ResponseEntity.ok(ApiResponse.success(details, "Token introspection complete"));
    }
}
