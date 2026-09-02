package com.iam.authn.controller;

import com.iam.authn.service.OAuth2Service;
import com.iam.common.dto.ApiResponse;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

@RestController
@RequestMapping("/oauth2")
public class OAuth2Controller {
    private final OAuth2Service oauth2Service;

    public OAuth2Controller(OAuth2Service oAuth2Service) {
        this.oauth2Service = oAuth2Service;
    }

    @GetMapping("/authorize")
    public ResponseEntity<ApiResponse<String>> authorize(
            @RequestParam("client_id") String clientId,
            @RequestParam("redirect_uri") String redirectUri,
            @RequestParam("response_type") String responseType,
            @RequestParam("code_challenge") String codeChallenge,
            @RequestParam(value = "code_challenge_method", defaultValue = "S256") String codeChallengeMethod,
            @RequestParam("username") String username
    ){
        if(!"code".equals(responseType)){
            return ResponseEntity.badRequest().body(ApiResponse.error("Unsupported response_type", "INVALID_RESPONSE_TYPE"));
        }
        String authCode = oauth2Service.generateAuthorizationCode(username, clientId, redirectUri, codeChallenge, codeChallengeMethod);
        return ResponseEntity.ok(ApiResponse.success(authCode, "Authorization code generated successfully"));
    }

    @PostMapping("/token")
    public ResponseEntity<ApiResponse<Map<String, Object>>> token(
            @RequestParam("grant_type") String grantType,
            @RequestParam("client_id") String clientId,
            @RequestParam(value = "client_secret", required = false) String clientSecret,
            @RequestParam(value = "code", required = false) String code,
            @RequestParam(value = "redirect_uri", required = false) String redirectUri,
            @RequestParam(value = "code_verifier", required = false) String codeVerifier,
            @RequestParam(value = "refresh_token", required = false) String refreshToken
    ){
        if ("authorization_code".equals(grantType)) {
            Map<String, Object> tokenResponse = oauth2Service.exchangeCodeForToken(code, clientId, redirectUri, codeVerifier);
            return ResponseEntity.ok(ApiResponse.success(tokenResponse, "Token exchange successful"));
        } else if ("client_credentials".equals(grantType)) {
            Map<String, Object> tokenResponse = oauth2Service.issueClientCredentialsToken(clientId, clientSecret);
            return ResponseEntity.ok(ApiResponse.success(tokenResponse, "Client credentials token issued successfully"));
        }else if ("refresh_token".equals(grantType)) {
            Map<String, Object> tokenResponse = oauth2Service.rotateRefreshToken(refreshToken);
            return ResponseEntity.ok(ApiResponse.success(tokenResponse, "Token refreshed successfully"));
        }

        return ResponseEntity.badRequest().body(ApiResponse.error("Unsupported grant_type", "UNSUPPORTED_GRANT_TYPE"));
    }
}
