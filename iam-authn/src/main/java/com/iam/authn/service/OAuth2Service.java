package com.iam.authn.service;

import com.iam.crypto.service.KeyManagementService;
import com.iam.directory.model.AuthorizationCodeEntity;
import com.iam.directory.model.ServicePrincipalEntity;
import com.iam.directory.model.UserEntity;
import com.iam.directory.repository.ServicePrincipalRepository;
import com.iam.directory.service.AuthorizationCodeService;
import com.iam.directory.service.RefreshTokenService;
import com.iam.directory.service.RefreshTokenService.IssuedRefreshToken;
import com.iam.directory.service.UserService;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import jakarta.transaction.Transactional;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.*;

@Service
public class OAuth2Service {

    private final AuthorizationCodeService authorizationCodeService;
    private final UserService userService;
    private final KeyManagementService keyManagementService;
    private final ServicePrincipalRepository servicePrincipalRepository;
    private final PasswordEncoder passwordEncoder;
    private final RefreshTokenService refreshTokenService;

    public OAuth2Service(AuthorizationCodeService authorizationCodeService,
                         UserService userService,
                         KeyManagementService keyManagementService,
                         ServicePrincipalRepository servicePrincipalRepository,
                         RefreshTokenService refreshTokenService,
                         PasswordEncoder passwordEncoder) {
        this.authorizationCodeService = authorizationCodeService;
        this.userService = userService;
        this.keyManagementService = keyManagementService;
        this.servicePrincipalRepository = servicePrincipalRepository;
        this.refreshTokenService = refreshTokenService;
        this.passwordEncoder = passwordEncoder;
    }

    public String generateAuthorizationCode(String username, String clientId, String redirectUri,
                                            String codeChallenge, String codeChallengeMethod) {
        return authorizationCodeService.createAuthorizationCode(
                username, clientId, redirectUri, codeChallenge, codeChallengeMethod
        );
    }

    @Transactional
    public Map<String, Object> exchangeCodeForToken(String code, String clientId, String redirectUri, String codeVerifier) {
        AuthorizationCodeEntity authCode = authorizationCodeService.consumeAndValidateCode(
                code, clientId, redirectUri, codeVerifier
        );

        UserEntity user = userService.getByUsername(authCode.getUsername());

        try {
            String accessToken = generateAccessToken(user.getId().toString(), user.getUsername(), user.getEmail());
            IssuedRefreshToken newRefreshToken = refreshTokenService.createRefreshToken(user.getUsername(), null);

            Map<String, Object> response = new HashMap<>();
            response.put("access_token", accessToken);
            response.put("token_type", "Bearer");
            response.put("expires_in", 3600);
            response.put("refresh_token", newRefreshToken.rawToken());
            return response;
        } catch (Exception e) {
            throw new IllegalStateException("Failed to generate tokens during code exchange", e);
        }
    }

    public Map<String, Object> issueClientCredentialsToken(String clientId, String clientSecret) {
        ServicePrincipalEntity principal = servicePrincipalRepository.findByClientId(clientId)
                .orElseThrow(() -> new IllegalArgumentException("Invalid client ID"));

        if (!principal.isActive() || !passwordEncoder.matches(clientSecret, principal.getClientSecretHash())) {
            throw new IllegalArgumentException("Invalid client credentials");
        }

        try {
            JWSSigner signer = new RSASSASigner(keyManagementService.getRsaKey().toRSAPrivateKey());
            Instant now = Instant.now();
            JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
                    .subject(principal.getId().toString())
                    .issuer("iam-system")
                    .issueTime(Date.from(now))
                    .expirationTime(Date.from(now.plusSeconds(3600)))
                    .claim("client_id", principal.getClientId())
                    .claim("service_name", principal.getServiceName())
                    .claim("scope", principal.getAllowedScopes())
                    .claim("token_type", "m2m")
                    .build();

            SignedJWT signedJWT = new SignedJWT(
                    new JWSHeader.Builder(JWSAlgorithm.RS256).keyID(keyManagementService.getKeyId()).build(),
                    claimsSet
            );
            signedJWT.sign(signer);

            Map<String, Object> response = new HashMap<>();
            response.put("access_token", signedJWT.serialize());
            response.put("token_type", "Bearer");
            response.put("expires_in", 3600);
            response.put("scope", principal.getAllowedScopes());
            return response;
        } catch (Exception e) {
            throw new IllegalStateException("Failed to generate M2M token", e);
        }
    }

    @Transactional
    public Map<String, Object> rotateRefreshToken(String rawRefreshToken) {
        IssuedRefreshToken rotatedToken = refreshTokenService.rotateToken(rawRefreshToken);
        UserEntity user = userService.getByUsername(rotatedToken.entity().getUsername());

        try {
            String accessToken = generateAccessToken(user.getId().toString(), user.getUsername(), user.getEmail());

            Map<String, Object> response = new HashMap<>();
            response.put("access_token", accessToken);
            response.put("token_type", "Bearer");
            response.put("expires_in", 3600);
            response.put("refresh_token", rotatedToken.rawToken());
            return response;
        } catch (Exception e) {
            throw new IllegalStateException("Failed to generate tokens during refresh rotation", e);
        }
    }

    private String generateAccessToken(String subject, String username, String email) throws Exception {
        JWSSigner signer = new RSASSASigner(keyManagementService.getRsaKey().toRSAPrivateKey());
        Instant now = Instant.now();
        JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
                .subject(subject)
                .issuer("iam-system")
                .issueTime(Date.from(now))
                .expirationTime(Date.from(now.plusSeconds(3600)))
                .claim("username", username)
                .claim("email", email)
                .build();

        SignedJWT signedJWT = new SignedJWT(
                new JWSHeader.Builder(JWSAlgorithm.RS256).keyID(keyManagementService.getKeyId()).build(),
                claimsSet
        );
        signedJWT.sign(signer);
        return signedJWT.serialize();
    }
}