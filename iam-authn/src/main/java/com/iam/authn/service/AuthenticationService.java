package com.iam.authn.service;

import com.iam.authn.dto.RegisterRequest;
import com.iam.authn.dto.UserResponse;
import com.iam.crypto.service.KeyManagementService;
import com.iam.directory.model.UserEntity;
import com.iam.directory.service.AccessRevocationService;
import com.iam.directory.service.PasswordResetTokenService;
import com.iam.directory.service.RefreshTokenService;
import com.iam.directory.service.UserService;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import jakarta.transaction.Transactional;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.Date;

@Service
public class AuthenticationService {

    private final UserService userService;
    private final PasswordResetTokenService passwordResetTokenService;
    private final RefreshTokenService refreshTokenService;
    private final AccessRevocationService accessRevocationService;
    private final KeyManagementService keyManagementService;

    public AuthenticationService(UserService userService,
                                 PasswordResetTokenService passwordResetTokenService,
                                 RefreshTokenService refreshTokenService,
                                 AccessRevocationService accessRevocationService,
                                 KeyManagementService keyManagementService) {
        this.userService = userService;
        this.passwordResetTokenService = passwordResetTokenService;
        this.refreshTokenService = refreshTokenService;
        this.accessRevocationService = accessRevocationService;
        this.keyManagementService = keyManagementService;
    }

    public String authenticateAndGenerateToken(String userName, String rawPassword) {
        UserEntity user = userService.validateCredentials(userName, rawPassword);
        try {
            JWSSigner signer = new RSASSASigner(keyManagementService.getRsaKey().toRSAPrivateKey());
            Instant now = Instant.now();

            JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
                    .subject(user.getId().toString())
                    .issuer("iam-system")
                    .issueTime(Date.from(now))
                    .expirationTime(Date.from(now.plusSeconds(3600)))
                    .claim("username", user.getUsername())
                    .claim("email", user.getEmail())
                    .build();

            SignedJWT signedJWT = new SignedJWT(
                    new JWSHeader.Builder(JWSAlgorithm.RS256).keyID(keyManagementService.getKeyId()).build(),
                    claimsSet
            );

            signedJWT.sign(signer);
            return signedJWT.serialize();
        } catch (Exception e) {
            throw new IllegalStateException("Failed to generate authentication token", e);
        }
    }

    @Transactional
    public UserResponse registerUser(RegisterRequest request) {
        UserEntity savedUser = userService.createUser(request.username(), request.email(), request.password());
        return new UserResponse(
                savedUser.getId(),
                savedUser.getUsername(),
                savedUser.getEmail(),
                savedUser.isActive(),
                savedUser.getCreatedAt()
        );
    }

    @Transactional
    public String initiatePasswordReset(String email) {
        UserEntity user = userService.getByEmail(email);
        return passwordResetTokenService.createTokenForUser(user.getUsername());
    }

    @Transactional
    public void resetPassword(String token, String newPassword) {
        String userName = passwordResetTokenService.validateAndConsumeToken(token);
        if (userName != null && !userName.isBlank()) {
            userService.updatePassword(userName, newPassword);
        }
    }

    @Transactional
    public void logout(String authHeader, String rawRefreshToken) {
        if (authHeader != null && authHeader.startsWith("Bearer ")) {
            accessRevocationService.revokeAccessToken(authHeader.substring(7));
        }
        if (rawRefreshToken != null && !rawRefreshToken.isBlank()) {
            refreshTokenService.revokeTokenAndFamily(rawRefreshToken);
        }
    }
}