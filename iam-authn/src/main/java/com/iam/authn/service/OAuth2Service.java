package com.iam.authn.service;

import com.iam.authn.util.PkceUtil;
import com.iam.crypto.service.KeyManagementService;
import com.iam.directory.model.AuthorizationCodeEntity;
import com.iam.directory.model.RefreshTokenEntity;
import com.iam.directory.model.ServicePrincipalEntity;
import com.iam.directory.model.UserEntity;
import com.iam.directory.repository.AuthorizationCodeRepository;
import com.iam.directory.repository.RefreshTokenRepository;
import com.iam.directory.repository.ServicePrincipalRepository;
import com.iam.directory.repository.UserRepository;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import jakarta.transaction.Transactional;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.*;

@Service
public class OAuth2Service {
    private final AuthorizationCodeRepository codeRepository;
    private final UserRepository userRepository;
    private final KeyManagementService keyManagementService;
    private final ServicePrincipalRepository servicePrincipalRepository;
    private final PasswordEncoder passwordEncoder ;
    private final SecureRandom secureRandom = new SecureRandom();
    private final RefreshTokenRepository refreshTokenRepository;
    private static final long REFRESH_TOKEN_VALIDITY_DAYS = 365;

    public OAuth2Service(AuthorizationCodeRepository codeRepository,
                         UserRepository userRepository,
                         KeyManagementService keyManagementService,
                         ServicePrincipalRepository servicePrincipalRepository,
                         RefreshTokenRepository refreshTokenRepository,
                         PasswordEncoder passwordEncoder) {
        this.codeRepository = codeRepository;
        this.userRepository = userRepository;
        this.keyManagementService = keyManagementService;
        this.servicePrincipalRepository = servicePrincipalRepository;
        this.refreshTokenRepository=refreshTokenRepository;
        this.passwordEncoder=passwordEncoder;
    }

    public String generateAuthorizationCode(String username, String clientId, String redirectUri, String codeChallenge, String codeChallengeMethod){
        AuthorizationCodeEntity codeEntity = new AuthorizationCodeEntity();
        codeEntity.setCode(UUID.randomUUID().toString());
        codeEntity.setUsername(username);
        codeEntity.setClientId(clientId);
        codeEntity.setRedirectUri(redirectUri);
        codeEntity.setCodeChallenge(codeChallenge);
        codeEntity.setCodeChallengeMethod(codeChallengeMethod);
        codeEntity.setExpiresAt(Instant.now().plusSeconds(120));
        codeRepository.save(codeEntity);
        return codeEntity.getCode();
    }

    @Transactional
    public Map<String, Object> exchangeCodeForToken(String code, String clientId, String redirectUri, String codeVerifier){
        AuthorizationCodeEntity authCode = codeRepository.findByCode(code)
                .orElseThrow(() -> new IllegalArgumentException("Invalid authorization code"));
        if(authCode.isUsed() || authCode.getExpiresAt().isBefore(Instant.now())){
            throw new IllegalStateException("Authorization code is expired or already used");
        }
        if(!authCode.getClientId().equals(clientId) || !authCode.getRedirectUri().equals(redirectUri)){
            throw new IllegalArgumentException("Client ID or Redirect URI mismatch");
        }

        if(!PkceUtil.verifyCodeVerifier(codeVerifier, authCode.getCodeChallenge(), authCode.getCodeChallengeMethod())){
            throw new IllegalArgumentException("Invalid PKCE code verifier");
        }

        authCode.setUsed(true);
        codeRepository.save(authCode);

        UserEntity user = userRepository.findByUsername(authCode.getUsername())
                .orElseThrow(() -> new IllegalStateException("User not found"));

        try{
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

            // Generate and store refresh token with family tracking
            String familyId = UUID.randomUUID().toString();
            String rawRefreshToken = generateSecureTokenString();
            String tokenHash = hashToken(rawRefreshToken);;

            RefreshTokenEntity refreshTokenEntity = new RefreshTokenEntity();
            refreshTokenEntity.setTokenHash(tokenHash);
            refreshTokenEntity.setUsername(user.getUsername());
            refreshTokenEntity.setFamilyId(familyId);
            refreshTokenEntity.setRevoked(false);
            refreshTokenEntity.setExpiresAt(now.plus(REFRESH_TOKEN_VALIDITY_DAYS, ChronoUnit.DAYS));
            refreshTokenRepository.save(refreshTokenEntity);

            Map<String, Object> response = new HashMap<>();
            response.put("access_token",signedJWT.serialize());
            response.put("token_type", "Bearer");
            response.put("expires_in", 3600);
            response.put("refresh_token", rawRefreshToken);
            return response;
        }catch (Exception e){
            throw new IllegalStateException("Failed to generate tokens during code exchange", e);
        }

    }

    public Map<String, Object> issueClientCredentialsToken(String clientId, String clientSecret){
        ServicePrincipalEntity principal = servicePrincipalRepository.findByClientId(clientId)
                .orElseThrow(() -> new IllegalArgumentException("Invalid client ID"));

        if(!principal.isActive() || !passwordEncoder.matches(clientSecret, principal.getClientSecretHash())){
            throw new IllegalArgumentException("Invalid client credentials");
        }

        try{
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
        }catch (Exception e){
            throw new IllegalStateException("Falied to generate M2M token", e);
        }
    }

    @Transactional
    public Map<String, Object> rotateRefreshToken(String rawRefreshToken){
        String incomingHash = hashToken(rawRefreshToken);
        RefreshTokenEntity existingToken = refreshTokenRepository.findByTokenHash(incomingHash)
                .orElseThrow(() -> new IllegalArgumentException("Invalid Refresh Token"));
        if(existingToken.isRevoked() || existingToken.getExpiresAt().isBefore(Instant.now())){
            refreshTokenRepository.deleteByFamilyId(existingToken.getFamilyId());
            throw new SecurityException("Refresh token reuse detected. Revoking token family for security.");
        }

        // Revoke the current token
        existingToken.setRevoked(true);
        // Issue new token in the same family chain
        String newRawToken = generateSecureTokenString();
        String newHash = hashToken(newRawToken);
        RefreshTokenEntity newTokenEntity = new RefreshTokenEntity();
        newTokenEntity.setTokenHash(newHash);
        newTokenEntity.setUsername(existingToken.getUsername());
        newTokenEntity.setFamilyId(existingToken.getFamilyId());
        newTokenEntity.setRevoked(false);
        newTokenEntity.setExpiresAt(Instant.now().plus(REFRESH_TOKEN_VALIDITY_DAYS, ChronoUnit.DAYS));
        refreshTokenRepository.save(newTokenEntity);

        // Fetch user info to construct a fresh access token
        UserEntity user = userRepository.findByUsername(existingToken.getUsername())
                .orElseThrow(() -> new IllegalStateException("User not found"));

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

            Map<String, Object> response = new HashMap<>();
            response.put("access_token", signedJWT.serialize());
            response.put("token_type", "Bearer");
            response.put("expires_in", 3600);
            response.put("refresh_token", newRawToken);
            return response;
        }catch (Exception e){
            throw new IllegalStateException("Failed to generate tokens during refresh rotation", e);
        }
    }

    private String generateSecureTokenString() {
        byte[] randomBytes = new byte[64];
        secureRandom.nextBytes(randomBytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(randomBytes);
    }

    private String hashToken(String rawToken) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] encodedhash = digest.digest(rawToken.getBytes(StandardCharsets.UTF_8));
            return Base64.getEncoder().encodeToString(encodedhash);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("SHA-256 algorithm not found for token hashing", e);
        }
    }

}
