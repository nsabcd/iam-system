package com.iam.authn.service;

import com.iam.authn.util.PkceUtil;
import com.iam.crypto.service.KeyManagementService;
import com.iam.directory.model.AuthorizationCodeEntity;
import com.iam.directory.model.ServicePrincipalEntity;
import com.iam.directory.model.UserEntity;
import com.iam.directory.repository.AuthorizationCodeRepository;
import com.iam.directory.repository.ServicePrincipalRepository;
import com.iam.directory.repository.UserRepository;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.produce.JWSSignerFactory;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.*;

@Service
public class OAuth2Service {
    private final AuthorizationCodeRepository codeRepository;
    private final UserRepository userRepository;
    private final KeyManagementService keyManagementService;
    private final ServicePrincipalRepository servicePrincipalRepository;
    private final BCryptPasswordEncoder bCryptPasswordEncoder = new BCryptPasswordEncoder();

    public OAuth2Service(AuthorizationCodeRepository codeRepository, UserRepository userRepository, KeyManagementService keyManagementService, ServicePrincipalRepository servicePrincipalRepository) {
        this.codeRepository = codeRepository;
        this.userRepository = userRepository;
        this.keyManagementService = keyManagementService;
        this.servicePrincipalRepository = servicePrincipalRepository;
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
            Map<String, Object> response = new HashMap<>();
            response.put("access_token",signedJWT.serialize());
            response.put("token_type", "Bearer");
            response.put("expires_in", 3600);
            return response;
        }catch (Exception e){
            throw new IllegalStateException("Failed to generate tokens during code exchange", e);
        }

    }

    public Map<String, Object> issueClientCredentialsToken(String clientId, String clientSecret){
        ServicePrincipalEntity principal = servicePrincipalRepository.findByClientId(clientId)
                .orElseThrow(() -> new IllegalArgumentException("Invalid client ID"));

        if(!principal.isActive() || !bCryptPasswordEncoder.matches(clientSecret, principal.getClientSecretHash())){
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
}
