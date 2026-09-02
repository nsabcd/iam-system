package com.iam.directory.service;

import com.iam.directory.util.PkceUtil;
import com.iam.directory.model.AuthorizationCodeEntity;
import com.iam.directory.repository.AuthorizationCodeRepository;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.UUID;

@Service
public class AuthorizationCodeService {

    private final AuthorizationCodeRepository codeRepository;
    private static final long CODE_VALIDITY_SECONDS = 120;

    public AuthorizationCodeService(AuthorizationCodeRepository codeRepository) {
        this.codeRepository = codeRepository;
    }

    @Transactional
    public String createAuthorizationCode(String username, String clientId, String redirectUri,
                                          String codeChallenge, String codeChallengeMethod) {
        AuthorizationCodeEntity codeEntity = new AuthorizationCodeEntity();
        codeEntity.setCode(UUID.randomUUID().toString());
        codeEntity.setUsername(username);
        codeEntity.setClientId(clientId);
        codeEntity.setRedirectUri(redirectUri);
        codeEntity.setCodeChallenge(codeChallenge);
        codeEntity.setCodeChallengeMethod(codeChallengeMethod);
        codeEntity.setExpiresAt(Instant.now().plusSeconds(CODE_VALIDITY_SECONDS));

        codeRepository.save(codeEntity);
        return codeEntity.getCode();
    }

    @Transactional
    public AuthorizationCodeEntity consumeAndValidateCode(String code, String clientId,
                                                          String redirectUri, String codeVerifier) {
        AuthorizationCodeEntity authCode = codeRepository.findByCode(code)
                .orElseThrow(() -> new IllegalArgumentException("Invalid authorization code"));

        if (authCode.isUsed() || authCode.getExpiresAt().isBefore(Instant.now())) {
            throw new IllegalStateException("Authorization code is expired or already used");
        }
        if (!authCode.getClientId().equals(clientId) || !authCode.getRedirectUri().equals(redirectUri)) {
            throw new IllegalArgumentException("Client ID or Redirect URI mismatch");
        }

        if (!PkceUtil.verifyCodeVerifier(codeVerifier, authCode.getCodeChallenge(), authCode.getCodeChallengeMethod())) {
            throw new IllegalArgumentException("Invalid PKCE code verifier");
        }

        // Mark code as consumed immediately to prevent replay attacks
        authCode.setUsed(true);
        return codeRepository.save(authCode);
    }
}