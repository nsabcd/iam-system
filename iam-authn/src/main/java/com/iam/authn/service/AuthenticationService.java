package com.iam.authn.service;

import com.iam.crypto.service.KeyManagementService;
import com.iam.directory.model.UserEntity;
import com.iam.directory.repository.UserRepository;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.Date;
import java.util.Optional;

@Service
public class AuthenticationService {
    private final UserRepository userRepository;
    private final KeyManagementService keyManagementService;
    private final PasswordEncoder passwordEncoder;

    public AuthenticationService(UserRepository userRepository, KeyManagementService keyManagementService, PasswordEncoder passwordEncoder){
        this.userRepository=userRepository;
        this.keyManagementService=keyManagementService;
        this.passwordEncoder=passwordEncoder;
    }

    public String authenticateAndGenerateToken(String userName, String rawPassword){
        Optional<UserEntity> userOpt = userRepository.findByUsername(userName);
        if(userOpt.isEmpty() || !passwordEncoder.matches(rawPassword, userOpt.get().getPasswordHash())){
            throw new IllegalArgumentException("Invalid username or password");
        }
        UserEntity user = userOpt.get();
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
            return signedJWT.serialize();
        }catch (Exception e){
            throw new IllegalStateException("Failed to generate authentication token", e);
        }

    }
}
