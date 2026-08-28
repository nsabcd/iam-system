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
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.Date;
import java.util.Optional;

@Service
public class AuthenticationService {
    private final UserRepository userRepository;
    private final KeyManagementService keyManagementService;
    private final BCryptPasswordEncoder bCryptPasswordEncoder = new BCryptPasswordEncoder();

    public AuthenticationService(UserRepository userRepository, KeyManagementService keyManagementService){
        this.userRepository=userRepository;
        this.keyManagementService=keyManagementService;
    }

    public String authenticateAndGenerateToken(String userName, String rawPassword){
        Optional<UserEntity> userOpt = userRepository.findByUsername(userName);
        if(userOpt.isEmpty() || !bCryptPasswordEncoder.matches(rawPassword, userOpt.get().getPasswordHash())){
            throw new IllegalArgumentException("Invalid username of password");
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
