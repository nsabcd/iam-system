package com.iam.crypto.service;

import jakarta.annotation.PostConstruct;
import org.springframework.stereotype.Service;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import com.nimbusds.jose.jwk.RSAKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.UUID;

@Service
public class KeyManagementService {
    private RSAKey rsaKey;

    public String getKeyId() {
        return keyId;
    }

    public RSAKey getRsaKey() {
        return rsaKey;
    }

    private String keyId;

    @PostConstruct
    public void init(){
        generateNewRsaKey();
    }

    public void generateNewRsaKey(){
        try{
            KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
            generator.initialize(2048);
            KeyPair keyPair = generator.generateKeyPair();
            RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
            RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();
            this.keyId = UUID.randomUUID().toString();
            this.rsaKey = new RSAKey.Builder(publicKey)
                    .privateKey(privateKey)
                    .keyID(keyId)
                    .build();
        }catch (Exception e){
            throw new IllegalStateException("Failed to generate RSA key pair for token signing", e);
        }
    }
}
