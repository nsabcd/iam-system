package com.iam.crypto.controller;

import com.iam.crypto.service.KeyManagementService;
import com.nimbusds.jose.jwk.JWKSet;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

@RestController
@RequestMapping("/.well-known")
public class JwksController {
    private final KeyManagementService keyManagementService;
    public JwksController(KeyManagementService keyManagementService){
        this.keyManagementService=keyManagementService;
    }

    @GetMapping("/jwks.json")
    public Map<String, Object> getJwks(){
        JWKSet jwkSet = new JWKSet(keyManagementService.getRsaKey().toPublicJWK());
        return jwkSet.toJSONObject();
    }
}
