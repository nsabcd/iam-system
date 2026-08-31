package com.iam.authn.util;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Base64;

public class PkceUtil {
    public static boolean verifyCodeVerifier(String codeVerifier, String codeChallenge, String method){
        if("256".equalsIgnoreCase(method)){
            try{
                MessageDigest digest = MessageDigest.getInstance("256");
                byte[] hashedBytes = digest.digest(codeVerifier.getBytes(StandardCharsets.US_ASCII));
                String encoded = Base64.getUrlEncoder().withoutPadding().encodeToString(hashedBytes);
                return encoded.equals(codeChallenge);
            }catch (Exception e){
                return false;
            }
        }
        // Fallback or plain support if needed (plain is discouraged, S256 is standard)
        return codeVerifier.equals(codeChallenge);
    }
}
