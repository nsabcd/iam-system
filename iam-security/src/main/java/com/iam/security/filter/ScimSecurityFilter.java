package com.iam.security.filter;

import com.iam.crypto.service.KeyManagementService;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.proc.JWSVerificationKeySelector;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.proc.DefaultJWTProcessor;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.stereotype.Component;
import jakarta.servlet.*;

import java.io.IOException;

@Component
public class ScimSecurityFilter implements Filter{
    private final KeyManagementService keyManagementService;

    public ScimSecurityFilter(KeyManagementService keyManagementService) {
        this.keyManagementService = keyManagementService;
    }

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
            throws IOException, ServletException{
        HttpServletRequest httpRequest = (HttpServletRequest) request;
        HttpServletResponse httpResponse = (HttpServletResponse) response;

        String path = httpRequest.getRequestURI();

        // Target only SCIM provisioning routes
        if(path.startsWith("/scim/v2")){
            String authHeader = httpRequest.getHeader("Authorization");
            if(authHeader==null || !authHeader.startsWith("Bearer ")){
                writeUnauthorized(httpResponse, "Missing or invalid Authorization header");
                return;
            }
            String token = authHeader.substring(7);
            try{
                // Validate token signature and expiration locally
                var publicRsaKey = keyManagementService.getRsaKey().toPublicJWK();
                var jwkSet = new ImmutableJWKSet<>(new JWKSet(publicRsaKey));
                var jwtProcessor = new DefaultJWTProcessor<SecurityContext>();
                jwtProcessor.setJWSKeySelector(new JWSVerificationKeySelector<>(com.nimbusds.jose.JWSAlgorithm.RS256, jwkSet));
                JWTClaimsSet claims = jwtProcessor.process(token, null);
                // Verify that this is an M2M token with administrative/provisioning privileges
                String tokenType = (String) claims.getClaim("token_type");
                String scopes = (String) claims.getClaim("scope");
                if(!"m2m".equals(tokenType) || (scopes==null || !scopes.contains("admin"))){
                    writeUnauthorized(httpResponse, "Insufficient privileges or invalid M2M token type");
                    return;
                }

            } catch (Exception e) {
                writeUnauthorized(httpResponse, "Token validation failed: " + e.getMessage());
                return;
            }
        }

    }
    private void writeUnauthorized(HttpServletResponse response, String message) throws IOException{
        response.setStatus(401);
        response.setContentType("application/json");
        response.getWriter().write("{\"success\":false,\"message\":\"" + message + "\",\"errorCode\":\"UNAUTHORIZED_SCIM_ACCESS\"}");
    }
}
