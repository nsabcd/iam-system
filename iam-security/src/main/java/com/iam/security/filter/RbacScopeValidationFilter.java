package com.iam.security.filter;

import com.iam.crypto.service.KeyManagementService;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.proc.JWSVerificationKeySelector;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.proc.DefaultJWTProcessor;
import jakarta.servlet.*;
import org.springframework.stereotype.Component;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import java.io.IOException;
import java.util.List;

@Component
public class RbacScopeValidationFilter implements Filter{
    private final KeyManagementService keyManagementService;

    public RbacScopeValidationFilter(KeyManagementService keyManagementService) {
        this.keyManagementService = keyManagementService;
    }

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
            throws IOException, ServletException{
        HttpServletRequest httpRequest = (HttpServletRequest) request;
        HttpServletResponse httpResponse = (HttpServletResponse) response;
        String path = httpRequest.getRequestURI();
        // Enforce RBAC/Scope requirements for API data endpoints
        if (path.startsWith("/api/v1/secure")) {
            String authHeader = httpRequest.getHeader("Authorization");
            if (authHeader == null || !authHeader.startsWith("Bearer ")) {
                writeForbidden(httpResponse, "Missing or invalid Authorization header");
                return;
            }
            String token = authHeader.substring(7);
            try {
                var publicKey = keyManagementService.getRsaKey().toPublicJWK();
                var jwkSet = new ImmutableJWKSet<>(new JWKSet(publicKey));
                var jwtProcessor = new DefaultJWTProcessor<SecurityContext>();
                jwtProcessor.setJWSKeySelector(new JWSVerificationKeySelector<>(com.nimbusds.jose.JWSAlgorithm.RS256, jwkSet));
                JWTClaimsSet claims = jwtProcessor.process(token, null);

                // Example RBAC check: Ensure user or service has required role/scope
                List<String> roles = (List<String>) claims.getClaim("roles");
                String scopes = (String) claims.getClaim("scope");

                if ((roles == null || !roles.contains("ROLE_ADMIN")) && (scopes == null || !scopes.contains("api:write"))) {
                    writeForbidden(httpResponse, "Insufficient scope or role permissions");
                    return;
                }
            } catch (Exception e) {
                writeForbidden(httpResponse, "Token validation failed: " + e.getMessage());
                return;
            }
        }
        chain.doFilter(request, response);

    }
    private void writeForbidden(HttpServletResponse response, String message) throws IOException {
        response.setStatus(403);
        response.setContentType("application/json");
        response.getWriter().write("{\"success\":false,\"message\":\"" + message + "\",\"errorCode\":\"FORBIDDEN_ACCESS\"}");
    }
}
