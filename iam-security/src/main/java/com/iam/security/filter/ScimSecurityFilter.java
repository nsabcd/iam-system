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
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import jakarta.servlet.*;

import java.util.Arrays;
import java.util.List;

import java.io.IOException;
import java.util.stream.Collectors;

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
                String scopesStr = (String) claims.getClaim("scope");

                List<String> scopes = scopesStr != null ? Arrays.asList(scopesStr.split(" ")) : List.of();
                boolean isAdminScoped = scopes.contains("admin") || scopes.contains("admin:scim");

                if(!"m2m".equals(tokenType) || (scopes==null || !isAdminScoped)){
                    writeUnauthorized(httpResponse, "Insufficient privileges or invalid M2M token type");
                    return;
                }
                // FIX: Populate Spring SecurityContext so downstream authorization manager accepts the request
                List<SimpleGrantedAuthority> authorities = scopes.stream()
                        .map(s -> new SimpleGrantedAuthority("SCOPE_" + s))
                        .collect(Collectors.toList());

                UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(
                        claims.getSubject(), null, authorities
                );
                SecurityContextHolder.getContext().setAuthentication(authentication);

            } catch (Exception e) {
                writeUnauthorized(httpResponse, "Token validation failed: " + e.getMessage());
                return;
            }
        }
        try {
            chain.doFilter(request, response);
        } finally {
            // Clean up context to avoid leaks across thread pools
            SecurityContextHolder.clearContext();
        }

    }
    private void writeUnauthorized(HttpServletResponse response, String message) throws IOException{
        response.setStatus(401);
        response.setContentType("application/json");
        response.getWriter().write("{\"success\":false,\"message\":\"" + message + "\",\"errorCode\":\"UNAUTHORIZED_SCIM_ACCESS\"}");
    }
}
