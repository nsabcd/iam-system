package com.iam.security.config;

import com.iam.security.filter.RbacScopeValidationFilter;
import com.iam.security.filter.ScimSecurityFilter;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
public class SecurityConfig {

    private final ScimSecurityFilter scimSecurityFilter;
    private final RbacScopeValidationFilter rbacScopeValidationFilter;

    public SecurityConfig(ScimSecurityFilter scimSecurityFilter, RbacScopeValidationFilter rbacScopeValidationFilter) {
        this.scimSecurityFilter = scimSecurityFilter;
        this.rbacScopeValidationFilter = rbacScopeValidationFilter;
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http.csrf(csrf -> csrf.disable())
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers(
                                "/.well-known/jwks.json",
                                "/.well-known/openid-configuration",
                                "/auth/**",
                                "/oauth2/token",
                                "/authz/introspect",
                                "/authz/revoke"
                        ).permitAll()
                        .anyRequest().authenticated()
                )
                .addFilterBefore(scimSecurityFilter, UsernamePasswordAuthenticationFilter.class)
                .addFilterBefore(rbacScopeValidationFilter, UsernamePasswordAuthenticationFilter.class);

        return http.build();
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
}