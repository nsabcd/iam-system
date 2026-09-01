package com.iam.security.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
public class SecurityConfig {
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception{
        http.csrf(csrf -> csrf.disable())
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers(
                                "/.well-known/jwks.json",
                                "/auth/login",
                                "/oauth2/token",
                                "/authz/introspect",
                                "/authz/revoke"
                        ).permitAll()
                        .requestMatchers("/scim/v2/**", "/api/v1/secure/**").permitAll()
                        .anyRequest().authenticated()
                );
        return http.build();
    }
}
