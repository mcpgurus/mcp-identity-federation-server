package org.mcpgurus.mcp.federation.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.web.SecurityFilterChain;

/**
 * Security Configuration for MCP Identity Federation Server
 * 
 * Configures security rules for the federation server endpoints.
 * Allows public access to discovery endpoints while protecting
 * sensitive operations.
 * 
 * @author Pramod Kumar Sahu
 */
@Configuration
@EnableWebSecurity
public class SecurityConfig {

    /**
     * Configure HTTP security for the application
     * 
     * @param http HttpSecurity configuration
     * @return SecurityFilterChain
     * @throws Exception if configuration fails
     */
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
            .authorizeHttpRequests(authz -> authz
                // Allow public access to discovery endpoints
                .requestMatchers("/.well-known/**").permitAll()
                .requestMatchers("/actuator/health").permitAll()
                .requestMatchers("/actuator/info").permitAll()
                
                // OAuth endpoints that should be publicly accessible
                .requestMatchers("/oauth/register").permitAll()
                
                // All other endpoints require authentication
                .anyRequest().authenticated()
            )
            .csrf(csrf -> csrf.disable()) // Disable CSRF for API endpoints
            .httpBasic(httpBasic -> {
                // Enable basic authentication for now
            });

        return http.build();
    }
}
