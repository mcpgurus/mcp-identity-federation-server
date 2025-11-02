package org.mcpgurus.mcp.federation.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.client.RestTemplate;
import org.springframework.boot.web.client.RestTemplateBuilder;
import org.springframework.http.client.HttpComponentsClientHttpRequestFactory;

import java.time.Duration;

/**
 * Web Configuration for MCP Identity Federation Server
 * 
 * Configures HTTP clients and web-related components for the federation server.
 * This includes RestTemplate configuration for external API calls to Identity
 * Providers and Policy Engines.
 * 
 * @author Pramod Kumar Sahu
 */
@Configuration
public class WebConfig {

    /**
     * Configure RestTemplate for external HTTP calls
     * 
     * @param builder RestTemplate builder
     * @return Configured RestTemplate
     */
    @Bean
    public RestTemplate restTemplate(RestTemplateBuilder builder) {
        return builder
            .setConnectTimeout(Duration.ofSeconds(10))
            .setReadTimeout(Duration.ofSeconds(30))
            .requestFactory(HttpComponentsClientHttpRequestFactory.class)
            .build();
    }
}
