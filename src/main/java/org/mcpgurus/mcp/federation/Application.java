package org.mcpgurus.mcp.federation;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.cache.annotation.EnableCaching;

/**
 * MCP Identity Federation Server
 * 
 * A standalone identity federation server that provides OAuth2/OIDC proxy services
 * for Model Context Protocol (MCP) implementations. This server acts as an intermediary
 * between MCP clients and multiple Identity Providers, providing:
 * 
 * - Multi-IdP federation (Entra ID, Okta, PingFederate, etc.)
 * - OAuth2 discovery and dynamic client registration
 * - PKCE-based authorization flows
 * - API key abstraction for MCP clients
 * - Optional policy engine integration
 * - Centralized token lifecycle management
 * 
 * @author Pramod Kumar Sahu
 * @version 1.0.0
 * @since 2024-01-15
 */
@SpringBootApplication
@EnableConfigurationProperties
@EnableCaching
public class Application {

    /**
     * Main entry point for the MCP Identity Federation Server
     * 
     * @param args Command line arguments
     */
    public static void main(String[] args) {
        SpringApplication.run(Application.class, args);
    }
}
