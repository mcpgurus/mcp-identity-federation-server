package org.mcpgurus.mcp.federation.config;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;
import org.springframework.validation.annotation.Validated;

import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Positive;
import java.util.Map;
import java.util.List;

/**
 * Configuration properties for the MCP Identity Federation Server
 * 
 * This class binds configuration from application.yml to strongly-typed
 * configuration objects, providing validation and easy access to all
 * federation settings.
 * 
 * @author Pramod Kumar Sahu
 */
@Data
@Component
@ConfigurationProperties(prefix = "mcp.federation")
@Validated
public class FederationProperties {

    @Valid
    @NotNull
    private ServerConfig server = new ServerConfig();

    @Valid
    @NotNull
    private Map<String, IdentityProvider> identityProviders;

    @Valid
    private PolicyEngine policyEngine = new PolicyEngine();

    @Valid
    @NotNull
    private ClientRegistration clientRegistration = new ClientRegistration();

    /**
     * Server configuration settings
     */
    @Data
    public static class ServerConfig {
        @NotBlank
        private String baseUrl = "http://localhost:8080/mcp-federation";
        
        @Positive
        private int apiKeyExpiryHours = 24;
        
        @Positive
        private int sessionTimeoutMinutes = 30;
    }

    /**
     * Identity Provider configuration
     */
    @Data
    public static class IdentityProvider {
        private boolean enabled = false;
        
        @NotBlank
        private String type; // oidc, oauth2, saml
        
        @NotBlank
        private String name;
        
        @NotBlank
        private String clientId;
        
        @NotBlank
        private String clientSecret;
        
        private String tenantId; // For Entra ID
        private String domain; // For Okta
        private String baseUrl; // For PingFederate
        
        @NotBlank
        private String authEndpoint;
        
        @NotBlank
        private String tokenEndpoint;
        
        private String userinfoEndpoint;
        
        @NotBlank
        private String scopes;
        
        @NotBlank
        private String redirectUri;
        
        // Additional provider-specific settings
        private Map<String, String> additionalParameters;
    }

    /**
     * Policy Engine configuration for additional authorization checks
     */
    @Data
    public static class PolicyEngine {
        private boolean enabled = false;
        
        private String endpoint;
        
        @Positive
        private long timeout = 5000; // milliseconds
        
        private Map<String, String> headers;
    }

    /**
     * Client registration configuration
     */
    @Data
    public static class ClientRegistration {
        private boolean dynamicRegistrationEnabled = true;
        
        @NotNull
        private List<String> defaultScopes = List.of("mcp:read", "mcp:write");
        
        @Positive
        private int maxClientsPerIp = 10;
        
        @Positive
        private int clientSecretLength = 32;
    }
}
