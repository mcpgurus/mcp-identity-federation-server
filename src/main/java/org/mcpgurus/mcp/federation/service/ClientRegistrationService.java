package org.mcpgurus.mcp.federation.service;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.cache.annotation.CacheEvict;
import org.springframework.cache.annotation.CachePut;
import org.springframework.cache.annotation.Cacheable;
import org.springframework.stereotype.Service;
import org.mcpgurus.mcp.federation.config.FederationProperties;

import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Client Registration Service for MCP Identity Federation Server
 * 
 * Manages OAuth2 client registrations for MCP clients. This service provides:
 * 
 * - Dynamic client registration
 * - Client credential management
 * - Client validation and authentication
 * - Rate limiting per IP address
 * - Client information retrieval
 * 
 * The service supports both dynamic and static client registration patterns
 * and integrates with Redis for distributed caching of client information.
 * 
 * @author Pramod Kumar Sahu
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class ClientRegistrationService {

    private static final String CLIENT_CACHE_NAME = "mcp-clients";
    private static final String IP_COUNTER_CACHE_NAME = "mcp-client-ip-counters";

    private final FederationProperties federationProperties;
    private final Map<String, Integer> ipRegistrationCounts = new ConcurrentHashMap<>();

    /**
     * Register a new OAuth2 client
     * 
     * @param clientId Generated client identifier
     * @param clientSecret Generated client secret
     * @param redirectUris List of allowed redirect URIs
     * @param clientName Human-readable client name
     * @param grantTypes Supported grant types
     * @param responseTypes Supported response types
     * @param scopes Allowed scopes
     * @param clientIp IP address of the registering client
     * @throws IllegalStateException if registration limits are exceeded
     */
    @CachePut(value = CLIENT_CACHE_NAME, key = "#clientId")
    public RegisteredClient registerClient(
            String clientId, 
            String clientSecret, 
            List<String> redirectUris,
            String clientName, 
            List<String> grantTypes, 
            List<String> responseTypes,
            List<String> scopes, 
            String clientIp) {

        // Check IP-based rate limiting
        int currentCount = ipRegistrationCounts.getOrDefault(clientIp, 0);
        int maxClients = federationProperties.getClientRegistration().getMaxClientsPerIp();
        
        if (currentCount >= maxClients) {
            log.warn("Registration limit exceeded for IP: {} (current: {}, max: {})", 
                    clientIp, currentCount, maxClients);
            throw new IllegalStateException("Registration limit exceeded for IP address");
        }

        // Create registered client
        RegisteredClient client = new RegisteredClient(
            clientId,
            clientSecret,
            redirectUris,
            clientName,
            grantTypes,
            responseTypes,
            scopes,
            clientIp,
            Instant.now(),
            true
        );

        // Update IP counter
        ipRegistrationCounts.put(clientIp, currentCount + 1);

        log.info("Client registered: {} from IP: {} (total from IP: {})", 
                clientName, clientIp, currentCount + 1);

        return client;
    }

    /**
     * Retrieve client information by client ID
     * 
     * @param clientId The client identifier
     * @return RegisteredClient if found, null otherwise
     */
    @Cacheable(value = CLIENT_CACHE_NAME, key = "#clientId")
    public RegisteredClient getClient(String clientId) {
        log.debug("Retrieving client: {}", clientId);
        // The @Cacheable annotation handles the actual retrieval from Redis
        // If not found in cache, this method returns null
        return null;
    }

    /**
     * Validate client credentials
     * 
     * @param clientId The client identifier
     * @param clientSecret The client secret
     * @return true if credentials are valid, false otherwise
     */
    public boolean isValidClient(String clientId, String clientSecret) {
        RegisteredClient client = getClient(clientId);
        boolean valid = client != null && 
                       client.isActive() && 
                       client.getClientSecret().equals(clientSecret);
        
        log.debug("Client validation for {}: {}", clientId, valid);
        return valid;
    }

    /**
     * Check if client ID exists (without secret validation)
     * 
     * @param clientId The client identifier
     * @return true if client exists and is active, false otherwise
     */
    public boolean isValidClient(String clientId) {
        RegisteredClient client = getClient(clientId);
        boolean valid = client != null && client.isActive();
        
        log.debug("Client existence check for {}: {}", clientId, valid);
        return valid;
    }

    /**
     * Get client information for OAuth2 metadata endpoint
     * 
     * @param clientId The client identifier
     * @return Optional containing client information map
     */
    public Optional<Map<String, Object>> getClientInfo(String clientId) {
        RegisteredClient client = getClient(clientId);
        if (client == null || !client.isActive()) {
            return Optional.empty();
        }

        Map<String, Object> clientInfo = Map.of(
            "client_id", client.getClientId(),
            "client_name", client.getClientName(),
            "redirect_uris", client.getRedirectUris(),
            "grant_types", client.getGrantTypes(),
            "response_types", client.getResponseTypes(),
            "scope", String.join(" ", client.getScopes()),
            "client_id_issued_at", client.getRegisteredAt().getEpochSecond(),
            "client_secret_expires_at", 0 // Never expires
        );

        return Optional.of(clientInfo);
    }

    /**
     * Deactivate a client
     * 
     * @param clientId The client identifier
     * @return true if client was deactivated, false if not found
     */
    @CachePut(value = CLIENT_CACHE_NAME, key = "#clientId")
    public boolean deactivateClient(String clientId) {
        RegisteredClient client = getClient(clientId);
        if (client != null) {
            client.setActive(false);
            log.info("Client deactivated: {}", clientId);
            return true;
        }
        return false;
    }

    /**
     * Remove client registration
     * 
     * @param clientId The client identifier
     */
    @CacheEvict(value = CLIENT_CACHE_NAME, key = "#clientId")
    public void removeClient(String clientId) {
        log.info("Client removed: {}", clientId);
        // The @CacheEvict annotation handles the actual removal from Redis
    }

    /**
     * Get registration count for an IP address
     * 
     * @param clientIp The IP address
     * @return Number of registered clients from this IP
     */
    public int getRegistrationCountForIp(String clientIp) {
        return ipRegistrationCounts.getOrDefault(clientIp, 0);
    }

    /**
     * Reset registration count for an IP address
     * 
     * @param clientIp The IP address
     */
    public void resetRegistrationCountForIp(String clientIp) {
        ipRegistrationCounts.remove(clientIp);
        log.info("Registration count reset for IP: {}", clientIp);
    }

    /**
     * Registered Client data structure
     */
    @Data
    @AllArgsConstructor
    public static class RegisteredClient implements java.io.Serializable {
        private static final long serialVersionUID = 1L;
        private String clientId;
        private String clientSecret;
        private List<String> redirectUris;
        private String clientName;
        private List<String> grantTypes;
        private List<String> responseTypes;
        private List<String> scopes;
        private String registeredFromIp;
        private Instant registeredAt;
        private boolean active;

        /**
         * Check if client supports a specific grant type
         * 
         * @param grantType The grant type to check
         * @return true if supported, false otherwise
         */
        public boolean supportsGrantType(String grantType) {
            return grantTypes != null && grantTypes.contains(grantType);
        }

        /**
         * Check if client supports a specific response type
         * 
         * @param responseType The response type to check
         * @return true if supported, false otherwise
         */
        public boolean supportsResponseType(String responseType) {
            return responseTypes != null && responseTypes.contains(responseType);
        }

        /**
         * Check if redirect URI is allowed for this client
         * 
         * @param redirectUri The redirect URI to check
         * @return true if allowed, false otherwise
         */
        public boolean isRedirectUriAllowed(String redirectUri) {
            return redirectUris != null && redirectUris.contains(redirectUri);
        }

        /**
         * Check if scope is allowed for this client
         * 
         * @param scope The scope to check
         * @return true if allowed, false otherwise
         */
        public boolean isScopeAllowed(String scope) {
            return scopes != null && scopes.contains(scope);
        }
    }
}
