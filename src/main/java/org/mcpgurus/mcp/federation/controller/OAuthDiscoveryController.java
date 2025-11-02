package org.mcpgurus.mcp.federation.controller;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.mcpgurus.mcp.federation.config.FederationProperties;
import org.mcpgurus.mcp.federation.service.ClientRegistrationService;

import jakarta.servlet.http.HttpServletRequest;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

/**
 * OAuth2 Discovery Controller for MCP Identity Federation Server
 * 
 * Provides OAuth2 discovery endpoints and dynamic client registration
 * as per RFC 8414 (OAuth 2.0 Authorization Server Metadata) and
 * RFC 7591 (OAuth 2.0 Dynamic Client Registration Protocol).
 * 
 * This controller enables MCP clients to:
 * - Discover OAuth2 authorization server capabilities
 * - Dynamically register as OAuth2 clients
 * - Obtain client credentials for subsequent authorization flows
 * 
 * @author Pramod Kumar Sahu
 */
@Slf4j
@RestController
@RequiredArgsConstructor
public class OAuthDiscoveryController {

    private final FederationProperties federationProperties;
    private final ClientRegistrationService clientRegistrationService;

    /**
     * OAuth2 Authorization Server Metadata Endpoint
     * 
     * Returns metadata about the authorization server's capabilities
     * as defined in RFC 8414. This enables clients to discover
     * endpoints and supported features.
     * 
     * <p><strong>Example Request:</strong></p>
     * <pre>
     * GET /.well-known/oauth-authorization-server HTTP/1.1
     * Host: localhost:8080
     * Accept: application/json
     * </pre>
     * 
     * <p><strong>Example Response:</strong></p>
     * <pre>
     * {
     *   "issuer": "http://localhost:8080/mcp-idp-federation",
     *   "authorization_endpoint": "http://localhost:8080/mcp-idp-federation/oauth/authorize",
     *   "token_endpoint": "http://localhost:8080/mcp-idp-federation/oauth/token",
     *   "registration_endpoint": "http://localhost:8080/mcp-idp-federation/oauth/register",
     *   "response_types_supported": ["code"],
     *   "grant_types_supported": ["authorization_code", "refresh_token"],
     *   "scopes_supported": ["openid", "profile", "email", "mcp:read", "mcp:write"]
     * }
     * </pre>
     * 
     * @return OAuth2 authorization server metadata as per RFC 8414
     * @see <a href="https://tools.ietf.org/html/rfc8414">RFC 8414 - OAuth 2.0 Authorization Server Metadata</a>
     */
    @GetMapping("/.well-known/oauth-authorization-server")
    public Map<String, Object> getOAuthMetadata() {
        log.debug("OAuth2 metadata requested");
        
        String baseUrl = federationProperties.getServer().getBaseUrl();
        
        Map<String, Object> metadata = new HashMap<>();
        metadata.put("issuer", baseUrl);
        metadata.put("authorization_endpoint", baseUrl + "/oauth/authorize");
        metadata.put("token_endpoint", baseUrl + "/oauth/token");
        metadata.put("registration_endpoint", baseUrl + "/oauth/register");
        metadata.put("userinfo_endpoint", baseUrl + "/oauth/userinfo");
        metadata.put("jwks_uri", baseUrl + "/.well-known/jwks.json");
        metadata.put("response_types_supported", List.of("code"));
        metadata.put("response_modes_supported", List.of("query", "fragment"));
        metadata.put("grant_types_supported", List.of("authorization_code", "refresh_token"));
        metadata.put("code_challenge_methods_supported", List.of("S256"));
        metadata.put("scopes_supported", List.of("openid", "profile", "email", "mcp:read", "mcp:write"));
        metadata.put("token_endpoint_auth_methods_supported", List.of("client_secret_basic", "client_secret_post"));
        metadata.put("claims_supported", List.of("sub", "iss", "aud", "exp", "iat", "auth_time", "nonce", "email", "name"));
        metadata.put("subject_types_supported", List.of("public"));
        metadata.put("id_token_signing_alg_values_supported", List.of("RS256"));
        
        return metadata;
    }

    /**
     * Dynamic Client Registration Endpoint
     * 
     * Allows MCP clients to register themselves dynamically as OAuth2 clients
     * as defined in RFC 7591. This eliminates the need for manual client
     * registration and enables automated MCP deployment scenarios.
     * 
     * <p><strong>Example Request:</strong></p>
     * <pre>
     * POST /oauth/register HTTP/1.1
     * Host: localhost:8080
     * Content-Type: application/json
     * 
     * {
     *   "client_name": "My MCP Client",
     *   "redirect_uris": [
     *     "http://localhost:3000/callback",
     *     "https://myapp.example.com/oauth/callback"
     *   ],
     *   "grant_types": ["authorization_code", "refresh_token"],
     *   "response_types": ["code"],
     *   "scope": ["mcp:read", "mcp:write", "openid", "profile"]
     * }
     * </pre>
     * 
     * <p><strong>Example Response:</strong></p>
     * <pre>
     * {
     *   "client_id": "ee2a5045-a612-4c88-a2f0-53104e648abf",
     *   "client_secret": "c9f78996ada44a8b9e81af52bc82b9ae",
     *   "client_name": "My MCP Client",
     *   "redirect_uris": ["http://localhost:3000/callback"],
     *   "grant_types": ["authorization_code", "refresh_token"],
     *   "response_types": ["code"],
     *   "scope": "mcp:read mcp:write openid profile",
     *   "token_endpoint_auth_method": "client_secret_basic"
     * }
     * </pre>
     * 
     * @param request Client registration request containing client metadata
     * @param httpRequest HTTP request for IP tracking and rate limiting
     * @return ResponseEntity with client registration response and credentials
     * @see <a href="https://tools.ietf.org/html/rfc7591">RFC 7591 - OAuth 2.0 Dynamic Client Registration Protocol</a>
     */
    @PostMapping("/oauth/register")
    public ResponseEntity<Map<String, Object>> registerClient(
            @RequestBody Map<String, Object> request,
            HttpServletRequest httpRequest) {
        
        log.info("Dynamic client registration requested from IP: {}", 
                httpRequest.getRemoteAddr());
        
        if (!federationProperties.getClientRegistration().isDynamicRegistrationEnabled()) {
            log.warn("Dynamic client registration is disabled");
            return ResponseEntity.status(403).body(Map.of(
                "error", "registration_not_supported",
                "error_description", "Dynamic client registration is not enabled"
            ));
        }

        try {
            // Extract client registration parameters
            String clientName = (String) request.get("client_name");
            @SuppressWarnings("unchecked")
            List<String> redirectUris = (List<String>) request.get("redirect_uris");
            @SuppressWarnings("unchecked")
            List<String> grantTypes = (List<String>) request.getOrDefault("grant_types", 
                List.of("authorization_code"));
            @SuppressWarnings("unchecked")
            List<String> responseTypes = (List<String>) request.getOrDefault("response_types", 
                List.of("code"));
            @SuppressWarnings("unchecked")
            List<String> scopes = (List<String>) request.getOrDefault("scope", 
                federationProperties.getClientRegistration().getDefaultScopes());

            // Validate required parameters
            if (clientName == null || clientName.trim().isEmpty()) {
                return ResponseEntity.badRequest().body(Map.of(
                    "error", "invalid_client_metadata",
                    "error_description", "client_name is required"
                ));
            }

            if (redirectUris == null || redirectUris.isEmpty()) {
                return ResponseEntity.badRequest().body(Map.of(
                    "error", "invalid_client_metadata",
                    "error_description", "redirect_uris is required"
                ));
            }

            // Generate client credentials
            String clientId = UUID.randomUUID().toString();
            String clientSecret = generateClientSecret();

            // Register the client
            clientRegistrationService.registerClient(
                clientId, clientSecret, redirectUris, clientName, 
                grantTypes, responseTypes, scopes, httpRequest.getRemoteAddr());

            log.info("Client registered successfully: {} ({})", clientName, clientId);

            // Return client registration response
            return ResponseEntity.status(201).body(Map.of(
                "client_id", clientId,
                "client_secret", clientSecret,
                "client_name", clientName,
                "redirect_uris", redirectUris,
                "grant_types", grantTypes,
                "response_types", responseTypes,
                "scope", String.join(" ", scopes),
                "token_endpoint_auth_method", "client_secret_basic",
                "client_id_issued_at", System.currentTimeMillis() / 1000,
                "client_secret_expires_at", 0 // Never expires
            ));

        } catch (Exception e) {
            log.error("Error during client registration", e);
            return ResponseEntity.status(500).body(Map.of(
                "error", "server_error",
                "error_description", "Internal server error during client registration"
            ));
        }
    }

    /**
     * Client Information Endpoint
     * 
     * Allows clients to retrieve their registration information
     * 
     * @param clientId The client identifier
     * @return Client information
     */
    @GetMapping("/oauth/client/{clientId}")
    public ResponseEntity<Map<String, Object>> getClientInfo(@PathVariable String clientId) {
        log.debug("Client info requested for: {}", clientId);
        
        var clientInfo = clientRegistrationService.getClientInfo(clientId);
        if (clientInfo.isEmpty()) {
            return ResponseEntity.notFound().build();
        }
        
        return ResponseEntity.ok(clientInfo.get());
    }

    /**
     * Generate a cryptographically secure client secret
     * 
     * @return Generated client secret
     */
    private String generateClientSecret() {
        int length = federationProperties.getClientRegistration().getClientSecretLength();
        return UUID.randomUUID().toString().replace("-", "") + 
               UUID.randomUUID().toString().replace("-", "").substring(0, length - 32);
    }
}
