package org.mcpgurus.mcp.federation.controller;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.*;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.client.RestTemplate;
import org.mcpgurus.mcp.federation.config.FederationProperties;
import org.mcpgurus.mcp.federation.model.TokenData;
import org.mcpgurus.mcp.federation.service.ClientRegistrationService;
import org.mcpgurus.mcp.federation.service.PolicyEngineService;
import org.mcpgurus.mcp.federation.service.TokenService;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

/**
 * MCP OAuth Proxy Controller
 * 
 * Implements the core OAuth2 PKCE proxy functionality for the MCP Identity Federation Server.
 * This controller acts as an intermediary between MCP clients and multiple Identity Providers,
 * implementing a dual PKCE flow that provides:
 * 
 * - Client PKCE challenge validation
 * - IdP-specific PKCE flow execution
 * - Token abstraction through API keys
 * - Optional policy engine integration
 * - Centralized token lifecycle management
 * 
 * The proxy shields MCP clients from IdP complexity while maintaining OAuth2 security standards.
 * 
 * @author Pramod Kumar Sahu
 */
@Slf4j
@RestController
@RequiredArgsConstructor
@RequestMapping("/oauth")
public class MCPOAuthProxy {

    private final Map<String, AuthSession> sessionStorage = new ConcurrentHashMap<>();
    private final FederationProperties federationProperties;
    private final RestTemplate restTemplate;
    private final TokenService tokenService;
    private final ClientRegistrationService clientRegistrationService;
    private final PolicyEngineService policyEngineService;

    /**
     * OAuth2 Authorization Endpoint
     * 
     * Initiates the OAuth2 authorization flow with PKCE. This endpoint:
     * 1. Validates the client and PKCE challenge
     * 2. Generates an internal PKCE challenge for the IdP
     * 3. Redirects to the appropriate Identity Provider
     * 
     * @param clientId OAuth2 client identifier
     * @param redirectUri Client's redirect URI
     * @param codeChallenge PKCE code challenge from client
     * @param codeChallengeMethod PKCE challenge method (S256)
     * @param state OAuth2 state parameter
     * @param responseType OAuth2 response type (code)
     * @param scope Requested OAuth2 scopes
     * @param idpHint Optional hint for IdP selection
     * @return Redirect response to Identity Provider
     */
    @GetMapping("/authorize")
    public ResponseEntity<Void> authorize(
            @RequestParam("client_id") String clientId,
            @RequestParam("redirect_uri") String redirectUri,
            @RequestParam("code_challenge") String codeChallenge,
            @RequestParam(value = "code_challenge_method", defaultValue = "S256") String codeChallengeMethod,
            @RequestParam("state") String state,
            @RequestParam(value = "response_type", defaultValue = "code") String responseType,
            @RequestParam(value = "scope", required = false) String scope,
            @RequestParam(value = "idp_hint", required = false) String idpHint) {

        log.info("Authorization request received for client: {} with IdP hint: {}", clientId, idpHint);

        try {
            // Validate client
            if (!clientRegistrationService.isValidClient(clientId)) {
                log.warn("Invalid client ID: {}", clientId);
                return ResponseEntity.status(400).build();
            }

            // Validate PKCE method
            if (!"S256".equals(codeChallengeMethod)) {
                log.warn("Unsupported code challenge method: {}", codeChallengeMethod);
                return ResponseEntity.status(400).build();
            }

            // Select Identity Provider
            String selectedIdp = selectIdentityProvider(idpHint);
            if (selectedIdp == null) {
                log.error("No available Identity Provider found");
                return ResponseEntity.status(503).build();
            }

            FederationProperties.IdentityProvider idpConfig = 
                federationProperties.getIdentityProviders().get(selectedIdp);

            // Generate session ID and internal PKCE challenge
            String sessionId = UUID.randomUUID().toString();
            String mcpCodeVerifier = generateCodeVerifier();
            String mcpCodeChallenge = generateCodeChallenge(mcpCodeVerifier);

            // Create auth session
            AuthSession session = new AuthSession(
                clientId, redirectUri, codeChallenge, state, 
                mcpCodeVerifier, selectedIdp, scope
            );
            sessionStorage.put(sessionId, session);

            // Build IdP authorization URL
            String idpAuthUrl = buildIdpAuthorizationUrl(
                idpConfig, mcpCodeChallenge, sessionId, scope
            );

            log.info("Redirecting to IdP: {} for session: {}", selectedIdp, sessionId);
            return ResponseEntity.status(302)
                .header("Location", idpAuthUrl)
                .build();

        } catch (Exception e) {
            log.error("Error during authorization", e);
            return ResponseEntity.status(500).build();
        }
    }

    /**
     * OAuth2 Callback Endpoint
     * 
     * Handles the callback from Identity Providers after user authentication.
     * This endpoint:
     * 1. Exchanges the authorization code for tokens
     * 2. Optionally validates with policy engine
     * 3. Generates an API key for the client
     * 4. Redirects back to the client
     * 
     * @param code Authorization code from IdP
     * @param state Session state parameter
     * @param error Optional error parameter
     * @param errorDescription Optional error description
     * @return Redirect response to client
     */
    @GetMapping("/callback/{idpName}")
    public ResponseEntity<Void> callback(
            @PathVariable String idpName,
            @RequestParam("code") String code,
            @RequestParam("state") String state,
            @RequestParam(value = "error", required = false) String error,
            @RequestParam(value = "error_description", required = false) String errorDescription) {

        log.info("OAuth callback received from IdP: {} for session: {}", idpName, state);

        if (error != null) {
            log.error("OAuth error from IdP {}: {} - {}", idpName, error, errorDescription);
            return ResponseEntity.status(400).build();
        }

        try {
            // Retrieve session
            AuthSession session = sessionStorage.get(state);
            if (session == null) {
                log.error("Invalid session state: {}", state);
                return ResponseEntity.status(400).build();
            }

            // Get IdP configuration
            FederationProperties.IdentityProvider idpConfig = 
                federationProperties.getIdentityProviders().get(idpName);
            if (idpConfig == null) {
                log.error("Unknown IdP: {}", idpName);
                return ResponseEntity.status(400).build();
            }

            // Exchange code for tokens
            TokenData tokenData = exchangeCodeForTokens(idpConfig, code, session.mcpCodeVerifier);
            
            // Optional policy engine validation
            if (federationProperties.getPolicyEngine().isEnabled()) {
                boolean authorized = policyEngineService.validateAccess(
                    tokenData.getIdToken(), session.clientId, session.scope
                );
                if (!authorized) {
                    log.warn("Policy engine denied access for client: {}", session.clientId);
                    return ResponseEntity.status(403).build();
                }
            }

            // Generate API key
            String apiKey = "mcp_ak_" + UUID.randomUUID().toString().replace("-", "");
            tokenService.storeTokenData(apiKey, tokenData);

            // Generate authorization code for client
            String clientCode = UUID.randomUUID().toString();
            session.setCode(clientCode);
            session.setApiKey(apiKey);
            sessionStorage.put(clientCode, session);

            // Redirect back to client
            String clientRedirectUrl = session.redirectUri + 
                "?code=" + clientCode + 
                "&state=" + session.state;

            log.info("Redirecting to client with code for session: {}", state);
            return ResponseEntity.status(302)
                .header("Location", clientRedirectUrl)
                .build();

        } catch (Exception e) {
            log.error("Error during callback processing", e);
            return ResponseEntity.status(500).build();
        } finally {
            // Clean up session
            sessionStorage.remove(state);
        }
    }

    /**
     * OAuth2 Token Endpoint
     * 
     * Exchanges the authorization code for an API key token.
     * This endpoint validates the PKCE challenge and returns
     * an API key that maps to the underlying IdP tokens.
     * 
     * @param code Authorization code from client callback
     * @param codeVerifier PKCE code verifier
     * @param clientId OAuth2 client identifier
     * @param grantType OAuth2 grant type
     * @return Token response with API key
     */
    @PostMapping("/token")
    public ResponseEntity<Map<String, Object>> token(
            @RequestParam("code") String code,
            @RequestParam("code_verifier") String codeVerifier,
            @RequestParam("client_id") String clientId,
            @RequestParam(value = "grant_type", defaultValue = "authorization_code") String grantType) {

        log.info("Token exchange requested for client: {}", clientId);

        try {
            // Validate grant type
            if (!"authorization_code".equals(grantType)) {
                return ResponseEntity.badRequest().body(Map.of(
                    "error", "unsupported_grant_type",
                    "error_description", "Only authorization_code grant type is supported"
                ));
            }

            // Retrieve session
            AuthSession session = sessionStorage.remove(code);
            if (session == null) {
                log.warn("Invalid authorization code: {}", code);
                return ResponseEntity.badRequest().body(Map.of(
                    "error", "invalid_grant",
                    "error_description", "Invalid authorization code"
                ));
            }

            // Validate client
            if (!clientId.equals(session.clientId)) {
                log.warn("Client ID mismatch: expected {}, got {}", session.clientId, clientId);
                return ResponseEntity.badRequest().body(Map.of(
                    "error", "invalid_client",
                    "error_description", "Client ID mismatch"
                ));
            }

            // Verify PKCE
            if (!verifyPKCE(session.codeChallenge, codeVerifier)) {
                log.warn("PKCE verification failed for client: {}", clientId);
                return ResponseEntity.badRequest().body(Map.of(
                    "error", "invalid_grant",
                    "error_description", "PKCE verification failed"
                ));
            }

            // Return API key token
            int expiresIn = federationProperties.getServer().getApiKeyExpiryHours() * 3600;
            
            Map<String, Object> tokenResponse = Map.of(
                "access_token", session.apiKey,
                "token_type", "Bearer",
                "expires_in", expiresIn,
                "scope", session.scope != null ? session.scope : "mcp:read mcp:write"
            );

            log.info("Token issued successfully for client: {}", clientId);
            return ResponseEntity.ok(tokenResponse);

        } catch (Exception e) {
            log.error("Error during token exchange", e);
            return ResponseEntity.status(500).body(Map.of(
                "error", "server_error",
                "error_description", "Internal server error"
            ));
        }
    }

    /**
     * Token Renewal Endpoint
     * 
     * Allows clients to renew expired API keys without full re-authentication
     * if the underlying IdP tokens are still valid.
     * 
     * @param expiredApiKey The expired API key
     * @return New API key or re-authentication requirement
     */
    @PostMapping("/renew")
    public ResponseEntity<Map<String, Object>> renewToken(
            @RequestParam("api_key") String expiredApiKey) {

        log.info("Token renewal requested for API key: {}", expiredApiKey.substring(0, 10) + "...");

        try {
            TokenData tokenData = tokenService.getTokenData(expiredApiKey);
            if (tokenData == null) {
                return ResponseEntity.status(401).body(Map.of(
                    "error", "invalid_token",
                    "error_description", "API key not found"
                ));
            }

            // Check if underlying tokens are still valid
            if (tokenData.isExpired()) {
                // Try to refresh if refresh token is available
                if (tokenData.getRefreshToken() != null) {
                    // Refresh token logic would go here
                    // For now, require re-authentication
                }
                
                return ResponseEntity.status(401).body(Map.of(
                    "error", "token_expired",
                    "error_description", "Underlying tokens expired, re-authentication required",
                    "auth_endpoint", federationProperties.getServer().getBaseUrl() + "/oauth/authorize"
                ));
            }

            // Generate new API key
            String newApiKey = "mcp_ak_" + UUID.randomUUID().toString().replace("-", "");
            tokenService.storeTokenData(newApiKey, tokenData);
            tokenService.removeTokenData(expiredApiKey);

            int expiresIn = federationProperties.getServer().getApiKeyExpiryHours() * 3600;
            
            Map<String, Object> tokenResponse = Map.of(
                "access_token", newApiKey,
                "token_type", "Bearer",
                "expires_in", expiresIn
            );

            log.info("Token renewed successfully");
            return ResponseEntity.ok(tokenResponse);

        } catch (Exception e) {
            log.error("Error during token renewal", e);
            return ResponseEntity.status(500).body(Map.of(
                "error", "server_error",
                "error_description", "Internal server error"
            ));
        }
    }

    // Private helper methods

    private String selectIdentityProvider(String idpHint) {
        if (idpHint != null && federationProperties.getIdentityProviders().containsKey(idpHint)) {
            FederationProperties.IdentityProvider idp = federationProperties.getIdentityProviders().get(idpHint);
            if (idp.isEnabled()) {
                return idpHint;
            }
        }

        // Return first enabled IdP
        return federationProperties.getIdentityProviders().entrySet().stream()
            .filter(entry -> entry.getValue().isEnabled())
            .map(Map.Entry::getKey)
            .findFirst()
            .orElse(null);
    }

    private String buildIdpAuthorizationUrl(
            FederationProperties.IdentityProvider idpConfig, 
            String codeChallenge, 
            String state, 
            String scope) {
        
        String scopes = scope != null ? scope : idpConfig.getScopes();
        
        return idpConfig.getAuthEndpoint() +
            "?client_id=" + idpConfig.getClientId() +
            "&response_type=code" +
            "&redirect_uri=" + URLEncoder.encode(idpConfig.getRedirectUri(), StandardCharsets.UTF_8) +
            "&scope=" + URLEncoder.encode(scopes, StandardCharsets.UTF_8) +
            "&code_challenge=" + codeChallenge +
            "&code_challenge_method=S256" +
            "&state=" + state;
    }

    private TokenData exchangeCodeForTokens(
            FederationProperties.IdentityProvider idpConfig, 
            String code, 
            String codeVerifier) {
        
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);

        MultiValueMap<String, String> params = new LinkedMultiValueMap<>();
        params.add("grant_type", "authorization_code");
        params.add("client_id", idpConfig.getClientId());
        params.add("client_secret", idpConfig.getClientSecret());
        params.add("code", code);
        params.add("redirect_uri", idpConfig.getRedirectUri());
        params.add("code_verifier", codeVerifier);

        HttpEntity<MultiValueMap<String, String>> request = new HttpEntity<>(params, headers);
        ResponseEntity<Map> response = restTemplate.exchange(
            idpConfig.getTokenEndpoint(), HttpMethod.POST, request, Map.class);

        Map<String, Object> body = response.getBody();
        return new TokenData(
            (String) body.get("access_token"),
            (String) body.get("refresh_token"),
            (String) body.get("id_token"),
            System.currentTimeMillis() + ((Integer) body.get("expires_in") * 1000L),
            "MCP-Client"
        );
    }

    private String generateCodeVerifier() {
        SecureRandom random = new SecureRandom();
        byte[] bytes = new byte[32];
        random.nextBytes(bytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }

    private String generateCodeChallenge(String verifier) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(verifier.getBytes(StandardCharsets.UTF_8));
            return Base64.getUrlEncoder().withoutPadding().encodeToString(hash);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    private boolean verifyPKCE(String challenge, String verifier) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(verifier.getBytes(StandardCharsets.UTF_8));
            String computed = Base64.getUrlEncoder().withoutPadding().encodeToString(hash);
            return challenge.equals(computed);
        } catch (Exception e) {
            return false;
        }
    }

    /**
     * Authentication session data structure
     */
    @Data
    @AllArgsConstructor
    public static class AuthSession {
        private String clientId;
        private String redirectUri;
        private String codeChallenge;
        private String state;
        private String mcpCodeVerifier;
        private String idpName;
        private String scope;
        private String code;
        private String apiKey;

        public AuthSession(String clientId, String redirectUri, String codeChallenge, 
                          String state, String mcpCodeVerifier, String idpName, String scope) {
            this.clientId = clientId;
            this.redirectUri = redirectUri;
            this.codeChallenge = codeChallenge;
            this.state = state;
            this.mcpCodeVerifier = mcpCodeVerifier;
            this.idpName = idpName;
            this.scope = scope;
        }
    }
}
