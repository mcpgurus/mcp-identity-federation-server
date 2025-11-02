package org.mcpgurus.mcp.federation.service;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.*;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.client.ResourceAccessException;
import org.mcpgurus.mcp.federation.config.FederationProperties;

import java.time.Duration;
import java.util.Map;

/**
 * Policy Engine Service for MCP Identity Federation Server
 * 
 * Integrates with external policy engines to provide additional authorization
 * checks beyond standard OAuth2 flows. This service enables:
 * 
 * - Fine-grained access control based on JWT claims
 * - Dynamic policy evaluation
 * - Integration with enterprise policy engines (OPA, etc.)
 * - Contextual authorization decisions
 * 
 * The service is optional and can be disabled via configuration.
 * When enabled, it validates access tokens against configured policies
 * before issuing API keys to MCP clients.
 * 
 * @author Pramod Kumar Sahu
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class PolicyEngineService {

    private final FederationProperties federationProperties;
    private final RestTemplate restTemplate;

    /**
     * Validate access using external policy engine
     * 
     * @param idToken JWT ID token from Identity Provider
     * @param clientId OAuth2 client identifier
     * @param scope Requested scope
     * @return true if access is allowed, false otherwise
     */
    public boolean validateAccess(String idToken, String clientId, String scope) {
        if (!federationProperties.getPolicyEngine().isEnabled()) {
            log.debug("Policy engine is disabled, allowing access");
            return true;
        }

        try {
            log.debug("Validating access with policy engine for client: {}", clientId);
            
            // Prepare policy evaluation request
            Map<String, Object> policyRequest = Map.of(
                "input", Map.of(
                    "token", idToken,
                    "client_id", clientId,
                    "scope", scope != null ? scope : "",
                    "timestamp", System.currentTimeMillis() / 1000,
                    "action", "mcp_access"
                )
            );

            // Set up HTTP headers
            HttpHeaders headers = new HttpHeaders();
            headers.setContentType(MediaType.APPLICATION_JSON);
            
            // Add configured headers (e.g., Authorization)
            if (federationProperties.getPolicyEngine().getHeaders() != null) {
                federationProperties.getPolicyEngine().getHeaders().forEach(headers::set);
            }

            HttpEntity<Map<String, Object>> request = new HttpEntity<>(policyRequest, headers);

            // Call policy engine
            String endpoint = federationProperties.getPolicyEngine().getEndpoint();
            ResponseEntity<Map> response = restTemplate.exchange(
                endpoint, 
                HttpMethod.POST, 
                request, 
                Map.class
            );

            // Parse response
            if (response.getStatusCode().is2xxSuccessful() && response.getBody() != null) {
                Map<String, Object> responseBody = response.getBody();
                Boolean allowed = extractAllowDecision(responseBody);
                
                if (allowed != null) {
                    log.info("Policy engine decision for client {}: {}", clientId, allowed);
                    return allowed;
                } else {
                    log.warn("Policy engine returned invalid response format for client: {}", clientId);
                    return false; // Fail closed
                }
            } else {
                log.warn("Policy engine returned non-success status: {} for client: {}", 
                        response.getStatusCode(), clientId);
                return false; // Fail closed
            }

        } catch (ResourceAccessException e) {
            log.error("Policy engine timeout or connection error for client: {}", clientId, e);
            return handlePolicyEngineError(clientId, e);
            
        } catch (Exception e) {
            log.error("Error calling policy engine for client: {}", clientId, e);
            return handlePolicyEngineError(clientId, e);
        }
    }

    /**
     * Validate access with additional context
     * 
     * @param idToken JWT ID token from Identity Provider
     * @param clientId OAuth2 client identifier
     * @param scope Requested scope
     * @param additionalContext Additional context for policy evaluation
     * @return true if access is allowed, false otherwise
     */
    public boolean validateAccessWithContext(
            String idToken, 
            String clientId, 
            String scope, 
            Map<String, Object> additionalContext) {
        
        if (!federationProperties.getPolicyEngine().isEnabled()) {
            log.debug("Policy engine is disabled, allowing access");
            return true;
        }

        try {
            log.debug("Validating access with context for client: {}", clientId);
            
            // Prepare enhanced policy evaluation request
            Map<String, Object> input = Map.of(
                "token", idToken,
                "client_id", clientId,
                "scope", scope != null ? scope : "",
                "timestamp", System.currentTimeMillis() / 1000,
                "action", "mcp_access",
                "context", additionalContext != null ? additionalContext : Map.of()
            );

            Map<String, Object> policyRequest = Map.of("input", input);

            // Set up HTTP headers
            HttpHeaders headers = new HttpHeaders();
            headers.setContentType(MediaType.APPLICATION_JSON);
            
            if (federationProperties.getPolicyEngine().getHeaders() != null) {
                federationProperties.getPolicyEngine().getHeaders().forEach(headers::set);
            }

            HttpEntity<Map<String, Object>> request = new HttpEntity<>(policyRequest, headers);

            // Call policy engine with timeout
            String endpoint = federationProperties.getPolicyEngine().getEndpoint();
            ResponseEntity<Map> response = restTemplate.exchange(
                endpoint, 
                HttpMethod.POST, 
                request, 
                Map.class
            );

            // Parse response
            if (response.getStatusCode().is2xxSuccessful() && response.getBody() != null) {
                Map<String, Object> responseBody = response.getBody();
                Boolean allowed = extractAllowDecision(responseBody);
                
                if (allowed != null) {
                    log.info("Policy engine decision with context for client {}: {}", clientId, allowed);
                    return allowed;
                } else {
                    log.warn("Policy engine returned invalid response format for client: {}", clientId);
                    return false; // Fail closed
                }
            } else {
                log.warn("Policy engine returned non-success status: {} for client: {}", 
                        response.getStatusCode(), clientId);
                return false; // Fail closed
            }

        } catch (Exception e) {
            log.error("Error calling policy engine with context for client: {}", clientId, e);
            return handlePolicyEngineError(clientId, e);
        }
    }

    /**
     * Check if policy engine is available
     * 
     * @return true if policy engine is enabled and reachable, false otherwise
     */
    public boolean isPolicyEngineAvailable() {
        if (!federationProperties.getPolicyEngine().isEnabled()) {
            return false;
        }

        try {
            // Simple health check - could be enhanced with a dedicated health endpoint
            String endpoint = federationProperties.getPolicyEngine().getEndpoint();
            HttpHeaders headers = new HttpHeaders();
            
            if (federationProperties.getPolicyEngine().getHeaders() != null) {
                federationProperties.getPolicyEngine().getHeaders().forEach(headers::set);
            }

            HttpEntity<String> request = new HttpEntity<>(headers);
            ResponseEntity<String> response = restTemplate.exchange(
                endpoint, 
                HttpMethod.HEAD, 
                request, 
                String.class
            );

            return response.getStatusCode().is2xxSuccessful();

        } catch (Exception e) {
            log.debug("Policy engine health check failed", e);
            return false;
        }
    }

    /**
     * Extract allow/deny decision from policy engine response
     * 
     * @param responseBody Policy engine response body
     * @return Boolean decision or null if format is invalid
     */
    private Boolean extractAllowDecision(Map<String, Object> responseBody) {
        // Handle different policy engine response formats
        
        // OPA format: {"result": true/false}
        if (responseBody.containsKey("result")) {
            Object result = responseBody.get("result");
            if (result instanceof Boolean) {
                return (Boolean) result;
            }
        }

        // Alternative format: {"allow": true/false}
        if (responseBody.containsKey("allow")) {
            Object allow = responseBody.get("allow");
            if (allow instanceof Boolean) {
                return (Boolean) allow;
            }
        }

        // Alternative format: {"decision": "allow"/"deny"}
        if (responseBody.containsKey("decision")) {
            Object decision = responseBody.get("decision");
            if (decision instanceof String) {
                return "allow".equalsIgnoreCase((String) decision);
            }
        }

        return null; // Invalid format
    }

    /**
     * Handle policy engine errors with appropriate fallback behavior
     * 
     * @param clientId Client identifier for logging
     * @param error The error that occurred
     * @return Fallback decision (typically false for fail-closed behavior)
     */
    private boolean handlePolicyEngineError(String clientId, Exception error) {
        // In production, you might want to implement more sophisticated
        // error handling, such as:
        // - Allowing access if policy engine is temporarily unavailable
        // - Using cached policy decisions
        // - Implementing circuit breaker patterns
        
        log.error("Policy engine error for client {}, failing closed", clientId);
        return false; // Fail closed - deny access on policy engine errors
    }
}
