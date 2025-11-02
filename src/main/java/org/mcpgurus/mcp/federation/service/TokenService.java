package org.mcpgurus.mcp.federation.service;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.cache.annotation.CacheEvict;
import org.springframework.cache.annotation.CachePut;
import org.springframework.cache.annotation.Cacheable;
import org.springframework.stereotype.Service;
import org.mcpgurus.mcp.federation.model.TokenData;

/**
 * Token Service for MCP Identity Federation Server
 * 
 * Manages the lifecycle of API keys and their mapping to Identity Provider tokens.
 * This service provides:
 * 
 * - Secure token storage using Redis cache
 * - API key to IdP token mapping
 * - Token expiration and cleanup
 * - Thread-safe token operations
 * 
 * The service abstracts the complexity of token management from controllers
 * and provides a clean interface for token operations.
 * 
 * @author Pramod Kumar Sahu
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class TokenService {

    private static final String TOKEN_CACHE_NAME = "mcp-tokens";

    /**
     * Store token data mapped to an API key
     * 
     * @param apiKey The API key identifier
     * @param tokenData The token data to store
     */
    @CachePut(value = TOKEN_CACHE_NAME, key = "#apiKey")
    public void storeTokenData(String apiKey, TokenData tokenData) {
        log.debug("Storing token data for API key: {}", maskApiKey(apiKey));
        // The @CachePut annotation handles the actual storage in Redis
    }

    /**
     * Retrieve token data by API key
     * 
     * @param apiKey The API key identifier
     * @return TokenData if found, null otherwise
     */
    @Cacheable(value = TOKEN_CACHE_NAME, key = "#apiKey")
    public TokenData getTokenData(String apiKey) {
        log.debug("Retrieving token data for API key: {}", maskApiKey(apiKey));
        // The @Cacheable annotation handles the actual retrieval from Redis
        // If not found in cache, this method returns null
        return null;
    }

    /**
     * Get access token by API key
     * 
     * @param apiKey The API key identifier
     * @return Access token if found and valid, null otherwise
     */
    public String getAccessToken(String apiKey) {
        TokenData tokenData = getTokenData(apiKey);
        if (tokenData != null && !tokenData.isExpired()) {
            log.debug("Access token retrieved for API key: {}", maskApiKey(apiKey));
            return tokenData.getAccessToken();
        }
        log.debug("No valid access token found for API key: {}", maskApiKey(apiKey));
        return null;
    }

    /**
     * Get ID token by API key
     * 
     * @param apiKey The API key identifier
     * @return ID token if found, null otherwise
     */
    public String getIdToken(String apiKey) {
        TokenData tokenData = getTokenData(apiKey);
        if (tokenData != null) {
            log.debug("ID token retrieved for API key: {}", maskApiKey(apiKey));
            return tokenData.getIdToken();
        }
        log.debug("No ID token found for API key: {}", maskApiKey(apiKey));
        return null;
    }

    /**
     * Remove token data for an API key
     * 
     * @param apiKey The API key identifier
     */
    @CacheEvict(value = TOKEN_CACHE_NAME, key = "#apiKey")
    public void removeTokenData(String apiKey) {
        log.debug("Removing token data for API key: {}", maskApiKey(apiKey));
        // The @CacheEvict annotation handles the actual removal from Redis
    }

    /**
     * Check if an API key exists and is valid
     * 
     * @param apiKey The API key identifier
     * @return true if the API key exists and is valid, false otherwise
     */
    public boolean isValidApiKey(String apiKey) {
        TokenData tokenData = getTokenData(apiKey);
        boolean valid = tokenData != null && !tokenData.isExpired();
        log.debug("API key validation for {}: {}", maskApiKey(apiKey), valid);
        return valid;
    }

    /**
     * Update token data for an existing API key
     * 
     * @param apiKey The API key identifier
     * @param tokenData The updated token data
     */
    @CachePut(value = TOKEN_CACHE_NAME, key = "#apiKey")
    public void updateTokenData(String apiKey, TokenData tokenData) {
        log.debug("Updating token data for API key: {}", maskApiKey(apiKey));
        // The @CachePut annotation handles the actual update in Redis
    }

    /**
     * Clean up expired tokens
     * This method can be called periodically to remove expired tokens
     * Note: Redis TTL should handle most cleanup automatically
     */
    public void cleanupExpiredTokens() {
        log.info("Token cleanup initiated - Redis TTL should handle automatic cleanup");
        // In a Redis-based implementation, TTL handles most cleanup
        // This method could be enhanced to perform additional cleanup if needed
    }

    /**
     * Mask API key for logging purposes
     * 
     * @param apiKey The API key to mask
     * @return Masked API key for safe logging
     */
    private String maskApiKey(String apiKey) {
        if (apiKey == null || apiKey.length() < 10) {
            return "***";
        }
        return apiKey.substring(0, 10) + "***";
    }
}
