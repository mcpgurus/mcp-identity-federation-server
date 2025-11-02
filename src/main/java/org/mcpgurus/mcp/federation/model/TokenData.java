package org.mcpgurus.mcp.federation.model;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.io.Serializable;

/**
 * Token Data Model for MCP Identity Federation Server
 * 
 * Represents the token information obtained from Identity Providers
 * and stored in the federation server. This model encapsulates:
 * 
 * - Access tokens for API access
 * - Refresh tokens for token renewal
 * - ID tokens for user identity information
 * - Token expiration and lifecycle metadata
 * 
 * The class implements Serializable to support Redis caching
 * and includes utility methods for token validation.
 * 
 * @author Pramod Kumar Sahu
 */
@Data
@NoArgsConstructor
@AllArgsConstructor
public class TokenData implements Serializable {

    private static final long serialVersionUID = 1L;

    /**
     * Access token from the Identity Provider
     * Used for accessing protected resources
     */
    private String accessToken;

    /**
     * Refresh token from the Identity Provider
     * Used for obtaining new access tokens without re-authentication
     */
    private String refreshToken;

    /**
     * ID token from the Identity Provider (JWT)
     * Contains user identity information and claims
     */
    private String idToken;

    /**
     * Token expiration timestamp (milliseconds since epoch)
     * Indicates when the access token expires
     */
    private long expiresAt;

    /**
     * User identifier or client identifier
     * Identifies the entity that owns these tokens
     */
    private String userId;

    /**
     * Timestamp when the token was issued (milliseconds since epoch)
     */
    private long issuedAt;

    /**
     * Identity Provider that issued the tokens
     */
    private String issuer;

    /**
     * Scopes associated with the access token
     */
    private String scopes;

    /**
     * Constructor for basic token data
     * 
     * @param accessToken Access token from IdP
     * @param refreshToken Refresh token from IdP
     * @param idToken ID token from IdP
     * @param expiresAt Token expiration timestamp
     * @param userId User or client identifier
     */
    public TokenData(String accessToken, String refreshToken, String idToken, 
                    long expiresAt, String userId) {
        this.accessToken = accessToken;
        this.refreshToken = refreshToken;
        this.idToken = idToken;
        this.expiresAt = expiresAt;
        this.userId = userId;
        this.issuedAt = System.currentTimeMillis();
    }

    /**
     * Check if the access token is expired
     * 
     * @return true if the token is expired, false otherwise
     */
    public boolean isExpired() {
        return System.currentTimeMillis() >= expiresAt;
    }

    /**
     * Check if the access token will expire within the specified time
     * 
     * @param milliseconds Time in milliseconds to check ahead
     * @return true if the token will expire within the specified time
     */
    public boolean willExpireWithin(long milliseconds) {
        return System.currentTimeMillis() + milliseconds >= expiresAt;
    }

    /**
     * Get remaining time until token expiration
     * 
     * @return Remaining time in milliseconds, 0 if already expired
     */
    public long getRemainingTime() {
        long remaining = expiresAt - System.currentTimeMillis();
        return Math.max(0, remaining);
    }

    /**
     * Check if refresh token is available
     * 
     * @return true if refresh token is present and not empty
     */
    public boolean hasRefreshToken() {
        return refreshToken != null && !refreshToken.trim().isEmpty();
    }

    /**
     * Check if ID token is available
     * 
     * @return true if ID token is present and not empty
     */
    public boolean hasIdToken() {
        return idToken != null && !idToken.trim().isEmpty();
    }

    /**
     * Get token age in milliseconds
     * 
     * @return Age of the token since issuance
     */
    public long getAge() {
        return System.currentTimeMillis() - issuedAt;
    }

    /**
     * Check if the token data is valid (not null and not expired)
     * 
     * @return true if valid, false otherwise
     */
    public boolean isValid() {
        return accessToken != null && 
               !accessToken.trim().isEmpty() && 
               !isExpired();
    }

    /**
     * Create a copy of this TokenData with updated access token and expiration
     * Useful for token refresh scenarios
     * 
     * @param newAccessToken New access token
     * @param newExpiresAt New expiration timestamp
     * @return New TokenData instance with updated values
     */
    public TokenData withUpdatedAccessToken(String newAccessToken, long newExpiresAt) {
        TokenData updated = new TokenData();
        updated.accessToken = newAccessToken;
        updated.refreshToken = this.refreshToken;
        updated.idToken = this.idToken;
        updated.expiresAt = newExpiresAt;
        updated.userId = this.userId;
        updated.issuedAt = System.currentTimeMillis(); // Update issued time
        updated.issuer = this.issuer;
        updated.scopes = this.scopes;
        return updated;
    }

    /**
     * Create a sanitized version of this TokenData for logging
     * Masks sensitive token values while preserving metadata
     * 
     * @return Sanitized TokenData for safe logging
     */
    public TokenData sanitizedForLogging() {
        TokenData sanitized = new TokenData();
        sanitized.accessToken = maskToken(this.accessToken);
        sanitized.refreshToken = maskToken(this.refreshToken);
        sanitized.idToken = maskToken(this.idToken);
        sanitized.expiresAt = this.expiresAt;
        sanitized.userId = this.userId;
        sanitized.issuedAt = this.issuedAt;
        sanitized.issuer = this.issuer;
        sanitized.scopes = this.scopes;
        return sanitized;
    }

    /**
     * Mask token for safe logging
     * 
     * @param token Token to mask
     * @return Masked token string
     */
    private String maskToken(String token) {
        if (token == null || token.length() < 10) {
            return "***";
        }
        return token.substring(0, 10) + "***";
    }

    @Override
    public String toString() {
        return "TokenData{" +
                "accessToken='" + maskToken(accessToken) + '\'' +
                ", refreshToken='" + maskToken(refreshToken) + '\'' +
                ", idToken='" + maskToken(idToken) + '\'' +
                ", expiresAt=" + expiresAt +
                ", userId='" + userId + '\'' +
                ", issuedAt=" + issuedAt +
                ", issuer='" + issuer + '\'' +
                ", scopes='" + scopes + '\'' +
                ", expired=" + isExpired() +
                '}';
    }
}
