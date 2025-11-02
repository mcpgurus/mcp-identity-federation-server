# MCP Identity Federation Server - API Documentation

This document provides detailed API documentation for the MCP Identity Federation Server endpoints with sample requests and responses.

## Base URL
```
http://localhost:8080/mcp-idp-federation
```

---

## 1. OAuth2 Authorization Server Discovery

### Endpoint
```http
GET /.well-known/oauth-authorization-server
```

### Description
Returns OAuth2 authorization server metadata as defined in RFC 8414. This endpoint provides clients with information about the server's capabilities, supported endpoints, and configuration.

### Authentication
- **Public endpoint** - No authentication required

### Request

#### HTTP Request
```http
GET http://localhost:8080/mcp-idp-federation/.well-known/oauth-authorization-server HTTP/1.1
Host: localhost:8080
Accept: application/json
```

#### cURL Example
```bash
curl -X GET \
  "http://localhost:8080/mcp-idp-federation/.well-known/oauth-authorization-server" \
  -H "Accept: application/json"
```

#### PowerShell Example
```powershell
Invoke-RestMethod -Uri "http://localhost:8080/mcp-idp-federation/.well-known/oauth-authorization-server" -Method GET
```

### Response

#### Success Response (200 OK)
```http
HTTP/1.1 200 OK
Content-Type: application/json
Cache-Control: no-cache, no-store, max-age=0, must-revalidate
X-Content-Type-Options: nosniff
X-Frame-Options: DENY

{
  "issuer": "http://localhost:8080/mcp-idp-federation",
  "authorization_endpoint": "http://localhost:8080/mcp-idp-federation/oauth/authorize",
  "token_endpoint": "http://localhost:8080/mcp-idp-federation/oauth/token",
  "registration_endpoint": "http://localhost:8080/mcp-idp-federation/oauth/register",
  "userinfo_endpoint": "http://localhost:8080/mcp-idp-federation/oauth/userinfo",
  "jwks_uri": "http://localhost:8080/mcp-idp-federation/.well-known/jwks.json",
  "response_types_supported": ["code"],
  "response_modes_supported": ["query", "fragment"],
  "grant_types_supported": ["authorization_code", "refresh_token"],
  "code_challenge_methods_supported": ["S256"],
  "scopes_supported": ["openid", "profile", "email", "mcp:read", "mcp:write"],
  "token_endpoint_auth_methods_supported": ["client_secret_basic", "client_secret_post"],
  "claims_supported": ["sub", "iss", "aud", "exp", "iat", "auth_time", "nonce", "email", "name"],
  "subject_types_supported": ["public"],
  "id_token_signing_alg_values_supported": ["RS256"]
}
```

#### Response Fields
| Field | Type | Description |
|-------|------|-------------|
| `issuer` | string | The authorization server's issuer identifier |
| `authorization_endpoint` | string | URL of the authorization endpoint |
| `token_endpoint` | string | URL of the token endpoint |
| `registration_endpoint` | string | URL for dynamic client registration |
| `userinfo_endpoint` | string | URL of the UserInfo endpoint |
| `jwks_uri` | string | URL of the JSON Web Key Set |
| `response_types_supported` | array | OAuth2 response types supported |
| `response_modes_supported` | array | OAuth2 response modes supported |
| `grant_types_supported` | array | OAuth2 grant types supported |
| `code_challenge_methods_supported` | array | PKCE code challenge methods |
| `scopes_supported` | array | OAuth2 scopes supported |
| `token_endpoint_auth_methods_supported` | array | Client authentication methods |
| `claims_supported` | array | Claims that can be returned in tokens |
| `subject_types_supported` | array | Subject identifier types supported |
| `id_token_signing_alg_values_supported` | array | ID token signing algorithms |

---

## 2. Dynamic Client Registration

### Endpoint
```http
POST /oauth/register
```

### Description
Allows MCP clients to register themselves dynamically as OAuth2 clients as defined in RFC 7591. This eliminates the need for manual client registration and enables automated MCP deployment scenarios.

### Authentication
- **Public endpoint** - No authentication required

### Request

#### HTTP Request
```http
POST http://localhost:8080/mcp-idp-federation/oauth/register HTTP/1.1
Host: localhost:8080
Content-Type: application/json
Accept: application/json

{
  "client_name": "My MCP Client",
  "redirect_uris": [
    "http://localhost:3000/callback",
    "https://myapp.example.com/oauth/callback"
  ],
  "grant_types": ["authorization_code", "refresh_token"],
  "response_types": ["code"],
  "scope": ["mcp:read", "mcp:write", "openid", "profile"]
}
```

#### cURL Example
```bash
curl -X POST \
  "http://localhost:8080/mcp-idp-federation/oauth/register" \
  -H "Content-Type: application/json" \
  -H "Accept: application/json" \
  -d '{
    "client_name": "My MCP Client",
    "redirect_uris": [
      "http://localhost:3000/callback",
      "https://myapp.example.com/oauth/callback"
    ],
    "grant_types": ["authorization_code", "refresh_token"],
    "response_types": ["code"],
    "scope": ["mcp:read", "mcp:write", "openid", "profile"]
  }'
```

#### PowerShell Example
```powershell
$body = @{
    client_name = "My MCP Client"
    redirect_uris = @(
        "http://localhost:3000/callback",
        "https://myapp.example.com/oauth/callback"
    )
    grant_types = @("authorization_code", "refresh_token")
    response_types = @("code")
    scope = @("mcp:read", "mcp:write", "openid", "profile")
} | ConvertTo-Json

Invoke-RestMethod -Uri "http://localhost:8080/mcp-idp-federation/oauth/register" `
  -Method POST `
  -ContentType "application/json" `
  -Body $body
```

#### Request Fields
| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `client_name` | string | **Yes** | Human-readable name of the client |
| `redirect_uris` | array | **Yes** | Array of redirect URIs for the client |
| `grant_types` | array | No | OAuth2 grant types (default: `["authorization_code"]`) |
| `response_types` | array | No | OAuth2 response types (default: `["code"]`) |
| `scope` | array | No | Requested scopes (default: server default scopes) |

### Response

#### Success Response (200 OK)
```http
HTTP/1.1 200 OK
Content-Type: application/json
Cache-Control: no-cache, no-store, max-age=0, must-revalidate
X-Content-Type-Options: nosniff
X-Frame-Options: DENY

{
  "client_id": "ee2a5045-a612-4c88-a2f0-53104e648abf",
  "client_secret": "c9f78996ada44a8b9e81af52bc82b9ae",
  "client_id_issued_at": 1762061812,
  "client_secret_expires_at": 0,
  "client_name": "My MCP Client",
  "redirect_uris": [
    "http://localhost:3000/callback",
    "https://myapp.example.com/oauth/callback"
  ],
  "grant_types": ["authorization_code", "refresh_token"],
  "response_types": ["code"],
  "scope": "mcp:read mcp:write openid profile",
  "token_endpoint_auth_method": "client_secret_basic"
}
```

#### Response Fields
| Field | Type | Description |
|-------|------|-------------|
| `client_id` | string | Unique client identifier (UUID format) |
| `client_secret` | string | Client secret for authentication |
| `client_id_issued_at` | number | Unix timestamp when client ID was issued |
| `client_secret_expires_at` | number | Unix timestamp when secret expires (0 = never) |
| `client_name` | string | Human-readable name of the client |
| `redirect_uris` | array | Registered redirect URIs |
| `grant_types` | array | Approved grant types |
| `response_types` | array | Approved response types |
| `scope` | string | Space-separated approved scopes |
| `token_endpoint_auth_method` | string | Client authentication method |

#### Error Responses

##### 400 Bad Request - Missing Required Fields
```http
HTTP/1.1 400 Bad Request
Content-Type: application/json

{
  "error": "invalid_client_metadata",
  "error_description": "client_name is required"
}
```

##### 400 Bad Request - Invalid Redirect URI
```http
HTTP/1.1 400 Bad Request
Content-Type: application/json

{
  "error": "invalid_redirect_uri",
  "error_description": "redirect_uris must be provided and contain valid URIs"
}
```

##### 403 Forbidden - Registration Disabled
```http
HTTP/1.1 403 Forbidden
Content-Type: application/json

{
  "error": "registration_not_supported",
  "error_description": "Dynamic client registration is not enabled"
}
```

##### 429 Too Many Requests - Rate Limited
```http
HTTP/1.1 429 Too Many Requests
Content-Type: application/json

{
  "error": "too_many_requests",
  "error_description": "Too many registration requests from this IP address"
}
```

##### 500 Internal Server Error
```http
HTTP/1.1 500 Internal Server Error
Content-Type: application/json

{
  "error": "server_error",
  "error_description": "An internal server error occurred"
}
```

---

## Configuration

### Enable/Disable Dynamic Registration
Dynamic client registration can be controlled via configuration:

```yaml
mcp:
  federation:
    client-registration:
      dynamic-registration-enabled: true  # Set to false to disable
      max-clients-per-ip: 10             # Rate limiting
      default-scopes:                    # Default scopes for new clients
        - mcp:read
        - mcp:write
```

### Environment Variables
```bash
# Enable/disable dynamic registration
MCP_DYNAMIC_REGISTRATION_ENABLED=true

# Set maximum clients per IP
MCP_MAX_CLIENTS_PER_IP=10
```

---

## Security Considerations

1. **Rate Limiting**: The server implements IP-based rate limiting for client registration
2. **Scope Validation**: Only predefined scopes are allowed
3. **URI Validation**: Redirect URIs are validated for security
4. **Public Endpoints**: Both endpoints are publicly accessible as per OAuth2 specifications
5. **HTTPS Recommended**: Use HTTPS in production environments

---

## Standards Compliance

- **RFC 8414**: OAuth 2.0 Authorization Server Metadata
- **RFC 7591**: OAuth 2.0 Dynamic Client Registration Protocol
- **RFC 6749**: The OAuth 2.0 Authorization Framework
- **RFC 7636**: Proof Key for Code Exchange (PKCE)

---

## Next Steps

After registering a client, you can use the returned `client_id` and `client_secret` to:

1. Initiate OAuth2 authorization flows
2. Exchange authorization codes for access tokens
3. Access protected MCP resources

For complete OAuth2 flow examples, see the main README.md file.