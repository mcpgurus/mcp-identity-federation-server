# MCP Identity Federation Server

A standalone identity federation server that provides OAuth2/OIDC proxy services for Model Context Protocol (MCP) implementations. This server acts as an intermediary between MCP clients and multiple Identity Providers, enabling secure, scalable, and centrally managed authentication for AI-driven enterprise systems.

## Features

### Core Capabilities
- **Multi-IdP Federation**: Support for Microsoft Entra ID, Okta, PingFederate, and other OIDC providers
- **OAuth2 Discovery**: RFC 8414 compliant authorization server metadata
- **Dynamic Client Registration**: RFC 7591 compliant client registration
- **PKCE Security**: Dual PKCE flow implementation for enhanced security
- **API Key Abstraction**: Shields MCP clients from IdP token complexity
- **Policy Engine Integration**: Optional integration with external policy engines (OPA, etc.)
- **Distributed Caching**: Redis-based token and client storage
- **Comprehensive Monitoring**: Actuator endpoints with Prometheus metrics

### Security Features
- **Zero Token Exposure**: MCP clients never handle raw IdP tokens
- **Centralized Token Management**: Secure token storage and lifecycle management
- **Rate Limiting**: IP-based client registration limits
- **Fail-Safe Design**: Secure defaults with fail-closed behavior
- **Audit Logging**: Comprehensive security event logging

## Quick API Reference

### Key Endpoints

#### OAuth2 Discovery
```http
GET /.well-known/oauth-authorization-server
```
Returns OAuth2 server metadata (RFC 8414 compliant)

#### Dynamic Client Registration  
```http
POST /oauth/register
Content-Type: application/json

{
  "client_name": "My MCP Client",
  "redirect_uris": ["http://localhost:3000/callback"]
}
```
Register a new OAuth2 client (RFC 7591 compliant)

📖 **[Complete API Documentation](API_DOCUMENTATION.md)** - Detailed examples, request/response formats, and error codes

## Quick Start

### Prerequisites
- Java 21 or higher
- Redis server (optional - auto-fallback to in-memory cache)
- At least one configured Identity Provider

### Installation

1. **Clone and Build**
   ```bash
   git clone <repository-url>
   cd mcp-identity-federation-server
   ./gradlew build
   ```

2. **Configure Identity Providers**
   
   Edit `src/main/resources/application.yml`:
   ```yaml
   mcp:
     federation:
       identity-providers:
         entra-id:
           enabled: true
           client-id: your-entra-client-id
           client-secret: your-entra-client-secret
           tenant-id: your-tenant-id
   ```

3. **Start Redis**
   ```bash
   docker run -d -p 6379:6379 redis:alpine
   ```

4. **Run the Server**
   ```bash
   ./gradlew bootRun
   ```

The server will start on `http://localhost:8080/mcp-federation`

### Environment Variables

Configure Identity Providers using environment variables:

```bash
# Microsoft Entra ID
export ENTRA_CLIENT_ID=your-entra-client-id
export ENTRA_CLIENT_SECRET=your-entra-client-secret
export ENTRA_TENANT_ID=your-tenant-id

# Okta
export OKTA_CLIENT_ID=your-okta-client-id
export OKTA_CLIENT_SECRET=your-okta-client-secret
export OKTA_DOMAIN=your-domain.okta.com

# PingFederate
export PING_CLIENT_ID=your-ping-client-id
export PING_CLIENT_SECRET=your-ping-client-secret
export PING_BASE_URL=https://your-ping-server.com

# Policy Engine (Optional)
export POLICY_ENGINE_ENDPOINT=http://localhost:9090/policy/evaluate
export POLICY_ENGINE_TOKEN=your-policy-token
```

## Configuration

### Identity Providers

The server supports multiple Identity Providers simultaneously. Each IdP can be enabled/disabled independently:

```yaml
mcp:
  federation:
    identity-providers:
      entra-id:
        enabled: true
        type: oidc
        name: "Microsoft Entra ID"
        client-id: ${ENTRA_CLIENT_ID}
        client-secret: ${ENTRA_CLIENT_SECRET}
        tenant-id: ${ENTRA_TENANT_ID}
        scopes: openid profile email offline_access
        
      okta:
        enabled: false
        type: oidc
        name: "Okta"
        client-id: ${OKTA_CLIENT_ID}
        client-secret: ${OKTA_CLIENT_SECRET}
        domain: ${OKTA_DOMAIN}
        scopes: openid profile email offline_access
```

### Policy Engine Integration

Enable optional policy engine integration for fine-grained access control:

```yaml
mcp:
  federation:
    policy-engine:
      enabled: true
      endpoint: http://localhost:9090/policy/evaluate
      timeout: 5000ms
      headers:
        Authorization: Bearer ${POLICY_ENGINE_TOKEN}
        Content-Type: application/json
```

### Redis Configuration

Configure Redis for distributed token storage:

```yaml
spring:
  data:
    redis:
      host: localhost
      port: 6379
      timeout: 2000ms
      lettuce:
        pool:
          max-active: 8
          max-idle: 8
          min-idle: 0
```

## API Endpoints

### OAuth2 Discovery
- `GET /.well-known/oauth-authorization-server` - OAuth2 server metadata

### Client Registration
- `POST /oauth/register` - Dynamic client registration
- `GET /oauth/client/{clientId}` - Client information

### OAuth2 Flow
- `GET /oauth/authorize` - Authorization endpoint
- `POST /oauth/token` - Token exchange endpoint
- `POST /oauth/renew` - Token renewal endpoint

### Monitoring
- `GET /actuator/health` - Health check
- `GET /actuator/metrics` - Application metrics
- `GET /actuator/prometheus` - Prometheus metrics

## Usage Examples

### 1. Client Registration

```bash
curl -X POST http://localhost:8080/mcp-federation/oauth/register \
  -H "Content-Type: application/json" \
  -d '{
    "client_name": "My MCP Client",
    "redirect_uris": ["http://localhost:3000/callback"]
  }'
```

Response:
```json
{
  "client_id": "550e8400-e29b-41d4-a716-446655440000",
  "client_secret": "abcd1234...",
  "client_name": "My MCP Client",
  "redirect_uris": ["http://localhost:3000/callback"],
  "grant_types": ["authorization_code"],
  "response_types": ["code"]
}
```

### 2. Authorization Flow

```bash
# Step 1: Authorization Request
curl -X GET "http://localhost:8080/mcp-federation/oauth/authorize?client_id=550e8400-e29b-41d4-a716-446655440000&redirect_uri=http://localhost:3000/callback&code_challenge=dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk&code_challenge_method=S256&state=xyz123&response_type=code"

# Step 2: Token Exchange (after callback)
curl -X POST http://localhost:8080/mcp-federation/oauth/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=authorization_code&code=auth_code_from_callback&code_verifier=dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk&client_id=550e8400-e29b-41d4-a716-446655440000"
```

Response:
```json
{
  "access_token": "mcp_ak_abcd1234...",
  "token_type": "Bearer",
  "expires_in": 86400,
  "scope": "mcp:read mcp:write"
}
```

### 3. Using API Key with MCP Server

```bash
curl -X GET http://your-mcp-server/api/resources \
  -H "Authorization: Bearer mcp_ak_abcd1234..."
```

## Docker Deployment

### Docker Compose

```yaml
version: '3.8'
services:
  mcp-federation:
    build: .
    ports:
      - "8080:8080"
    environment:
      - ENTRA_CLIENT_ID=your-client-id
      - ENTRA_CLIENT_SECRET=your-client-secret
      - ENTRA_TENANT_ID=your-tenant-id
      - SPRING_DATA_REDIS_HOST=redis
    depends_on:
      - redis
      
  redis:
    image: redis:alpine
    ports:
      - "6379:6379"
```

### Kubernetes Deployment

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: mcp-federation-server
spec:
  replicas: 3
  selector:
    matchLabels:
      app: mcp-federation-server
  template:
    metadata:
      labels:
        app: mcp-federation-server
    spec:
      containers:
      - name: mcp-federation
        image: mcp-federation-server:latest
        ports:
        - containerPort: 8080
        env:
        - name: ENTRA_CLIENT_ID
          valueFrom:
            secretKeyRef:
              name: idp-credentials
              key: entra-client-id
        - name: ENTRA_CLIENT_SECRET
          valueFrom:
            secretKeyRef:
              name: idp-credentials
              key: entra-client-secret
```

## Monitoring and Observability

### Health Checks
```bash
curl http://localhost:8080/mcp-federation/actuator/health
```

### Metrics
```bash
curl http://localhost:8080/mcp-federation/actuator/metrics
curl http://localhost:8080/mcp-federation/actuator/prometheus
```

### Logging

Configure logging levels in `application.yml`:
```yaml
logging:
  level:
    org.mcpgurus.mcp.federation: DEBUG
    org.springframework.security: INFO
```

## Security Considerations

### Production Deployment
1. **Use HTTPS**: Always deploy with TLS/SSL in production
2. **Secure Redis**: Use Redis AUTH and TLS for production deployments
3. **Environment Variables**: Never commit secrets to version control
4. **Network Security**: Restrict network access to federation server
5. **Monitoring**: Implement comprehensive security monitoring

### Token Security
- API keys are opaque and high-entropy
- IdP tokens are never exposed to clients
- Automatic token cleanup via Redis TTL
- Secure token storage with encryption at rest

## Troubleshooting

### Common Issues

1. **Redis Connection Failed**
   ```
   Solution: Ensure Redis is running and accessible
   Check: spring.data.redis.host and port configuration
   ```

2. **IdP Authentication Failed**
   ```
   Solution: Verify client credentials and endpoints
   Check: Identity provider configuration in application.yml
   ```

3. **Policy Engine Timeout**
   ```
   Solution: Check policy engine availability
   Check: mcp.federation.policy-engine.endpoint configuration
   ```

### Debug Mode

Enable debug logging:
```yaml
logging:
  level:
    org.mcpgurus.mcp.federation: DEBUG
```

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests
5. Submit a pull request

## License

Copyright (c) 2024 Pramod Kumar Sahu. All rights reserved.

## Support

For support and questions:
- Create an issue in the repository
- Contact the Enterprise Architecture Team
- Review the [Architecture Documentation](ARCHITECTURE.md)