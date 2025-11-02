package org.mcpgurus.mcp.federation.config;

import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.cache.CacheManager;
import org.springframework.cache.annotation.EnableCaching;
import org.springframework.cache.concurrent.ConcurrentMapCacheManager;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Primary;
import org.springframework.data.redis.cache.RedisCacheManager;
import org.springframework.data.redis.connection.RedisConnectionFactory;

/**
 * Cache Configuration for MCP Identity Federation Server
 * 
 * Provides flexible caching configuration with automatic fallback:
 * - Redis cache when available and configured
 * - Simple in-memory cache as fallback or when explicitly configured
 * - Auto mode that tries Redis first, falls back to simple cache
 * 
 * Configuration options:
 * - spring.cache.type=redis: Use Redis cache (fails if Redis unavailable)
 * - spring.cache.type=simple: Use in-memory cache
 * - spring.cache.type=auto: Try Redis, fallback to simple (default)
 * 
 * @author Pramod Kumar Sahu
 */
@Slf4j
@Configuration
@EnableCaching
public class CacheConfig {

    @Value("${spring.cache.type:simple}")
    private String cacheType;

    /**
     * Primary Cache Manager with auto-fallback logic
     */
    @Bean
    @Primary
    public CacheManager cacheManager(RedisConnectionFactory redisConnectionFactory) {
        
        // If explicitly set to simple, use simple cache
        if ("simple".equals(cacheType)) {
            log.info("Cache type set to 'simple' - using in-memory cache");
            return createSimpleCacheManager();
        }
        
        // If set to redis or auto, try Redis first
        if ("redis".equals(cacheType) || "auto".equals(cacheType)) {
            try {
                // Test Redis connection
                redisConnectionFactory.getConnection().ping();
                log.info("Redis connection successful - using Redis cache");
                
                return RedisCacheManager.builder(redisConnectionFactory)
                        .cacheDefaults(org.springframework.data.redis.cache.RedisCacheConfiguration.defaultCacheConfig()
                                .entryTtl(java.time.Duration.ofHours(1)))
                        .build();
                        
            } catch (Exception e) {
                if ("redis".equals(cacheType)) {
                    log.error("Redis cache explicitly requested but connection failed: {}", e.getMessage());
                    throw new RuntimeException("Redis cache unavailable but explicitly required", e);
                } else {
                    log.warn("Redis connection failed: {}. Falling back to simple in-memory cache", e.getMessage());
                    return createSimpleCacheManager();
                }
            }
        }
        
        // Default fallback
        log.info("Using default simple in-memory cache");
        return createSimpleCacheManager();
    }

    /**
     * Create simple cache manager with predefined cache names
     */
    private CacheManager createSimpleCacheManager() {
        return new ConcurrentMapCacheManager("mcp-clients", "mcp-client-ip-counters");
    }
}
