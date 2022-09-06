package com.forgerock.securebanking.uk.gateway.jwks.cache.caffeine;

import static org.forgerock.openig.util.JsonValues.javaDuration;

import java.net.URL;
import java.time.Duration;

import org.forgerock.json.jose.jwk.JWKSet;
import org.forgerock.openig.heap.HeapException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.forgerock.securebanking.uk.gateway.jwks.RestJwkSetService;
import com.forgerock.securebanking.uk.gateway.jwks.RestJwkSetServiceHeaplet;
import com.forgerock.securebanking.uk.gateway.jwks.cache.CachingJwkSetService;
import com.forgerock.securebanking.uk.gateway.jwks.cache.caffeine.CaffeineCache.CacheOptions;

/**
 * Creates a {@link CachingJwkSetService} which is backed by a {@link CaffeineCache}
 * <p>
 * Delegates to {@link RestJwkSetServiceHeaplet} to create the {@link RestJwkSetService}, configuration for RestJwkSetService
 * will be honoured.
 */
public class CaffeineCachingJwkSetServiceHeaplet extends RestJwkSetServiceHeaplet {

    private final Logger logger = LoggerFactory.getLogger(getClass());
    private static final long DEFAULT_MAX_CACHE_SIZE = 100L;
    /**
     * Represents a {@link org.forgerock.util.time.Duration}, an english representation of a duration.
     */
    private static final String DEFAULT_EXPIRE_AFTER_WRITE_DURATION = "5 minutes";

    @Override
    public Object create() throws HeapException {
        final RestJwkSetService restJwkSetService = createRestJwkSetService();
        return new CachingJwkSetService(restJwkSetService, createCaffeineCache());
    }

    private CaffeineCache<URL, JWKSet> createCaffeineCache() {
        final long maxCacheEntries = config.get("maxCacheEntries")
                .as(evaluatedWithHeapProperties())
                .defaultTo(DEFAULT_MAX_CACHE_SIZE)
                .asLong();
        final Duration expireAfterWrite = config.get("expireAfterWriteDuration")
                .as(evaluatedWithHeapProperties())
                .defaultTo(DEFAULT_EXPIRE_AFTER_WRITE_DURATION)
                .as(javaDuration());
        final CacheOptions options = new CacheOptions().maximumCacheEntries(maxCacheEntries)
                .expireAfterWrite(expireAfterWrite);
        logger.info("Creating a cache with options: {}", options);
        return new CaffeineCache<>(options);
    }
}
