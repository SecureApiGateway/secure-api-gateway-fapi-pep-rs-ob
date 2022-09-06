package com.forgerock.securebanking.uk.gateway.jwks.cache.caffeine;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

import java.lang.reflect.Field;
import java.time.Duration;
import java.util.concurrent.locks.LockSupport;
import java.util.stream.LongStream;

import org.junit.jupiter.api.Test;

import com.forgerock.securebanking.uk.gateway.jwks.cache.caffeine.CaffeineCache.CacheOptions;
import com.github.benmanes.caffeine.cache.Cache;

class CaffeineCacheTest {

    public static <K, V> CaffeineCache<K, V> createCacheNoTimeExpiry(long maxSize) {
        return createCache(maxSize, Duration.ofDays(10));
    }

    /**
     * Creates a CaffeineCache which configures the cache executor thread to run on the calling thread.
     * <p>
     * The executor thread handles cache housekeeping tasks, such as evicting items. For test purposes we want the
     * housekeeping work to be done on the calling thread, so that items are evicted synchronously.
     */
    public static <K, V> CaffeineCache<K, V> createCache(long maxSize, Duration expireAfterWrite) {
        return new CaffeineCache<>(new CacheOptions().executor(Runnable::run)
                .expireAfterWrite(expireAfterWrite)
                .maximumCacheEntries(maxSize));
    }

    @Test
    void shouldCacheThings() {
        long maxSize = 1000L;
        final CaffeineCache<String, Long> cache = createCacheNoTimeExpiry(maxSize);
        LongStream.range(0, maxSize).forEach(index -> cache.put(String.valueOf(index), index));
        LongStream.range(0, maxSize).forEach(index -> assertEquals(index, cache.get(String.valueOf(index))));
    }

    @Test
    void shouldLimitCacheSize() {
        final int maxSize = 5;
        final CaffeineCache<String, String> cache = createCacheNoTimeExpiry(maxSize);
        final int numWrites = 100;
        for (int i = 0; i < numWrites; i++) {
            cache.put("key" + i, "value" + i);
        }
        assertEquals(maxSize, getUnderlyingCache(cache).estimatedSize());
    }

    @Test
    void shouldEvictEntriesBasedOnTime() {
        final int maxSize = 100;
        final Duration expiryDuration = Duration.ofMillis(10L);
        final CaffeineCache<String, String> cache = createCache(maxSize, expiryDuration);
        for (int i = 0; i < maxSize; i++) {
            cache.put("key" + i, "value" + i);
        }
        final Cache<String, String> underlyingCache = getUnderlyingCache(cache);
        assertEquals(maxSize, underlyingCache.estimatedSize());

        LockSupport.parkNanos(expiryDuration.toNanos());
        // Attempt to get something from the cache, which will trigger the eviction
        assertNull(cache.get("key1"));
        assertEquals(0, underlyingCache.estimatedSize());
    }

    @Test
    void shouldRetainRecentlyUsedEntries() {
        final int maxSize = 5;
        final CaffeineCache<String, String> cache = createCacheNoTimeExpiry(maxSize);

        final int numWrites = 100;
        for (int i = 0; i < numWrites; i++) {
            cache.put("key" + i, "value" + i);
            // Keep fetching the first key so that it doesnt get evicted
            assertEquals("value0", cache.get("key0"));
        }
        final Cache<String, String> underlyingCache = getUnderlyingCache(cache);
        assertEquals("value0", cache.get("key0"));
        assertEquals(maxSize, underlyingCache.estimatedSize());
    }

    /**
     * Helper method to retrieve the underlying cache impl to do some asserts on
     */
    private <K, V> Cache<K, V> getUnderlyingCache(CaffeineCache<K, V> caffeineCache) {
        try {
            final Field cacheField = CaffeineCache.class.getDeclaredField("cache");
            cacheField.setAccessible(true);
            return (Cache<K, V>) cacheField.get(caffeineCache);
        } catch (NoSuchFieldException | IllegalAccessException e) {
            throw new RuntimeException(e);
        }
    }
}