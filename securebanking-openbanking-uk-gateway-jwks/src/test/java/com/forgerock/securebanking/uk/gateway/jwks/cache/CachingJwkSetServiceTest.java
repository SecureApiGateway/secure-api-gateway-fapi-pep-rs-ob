package com.forgerock.securebanking.uk.gateway.jwks.cache;

import java.net.URL;

import org.forgerock.json.jose.jwk.JWKSet;

/**
 * Test CachingJwkSetService with a HashMapCache as the Cache implementation.
 */
public class CachingJwkSetServiceTest extends BaseCachingJwkSetServiceTest {
    @Override
    protected Cache<URL, JWKSet> createSimpleCache() {
        return new HashMapCache<>();
    }
}
