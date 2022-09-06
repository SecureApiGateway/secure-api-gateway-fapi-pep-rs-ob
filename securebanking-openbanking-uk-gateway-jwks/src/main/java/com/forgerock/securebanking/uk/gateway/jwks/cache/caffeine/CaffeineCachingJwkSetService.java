package com.forgerock.securebanking.uk.gateway.jwks.cache.caffeine;

import java.net.URL;

import org.forgerock.json.jose.jwk.JWKSet;

import com.forgerock.securebanking.uk.gateway.jwks.JwkSetService;
import com.forgerock.securebanking.uk.gateway.jwks.cache.CachingJwkSetService;

/**
 * Implementation of {@link CachingJwkSetService} which uses a {@link CaffeineCache} as its cache implementation.
 * This class is required in order to be able to create an instance via IG config.
 */
public class CaffeineCachingJwkSetService extends CachingJwkSetService {
    public CaffeineCachingJwkSetService(JwkSetService underlyingStore, CaffeineCache<URL, JWKSet> jwkSetCache) {
        super(underlyingStore, jwkSetCache);
    }
}
