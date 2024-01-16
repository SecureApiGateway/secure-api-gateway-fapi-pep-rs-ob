/*
 * Copyright © 2020-2024 ForgeRock AS (obst@forgerock.com)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.forgerock.sapi.gateway.jwks.mocks;

import java.net.URL;
import java.util.Collection;
import java.util.Map;

import org.forgerock.json.jose.exceptions.FailedToLoadJWKException;
import org.forgerock.json.jose.jwk.JWKSet;
import org.forgerock.util.promise.Promise;
import org.forgerock.util.promise.Promises;

import com.forgerock.sapi.gateway.jwks.cache.BaseCachingJwkSetServiceTest;

/**
 * JwkSetService impl which returns a pre-canned JWKSet for an expectedJwkStoreUrl.
 * Returns an error if getJwkSet is called with a different url, or i getJwk is called.
 */
public class MockJwkSetService extends BaseCachingJwkSetServiceTest.BaseCachingTestJwkSetService {
    private final Map<URL, JWKSet> jwkSetsByUrl;

    public MockJwkSetService(Map<URL, JWKSet> jwkSetsByURL) {
        this.jwkSetsByUrl = jwkSetsByURL;
    }

    @Override
    public Promise<JWKSet, FailedToLoadJWKException> getJwkSet(URL jwkStoreUrl) {
        if (jwkSetsByUrl.containsKey(jwkStoreUrl)) {
            return Promises.newResultPromise(jwkSetsByUrl.get(jwkStoreUrl));
        }
        return Promises.newExceptionPromise(new FailedToLoadJWKException("actual jwkStoreUrl: " + jwkStoreUrl
                + ", does not match expected: " + jwkSetsByUrl.keySet()));
    }
}