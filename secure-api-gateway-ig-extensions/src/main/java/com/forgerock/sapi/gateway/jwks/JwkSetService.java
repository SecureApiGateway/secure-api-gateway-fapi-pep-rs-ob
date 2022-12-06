/*
 * Copyright © 2020-2022 ForgeRock AS (obst@forgerock.com)
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
package com.forgerock.sapi.gateway.jwks;

import java.net.URL;

import org.forgerock.json.jose.exceptions.FailedToLoadJWKException;
import org.forgerock.json.jose.jwk.JWK;
import org.forgerock.json.jose.jwk.JWKSet;
import org.forgerock.util.promise.Promise;

/**
 * Service which can retrieve JWKSet and JWK objects
 */
public interface JwkSetService {

    /**
     * Retrieves a JWKSet for the specified url
     *
     * @param jwkStoreUrl - url of the JWKSet store
     * @return Promise which either returns a non-null JWKSet or fails with a FailedToLoadJWKException
     */
    Promise<JWKSet, FailedToLoadJWKException> getJwkSet(URL jwkStoreUrl);

    /**
     * Retrieves a JWK with the specified keyId from the JWKSet at the specified url.
     *
     * @param jwkStoreUrl - url of the JWKSet store
     * @param keyId - the id (kid) of the JWK within the store to return
     * @return Promise which either returns a non-null JWK or fails with a FailedToLoadJWKException
     */
    Promise<JWK, FailedToLoadJWKException> getJwk(URL jwkStoreUrl, String keyId);

}
