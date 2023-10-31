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
package com.forgerock.sapi.gateway.metrics;

import java.io.IOException;
import java.util.Collections;
import java.util.List;
import java.util.Map;

import org.forgerock.http.protocol.Request;
import org.forgerock.openig.heap.GenericHeaplet;
import org.forgerock.openig.heap.HeapException;
import org.forgerock.services.context.Context;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Supplies Context information for the Token Endpoint route.
 * <p>
 * The context contains a single field: "grant_type" which is extracted from the Request's form parameter of the same
 * name. This represents the OAuth2.0 grant_type of the token that is being requested.
 */
public class TokenEndpointMetricsContextSupplier implements MetricsContextSupplier {

    private static final String GRANT_TYPE = "grant_type";

    private final Logger logger = LoggerFactory.getLogger(getClass());

    @Override
    public Map<String, Object> getMetricsContext(Context requestContext, Request request) {
        final String grantType = getGrantType(request);
        if (grantType != null) {
            return Map.of("grant_type", grantType);
        }
        return Collections.emptyMap();
    }

    private String getGrantType(Request request) {
        final List<String> grantTypeParams;
        try {
            grantTypeParams = request.getEntity().getForm().get(GRANT_TYPE);
            if (grantTypeParams != null && grantTypeParams.size() > 0) {
                return grantTypeParams.get(0);
            }
        } catch (IOException e) {
            logger.error("Failed to get grant_type from request form", e);
        }
        return null;
    }

    public static class Heaplet extends GenericHeaplet {
        @Override
        public Object create() throws HeapException {
            return new TokenEndpointMetricsContextSupplier();
        }
    }
}
