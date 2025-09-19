/*
 * Copyright © 2020-2025 ForgeRock AS (obst@forgerock.com)
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
package com.forgerock.sapi.gateway.ob.consent;

import static org.forgerock.http.protocol.Response.newResponsePromise;
import static org.forgerock.http.protocol.Responses.newInternalServerError;
import static org.forgerock.json.JsonValue.field;
import static org.forgerock.json.JsonValue.fieldIfNotNull;
import static org.forgerock.json.JsonValue.json;
import static org.forgerock.json.JsonValue.object;

import java.util.List;
import java.util.Map;

import org.forgerock.http.Filter;
import org.forgerock.http.Handler;
import org.forgerock.http.header.ContentTypeHeader;
import org.forgerock.http.protocol.Request;
import org.forgerock.http.protocol.Response;
import org.forgerock.json.JsonValue;
import org.forgerock.openig.heap.GenericHeaplet;
import org.forgerock.services.context.Context;
import org.forgerock.util.promise.NeverThrowsException;
import org.forgerock.util.promise.Promise;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Filter responsible for transforming RCS API error responses appropriately for OpenBanking use. Notably, RCS failures
 * have the form:
 * <pre>
 * {@code
 *     {
 *       "errorMessage": "Request binding failed.",
 *       "reason": "Null or empty redirect URL. Falling back to just throwing error back to UI"
 *     }
 * }
 * </pre>
 * <p>This is reformatted to OAuth2 expected error format with fields {@code error} and {@code error_description}.
 *
 * @see <a href="https://datatracker.ietf.org/doc/html/rfc6749#section-5.2">RFC-6749, section 5.2</a>
 */
public class RepoApiErrorTransformFilter implements Filter {

    private static final Logger logger = LoggerFactory.getLogger(RepoApiErrorTransformFilter.class);

    private static final String LEGACY_ERROR_MESSAGE = "errorMessage";
    private static final String OAUTH2_ERROR = "error";
    private static final String OAUTH2_ERROR_DESCRIPTION = "error_description";
    private static final String DEFAULT_OAUTH2_ERROR = "invalid_request_object";

    // Map of AM error_description to transformed error.
    private static final Map<String, String> ERROR_TRANSFORMS = Map.of(
            "code_verifier parameter required", "invalid_grant",
            "The redirection URI provided does not match a pre-registered value.", "invalid_request_object");

    @Override
    public Promise<Response, NeverThrowsException> filter(final Context context,
                                                          final Request request,
                                                          final Handler next) {
        return next.handle(context, request)
                   .thenAsync(response -> {
                       if (!isApplicationJsonResponse(response)) {
                           return newResponsePromise(response);
                       }
                       if (!response.getStatus().isClientError()) {
                           return newResponsePromise(response);
                       }
                       return response.getEntity()
                                      .getJsonAsync()
                                      .then(JsonValue::json)
                                      .then(errorResponseJson -> {
                                          logger.debug("Response has a client error {}", response.getStatus());
                                          response.getEntity()
                                                  .setJson(transformErrorResponse(errorResponseJson));
                                          return response;
                                      }, ioe -> newInternalServerError());
                   });
    }

    private static boolean isApplicationJsonResponse(final Response response) {
        List<String> mediaTypes = response.getHeaders().getAll(ContentTypeHeader.NAME);
        return mediaTypes.stream().anyMatch(mediaType -> mediaType.startsWith("application/json"));
    }

    private static JsonValue transformErrorResponse(final JsonValue errorResponseJson) {
        JsonValue legacyErrorMessageJson = errorResponseJson.get(LEGACY_ERROR_MESSAGE);
        JsonValue transformedErrorJson = json(object(
                field(OAUTH2_ERROR, DEFAULT_OAUTH2_ERROR),
                fieldIfNotNull(OAUTH2_ERROR_DESCRIPTION, legacyErrorMessageJson.asString())
        ));
        logger.debug("Transformed RCS API error from {} to {}", errorResponseJson, transformedErrorJson);
        return transformedErrorJson;
    }

    /** Create a new {@link RepoApiErrorTransformFilter} in a heap environment. */
    public static class Heaplet extends GenericHeaplet {
        @Override
        public Object create() {
            return new RepoApiErrorTransformFilter();
        }
    }
}
