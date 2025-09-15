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

import static org.assertj.core.api.Assertions.assertThat;
import static org.forgerock.http.protocol.Status.BAD_REQUEST;
import static org.forgerock.http.protocol.Status.INTERNAL_SERVER_ERROR;
import static org.forgerock.http.protocol.Status.OK;
import static org.forgerock.json.JsonValue.field;
import static org.forgerock.json.JsonValue.json;
import static org.forgerock.json.JsonValue.object;
import static org.forgerock.util.promise.Promises.newResultPromise;

import java.io.IOException;

import org.forgerock.http.Handler;
import org.forgerock.http.header.ContentTypeHeader;
import org.forgerock.http.protocol.Request;
import org.forgerock.http.protocol.Response;
import org.forgerock.http.protocol.Status;
import org.forgerock.json.JsonValue;
import org.forgerock.services.context.RootContext;
import org.junit.jupiter.api.Test;

public class RepoApiErrorTransformFilterTest {

    @Test
    void shouldTransformResponseWithClientError() throws IOException {
        // Given
        final Response clientErrorResponse = new Response(BAD_REQUEST);
        clientErrorResponse.getHeaders().put(ContentTypeHeader.NAME, "application/json");
        clientErrorResponse.getEntity().setJson(json(object(field("errorMessage", "Invalid request"))));
        Handler mockHandler = (context, request) -> newResultPromise(clientErrorResponse);
        RepoApiErrorTransformFilter filter = new RepoApiErrorTransformFilter();
        // When
        Response response = filter.filter(new RootContext(), new Request(), mockHandler).getOrThrowIfInterrupted();
        //Then
        assertThat(response.getStatus()).isEqualTo(BAD_REQUEST);
        JsonValue responseJson = json(response.getEntity().getJson());
        assertThat(responseJson.get("error").asString()).isEqualTo("invalid_request_object");
        assertThat(responseJson.get("error_description").asString()).isEqualTo("Invalid request");
    }

    @Test
    void shouldNotTransformResponseWithoutJsonContent() {
        // Given
        Response nonJsonResponse = new Response(BAD_REQUEST);
        nonJsonResponse.getHeaders().put(ContentTypeHeader.NAME, "text/plain");
        Handler mockHandler = (context, request) -> newResultPromise(nonJsonResponse);
        RepoApiErrorTransformFilter filter = new RepoApiErrorTransformFilter();
        // When
        Response response = filter.filter(new RootContext(), new Request(), mockHandler).getOrThrowIfInterrupted();
        // Then
        assertThat(response.getStatus()).isEqualTo(BAD_REQUEST);
        assertThat(response.getHeaders().getFirst(ContentTypeHeader.NAME)).isEqualTo("text/plain");
    }

    @Test
    void shouldNotTransformResponseWithoutClientError() throws IOException {
        // Given
        Response successResponse = new Response(Status.OK);
        successResponse.getHeaders().put(ContentTypeHeader.NAME, "application/json");
        successResponse.getEntity().setJson(json(object(field("meaning", 42))));
        Handler mockHandler = (context, request) -> newResultPromise(successResponse);
        RepoApiErrorTransformFilter filter = new RepoApiErrorTransformFilter();
        // When
        Response response = filter.filter(new RootContext(), new Request(), mockHandler).getOrThrowIfInterrupted();
        // Then - response unchanged
        assertThat(response.getStatus()).isEqualTo(OK);
        assertThat(response.getHeaders().getFirst(ContentTypeHeader.NAME)).startsWith("application/json");
        JsonValue responseJson = json(response.getEntity().getJson());
        assertThat(responseJson.get("meaning").asInteger()).isEqualTo(42);
    }

    @Test
    void shouldHandleInvalidJsonGracefully() {
        // Given
        Response invalidJsonResponse = new Response(BAD_REQUEST);
        invalidJsonResponse.getHeaders().put(ContentTypeHeader.NAME, "application/json");
        invalidJsonResponse.getEntity().setString("Invalid JSON");
        Handler mockHandler = (context, request) -> newResultPromise(invalidJsonResponse);
        RepoApiErrorTransformFilter filter = new RepoApiErrorTransformFilter();
        // When
        Response response = filter.filter(new RootContext(), new Request(), mockHandler).getOrThrowIfInterrupted();
        // Then
        assertThat(response.getStatus()).isEqualTo(INTERNAL_SERVER_ERROR);
    }
}
