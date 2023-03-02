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
package com.forgerock.sapi.gateway.dcr.idm;

import static com.forgerock.sapi.gateway.dcr.idm.IdmApiClientDecoderTest.createIdmApiClientDataRequiredFieldsOnly;
import static com.forgerock.sapi.gateway.dcr.idm.IdmApiClientDecoderTest.verifyIdmClientDataMatchesApiClientObject;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.net.URISyntaxException;
import java.util.concurrent.TimeUnit;

import org.forgerock.http.Client;
import org.forgerock.http.Handler;
import org.forgerock.http.MutableUri;
import org.forgerock.http.protocol.Form;
import org.forgerock.http.protocol.Request;
import org.forgerock.http.protocol.Response;
import org.forgerock.http.protocol.Status;
import org.forgerock.json.JsonValue;
import org.forgerock.openig.handler.Handlers;
import org.forgerock.services.context.Context;
import org.forgerock.util.promise.NeverThrowsException;
import org.forgerock.util.promise.Promise;
import org.forgerock.util.promise.Promises;
import org.junit.jupiter.api.Test;

import com.forgerock.sapi.gateway.dcr.models.ApiClient;

public class IdmApiClientServiceTest {

    public static final String TEST_IDM_BASE_URI = "http://localhost/openidm/managed/";
    public static final String TEST_CLIENT_ID = "9999";
    final IdmApiClientDecoder idmApiClientDecoder = new IdmApiClientDecoder();

    @Test
    void testGetApiClient() throws Exception {
        final JsonValue idmClientData = createIdmApiClientDataRequiredFieldsOnly(TEST_CLIENT_ID);
        final MockApiClientTestDataIdmHandler idmResponseHandler = new MockApiClientTestDataIdmHandler(TEST_IDM_BASE_URI, TEST_CLIENT_ID, idmClientData);

        final ApiClientService apiClientService = new IdmApiClientService(new Client(idmResponseHandler), TEST_IDM_BASE_URI, idmApiClientDecoder);
        final Promise<ApiClient, Exception> apiClientPromise = apiClientService.getApiClient(TEST_CLIENT_ID);
        final ApiClient apiClient = apiClientPromise.get(1, TimeUnit.MILLISECONDS);

        verifyIdmClientDataMatchesApiClientObject(idmClientData, apiClient);
    }

    @Test
    void testThrowsExceptionWhenIdmReturnsErrorResponse() {
        final Handler idmResponse = Handlers.INTERNAL_SERVER_ERROR;
        final ApiClientService apiClientService = new IdmApiClientService(new Client(idmResponse), TEST_IDM_BASE_URI, idmApiClientDecoder);
        final Promise<ApiClient, Exception> apiClientPromise = apiClientService.getApiClient(TEST_CLIENT_ID);
        final Exception exception = assertThrows(Exception.class, () -> apiClientPromise.getOrThrow(1, TimeUnit.MILLISECONDS));

        assertEquals("Failed to get ApiClient from IDM, response status: [Status: 500 Internal Server Error]",
                exception.getMessage());
    }

    @Test
    void testThrowsExceptionWhenIdmReturnsNonJsonResponse() {
        // IDM returns a Form instead of json
        final Response invalidIdmResponse = new Response(Status.OK).setEntity(new Form());
        final Client idmClientHandler = new Client((ctx, req) -> Promises.newResultPromise(invalidIdmResponse));

        final ApiClientService apiClientService = new IdmApiClientService(idmClientHandler, TEST_IDM_BASE_URI, idmApiClientDecoder);
        final Promise<ApiClient, Exception> apiClient = apiClientService.getApiClient("123");
        final Exception exception = assertThrows(Exception.class, () -> apiClient.getOrThrow(1, TimeUnit.MILLISECONDS));

        assertEquals("Failed to decode apiClient response json", exception.getMessage());
    }

    @Test
    void testThrowsExceptionWhenIdmReturnsApiClientMissingRequiredFields() {
        final JsonValue idmClientData = createIdmApiClientDataRequiredFieldsOnly(TEST_CLIENT_ID);
        idmClientData.remove("ssa"); // Remove the required ssa field
        final MockApiClientTestDataIdmHandler idmResponseHandler = new MockApiClientTestDataIdmHandler(TEST_IDM_BASE_URI, TEST_CLIENT_ID, idmClientData);

        final ApiClientService apiClientService = new IdmApiClientService(new Client(idmResponseHandler), TEST_IDM_BASE_URI, idmApiClientDecoder);
        final Promise<ApiClient, Exception> apiClientPromise = apiClientService.getApiClient(TEST_CLIENT_ID);
        final Exception exception = assertThrows(Exception.class, () -> apiClientPromise.getOrThrow(1, TimeUnit.MILLISECONDS));

        assertEquals("/ssa: is a required field, failed to decode IDM ApiClient", exception.getMessage());
    }

    @Test
    void testThrowsExceptionWhenIdmUrlIsInvalid() {
        final String badIdmUri = "999://localhost/openidm/managed/";

        final ApiClientService apiClientService = new IdmApiClientService(new Client(Handlers.FORBIDDEN), badIdmUri, idmApiClientDecoder);
        final Promise<ApiClient, Exception> apiClientPromise = apiClientService.getApiClient(TEST_CLIENT_ID);
        final Exception exception = assertThrows(Exception.class, () -> apiClientPromise.getOrThrow(1, TimeUnit.MILLISECONDS));

        assertEquals("java.net.URISyntaxException: Illegal character in scheme name at index 0:" +
                " 999://localhost/openidm/managed/9999?_fields=apiClientOrg/*,*", exception.getMessage());
    }

    /**
     * Mocks the expected response from IDM.
     *
     * Validates that it is called with the expected uri (including the expected clientId), and then returns a pre-canned
     * response json for that clientId.
     *
     * If the validation fails then a Runtime exception is returned, which will be thrown when Promise.get is called.
     */
    public static class MockApiClientTestDataIdmHandler implements Handler {
        private final MutableUri idmBaseUri;
        private final String expectedClientId;
        private final JsonValue staticApiClientData;

        public MockApiClientTestDataIdmHandler(String idmBaseUri, String expectedClientId, JsonValue staticApiClientData) {
            try {
                this.idmBaseUri = MutableUri.uri(idmBaseUri);
            } catch (URISyntaxException e) {
                throw new RuntimeException(e);
            }
            this.expectedClientId = expectedClientId;
            this.staticApiClientData = staticApiClientData;
        }

        @Override
        public Promise<Response, NeverThrowsException> handle(Context context, Request request) {
            final MutableUri requestUri = request.getUri();
            if (requestUri.getHost().equals(idmBaseUri.getHost()) && requestUri.getScheme().equals(idmBaseUri.getScheme())
                    && requestUri.getPath().equals(idmBaseUri.getPath() + expectedClientId)) {
                Response idmResponse = new Response(Status.OK);
                idmResponse.setEntity(staticApiClientData);
                return Promises.newResultPromise(idmResponse);
            }
            return Promises.newRuntimeExceptionPromise(new IllegalStateException("Unexpected requestUri: " + requestUri));
        }
    }
}
