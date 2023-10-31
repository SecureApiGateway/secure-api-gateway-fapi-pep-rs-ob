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

import static com.forgerock.sapi.gateway.dcr.idm.FetchApiClientFilterTest.createApiClientService;
import static com.forgerock.sapi.gateway.dcr.idm.IdmApiClientDecoderTest.createIdmApiClientDataAllFields;
import static com.forgerock.sapi.gateway.dcr.idm.IdmApiClientDecoderTest.createIdmApiClientDataRequiredFieldsOnly;
import static com.forgerock.sapi.gateway.dcr.idm.IdmApiClientDecoderTest.verifyIdmClientDataMatchesApiClientObject;
import static org.assertj.core.api.Assertions.assertThat;
import static org.forgerock.json.JsonValue.field;
import static org.forgerock.json.JsonValue.json;
import static org.forgerock.json.JsonValue.object;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.net.URISyntaxException;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.function.BiConsumer;

import org.forgerock.http.Client;
import org.forgerock.http.Handler;
import org.forgerock.http.protocol.Request;
import org.forgerock.http.protocol.Response;
import org.forgerock.http.protocol.Status;
import org.forgerock.json.JsonValue;
import org.forgerock.json.JsonValueException;
import org.forgerock.openig.handler.Handlers;
import org.forgerock.openig.heap.HeapException;
import org.forgerock.openig.heap.HeapImpl;
import org.forgerock.openig.heap.Name;
import org.forgerock.services.context.AttributesContext;
import org.forgerock.services.context.RootContext;
import org.forgerock.util.promise.NeverThrowsException;
import org.forgerock.util.promise.Promise;
import org.forgerock.util.promise.Promises;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import com.forgerock.sapi.gateway.dcr.idm.AuthorizeResponseFetchApiClientFilter.Heaplet;
import com.forgerock.sapi.gateway.dcr.idm.IdmApiClientServiceTest.MockApiClientTestDataIdmHandler;
import com.forgerock.sapi.gateway.dcr.models.ApiClient;
import com.forgerock.sapi.gateway.util.TestHandlers.FixedResponseHandler;
import com.forgerock.sapi.gateway.util.TestHandlers.TestSuccessResponseHandler;

class AuthorizeResponseFetchApiClientFilterTest {

    static final String idmBaseUri = "http://localhost/openidm/managed/";
    static final String clientId = "9999";


    @Test
    void fetchApiClientForSuccessResponse() throws Exception {
        final JsonValue idmClientData = createIdmApiClientDataRequiredFieldsOnly(clientId);
        final MockApiClientTestDataIdmHandler idmResponseHandler = new MockApiClientTestDataIdmHandler(idmBaseUri, clientId, idmClientData);
        final AuthorizeResponseFetchApiClientFilter filter = new AuthorizeResponseFetchApiClientFilter(createApiClientService(new Client(idmResponseHandler), idmBaseUri));
        callFilterValidateSuccessBehaviour(idmClientData, filter);
    }

    private static void callFilterValidateSuccessBehaviour(JsonValue idmClientData, AuthorizeResponseFetchApiClientFilter filter) throws Exception {

        final BiConsumer<Response, AttributesContext> successBehaviourValidator = (response, ctxt) -> {
            // Verify we hit the end of the chain and got the NO_CONTENT response
            assertEquals(Status.NO_CONTENT, response.getStatus());

            // Verify that the context was updated with the apiClient data
            final ApiClient apiClient = FetchApiClientFilter.getApiClientFromContext(ctxt);
            assertNotNull(apiClient, "apiClient was not found in context");
            verifyIdmClientDataMatchesApiClientObject(idmClientData, apiClient);
        };
        callFilter(filter, successBehaviourValidator);
    }

    private static void callFilter(AuthorizeResponseFetchApiClientFilter filter, BiConsumer<Response, AttributesContext> responseAndContextValidator) throws Exception {
        final AttributesContext attributesContext = createContext();

        // This is the next handler called after the AuthoriseResponseFetchApiClientFilter
        final Handler endOfFilterChainHandler = Handlers.NO_CONTENT;
        final Request request = createRequest();
        final Promise<Response, NeverThrowsException> responsePromise = filter.filter(attributesContext, request, endOfFilterChainHandler);

        final Response response = responsePromise.getOrThrow(1L, TimeUnit.SECONDS);

        // Do the validation
        responseAndContextValidator.accept(response, attributesContext);
    }

    private static Request createRequest() {
        final Request request = new Request();
        try {
            request.setUri("/authorize?client_id=" + clientId);
        } catch (URISyntaxException e) {
            throw new RuntimeException(e);
        }
        return request;
    }

    private static AttributesContext createContext() {
        return new AttributesContext(new RootContext("root"));
    }

    @Test
    void doesNotFetchApiClientForErrorResponses() throws InterruptedException, TimeoutException {
        final JsonValue idmClientData = createIdmApiClientDataRequiredFieldsOnly(clientId);
        final MockApiClientTestDataIdmHandler idmResponseHandler = new MockApiClientTestDataIdmHandler(idmBaseUri, clientId, idmClientData);
        final AuthorizeResponseFetchApiClientFilter filter = new AuthorizeResponseFetchApiClientFilter(createApiClientService(new Client(idmResponseHandler), idmBaseUri));
        final AttributesContext context = createContext();

        final Promise<Response, NeverThrowsException> responsePromise = filter.filter(context, createRequest(), new FixedResponseHandler(new Response(Status.BAD_GATEWAY)));
        final Response response = responsePromise.getOrThrow(1, TimeUnit.SECONDS);

        assertThat(response.getStatus()).isEqualTo(Status.BAD_GATEWAY);
        assertThat(FetchApiClientFilter.getApiClientFromContext(context)).isNull();
    }

    @Test
    void returnsErrorResponseWhenClientIdParamNotFound() throws Exception {
        final JsonValue idmClientData = createIdmApiClientDataRequiredFieldsOnly(clientId);
        final MockApiClientTestDataIdmHandler idmResponseHandler = new MockApiClientTestDataIdmHandler(idmBaseUri, clientId, idmClientData);
        final AuthorizeResponseFetchApiClientFilter filter = new AuthorizeResponseFetchApiClientFilter(createApiClientService(new Client(idmResponseHandler), idmBaseUri));
        final AttributesContext context = createContext();

        final Request request = new Request();
        request.setUri("/authorize");
        final Promise<Response, NeverThrowsException> responsePromise = filter.filter(context, request, new TestSuccessResponseHandler());
        final Response response = responsePromise.getOrThrow(1, TimeUnit.SECONDS);

        assertThat(response.getStatus()).isEqualTo(Status.INTERNAL_SERVER_ERROR);
        assertThat(FetchApiClientFilter.getApiClientFromContext(context)).isNull();
    }

    @Test
    void returnsErrorResponseWhenApiClientServiceReturnsException() throws Exception {
        final AuthorizeResponseFetchApiClientFilter filter = new AuthorizeResponseFetchApiClientFilter(createApiClientService(new Client(Handlers.INTERNAL_SERVER_ERROR), idmBaseUri));
        final AttributesContext context = createContext();

        final Promise<Response, NeverThrowsException> responsePromise = filter.filter(context, createRequest(), new TestSuccessResponseHandler());
        final Response response = responsePromise.getOrThrow(1, TimeUnit.SECONDS);

        assertThat(response.getStatus()).isEqualTo(Status.INTERNAL_SERVER_ERROR);
        assertThat(FetchApiClientFilter.getApiClientFromContext(context)).isNull();
    }

    @Nested
    public class HeapletTests {
        @Test
        void failsToConstructIfClientHandlerIsMissing() {
            final HeapException heapException = assertThrows(HeapException.class, () -> new Heaplet().create(Name.of("test"),
                    json(object()), new HeapImpl(Name.of("heap"))), "Invalid object declaration");
            assertEquals(heapException.getCause().getMessage(), "/clientHandler: Expecting a value");
        }

        @Test
        void failsToConstructIfIdmUrlIsMissing() {
            final Handler idmClientHandler = (ctx, req) -> Promises.newResultPromise(new Response(Status.OK));
            final HeapImpl heap = new HeapImpl(Name.of("heap"));
            heap.put("idmClientHandler", idmClientHandler);

            assertThrows(JsonValueException.class, () -> new Heaplet().create(Name.of("test"),
                    json(object(field("clientHandler", "idmClientHandler"))), heap), "/idmGetApiClientBaseUri: Expecting a value");
        }

        @Test
        void successfullyCreatesFilterWithRequiredConfigOnly() throws Exception {
            final JsonValue idmApiClientData = createIdmApiClientDataAllFields(clientId);
            final Handler idmClientHandler = new MockApiClientTestDataIdmHandler(idmBaseUri, clientId, idmApiClientData);

            final HeapImpl heap = new HeapImpl(Name.of("heap"));
            heap.put("idmClientHandler", idmClientHandler);

            final JsonValue config = json(object(field("clientHandler", "idmClientHandler"),
                    field("idmGetApiClientBaseUri", idmBaseUri)));
            final AuthorizeResponseFetchApiClientFilter filter = (AuthorizeResponseFetchApiClientFilter) new Heaplet().create(Name.of("test"), config, heap);

            // Test the filter created by the Heaplet
            callFilterValidateSuccessBehaviour(idmApiClientData, filter);
        }
    }
}