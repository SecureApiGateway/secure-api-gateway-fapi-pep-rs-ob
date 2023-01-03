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
package com.forgerock.sapi.gateway.dcr;

import static com.forgerock.sapi.gateway.dcr.FetchApiClientFilter.API_CLIENT_ATTR_KEY;
import static org.junit.jupiter.api.Assertions.*;
import static org.forgerock.json.JsonValue.*;

import java.net.URISyntaxException;
import java.nio.charset.StandardCharsets;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.TimeUnit;
import java.util.function.BiConsumer;

import org.forgerock.http.Client;
import org.forgerock.http.Handler;
import org.forgerock.http.MutableUri;
import org.forgerock.http.oauth2.AccessTokenInfo;
import org.forgerock.http.oauth2.OAuth2Context;
import org.forgerock.http.protocol.Form;
import org.forgerock.http.protocol.Request;
import org.forgerock.http.protocol.Response;
import org.forgerock.http.protocol.Status;
import org.forgerock.json.JsonValue;
import org.forgerock.json.JsonValueException;
import org.forgerock.json.jose.common.JwtReconstruction;
import org.forgerock.json.jose.jws.JwsAlgorithm;
import org.forgerock.json.jose.jws.JwsHeader;
import org.forgerock.json.jose.jws.SignedJwt;
import org.forgerock.json.jose.jws.handlers.SigningHandler;
import org.forgerock.json.jose.jwt.JwtClaimsSet;
import org.forgerock.openig.handler.Handlers;
import org.forgerock.openig.heap.HeapException;
import org.forgerock.openig.heap.HeapImpl;
import org.forgerock.openig.heap.Name;
import org.forgerock.services.context.AttributesContext;
import org.forgerock.services.context.Context;
import org.forgerock.services.context.RootContext;
import org.forgerock.util.promise.NeverThrowsException;
import org.forgerock.util.promise.Promise;
import org.forgerock.util.promise.Promises;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import com.forgerock.sapi.gateway.dcr.FetchApiClientFilter.Heaplet;

/**
 * Unit tests for {@link FetchApiClientFilter}.
 *
 * IDM behaviour is simulated using Handlers installed as the httpClient within the Filter.
 * See {@link MockApiClientTestDataIdmHandler} for an example Handler which returns mocked ApiClient data.
 */
class FetchApiClientFilterTest {

    @Test
    void fetchApiClientUsingMockedIdmResponse() throws Exception {
        final String idmBaseUri = "http://localhost/openidm/managed/";
        final String clientId = "1234-5678-9101";
        final JsonValue idmClientData = createIdmApiClientData(clientId);
        final MockApiClientTestDataIdmHandler idmResponseHandler = new MockApiClientTestDataIdmHandler(idmBaseUri, clientId, idmClientData);

        final String clientIdClaim = "aud";
        final AccessTokenInfo accessToken = createAccessToken(clientIdClaim, clientId);
        final FetchApiClientFilter filter = new FetchApiClientFilter(new Client(idmResponseHandler), idmBaseUri, clientIdClaim);
        callFilterValidateSuccessBehaviour(accessToken, idmClientData, filter);
    }

    @Test
    void failsWhenNoOAuth2ContextIsFound() {
        final FetchApiClientFilter filter = new FetchApiClientFilter(new Client(Handlers.FORBIDDEN), "notUsed", "aud");
        assertThrows(IllegalArgumentException.class, () -> filter.filter(new RootContext("root"), new Request(), Handlers.FORBIDDEN),
                "No context of type org.forgerock.http.oauth2.OAuth2Context found");
    }

    @Test
    void returnsErrorResponseWhenUnableToDetermineClientId() throws Exception{
        final FetchApiClientFilter filter = new FetchApiClientFilter(new Client(Handlers.FORBIDDEN), "notUsed", "aud");
        final AccessTokenInfo accessTokenWithoutAudClaim = new AccessTokenInfo(json(object()), "token", Set.of("scope1"), 0L);
        final Promise<Response, NeverThrowsException> responsePromise = filter.filter(new OAuth2Context(new RootContext("root"), accessTokenWithoutAudClaim), new Request(), Handlers.FORBIDDEN);

        final Response response = responsePromise.get(1, TimeUnit.SECONDS);
        assertEquals(Status.INTERNAL_SERVER_ERROR, response.getStatus());
    }

    @Test
    void returnsErrorResponseWhenIdmReturnsErrorResponse() throws Exception {
        // Mock IDM returning 500 response
        final Client idmClientHandler = new Client(Handlers.INTERNAL_SERVER_ERROR);
        final String clientIdClaim = "client_id";
        final FetchApiClientFilter filter = new FetchApiClientFilter(idmClientHandler, "notUsed", clientIdClaim);
        final OAuth2Context context = new OAuth2Context(new RootContext("root"), createAccessToken(clientIdClaim, "1234"));
        final Promise<Response, NeverThrowsException> responsePromise = filter.filter(context, new Request(), Handlers.FORBIDDEN);

        final Response response = responsePromise.get(1, TimeUnit.SECONDS);
        assertEquals(Status.INTERNAL_SERVER_ERROR, response.getStatus());
    }

    @Test
    void returnsErrorResponseWhenIdmReturnsInvalidJsonResponse() throws Exception {
        // IDM returns a Form instead of json
        final Response invalidIdmResponse = new Response(Status.OK).setEntity(new Form());
        final Client idmClientHandler = new Client((ctx, req) -> Promises.newResultPromise(invalidIdmResponse));
        final String clientIdClaim = "aud";
        final FetchApiClientFilter filter = new FetchApiClientFilter(idmClientHandler, "notUsed", clientIdClaim);
        final OAuth2Context context = new OAuth2Context(new RootContext("root"), createAccessToken(clientIdClaim, "1234"));
        final Promise<Response, NeverThrowsException> responsePromise = filter.filter(context, new Request(), Handlers.FORBIDDEN);

        final Response response = responsePromise.get(1, TimeUnit.SECONDS);
        assertEquals(Status.INTERNAL_SERVER_ERROR, response.getStatus());
    }

    @Test
    void returnsErrorResponseWhenIdmUrlIsInvalid() throws Exception {
        // Invalid base uri
        final String idmBaseUri = "999://localhost/openidm/managed/";
        final String clientId = "1234-5678-9101";

        final String clientIdClaim = "aud";
        final AccessTokenInfo accessToken = createAccessToken(clientIdClaim, clientId);
        final FetchApiClientFilter filter = new FetchApiClientFilter(new Client(Handlers.FORBIDDEN), idmBaseUri, clientIdClaim);

        callFilter(accessToken, filter, (response, attributesContext) -> {
            assertEquals(Status.INTERNAL_SERVER_ERROR, response.getStatus());
        });
    }

    @Nested
    class HeapletTests {
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
            final String idmBaseUri = "http://idm/managed/";
            final String clientId = "999999999";
            final JsonValue idmApiClientData = createIdmApiClientData(clientId);
            final Handler idmClientHandler = new MockApiClientTestDataIdmHandler(idmBaseUri, clientId, idmApiClientData);

            final HeapImpl heap = new HeapImpl(Name.of("heap"));
            heap.put("idmClientHandler", idmClientHandler);

            final JsonValue config = json(object(field("clientHandler", "idmClientHandler"),
                                                 field("idmGetApiClientBaseUri", idmBaseUri)));
            final FetchApiClientFilter filter = (FetchApiClientFilter) new Heaplet().create(Name.of("test"), config, heap);


            // optional config: accessTokenClientIdClaim will be defaulted to aud
            final AccessTokenInfo accessToken = createAccessToken("aud", clientId);
            // Test the filter created by the Heaplet
            callFilterValidateSuccessBehaviour(accessToken, idmApiClientData, filter);
        }

        @Test
        void successfullyCreatesFilterWithAllOptionalConfigSupplied() throws Exception {
            final String idmBaseUri = "http://idm/managed/";
            final String clientId = "999999999";
            final JsonValue idmApiClientData = createIdmApiClientData(clientId);
            final Handler idmClientHandler = new MockApiClientTestDataIdmHandler(idmBaseUri, clientId, idmApiClientData);

            final HeapImpl heap = new HeapImpl(Name.of("heap"));
            heap.put("idmClientHandler", idmClientHandler);

            final String clientIdClaim = "client_id";
            final JsonValue config = json(object(field("clientHandler", "idmClientHandler"),
                                                 field("idmGetApiClientBaseUri", idmBaseUri),
                                                 field("accessTokenClientIdClaim", clientIdClaim)));
            final FetchApiClientFilter filter = (FetchApiClientFilter) new Heaplet().create(Name.of("test"), config, heap);

            final AccessTokenInfo accessToken = createAccessToken(clientIdClaim, clientId);
            // Test the filter created by the Heaplet
            callFilterValidateSuccessBehaviour(accessToken, createIdmApiClientData(clientId), filter);
        }
    }

    /**
     * Mocks the expected response from IDM.
     *
     * Validates that it is called with the expected uri (including the expected clientId), and then returns a pre-canned
     * response json for that clientId.
     *
     * If the validation fails then a Runtime exception is returned, which will be thrown when Promise.get is called.
     */
    private static class MockApiClientTestDataIdmHandler implements Handler {
        private final MutableUri idmBaseUri;
        private final String expectedClientId;
        private final JsonValue staticApiClientData;

        private MockApiClientTestDataIdmHandler(String idmBaseUri, String expectedClientId, JsonValue staticApiClientData) {
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

    private static void callFilterValidateSuccessBehaviour(AccessTokenInfo accessToken, JsonValue idmClientData,
                                                          FetchApiClientFilter filter) throws Exception {

        final BiConsumer<Response, AttributesContext> successBehaviourValidator = (response, ctxt) -> {
            // Verify we hit the end of the chain and got the NO_CONTENT response
            assertEquals(Status.NO_CONTENT, response.getStatus());

            // Verify that the context was updated with the apiClient data
            final ApiClient apiClient = (ApiClient) ctxt.getAttributes().get(API_CLIENT_ATTR_KEY);
            assertNotNull(apiClient, "apiClient was not found in context");
            verifyIdmClientDataMatchesApiClientObject(idmClientData, apiClient);
        };
        callFilter(accessToken, filter, successBehaviourValidator);
    }

    private static void callFilter(AccessTokenInfo accessToken, FetchApiClientFilter filter,
                                   BiConsumer<Response, AttributesContext> responseAndContextValidator) throws Exception {
        final AttributesContext attributesContext = new AttributesContext(new RootContext("root"));
        final OAuth2Context oauth2Context = new OAuth2Context(attributesContext, accessToken);

        // This is the next handler called after the FetchApiClientFilter
        final Handler endOfFilterChainHandler = Handlers.NO_CONTENT;
        final Promise<Response, NeverThrowsException> responsePromise = filter.filter(oauth2Context, new Request(), endOfFilterChainHandler);

        final Response response = responsePromise.get(1L, TimeUnit.SECONDS);

        // Do the validation
        responseAndContextValidator.accept(response, attributesContext);
    }

    private static AccessTokenInfo createAccessToken(String clientIdClaim, String clientId) {
        return new AccessTokenInfo(json(object(field(clientIdClaim, clientId))), "token", Set.of("scope1"), 0L);
    }

    private static void verifyIdmClientDataMatchesApiClientObject(JsonValue idmClientData, ApiClient actualApiClient) {
        assertEquals(idmClientData.get("id").asString(), actualApiClient.getSoftwareClientId());
        assertEquals(idmClientData.get("name").asString(), actualApiClient.getClientName());
        assertEquals(idmClientData.get("oauth2ClientId").asString(), actualApiClient.getOauth2ClientId());
        assertEquals(idmClientData.get("jwksUri").asString(), actualApiClient.getJwksUri().toString());
        assertEquals(idmClientData.get("apiClientOrg").get("id").asString(), actualApiClient.getOrganisation().getId());
        assertEquals(idmClientData.get("apiClientOrg").get("name").asString(), actualApiClient.getOrganisation().getName());

        final String ssaStr = idmClientData.get("ssa").asString();
        final SignedJwt expectedSignedJwt = new JwtReconstruction().reconstructJwt(ssaStr, SignedJwt.class);
        assertEquals(expectedSignedJwt.getHeader(), actualApiClient.getSoftwareStatementAssertion().getHeader());
        assertEquals(expectedSignedJwt.getClaimsSet(), actualApiClient.getSoftwareStatementAssertion().getClaimsSet());
    }

    private static JsonValue createIdmApiClientData(String clientId) {
        return json(object(field("id", "ebSqTNqmQXFYz6VtWGXZAa"),
                           field("name", "Automated Testing"),
                           field("description", "Blah blah blah"),
                           field("ssa", createTestSoftwareStatementAssertion().build()),
                           field("oauth2ClientId", clientId),
                           field("jwksUri", "https://somelocation/jwks.jwks"),
                           field("apiClientOrg", object(field("id", "98761234"),
                                                        field("name", "Test Organisation")))));
    }

    /**
     * @return SignedJwt which represents a Software Statement Assertion (ssa). This is a dummy JWT in place of a real
     * software statement, it does not contain a realistic set of claims and the signature (and kid) are junk.
     *
     * This is good enough for this test as the ssa is not processed, only decoded into a SignedJwt object
     */
    private static SignedJwt createTestSoftwareStatementAssertion() {
        final JwsHeader header = new JwsHeader();
        header.setKeyId("12345");
        header.setAlgorithm(JwsAlgorithm.PS256);
        return new SignedJwt(header, new JwtClaimsSet(Map.of("claim1", "value1")), new SigningHandler() {
            @Override
            public byte[] sign(JwsAlgorithm algorithm, byte[] data) {
                return "gYdMUpAvrotMnMP8tHj".getBytes(StandardCharsets.UTF_8);
            }

            @Override
            public boolean verify(JwsAlgorithm algorithm, byte[] data, byte[] signature) {
                return true;
            }
        });
    }
}