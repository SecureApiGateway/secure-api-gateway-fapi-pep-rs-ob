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

import static org.forgerock.json.JsonValue.field;
import static org.forgerock.json.JsonValue.json;
import static org.forgerock.json.JsonValue.object;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.net.URI;
import java.net.URL;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.TimeUnit;

import org.forgerock.http.protocol.Request;
import org.forgerock.http.protocol.Response;
import org.forgerock.http.protocol.Status;
import org.forgerock.json.JsonValue;
import org.forgerock.json.jose.exceptions.FailedToLoadJWKException;
import org.forgerock.json.jose.jwk.JWKSet;
import org.forgerock.json.jose.jws.JwsHeader;
import org.forgerock.json.jose.jws.SignedJwt;
import org.forgerock.json.jose.jwt.JwtClaimsSet;
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

import com.forgerock.sapi.gateway.dcr.ApiClient;
import com.forgerock.sapi.gateway.dcr.FetchApiClientFilter;
import com.forgerock.sapi.gateway.jwks.FetchApiClientJwksFilter.Heaplet;
import com.forgerock.sapi.gateway.jwks.cache.BaseCachingJwkSetServiceTest.BaseCachingTestJwkSetService;
import com.forgerock.sapi.gateway.jwks.cache.BaseCachingJwkSetServiceTest.ReturnsErrorsJwkStore;
import com.forgerock.sapi.gateway.trusteddirectories.FetchTrustedDirectoryFilter;
import com.forgerock.sapi.gateway.trusteddirectories.TrustedDirectory;
import com.forgerock.sapi.gateway.trusteddirectories.TrustedDirectoryOpenBankingTest;
import com.forgerock.sapi.gateway.trusteddirectories.TrustedDirectorySecureApiGateway;
import com.forgerock.sapi.gateway.util.TestHandlers.TestSuccessResponseHandler;

class FetchApiClientJwksFilterTest {

    @Test
    void fetchJwkSetFromJwksUri() throws Exception {
        final JWKSet jwkSet = createJwkSet();
        final URL jwksUri = new URL("https://directory.com/jwks/12345");
        final MockJwkSetService jwkSetService = new MockJwkSetService(jwkSet, jwksUri);
        final FetchApiClientJwksFilter filter = new FetchApiClientJwksFilter(jwkSetService);

        fetchJwkSetFromJwksUri(jwkSet, jwksUri, filter);
    }

    private void fetchJwkSetFromJwksUri(JWKSet expectedJwkSet, URL jwksUri, FetchApiClientJwksFilter filter) throws Exception {
        final ApiClient apiClient = createApiClientWithJwksUri(jwksUri.toURI());
        // OB Trusted Dir uses the jwksUri
        final TrustedDirectory trustedDirectory = new TrustedDirectoryOpenBankingTest();
        invokeFilterAndValidateSuccessResponse(expectedJwkSet, apiClient, trustedDirectory, filter);
    }

    @Test
    void fetchJwkSetFromSoftwareStatement() throws Exception {
        // Never expect the JwkSetService to get called in this case
        final ReturnsErrorsJwkStore errorsJwkStore = new ReturnsErrorsJwkStore();
        final FetchApiClientJwksFilter filter = new FetchApiClientJwksFilter(errorsJwkStore);
        fetchJwkSetFromSoftwareStatement(filter);
    }

    private void fetchJwkSetFromSoftwareStatement(FetchApiClientJwksFilter filter) throws Exception {
        final JWKSet jwkSet = createJwkSet();
        // SAPI-G directory uses the software statement jwks
        final URL secureApiGatewayJwksURI = new URL("https://blah.com");
        final TrustedDirectory trustedDirectory = new TrustedDirectorySecureApiGateway(secureApiGatewayJwksURI);
        final ApiClient apiClient = createApiClientWithSoftwareStatementJwks(jwkSet, trustedDirectory.getSoftwareStatementJwksClaimName());

        invokeFilterAndValidateSuccessResponse(jwkSet, apiClient, trustedDirectory, filter);
    }

    @Test
    void failsIfApiClientNotFound() {
        final TestSuccessResponseHandler responseHandler = new TestSuccessResponseHandler();
        final Context context = new AttributesContext(new RootContext());

        final FetchApiClientJwksFilter filter = new FetchApiClientJwksFilter(new ReturnsErrorsJwkStore());

        final IllegalStateException exception = assertThrows(IllegalStateException.class,
                () -> filter.filter(context, new Request(), responseHandler));
        assertEquals("apiClient not found in request context", exception.getMessage());
    }

    @Test
    void failsIfTrustedDirectoryNotFound() {
        final TestSuccessResponseHandler responseHandler = new TestSuccessResponseHandler();
        final Context context = new AttributesContext(new RootContext());
        addApiClientToContext(context, new ApiClient());

        final FetchApiClientJwksFilter filter = new FetchApiClientJwksFilter(new ReturnsErrorsJwkStore());

        final IllegalStateException exception = assertThrows(IllegalStateException.class,
                () -> filter.filter(context, new Request(), responseHandler));
        assertEquals("trustedDirectory not found in request context", exception.getMessage());
    }

    @Test
    void failsIfJwkSetServiceThrowsException() throws Exception {
        final URL jwksUri = new URL("https://directory.com/jwks/12345");
        final ApiClient apiClient = createApiClientWithJwksUri(jwksUri.toURI());
        final TrustedDirectory trustedDirectory = new TrustedDirectoryOpenBankingTest();

        final TestSuccessResponseHandler responseHandler = new TestSuccessResponseHandler();
        final Context context = new AttributesContext(new RootContext());
        addApiClientToContext(context, apiClient);
        addTrustedDirectoryToContext(context, trustedDirectory);

        // Returns an Exception promise on every call
        final JwkSetService jwkSetService = new ReturnsErrorsJwkStore();
        final FetchApiClientJwksFilter filter = new FetchApiClientJwksFilter(jwkSetService);

        final Promise<Response, NeverThrowsException> responsePromise = filter.filter(context, new Request(), responseHandler);
        final Response response = responsePromise.get(1, TimeUnit.SECONDS);
        assertEquals(Status.INTERNAL_SERVER_ERROR, response.getStatus());
        assertFalse(responseHandler.hasBeenInteractedWith(), "ResponseHandler must not get invoked");
    }

    @Test
    void failsIfJwksUriIsInvalid() throws Exception {
        final ApiClient apiClient = createApiClientWithJwksUri(new URI("foo://bar"));
        final TrustedDirectory trustedDirectory = new TrustedDirectoryOpenBankingTest();

        final TestSuccessResponseHandler responseHandler = new TestSuccessResponseHandler();
        final Context context = new AttributesContext(new RootContext());
        addApiClientToContext(context, apiClient);
        addTrustedDirectoryToContext(context, trustedDirectory);

        final JwkSetService jwkSetService = new ReturnsErrorsJwkStore();
        final FetchApiClientJwksFilter filter = new FetchApiClientJwksFilter(jwkSetService);

        final Promise<Response, NeverThrowsException> responsePromise = filter.filter(context, new Request(), responseHandler);
        final Response response = responsePromise.get(1, TimeUnit.SECONDS);
        assertEquals(Status.INTERNAL_SERVER_ERROR, response.getStatus());
        assertFalse(responseHandler.hasBeenInteractedWith(), "ResponseHandler must not get invoked");
    }

    @Test
    void failsIfJwksUriIsNull() throws Exception {
        final ApiClient apiClient = createApiClientWithJwksUri(null);
        final TrustedDirectory trustedDirectory = new TrustedDirectoryOpenBankingTest();

        final TestSuccessResponseHandler responseHandler = new TestSuccessResponseHandler();
        final Context context = new AttributesContext(new RootContext());
        addApiClientToContext(context, apiClient);
        addTrustedDirectoryToContext(context, trustedDirectory);

        final JwkSetService jwkSetService = new ReturnsErrorsJwkStore();
        final FetchApiClientJwksFilter filter = new FetchApiClientJwksFilter(jwkSetService);

        final Promise<Response, NeverThrowsException> responsePromise = filter.filter(context, new Request(), responseHandler);
        final Response response = responsePromise.get(1, TimeUnit.SECONDS);
        assertEquals(Status.INTERNAL_SERVER_ERROR, response.getStatus());
        assertFalse(responseHandler.hasBeenInteractedWith(), "ResponseHandler must not get invoked");
    }

    @Test
    void failsToGetJwksFromSoftwareStatementIfTrustedDirectorySoftwareStatementJwksClaimNameIsMissing() throws Exception {
        final ReturnsErrorsJwkStore errorsJwkStore = new ReturnsErrorsJwkStore();
        final FetchApiClientJwksFilter filter = new FetchApiClientJwksFilter(errorsJwkStore);
        final JWKSet jwkSet = createJwkSet();
        final URL secureApiGatewayJwksURI = new URL("https://blah.com");
        final TrustedDirectory misconfiguredDirectory = new TrustedDirectorySecureApiGateway(secureApiGatewayJwksURI) {
            @Override
            public String getSoftwareStatementJwksClaimName() {
                return null;
            }
        };
        final ApiClient apiClient = createApiClientWithSoftwareStatementJwks(jwkSet,"jwks");
        final Context context = new AttributesContext(new RootContext());
        addApiClientToContext(context, apiClient);
        addTrustedDirectoryToContext(context, misconfiguredDirectory);

        final TestSuccessResponseHandler responseHandler = new TestSuccessResponseHandler();
        final Promise<Response, NeverThrowsException> responsePromise = filter.filter(context, new Request(), responseHandler);
        final Response response = responsePromise.get(1, TimeUnit.SECONDS);
        assertEquals(Status.INTERNAL_SERVER_ERROR, response.getStatus());
        assertFalse(responseHandler.hasBeenInteractedWith(), "ResponseHandler must not get invoked");
    }

    @Test
    void failsToGetJwksFromSoftwareStatementIfClaimIsNull() throws Exception {
        final ReturnsErrorsJwkStore errorsJwkStore = new ReturnsErrorsJwkStore();
        final FetchApiClientJwksFilter filter = new FetchApiClientJwksFilter(errorsJwkStore);
        final JWKSet jwkSet = createJwkSet();
        final URL secureApiGatewayJwksURI = new URL("https://blah.com");
        final TrustedDirectory misconfiguredDirectory = new TrustedDirectorySecureApiGateway(secureApiGatewayJwksURI);
        final ApiClient apiClient = createApiClientWithSoftwareStatementJwks(jwkSet,null);
        final Context context = new AttributesContext(new RootContext());
        addApiClientToContext(context, apiClient);
        addTrustedDirectoryToContext(context, misconfiguredDirectory);

        final TestSuccessResponseHandler responseHandler = new TestSuccessResponseHandler();
        final Promise<Response, NeverThrowsException> responsePromise = filter.filter(context, new Request(), responseHandler);
        final Response response = responsePromise.get(1, TimeUnit.SECONDS);
        assertEquals(Status.INTERNAL_SERVER_ERROR, response.getStatus());
        assertFalse(responseHandler.hasBeenInteractedWith(), "ResponseHandler must not get invoked");
    }

    @Test
    void failsToGetJwksFromSoftwareStatementIfClaimsIsInvalidJwksJson() throws Exception {
        final ReturnsErrorsJwkStore errorsJwkStore = new ReturnsErrorsJwkStore();
        final FetchApiClientJwksFilter filter = new FetchApiClientJwksFilter(errorsJwkStore);
        final URL secureApiGatewayJwksURI = new URL("https://blah.com");
        final TrustedDirectory misconfiguredDirectory = new TrustedDirectorySecureApiGateway(secureApiGatewayJwksURI);
        final ApiClient apiClient = new ApiClient();
        final JwtClaimsSet claimsSet = new JwtClaimsSet();
        claimsSet.setClaim(misconfiguredDirectory.getSoftwareStatementJwksClaimName(), json(object(field("keys", "should be a list"))));
        apiClient.setSoftwareStatementAssertion(new SignedJwt(new JwsHeader(), claimsSet, new byte[0], new byte[0]));
        final Context context = new AttributesContext(new RootContext());
        addApiClientToContext(context, apiClient);
        addTrustedDirectoryToContext(context, misconfiguredDirectory);

        final TestSuccessResponseHandler responseHandler = new TestSuccessResponseHandler();
        final Promise<Response, NeverThrowsException> responsePromise = filter.filter(context, new Request(), responseHandler);
        final Response response = responsePromise.get(1, TimeUnit.SECONDS);
        assertEquals(Status.INTERNAL_SERVER_ERROR, response.getStatus());
        assertFalse(responseHandler.hasBeenInteractedWith(), "ResponseHandler must not get invoked");
    }

    @Nested
    class HeapletTests {

        @Test
        void failsToConstructWhenMissingJwksService() {
            final HeapImpl heap = new HeapImpl(Name.of("heap"));
            final JsonValue config = json(object());
            final HeapException heapException = assertThrows(HeapException.class, () -> new Heaplet().create(Name.of("test"), config, heap));
            assertEquals("/jwkSetService: Expecting a value", heapException.getCause().getMessage());
        }

        @Test
        void successfullyCreatesFilter() throws Exception {
            final JWKSet jwkSet = createJwkSet();
            final URL jwksUri = new URL("https://directory.com/jwks/12345");
            final MockJwkSetService jwkSetService = new MockJwkSetService(jwkSet, jwksUri);

            final HeapImpl heap = new HeapImpl(Name.of("heap"));
            heap.put("JwkSetService", jwkSetService);
            final JsonValue config = json(object(field("jwkSetService", "JwkSetService")));

            final FetchApiClientJwksFilter filter = (FetchApiClientJwksFilter) new Heaplet().create(Name.of("test"), config, heap);
            fetchJwkSetFromJwksUri(jwkSet, jwksUri, filter);
            fetchJwkSetFromSoftwareStatement(filter);
        }
    }

    /**
     * JwkSetService impl which returns a pre-canned JWKSet for an expectedJwkStoreUrl.
     * Returns an error if getJwkSet is called with a different url, or i getJwk is called.
     */
    private static class MockJwkSetService extends BaseCachingTestJwkSetService {
        private final JWKSet jwkSet;
        private final URL expectedJwkStoreUrl;

        private MockJwkSetService(JWKSet jwkSet, URL expectedJwkStoreUrl) {
            this.jwkSet = jwkSet;
            this.expectedJwkStoreUrl = expectedJwkStoreUrl;
        }

        @Override
        public Promise<JWKSet, FailedToLoadJWKException> getJwkSet(URL jwkStoreUrl) {
            if (jwkStoreUrl.equals(expectedJwkStoreUrl)) {
                return Promises.newResultPromise(jwkSet);
            }
            return Promises.newExceptionPromise(new FailedToLoadJWKException("actual jwkStoreUrl: " + jwkStoreUrl
                    + ", does not match expected: " + expectedJwkStoreUrl));
        }
    }

    private JWKSet createJwkSet() {
        return new JWKSet(List.of(RestJwkSetServiceTest.createJWK(UUID.randomUUID().toString()),
                                  RestJwkSetServiceTest.createJWK(UUID.randomUUID().toString())));
    }

    private ApiClient createApiClientWithJwksUri(URI jwksUri) {
        final ApiClient apiClient = new ApiClient();
        apiClient.setJwksUri(jwksUri);
        return apiClient;
    }

    private ApiClient createApiClientWithSoftwareStatementJwks(JWKSet jwkSet, String softwareStatementJwksClaimName) {
        final ApiClient apiClient = new ApiClient();
        final JwtClaimsSet claimsSet = new JwtClaimsSet();
        if (softwareStatementJwksClaimName != null) {
            claimsSet.setClaim(softwareStatementJwksClaimName, jwkSet.toJsonValue());
        }
        apiClient.setSoftwareStatementAssertion(new SignedJwt(new JwsHeader(), claimsSet, new byte[0], new byte[0]));
        return apiClient;
    }

    private void addApiClientToContext(Context context, ApiClient apiClient) {
        context.asContext(AttributesContext.class).getAttributes().put(FetchApiClientFilter.API_CLIENT_ATTR_KEY, apiClient);
    }

    private void addTrustedDirectoryToContext(Context context, TrustedDirectory trustedDirectory) {
        context.asContext(AttributesContext.class).getAttributes()
                .put(FetchTrustedDirectoryFilter.TRUSTED_DIRECTORY_ATTR_KEY, trustedDirectory);
    }

    private void invokeFilterAndValidateSuccessResponse(JWKSet expectedJwkSet, ApiClient apiClient,
            TrustedDirectory trustedDirectory, FetchApiClientJwksFilter filter) throws Exception {
        final TestSuccessResponseHandler responseHandler = new TestSuccessResponseHandler();
        final Context context = new AttributesContext(new RootContext());
        addApiClientToContext(context, apiClient);
        addTrustedDirectoryToContext(context, trustedDirectory);

        assertNull(FetchApiClientJwksFilter.getApiClientJwkSetFromContext(context),
                "there must be no apiClientJwkSet in the context before the filter is called");

        final Promise<Response, NeverThrowsException> responsePromise = filter.filter(context, new Request(), responseHandler);
        final Response response = responsePromise.get(1, TimeUnit.SECONDS);
        assertEquals(Status.OK, response.getStatus());
        assertTrue(responseHandler.hasBeenInteractedWith());
        assertEquals(expectedJwkSet, FetchApiClientJwksFilter.getApiClientJwkSetFromContext(context));
    }
}
