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
package com.forgerock.sapi.gateway.dcr.request;

import static org.assertj.core.api.AssertionsForClassTypes.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.reset;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.net.MalformedURLException;
import java.net.URL;
import java.security.NoSuchAlgorithmException;
import java.util.List;
import java.util.Map;

import org.forgerock.http.Handler;
import org.forgerock.http.protocol.Request;
import org.forgerock.http.protocol.Response;
import org.forgerock.http.protocol.Status;
import org.forgerock.json.jose.jwk.JWKSet;
import org.forgerock.services.context.AttributesContext;
import org.forgerock.services.context.Context;
import org.forgerock.services.context.RootContext;
import org.forgerock.util.promise.NeverThrowsException;
import org.forgerock.util.promise.Promise;
import org.forgerock.util.promise.Promises;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import com.forgerock.sapi.gateway.common.rest.AcceptHeaderSupplier;
import com.forgerock.sapi.gateway.dcr.common.ResponseFactory;
import com.forgerock.sapi.gateway.dcr.models.RegistrationRequest;
import com.forgerock.sapi.gateway.dcr.models.SoftwareStatement;
import com.forgerock.sapi.gateway.jws.JwtDecoder;
import com.forgerock.sapi.gateway.trusteddirectories.TrustedDirectoryService;
import com.forgerock.sapi.gateway.trusteddirectories.TrustedDirectoryServiceStatic;
import com.forgerock.sapi.gateway.util.CryptoUtils;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.crypto.RSASSASigner;

class RegistrationRequestEntityValidatorFilterTest {

    private RegistrationRequestEntityValidatorFilter filter;
    private final RegistrationRequestEntitySupplier reqRequestSupplier = mock(RegistrationRequestEntitySupplier.class);
    private final AcceptHeaderSupplier acceptHeaderSupplier = mock(AcceptHeaderSupplier.class);
    private static TrustedDirectoryService trustedDirectoryService;
    private static SoftwareStatement.Builder softwareStatementBuilder;
    private static RegistrationRequest.Builder registrationRequestBuilder ;
    private static final JwtDecoder jwtDecoder = new JwtDecoder();
    private final ResponseFactory responseFactory = mock(ResponseFactory.class);
    private final Handler handler = mock(Handler.class);

    @BeforeAll
    static void setupClass() throws MalformedURLException {
        trustedDirectoryService =  new TrustedDirectoryServiceStatic(true, new URL("https://jwks.com"));
        softwareStatementBuilder = new SoftwareStatement.Builder(trustedDirectoryService, jwtDecoder);
        registrationRequestBuilder = new RegistrationRequest.Builder(softwareStatementBuilder, jwtDecoder);
    }

    @BeforeEach
    void setUp() {
        when(handler.handle(any(Context.class), any(Request.class)))
                .thenReturn(Promises.newResultPromise(new Response(Status.OK)));
        filter = new RegistrationRequestEntityValidatorFilter(reqRequestSupplier, registrationRequestBuilder,
                responseFactory);
    }

    @AfterEach
    void tearDown() {
        reset(reqRequestSupplier, acceptHeaderSupplier, responseFactory, handler);
    }

    @Test
    void successWithIGDirectoryRequest() throws InterruptedException, NoSuchAlgorithmException {
        // Given
        final AttributesContext context = new AttributesContext(new RootContext());
        Request request = new Request();
        Map<String, Object> ssaClaims = Map.of("iss", "test-publisher", "software_jwks", getJwkSetObject(),
                "org_id", "Acme Inc", "software_id", "Acme Banking App");
        // When
        when(reqRequestSupplier.apply(context, request)).thenReturn(createRegistrationRequestWithJwksBasedSSA(ssaClaims));
        Promise<Response, NeverThrowsException> promise = filter.filter(context, request, handler);

        assertThat(promise).isNotNull();
        Response response = promise.getOrThrow();
        assertThat(response.getStatus()).isEqualTo(Status.OK);
        RegistrationRequest registrationRequest = (RegistrationRequest) context.getAttributes().get("registrationRequest");
        assertThat(registrationRequest).isNotNull();
        SoftwareStatement softwareStatement = registrationRequest.getSoftwareStatement();
        assertThat(softwareStatement).isNotNull();
        assertThat(softwareStatement.hasJwksUri()).isFalse();
    }

    @Test
    void errorWhenUnrecognisedSSAIssuer_filter() throws InterruptedException, NoSuchAlgorithmException {
        // Given
        final AttributesContext context = new AttributesContext(new RootContext());
        Request request = new Request();
        Map<String, Object> ssaClaims = Map.of("iss", "invalid_isser", "software_jwks_endpoint", "https://jwks.com",
                "org_id", "Acme Inc", "software_id", "Acme Banking App");
        // When
        when(reqRequestSupplier.apply(context, request)).thenReturn(createRegistrationRequestWithJwksUriBasedSSA(ssaClaims));
        when(responseFactory.getResponse(any(String.class), any(List.class), eq(Status.BAD_REQUEST), any(Map.class))).thenReturn(new Response(Status.BAD_REQUEST));
        Promise<Response, NeverThrowsException> promise = filter.filter(context, request, handler);

        assertThat(promise).isNotNull();
        Response response = promise.getOrThrow();
        assertThat(response.getStatus()).isEqualTo(Status.BAD_REQUEST);
        RegistrationRequest registrationRequest = (RegistrationRequest) context.getAttributes().get("registrationRequest");
        assertThat(registrationRequest).isNull();
        verify(handler, never()).handle(context, request);
    }

    private String createRegistrationRequestWithJwksBasedSSA(Map<String, Object> ssaClaims) throws NoSuchAlgorithmException {
        RSASSASigner signer = CryptoUtils.createRSASSASigner();
        // Can make valid JWKS entry!! Grrr
        String ssa = CryptoUtils.createEncodedJwtString(ssaClaims, JWSAlgorithm.PS256);
        Map<String, Object> regRequestClaims = Map.of("iss", "Acme App", "software_statement", ssa);
        return CryptoUtils.createEncodedJwtString(regRequestClaims, JWSAlgorithm.PS256);
    }

    @Test
    void successWithOBTestDirectoryRequest_filter() throws InterruptedException, NoSuchAlgorithmException {
        // Given
        final AttributesContext context = new AttributesContext(new RootContext());
        Request request = new Request();
        Map<String, Object> ssaClaims = Map.of("iss", "OpenBanking Ltd", "software_jwks_endpoint", "https://jwks.com",
                "org_id", "Acme Inc", "software_id", "Acme Banking App");

        // When
        when(reqRequestSupplier.apply(context, request)).thenReturn(createRegistrationRequestWithJwksUriBasedSSA(ssaClaims));
        Promise<Response, NeverThrowsException> promise = filter.filter(context, request, handler);

        assertThat(promise).isNotNull();
        Response response = promise.getOrThrow();
        assertThat(response.getStatus()).isEqualTo(Status.OK);
        RegistrationRequest registrationRequest = (RegistrationRequest) context.getAttributes().get("registrationRequest");
        assertThat(registrationRequest).isNotNull();
        SoftwareStatement softwareStatement = registrationRequest.getSoftwareStatement();
        assertThat(softwareStatement).isNotNull();
        assertThat(softwareStatement.hasJwksUri()).isTrue();
    }

    private String createRegistrationRequestWithJwksUriBasedSSA(Map<String, Object> ssaClaims) throws NoSuchAlgorithmException {
        RSASSASigner signer = CryptoUtils.createRSASSASigner();
        String ssa = CryptoUtils.createEncodedJwtString(ssaClaims, JWSAlgorithm.PS256);
        Map<String, Object> regRequestClaims = Map.of("iss", "Acme App", "software_statement", ssa);
        String registrationRequest = CryptoUtils.createEncodedJwtString(regRequestClaims, JWSAlgorithm.PS256);
        return registrationRequest;
    }

    private Object getJwkSetObject(){
        JWKSet jwkSet = CryptoUtils.createJwkSet();
        return jwkSet.toJsonValue().getObject();
    }
}