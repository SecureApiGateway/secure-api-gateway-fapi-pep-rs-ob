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
package com.forgerock.sapi.gateway.am;

import static org.forgerock.json.JsonValue.field;
import static org.forgerock.json.JsonValue.json;
import static org.forgerock.json.JsonValue.object;
import static org.forgerock.json.jose.utils.BigIntegerUtils.base64UrlEncodeUnsignedBigEndian;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

import java.io.IOException;
import java.net.URISyntaxException;
import java.security.KeyPair;
import java.security.interfaces.RSAPublicKey;
import java.text.ParseException;
import java.time.Clock;
import java.time.Instant;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

import org.forgerock.http.MutableUri;
import org.forgerock.http.header.LocationHeader;
import org.forgerock.http.protocol.Form;
import org.forgerock.http.protocol.Header;
import org.forgerock.http.protocol.Request;
import org.forgerock.http.protocol.Response;
import org.forgerock.http.protocol.Status;
import org.forgerock.json.JsonValue;
import org.forgerock.json.jose.jwk.JWKSet;
import org.forgerock.json.jose.jwk.RsaJWK;
import org.forgerock.openig.heap.HeapException;
import org.forgerock.openig.heap.HeapImpl;
import org.forgerock.openig.heap.Name;
import org.forgerock.secrets.NoSuchSecretException;
import org.forgerock.secrets.Purpose;
import org.forgerock.secrets.SecretBuilder;
import org.forgerock.secrets.SecretsProvider;
import org.forgerock.secrets.jwkset.JwkSetSecretStore;
import org.forgerock.secrets.keys.SigningKey;
import org.forgerock.secrets.keys.VerificationKey;
import org.forgerock.services.context.AttributesContext;
import org.forgerock.services.context.Context;
import org.forgerock.services.context.RootContext;
import org.forgerock.util.Options;
import org.forgerock.util.promise.NeverThrowsException;
import org.forgerock.util.promise.Promise;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import com.forgerock.sapi.gateway.am.ReSignIdTokenFilter.AccessTokenEndpointIdTokenAccessorLocator;
import com.forgerock.sapi.gateway.am.ReSignIdTokenFilter.AuthorizeEndpointIdTokenAccessorLocator;
import com.forgerock.sapi.gateway.am.ReSignIdTokenFilter.Heaplet;
import com.forgerock.sapi.gateway.am.ReSignIdTokenFilter.IdTokenAccessorLocator;
import com.forgerock.sapi.gateway.util.CryptoUtils;
import com.forgerock.sapi.gateway.util.TestHandlers.FixedResponseHandler;
import com.forgerock.sapi.gateway.util.TestHandlers.TestHandler;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSHeader.Builder;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

class ReSignIdTokenFilterTest {

    // Filter does not touch this value so does not need to be a valid JWT
    private static final String ACCESS_TOKEN_VALUE = "access-token-123";
    private static final String SCOPE_VALUE = "openid payments";
    private static final String TOKEN_TYPE_VALUE = "Bearer";
    private static final int EXPIRES_IN_VALUE = 359999;
    private static final String ACCESS_TOKEN = "access_token";
    private static final String SCOPE = "scope";
    private static final String ID_TOKEN = "id_token";
    private static final String TOKEN_TYPE = "token_type";
    private static final String EXPIRES_IN = "expires_in";
    private static final String ID_TOKEN_ISSUER = "openam";
    private static final String TOKEN_NAME = "tokenName";
    private static final String TOKEN_NAME_VALUE = "id_token";
    private static final String REDIRECT_URI = "https://acme-fintech/callback";
    private static final String AUTHORISATION_CODE_PARAM = "code";
    private static final String AUTHORISATION_CODE_VALUE = "fsfgfgftwtqrtwq34";

    // AM related secrets
    private final RSASSASigner amJwtSigner;
    private final String amSigningKeyId;
    private final SecretsProvider amVerifyingSecretsProvider;
    private final Purpose<VerificationKey> amVerificationKeyPurpose;

    // OB releated secrets
    private final RSASSAVerifier obJwtVerifier;
    private final String obSigningKeyId;
    private final SecretsProvider obSigningSecretsProvider;
    private final Purpose<SigningKey> signingKeyPurpose = Purpose.SIGN;

    public ReSignIdTokenFilterTest() {
        final KeyPair amKeyPair = CryptoUtils.generateRsaKeyPair();
        this.amJwtSigner = new RSASSASigner(amKeyPair.getPrivate());
        this.amSigningKeyId = "am-kid";

        this.amVerifyingSecretsProvider = new SecretsProvider(Clock.systemUTC());

        // Create a JwkSetSecretStore using the AM public key, used in the filter to verify signs from AM
        final RSAPublicKey amPublicKey = (RSAPublicKey) amKeyPair.getPublic();
        final RsaJWK amSigningKeyJwk = RsaJWK.builder(base64UrlEncodeUnsignedBigEndian(amPublicKey.getModulus()),
                                                      base64UrlEncodeUnsignedBigEndian(amPublicKey.getPublicExponent()))
                                             .keyId(amSigningKeyId).build();
        final JWKSet amJwks = new JWKSet(amSigningKeyJwk);
        amVerifyingSecretsProvider.setDefaultStores(new JwkSetSecretStore(amJwks, Options.unmodifiableDefaultOptions()));

        // When using the JwkSetSecretStore, the verification key id is not used but needs to be valid as per the regex.
        this.amVerificationKeyPurpose = Purpose.purpose("any.value", VerificationKey.class);

        final KeyPair obKeyPair = CryptoUtils.generateRsaKeyPair();
        this.obJwtVerifier = new RSASSAVerifier((RSAPublicKey) obKeyPair.getPublic());
        this.obSigningKeyId = "ob-kid";

        // SecretProvider installed into the filter that does the signing
        obSigningSecretsProvider = new SecretsProvider(Clock.systemUTC());
        try {
            obSigningSecretsProvider.useSpecificSecretForPurpose(signingKeyPurpose,
                    new SigningKey(new SecretBuilder().stableId(obSigningKeyId).secretKey(obKeyPair.getPrivate()).expiresAt(Instant.MAX)));
        } catch (NoSuchSecretException e) {
            throw new RuntimeException(e);
        }

    }

    private static Response buildAccessTokenEndpointResponse(String idToken) {
        return new Response(Status.OK).setEntity(json(object(
                field(ACCESS_TOKEN, ACCESS_TOKEN_VALUE),
                field(SCOPE, SCOPE_VALUE),
                field(ID_TOKEN, idToken),
                field(TOKEN_TYPE, TOKEN_TYPE_VALUE),
                field(EXPIRES_IN, EXPIRES_IN_VALUE)

        )));
    }

    private static Response buildAuthoriseEndpointFragmentResponse(String idToken) {
        return buildAuthoriseEndpointResponse(true, idToken);
    }

    private static Response buildAuthoriseEndpointQueryResponse(String idToken) {
        return buildAuthoriseEndpointResponse(false, idToken);
    }

    private static Response buildAuthoriseEndpointResponse(boolean fragment, String idToken) {
        final String locationUri = REDIRECT_URI + (fragment ? "#" : "?")
                + AUTHORISATION_CODE_PARAM + "=" + AUTHORISATION_CODE_VALUE + "&" + ID_TOKEN + "=" + idToken;

        return new Response(Status.OK).addHeaders(new LocationHeader(locationUri));
    }

    private String createAmSignedIdToken(String jti) {
        try {
            return createSignedIdToken(amJwtSigner, amSigningKeyId, jti);
        } catch (JOSEException e) {
            throw new RuntimeException(e);
        }
    }

    private static String createSignedIdToken(RSASSASigner signer, String kid, String jti) throws JOSEException {
        final SignedJWT signedJWT = new SignedJWT(new Builder(JWSAlgorithm.PS256).keyID(kid).build(),
                new JWTClaimsSet.Builder().issuer(ID_TOKEN_ISSUER).claim(TOKEN_NAME, TOKEN_NAME_VALUE).jwtID(jti).build());

        signedJWT.sign(signer);
        return signedJWT.serialize();
    }

    private ReSignIdTokenFilter createFilter(IdTokenAccessorLocator idTokenAccessorLocator) {
        return new ReSignIdTokenFilter(amVerifyingSecretsProvider, amVerificationKeyPurpose, obSigningKeyId,
                obSigningSecretsProvider, signingKeyPurpose, idTokenAccessorLocator);
    }

    @Test
    void testAccessTokenEndpointIdTokenIsReSigned() {
        testAccessTokenEndpointIdTokenIsReSigned(createFilter(new AccessTokenEndpointIdTokenAccessorLocator()));
    }

    private void testAccessTokenEndpointIdTokenIsReSigned(ReSignIdTokenFilter reSignIdTokenFilter) {
        final String expectedJti = UUID.randomUUID().toString();
        final TestHandler responseHandler = new FixedResponseHandler(buildAccessTokenEndpointResponse(createAmSignedIdToken(expectedJti)));

        final Response response = invokeFilter(reSignIdTokenFilter, responseHandler);

        validateSuccessResponseJwt(response, expectedJti);
    }

    @Test
    void testAuthoriseEndpointFragmentIdTokenIsReSigned() {
        testAuthoriseEndpointFragmentIdTokenIsReSigned(createFilter(new AuthorizeEndpointIdTokenAccessorLocator()));
    }

    private void testAuthoriseEndpointFragmentIdTokenIsReSigned(ReSignIdTokenFilter reSignIdTokenFilter) {
        final String expectedJti = UUID.randomUUID().toString();
        final TestHandler responseHandler = new FixedResponseHandler(buildAuthoriseEndpointFragmentResponse(createAmSignedIdToken(expectedJti)));

        final Response response = invokeFilter(reSignIdTokenFilter, responseHandler);

        validateSuccessAuthoriseFragmentResponse(response, expectedJti);
    }

    @Test
    void testAuthoriseEndpointQueryIdTokenIsReSigned() {
        testAuthoriseEndpointQueryIdTokenIsReSigned(createFilter(new AuthorizeEndpointIdTokenAccessorLocator()));
    }

    private void testAuthoriseEndpointQueryIdTokenIsReSigned(ReSignIdTokenFilter reSignIdTokenFilter) {
        final String expectedJti = UUID.randomUUID().toString();
        final TestHandler responseHandler = new FixedResponseHandler(buildAuthoriseEndpointQueryResponse(createAmSignedIdToken(expectedJti)));

        final Response response = invokeFilter(reSignIdTokenFilter, responseHandler);

        validateSuccessAuthoriseQueryResponse(response, expectedJti);
    }

    @Test
    void testAmErrorResponsesArePassedThrough()  {
        final ReSignIdTokenFilter reSignIdTokenFilter = createFilter(new AccessTokenEndpointIdTokenAccessorLocator());
        final TestHandler responseHandler = new FixedResponseHandler(new Response(Status.BAD_REQUEST));

        final Response response = invokeFilter(reSignIdTokenFilter, responseHandler);
        assertEquals(Status.BAD_REQUEST, response.getStatus());
    }

    @Test
    void testAccessTokenResponsesWithNoIdTokenArePassedThrough() throws IOException {
        final ReSignIdTokenFilter reSignIdTokenFilter = createFilter(new AccessTokenEndpointIdTokenAccessorLocator());
        final TestHandler responseHandler = new FixedResponseHandler(buildAccessTokenEndpointResponse(null));

        final Response response = invokeFilter(reSignIdTokenFilter, responseHandler);

        assertEquals(Status.OK, response.getStatus());
        validateResponseJwtNonIdTokenFields(response);
        assertTrue(json(response.getEntity().getJson()).get("id_token").isNull());
    }



    @Test
    void testAccessTokenResponseNotJsonRaisesError() {
        final ReSignIdTokenFilter reSignIdTokenFilter = createFilter(new AccessTokenEndpointIdTokenAccessorLocator());

        // Form response instead of json
        final TestHandler responseHandler = new FixedResponseHandler(new Response(Status.OK).setEntity(new Form().fromQueryString("key=value")));

        final Response response = invokeFilter(reSignIdTokenFilter, responseHandler);
        assertEquals(Status.INTERNAL_SERVER_ERROR, response.getStatus());
    }

    @Test
    void testIdTokensNotSignedCorrectlyRaisesError() throws JOSEException {
        final ReSignIdTokenFilter reSignIdTokenFilter = createFilter(new AccessTokenEndpointIdTokenAccessorLocator());
        final String expectedJti = UUID.randomUUID().toString();

        final RSASSASigner signerWithUnknownKey = new RSASSASigner(CryptoUtils.generateRsaKeyPair().getPrivate());
        final TestHandler responseHandler = new FixedResponseHandler(buildAccessTokenEndpointResponse(
                createSignedIdToken(signerWithUnknownKey, amSigningKeyId, expectedJti)));

        final Response response = invokeFilter(reSignIdTokenFilter, responseHandler);
        assertEquals(Status.INTERNAL_SERVER_ERROR, response.getStatus());
    }

    @Nested
    class HeapletTests {

        @Test
        void testConstructAccessTokenEndpointFilter() throws HeapException {
            final Name test = Name.of("test");
            final ReSignIdTokenFilter filter = (ReSignIdTokenFilter) new Heaplet().create(test,
                    createJsonConfig("access_token"), createHeap());

            testAccessTokenEndpointIdTokenIsReSigned(filter);
        }

        @Test
        void testConstructAuthoriseEndpointFilter() throws HeapException {
            final Name test = Name.of("test");

            final ReSignIdTokenFilter filter = (ReSignIdTokenFilter) new Heaplet().create(test,
                    createJsonConfig("authorize"), createHeap());

            testAuthoriseEndpointFragmentIdTokenIsReSigned(filter);
            testAuthoriseEndpointQueryIdTokenIsReSigned(filter);
        }

        @Test
        void failToConstructForUnsupportedEndpointType() {
            final Name test = Name.of("test");

            final NullPointerException exception = assertThrows(NullPointerException.class, () -> new Heaplet().create(test,
                    createJsonConfig("blah"), createHeap()));
            assertEquals("Unsupported endpointType: blah, specify one of: [access_token, authorize]", exception.getMessage());
        }

        private HeapImpl createHeap() {
            final HeapImpl heap = new HeapImpl(Name.of("test"));
            heap.put("ObSigningSecretsProvider", obSigningSecretsProvider);
            heap.put("AMSecretsProvider", amVerifyingSecretsProvider);
            return heap;
        }

        private JsonValue createJsonConfig(String endpointType) {
            return json(object(field("verificationSecretsProvider", "AMSecretsProvider"),
                               field("verificationSecretId", "value.is.ignored"),
                               field("signingSecretsProvider", "ObSigningSecretsProvider"),
                               field("signingKeyId", obSigningKeyId),
                               field("signingKeySecretId", signingKeyPurpose.getLabel()),
                               field("endpointType", endpointType)));
        }

    }

    private static Response invokeFilter(ReSignIdTokenFilter reSignIdTokenFilter, TestHandler responseHandler)  {
        final Context context = new AttributesContext(new RootContext());
        final Promise<Response, NeverThrowsException> responsePromise = reSignIdTokenFilter.filter(context, new Request(), responseHandler);
        try {
            return responsePromise.get(1, TimeUnit.SECONDS);
        } catch (ExecutionException | TimeoutException | InterruptedException e) {
            throw new RuntimeException(e);
        } finally {
            assertTrue(responseHandler.hasBeenInteractedWith());
        }
    }

    private void validateSuccessResponseJwt(Response response, String expectedIdTokenJti) {
        assertEquals(Status.OK, response.getStatus());
        try {
            final JsonValue json = validateResponseJwtNonIdTokenFields(response);

            final String idToken = json.get(ID_TOKEN).asString();
            validateIdTokenHasBeenReSigned(expectedIdTokenJti, idToken);
        } catch (IOException | ParseException e) {
            throw new RuntimeException(e);
        }
    }

    private static JsonValue validateResponseJwtNonIdTokenFields(Response response) throws IOException {
        final JsonValue json = json(response.getEntity().getJson());
        assertTrue(json.isMap());
        // Valid non id_token fields in AM response are untouched by the filter
        assertEquals(ACCESS_TOKEN_VALUE, json.get(ACCESS_TOKEN).asString());
        assertEquals(SCOPE_VALUE, json.get(SCOPE).asString());
        assertEquals(TOKEN_TYPE_VALUE, json.get(TOKEN_TYPE).asString());
        assertEquals(EXPIRES_IN_VALUE, json.get(EXPIRES_IN).asInteger());
        return json;
    }

    private void validateIdTokenHasBeenReSigned(String expectedIdTokenJti, String idToken) throws ParseException {
        final SignedJWT idTokenJwt = SignedJWT.parse(idToken);
        try {
            idTokenJwt.verify(obJwtVerifier);
        } catch (JOSEException e) {
            fail("Failed to verify id_token was signed by ob key", e);
        }

        // Valid the id_token header and claims match what is expected
        final JWSHeader header = idTokenJwt.getHeader();
        assertEquals(JWSAlgorithm.PS256, header.getAlgorithm());
        assertEquals(obSigningKeyId, header.getKeyID());
        final JWTClaimsSet jwtClaimsSet = idTokenJwt.getJWTClaimsSet();
        assertEquals(ID_TOKEN_ISSUER, jwtClaimsSet.getIssuer());
        assertEquals(TOKEN_NAME_VALUE, jwtClaimsSet.getClaim(TOKEN_NAME));
        assertEquals(expectedIdTokenJti, jwtClaimsSet.getJWTID());
    }

    private void validateSuccessAuthoriseFragmentResponse(Response response, String expectedIdTokenJti) {
        assertEquals(Status.OK, response.getStatus());
        final MutableUri locationUri = getLocationUri(response);
        try {
            final Optional<String> idToken = new Form().fromQueryString(locationUri.getFragment()).get(ID_TOKEN).stream().findFirst();
            assertTrue(idToken.isPresent());
            validateIdTokenHasBeenReSigned(expectedIdTokenJti, idToken.get());
        } catch (ParseException ex) {
            throw new RuntimeException(ex);
        }
    }

    private void validateSuccessAuthoriseQueryResponse(Response response, String expectedIdTokenJti) {
        assertEquals(Status.OK, response.getStatus());
        final MutableUri locationUri = getLocationUri(response);
        try {
            final Optional<String> idToken = new Form().fromQueryString(locationUri.getQuery()).get(ID_TOKEN).stream().findFirst();
            assertTrue(idToken.isPresent());
            validateIdTokenHasBeenReSigned(expectedIdTokenJti, idToken.get());
        } catch (ParseException ex) {
            throw new RuntimeException(ex);
        }
    }

    private static MutableUri getLocationUri(Response response) {
        final Header location = response.getHeaders().get("location");
        try {
            return MutableUri.uri(location.getFirstValue());
        } catch (URISyntaxException e) {
            throw new RuntimeException(e);
        }
    }

}