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

import static org.forgerock.json.JsonValue.json;
import static org.forgerock.json.jose.utils.JoseSecretConstraints.allowedAlgorithm;
import static org.forgerock.openig.util.JsonValues.purposeOf;
import static org.forgerock.openig.util.JsonValues.requiredHeapObject;
import static org.forgerock.util.promise.Promises.newExceptionPromise;
import static org.forgerock.util.promise.Promises.newResultPromise;

import java.net.URISyntaxException;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.function.Consumer;
import java.util.function.Function;
import java.util.function.Supplier;

import org.forgerock.http.Filter;
import org.forgerock.http.Handler;
import org.forgerock.http.MutableUri;
import org.forgerock.http.protocol.Form;
import org.forgerock.http.protocol.Request;
import org.forgerock.http.protocol.Response;
import org.forgerock.http.protocol.Status;
import org.forgerock.json.JsonValue;
import org.forgerock.json.jose.common.JwtReconstruction;
import org.forgerock.json.jose.jws.JwsAlgorithm;
import org.forgerock.json.jose.jws.JwsHeader;
import org.forgerock.json.jose.jws.SignedJwt;
import org.forgerock.json.jose.jws.SigningManager;
import org.forgerock.json.jose.jws.handlers.SigningHandler;
import org.forgerock.openig.heap.GenericHeaplet;
import org.forgerock.openig.heap.HeapException;
import org.forgerock.secrets.Purpose;
import org.forgerock.secrets.SecretsProvider;
import org.forgerock.secrets.keys.SigningKey;
import org.forgerock.secrets.keys.VerificationKey;
import org.forgerock.services.context.Context;
import org.forgerock.util.Reject;
import org.forgerock.util.promise.NeverThrowsException;
import org.forgerock.util.promise.Promise;
import org.forgerock.util.promise.Promises;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.forgerock.sapi.gateway.am.ReSignIdTokenFilter.IdTokenAccessorLocator.IdTokenAccessor;

/**
 * This filter aims to fix an issue in AM relating to signing of the id_token JWTs.
 * <p>
 * Certain use cases, such as OpenBanking UK, require keys from an external (to AM) jwks_uri be used to sign JWTs.
 * AM can be configured to use these private keys via secret mappings, but there is an issue with how AM determines
 * the kid value to use in the JWS header.
 * For the OpenBanking UK case, the kid value does not match what is expected which means that clients will not trust
 * id_token values return by AM.
 * <p>
 * To resolve this issue, this filter decodes the id_token returned by AM and creates a new one with the correct kid,
 * it is then signed using a key that must be configured to match the expected key in the external jwks_uri
 * <p>
 * There is a ticket open with AM to fix this issue: https://bugster.forgerock.org/jira/browse/OPENAM-15617
 */
public class ReSignIdTokenFilter implements Filter {

    private static final String ID_TOKEN_FIELD_NAME = "id_token";

    private final Logger logger = LoggerFactory.getLogger(getClass());

    /**
     * SigningManager containing AM Secrets to be used to validate that JWTs in the response path have been signed
     * correctly by AM before we re-sign them.
     */
    private final SigningManager verificationSigningManager;
    /**
     * Purpose used to find the VerificationKey in the verificationSigningManager to verify signatures with
     */
    private final Purpose<VerificationKey> verificationKeyPurpose;
    /**
     * The kid value to specify in the header of the re-signed JWT (must match a value in the trusted directories' jwks_uri)
     */
    private final String signingKeyId;
    /**
     * Purpose used to find the SigningKey in the SigningManager, should be configured to find the private key for
     * the signingKeyId
     */
    private final Purpose<SigningKey> signingKeyPurpose;
    /**
     * Created using the {@link SecretsProvider} passed to the constructor, used to create new {@link SigningHandler}
     * objects on a per Response processing basis.
     */
    private final SigningManager signingManager;
    /**
     * Locator of an {@link IdTokenAccessor} for a given Response.
     * <p>
     * The filter logic uses this to get and set the id_token value in the Response. Different implementations are
     * available, allowing this filter to be used to process responses from different AM endpoints.
     */
    private final IdTokenAccessorLocator idTokenAccessorLocator;

    public ReSignIdTokenFilter(SecretsProvider verificationSecretsProvider,
                               Purpose<VerificationKey> verificationKeyPurpose,
                               String signingKeyId,
                               SecretsProvider signingSecretsProvider,
                               Purpose<SigningKey> signingKeyPurpose,
                               IdTokenAccessorLocator idTokenAccessorLocator) {

        Reject.ifNull(verificationSecretsProvider, "verificationSecretsProvider must be supplied");
        Reject.ifNull(verificationKeyPurpose, "verificationKeyPurpose must be supplied");
        Reject.ifNull(signingKeyId, "signingKeyId must be supplied");
        Reject.ifNull(signingSecretsProvider, "signingSecretsProvider must be supplied");
        Reject.ifNull(signingKeyPurpose, "signingKeyPurpose must be supplied");
        Reject.ifNull(idTokenAccessorLocator, "idTokenLocator must be supplied");
        this.verificationSigningManager = new SigningManager(verificationSecretsProvider);
        this.verificationKeyPurpose = verificationKeyPurpose;
        this.signingKeyId = signingKeyId;
        this.signingKeyPurpose = signingKeyPurpose;
        this.signingManager = new SigningManager(signingSecretsProvider);
        this.idTokenAccessorLocator = idTokenAccessorLocator;
    }

    @Override
    public Promise<Response, NeverThrowsException> filter(Context context, Request request, Handler handler) {
        return handler.handle(context, request).thenAsync(response -> {
            // Allow AM errors to pass through
            if (!response.getStatus().isSuccessful() && !response.getStatus().isRedirection()) {
                return newResultPromise(response);
            } else {
                return idTokenAccessorLocator.createIdTokenAccessor(response).thenAsync(optionalIdTokenAccessor -> {
                    if (optionalIdTokenAccessor.isEmpty()) {
                        logger.debug("No id_token found in response, doing nothing.");
                        return newResultPromise(response);
                    }
                    final IdTokenAccessor idTokenAccessor = optionalIdTokenAccessor.get();
                    final String idTokenJwtString = idTokenAccessor.getIdToken();
                    logger.debug("Located id_token: {}", idTokenJwtString);

                    final SignedJwt signedJwt = new JwtReconstruction().reconstructJwt(idTokenJwtString, SignedJwt.class);
                    return verifyAmSignedIdToken(signedJwt).thenAsync(signatureValid -> {
                        if (!signatureValid) {
                            logger.error("id_token: {} does not have a valid signature", idTokenJwtString);
                            return newResultPromise(new Response(Status.INTERNAL_SERVER_ERROR));
                        }

                        return signingManager.newSigningHandler(signingKeyPurpose).then(signingHandler -> {
                            final String resignedIdTokenJwtString = reSignJwt(signedJwt, signingHandler);
                            logger.debug("id_token re-signed: {}", resignedIdTokenJwtString);
                            idTokenAccessor.setIdToken(resignedIdTokenJwtString);
                            return response;
                        }, nsse -> {
                            logger.error("Failed to create signingHandler", nsse);
                            return new Response(Status.INTERNAL_SERVER_ERROR);
                        });
                    });
                }, e -> {
                    logger.warn("Failed to locate id_token", e);
                    return newResultPromise(new Response(Status.INTERNAL_SERVER_ERROR));
                });
            }
        });
    }

    /**
     * Method to verify that the id_token SignedJwt was signed by AM
     *
     * @param signedJwt SignedJwt the JWT to verify that AM has signed
     * @return Promise<Boolean, NeverThrowsException> the result of signature verification
     */
    private Promise<Boolean, NeverThrowsException> verifyAmSignedIdToken(SignedJwt signedJwt) {
        final JwsAlgorithm algorithm = signedJwt.getHeader().getAlgorithm();
        final Purpose<VerificationKey> constrainedPurpose =
                verificationKeyPurpose.withConstraints(allowedAlgorithm(algorithm));

        final String keyId = signedJwt.getHeader().getKeyId();
        return verificationSigningManager.newVerificationHandler(constrainedPurpose, keyId)
                                         .then(signedJwt::verify);
    }

    /**
     * Re-signs the supplied jwt using the signingKeyId and supplied signingHandler
     *
     * @param signedJwt      SignedJwt the JWT to re-sign
     * @param signingHandler SigningHandler capable of signing the JWT
     * @return String jwt signed using the signingKeyId
     */
    private String reSignJwt(SignedJwt signedJwt, SigningHandler signingHandler) {
        final JwsHeader headerWithCorrectKeyId = new JwsHeader(signedJwt.getHeader().getParameters());
        headerWithCorrectKeyId.setKeyId(signingKeyId);
        final SignedJwt resignedIdTokenJwt = new SignedJwt(headerWithCorrectKeyId, signedJwt.getClaimsSet(), signingHandler);
        return resignedIdTokenJwt.build();
    }

    /**
     * Locator of IdTokenAccessors for a particular Response object.
     */
    interface IdTokenAccessorLocator {

        /**
         * Represents a getter/setter for an id_token, which allows the calling class to be agnostic of the actual
         * location of the id_token within the Response object.
         */
        class IdTokenAccessor {

            private final String idToken;
            private final Consumer<String> idTokenSetter;

            private IdTokenAccessor(String idToken, Consumer<String> idTokenSetter) {
                this.idToken = idToken;
                this.idTokenSetter = idTokenSetter;
            }

            public String getIdToken() {
                return idToken;
            }

            public void setIdToken(String idToken) {
                idTokenSetter.accept(idToken);
            }
        }

        /**
         * @param response Response object to create the IdTokenAccessor for
         * @return Optional<IdTokenAccessor> an IdTokenAccessor which is capable of getting and setting the id_token,
     *                                       or an empty Optional if no id_token can be located
         */
        Promise<Optional<IdTokenAccessor>, Exception> createIdTokenAccessor(Response response);

    }

    /**
     * IdTokenLocator implementation that works with /access_token responses:
     * https://backstage.forgerock.com/docs/am/7.2/oauth2-guide/oauth2-access_token-endpoint.html
     * <p>
     * The id_token field is optional in the json response, only being returned if the openid scope was requested.
     */
    static class AccessTokenEndpointIdTokenAccessorLocator implements IdTokenAccessorLocator {

        private final Logger logger = LoggerFactory.getLogger(getClass());

        @Override
        public Promise<Optional<IdTokenAccessor>, Exception> createIdTokenAccessor(Response response) {
            return response.getEntity().getJsonAsync().thenAsync(jsonObj -> {
                logger.debug("Locating id_token in response json");
                final JsonValue json = json(jsonObj);
                final JsonValue idTokenValue = json.get(ID_TOKEN_FIELD_NAME);
                if (idTokenValue.isNull() || !idTokenValue.isString()) {
                    logger.debug("No id_token in response json");
                    return newResultPromise(Optional.empty());
                }
                final String idToken = idTokenValue.asString();
                return newResultPromise(Optional.of(new IdTokenAccessor(idToken, (updatedIdToken) -> {
                    // Assumption that json contents will not change between call to findIdToken and call to set the updated token
                    json.put("id_token", updatedIdToken);
                    response.getEntity().setJson(json);
                })));
            }, Promises::newExceptionPromise);
        }
    }


    /**
     * IdTokenLocator implementation that works with the /authorize endpoint:
     * https://backstage.forgerock.com/docs/am/7.2/oauth2-guide/oauth2-authorize-endpoint.html
     * <p>
     * For this endpoint, the location of the token depends on the response_mode sent in the request (or the default
     * if none was supplied). Currently, the implementation assumes that the token is in the URI fragment of the
     * location header as per the OIDC Hybrid flow:
     * https://backstage.forgerock.com/docs/am/7.2/oidc1-guide/openid-connect-hybrid-flow.html
     * <p>
     * Further work is required to support JARM (response_mode=jwt), as the jwt containing the id_token would also
     * need to be re-signed.
     */
    static class AuthorizeEndpointIdTokenAccessorLocator implements IdTokenAccessorLocator {

        private final Logger logger = LoggerFactory.getLogger(getClass());

        @Override
        public Promise<Optional<IdTokenAccessor>, Exception> createIdTokenAccessor(Response response) {
            try {
                final Optional<MutableUri> optionalLocationUri = getLocationHeader(response);
                if (optionalLocationUri.isEmpty()) {
                    logger.debug("No location header found, skipping");
                    return newResultPromise(Optional.empty());
                }
                final MutableUri locationUri = optionalLocationUri.get();
                logger.debug("Locating id_token in response location header: {}", locationUri);
                final String fragment = locationUri.getFragment();
                if (fragment == null) {
                    final String query = locationUri.getQuery();
                    if (query == null) {
                        return newResultPromise(Optional.empty());
                    } else {
                        return buildIdTokenQueryAccessor(response, locationUri, query);
                    }
                }
                return buildIdTokenFragmentAccessor(response, locationUri, fragment);
            } catch (URISyntaxException e) {
                return newExceptionPromise(e);
            }
        }

        private Promise<Optional<IdTokenAccessor>, Exception> buildIdTokenFragmentAccessor(Response response,
                                                                                           MutableUri locationUri,
                                                                                           String fragment) {
            return buildFormAccessor(response, fragment, (fragmentOrQuery) -> {
                try {
                    locationUri.setFragment(fragmentOrQuery);
                    return locationUri;
                } catch (URISyntaxException e) {
                    throw new RuntimeException(e);
                }
            });
        }

        private Promise<Optional<IdTokenAccessor>, Exception> buildIdTokenQueryAccessor(Response response,
                                                                                        MutableUri locationUri,
                                                                                        String query) {
            return buildFormAccessor(response, query, (fragmentOrQuery) -> {
                try {
                    locationUri.setQuery(fragmentOrQuery);
                    return locationUri;
                } catch (URISyntaxException e) {
                    throw new RuntimeException(e);
                }
            });
        }

        private Promise<Optional<IdTokenAccessor>, Exception> buildFormAccessor(Response response, String fragmentOrQuery,
                                                                                Function<String, MutableUri> uriUpdater) {
            // fragments and query strings have the same format, both are parsable by the fromQueryString method
            final Form form = new Form().fromQueryString(fragmentOrQuery);
            final String idToken = form.getFirst(ID_TOKEN_FIELD_NAME);
            if (idToken == null) {
                logger.debug("No id_token found in location header");
                return newResultPromise(Optional.empty());
            }
            final Consumer<String> idTokenSetter = updatedIdToken -> {
                form.replace(ID_TOKEN_FIELD_NAME, List.of(updatedIdToken));
                final MutableUri updatedUri = uriUpdater.apply(form.toQueryString());
                response.getHeaders().replace("location", updatedUri.toString());
            };
            return newResultPromise(Optional.of(new IdTokenAccessor(idToken, idTokenSetter)));
        }

        private static Optional<MutableUri> getLocationHeader(Response response) throws URISyntaxException {
            final String locationHeader = response.getHeaders().getFirst("location");
            if (locationHeader == null) {
                return Optional.empty();
            }
            return Optional.of(MutableUri.uri(locationHeader));
        }
    }

    /**
     * Heaplet which creates {@link ReSignIdTokenFilter} objects.
     * <p>
     * Configuration:
     * - verificationSecretsProvider the name of the SecretsProvider heap object that contains the AM secrets
     *                               used to verify the id_token was signed by AM before re-signing it.
     * - verificationSecretId the secret id of the verification key in the verificationSecretsProvider.
     *                        Note: when using a {@link org.forgerock.secrets.jwkset.JwkSetSecretStore} based provider
     *                        then this value is not used in the key lookup but must be a non-blank value
     * - signingKeyId the kid value to specify in the re-signed JWS header
     * - signingSecretsProvider the name of the SecretsProvider heap object that contains the signing private key for the kid
     * - signingKeySecretId the secretId used to find the signing key in the secretsProvider
     * - endpointType which endpoint is this filter being used with, valid values: [access_token, authorize]
     * <p>
     * Example config:
     * {
     *   "name": "ReSignIdTokenFilter",
     *   "type": "ReSignIdTokenFilter",
     *   "comment": "Re-sign the id_token returned by AM to fix OB keyId issue",
     *   "config": {
     *     "verificationSecretsProvider": "SecretsProvider-AmJWK",
     *     "verificationSecretId": "any.valid.regex.value",
     *     "signingKeyId": "&{ig.ob.aspsp.signing.kid}",
     *     "signingSecretsProvider": "SecretsProvider-ASPSP",
     *     "signingKeySecretId": "jwt.signer",
     *     "endpointType": "access_token"
     *   }
      *}
     */
    public static class Heaplet extends GenericHeaplet {
        private static final Map<String, Supplier<IdTokenAccessorLocator>> ENDPOINT_TYPE_REGISTRY = new HashMap<>();

        static {
            ENDPOINT_TYPE_REGISTRY.put("authorize", AuthorizeEndpointIdTokenAccessorLocator::new);
            ENDPOINT_TYPE_REGISTRY.put("access_token", AccessTokenEndpointIdTokenAccessorLocator::new);
        }

        @Override
        public Object create() throws HeapException {
            final SecretsProvider signingSecretsProvider = config.get("signingSecretsProvider")
                                                                 .as(requiredHeapObject(heap, SecretsProvider.class));
            final Purpose<SigningKey> signingKeyPurpose = config.get("signingKeySecretId")
                                                                .as(purposeOf(SigningKey.class));

            final String endpointType = config.get("endpointType").asString();
            final Supplier<IdTokenAccessorLocator> idTokenAccessorLocatorSupplier = ENDPOINT_TYPE_REGISTRY.get(endpointType);
            Reject.ifNull(idTokenAccessorLocatorSupplier,
                    "Unsupported endpointType: " + endpointType + ", specify one of: " + ENDPOINT_TYPE_REGISTRY.keySet());

            final SecretsProvider verificationSecretsProvider = config.get("verificationSecretsProvider")
                                                                      .as(requiredHeapObject(heap, SecretsProvider.class));
            final Purpose<VerificationKey> verificationKeyPurpose = config.get("verificationSecretId")
                                                                          .as(purposeOf(VerificationKey.class));

            final String signingKeyId = config.get("signingKeyId").asString();
            return new ReSignIdTokenFilter(verificationSecretsProvider,
                                           verificationKeyPurpose,
                                           signingKeyId,
                                           signingSecretsProvider,
                                           signingKeyPurpose,
                                           idTokenAccessorLocatorSupplier.get());
        }
    }
}
