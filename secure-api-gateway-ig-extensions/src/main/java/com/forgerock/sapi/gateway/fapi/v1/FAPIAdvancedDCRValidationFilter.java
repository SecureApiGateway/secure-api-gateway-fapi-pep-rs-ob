/*
 * Copyright © 2020-2024 ForgeRock AS (obst@forgerock.com)
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
package com.forgerock.sapi.gateway.fapi.v1;

import static org.forgerock.openig.util.JsonValues.requiredHeapObject;

import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.function.BiFunction;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import org.forgerock.http.Filter;
import org.forgerock.http.Handler;
import org.forgerock.http.protocol.Request;
import org.forgerock.http.protocol.Response;
import org.forgerock.json.JsonValue;
import org.forgerock.json.jose.common.JwtReconstruction;
import org.forgerock.json.jose.exceptions.InvalidJwtException;
import org.forgerock.json.jose.jws.JwsAlgorithm;
import org.forgerock.json.jose.jws.SignedJwt;
import org.forgerock.json.jose.jwt.JwtClaimsSet;
import org.forgerock.openig.heap.GenericHeaplet;
import org.forgerock.openig.heap.HeapException;
import org.forgerock.services.context.Context;
import org.forgerock.util.promise.NeverThrowsException;
import org.forgerock.util.promise.Promise;
import org.forgerock.util.promise.Promises;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.forgerock.sapi.gateway.dcr.common.DCRErrorCode;
import com.forgerock.sapi.gateway.dcr.common.ErrorResponseFactory;
import com.forgerock.sapi.gateway.dcr.common.Validator;
import com.forgerock.sapi.gateway.dcr.common.exceptions.ValidationException;
import com.forgerock.sapi.gateway.mtls.CertificateRetriever;
import com.forgerock.sapi.gateway.mtls.ContextCertificateRetriever;
import com.forgerock.sapi.gateway.mtls.HeaderCertificateRetriever;

/**
 * Filter which rejects Dynamic Client Registration (DCR) request that would result in OAuth2 clients that would not
 * meet the following FAPI specifications:
 * <p>
 * <a href="https://openid.net/specs/openid-financial-api-part-1-1_0.html#authorization-server">
 * Financial-grade API Security Profile 1.0 - Part 1: Baseline</a>
 * </p>
 * <p>
 * <a href="https://openid.net/specs/openid-financial-api-part-2-1_0.html">
 * Financial-grade API Security Profile 1.0 - Part 2: Advanced</a>
 * </p>
 *
 * This filter ensures that when subsequent filters are called the following conditions of the FAPI spec have been
 * met:
 *
 * <ul>
 *   <li>5.2.2 2: shall require:</li>
 *   <ul>
 *     <li>the response_type value code id_token, or</li>
 *     <li>the response_type value code in conjunction with the response_mode value jwt;</li>
 *   </ul>
 * </ul>
 *
 * <a href="https://openid.net/specs/openid-financial-api-part-2-1_0.html#algorithm-considerations">
 *     Financial-grade API Security Profile 1.0 - Part 2: Advanced </a>  section 8.6 states:
 *
 * <p>For JWS, both clients and authorization servers
 * <ol>
 *     <li>shall use PS256 or ES256 algorithms; </li>
 *     <li>should not use algorithms that use RSASSA-PKCS1-v1_5 (e.g. RS256); and </li>
 *     <li>shall not use none</li>
 * </ol>
 *
 * <p>
 * <a href="https://openid.net/specs/openid-financial-api-part-2-1_0.html#algorithm-considerations">
 *  Financial-grade API Security Profile 1.0 - Part 2: Advanced</a>, in section 5.2.2-14 states:
 *  </p>
 *  <p>>
 *  shall authenticate the confidential client using one of the following methods (this overrides FAPI Security Profile 1.0 - Part 1: Baseline clause 5.2.2-4):
 *  <ol>
 *     <li>tls_client_auth or self_signed_tls_client_auth as specified in section 2 of <a href="https://tools.ietf.org/html/rfc8705">MTLS</a>, or</li>
 *     <li>private_key_jwt as specified in section 9 of <a href="http://openid.net/specs/openid-connect-core-1_0.html">OIDC</a>;</li>
 *  </ol>
 *  </p>
 *
 * From the <a href="https://openid.net/specs/openid-financial-api-part-1-1_0.html#authorization-server">
 * Financial-grade API Security Profile 1.0 - Part 1: Baseline</a>:
 * <ul>
 *     <li>5.2.2 8: shall require redirect URIs to be pre-registered; </li>
 *     <li>5.2.2 9: shall require the redirect_uri in the authorization request; </li>
 *     <li>5.2.2 20: shall require redirect URIs to use the https scheme; </li>
 * </ul>
 *
*  Note, we also check that the redirect_uri does not contain localhost as we don't want redirects to URIs on the
 * </p>
 *
 * <p>
 * This filter should sit in front of filter(s) which implement DCR for a particular API.
 * <p>
 * This filter will reject any requests which would result in an OAuth2 client being created which did not conform to
 * the FAPI spec.
 * <p>
 * IG Config required to create this filter:
 * <pre>
 *     {@code {
 *         "type": "FAPIAdvancedDCRValidationFilter",
 *         "config": {
 *             "certificateRetriever"                   : CertificateRetriever [OPTIONAL]
 *             "clientTlsCertHeader"                    : String               [OPTIONAL] [DEPRECATED]
 *             "supportedSigningAlgorithms"             : String[]             [OPTIONAL]
 *             "supportedTokenEndpointAuthMethods"      : String[]             [OPTIONAL]
 *             "registrationObjectSigningFieldNames"    : String[]             [OPTIONAL]
 *         }
 *    }
 *    }
 * </pre>
 * certificateRetriever is a {@link CertificateRetriever} object heap reference, this object is used to retrieve the
 * client's MTLS transport certificate in order to carry out validation on it. Different implementations are available,
 * see {@link HeaderCertificateRetriever} and {@link ContextCertificateRetriever} for examples.
 * This configuration is OPTIONAL but is strongly recommended to be used in preference to the deprecated
 * clientTlsCertHeader config.
 * <p>
 * clientTlsCertHeader is the name of the header to extract the client's MTLS cert from.
 * The header value must contain a PEM encoded, then URL encoded, x509 certificate.
 * This configuration is OPTIONAL.
 * This configuration is now deprecated, use certificateRetriever instead
 * <p>
 * supportedSigningAlgorithms configures which JWS algorithms are supported for signing, see DEFAULT_SUPPORTED_JWS_ALGORITHMS for the default
 * values if this config is omitted.
 * <p>
 * supportedTokenEndpointAuthMethods configures which OAuth2 token_endpoint_auth_method values are accepted,
 * see DEFAULT_SUPPORTED_TOKEN_ENDPOINT_AUTH_METHODS for the default values if this config is omitted.
 * <p>
 * registrationObjectSigningFieldNames configures which fields inside the registration request object should be validated
 * against the supportedSigningAlgorithms
 */
public class FAPIAdvancedDCRValidationFilter implements Filter {

    private static final Logger LOGGER = LoggerFactory.getLogger(FAPIAdvancedDCRValidationFilter.class);

    /**
     * The HTTP methods to apply FAPI validation to.
     * POST is used to create new OAuth2 client's and PUT updates existing OAuth2 clients, both of these types of
     * request must be validated.
     * DCR API also supports GET and DELETE, there is no validation to apply here so requests with these methods should
     * be passed on down the chain.
     */
    private static final Set<String> VALIDATABLE_HTTP_REQUEST_METHODS = Set.of("POST", "PUT");

    private static final Set<String> RESPONSE_TYPE_CODE = Set.of("code");
    private static final Set<String> RESPONSE_TYPE_CODE_ID_TOKEN = Set.of("code", "id_token");

    private static final List<String> DEFAULT_SUPPORTED_JWS_ALGORITHMS = Stream.of(JwsAlgorithm.PS256, JwsAlgorithm.ES256)
                                                                               .map(JwsAlgorithm::getJwaAlgorithmName)
                                                                               .collect(Collectors.toList());

    private static final List<String> DEFAULT_SUPPORTED_TOKEN_ENDPOINT_AUTH_METHODS = List.of("tls_client_auth",
                                                                                              "self_signed_tls_client_auth",
                                                                                              "private_key_jwt");

    private static final List<String> DEFAULT_REG_OBJ_SIGNING_FIELD_NAMES = List.of("token_endpoint_auth_signing_alg",
                                                                                    "id_token_signed_response_alg",
                                                                                    "request_object_signing_alg");
    /**
     * The JWS signing algorithm's supported by FAPI.
     *
     * This is used to validate the registration JWT (if the registration is in JWT format) alg header and fields in
     * the registration request object which configure the signing algorithms to use for the OAuth2 client,
     * see {@link #registrationObjectSigningFieldNames}.
     *
     * This is configurable, for the default set of signing algorithms see {@link #DEFAULT_SUPPORTED_JWS_ALGORITHMS}
     */
    private Set<String> supportedSigningAlgorithms;

    /**
     * The registration request object's token_endpoint_auth_method values which are allowed by FAPI.
     *
     * This is configurable, for the default set of auth methods see {@link #DEFAULT_SUPPORTED_TOKEN_ENDPOINT_AUTH_METHODS}
     */
    private Set<String> supportedTokenEndpointAuthMethods;

    /**
     * The fields within the registration request object to validate against the {@link #supportedSigningAlgorithms}
     *
     * This is configurable, for the default set of fields see {@link #DEFAULT_REG_OBJ_SIGNING_FIELD_NAMES}
     */
    private Collection<String> registrationObjectSigningFieldNames;

    /**
     * Retrieves the client's mTLS certificate
     */
    private CertificateRetriever clientCertificateRetriever;

    /**
     * Function which returns the DCR Registration Request json object.
     *
     * NOTE: If a JWT is submitted which contains the DCR Registration Request as claims, then those claims should
     * be extracted from the JWT and returned. This function provides flexibility, allowing the registration request
     * to be sourced directly or unwrapped from within a JWT.
     */
    private BiFunction<Context, Request, JsonValue> registrationRequestObjectSupplier;

    /**
     * List of Validators which will validate the DCR Registration json object
     */
    private List<Validator<JsonValue>> registrationRequestObjectValidators;

    /**
     * Factory which produces HTTP Responses for DCR error conditions
     */
    private final ErrorResponseFactory errorResponseFactory;

    /**
     * The filter should be constructed using the {@link Heaplet}.
     * This object is complex to create, the Heaplet follows the builder pattern to produce a coherent object.
     */
    private FAPIAdvancedDCRValidationFilter() {
        errorResponseFactory = new ErrorResponseFactory();
    }

    /**
     * Checks the request conforms to the
     * <a href="https://openid.net/specs/openid-financial-api-part-2-1_0.html#authorization-server">
     *    Financial-grade API Security Profile 1.0 - Part 2: Advanced</a> specs.
     *
     *
     * @param context
     *            The request context.
     * @param request
     *            The request.
     * @param next
     *            The next filter or handler in the chain to handle the request.
     * @return
     */
    @Override
    public Promise<Response, NeverThrowsException> filter(Context context, Request request, Handler next) {
        if (!VALIDATABLE_HTTP_REQUEST_METHODS.contains(request.getMethod())) {
            return next.handle(context, request);
        }

        final X509Certificate x509Certificate;
        try {
            x509Certificate = clientCertificateRetriever.retrieveCertificate(context, request);
        } catch (CertificateException ce) {
            LOGGER.debug("FAPI Validation failed due to client certificate error", ce);
            return Promises.newResultPromise(errorResponseFactory.errorResponse(context, DCRErrorCode.INVALID_CLIENT_METADATA,
                    "MTLS client certificate is missing or malformed"));
        }
        try {
            x509Certificate.checkValidity();
        } catch (CertificateException ce) {
            LOGGER.debug("FAPI Validation failed due to client certificate validity date check failure", ce);
            return Promises.newResultPromise(errorResponseFactory.errorResponse(context, DCRErrorCode.INVALID_CLIENT_METADATA,
                    "MTLS client certificate has expired or cannot be used yet"));
        }

        try {
            final JsonValue registrationRequestObject = registrationRequestObjectSupplier.apply(context, request);
            if (registrationRequestObject == null) {
                throw new ValidationException(DCRErrorCode.INVALID_CLIENT_METADATA, "registration request entity is missing or malformed");
            }
            validateRegistrationRequestObject(registrationRequestObject);
        } catch (ValidationException ve) {
            LOGGER.debug("FAPI Validation failed", ve);
            return Promises.newResultPromise(errorResponseFactory.errorResponse(context, ve));
        } catch (RuntimeException re) {
            // Log that an unexpected RuntimeException occurred and throw it on
            LOGGER.warn("FAPI Validation failed due to unexpected RuntimeException", re);
            throw re;
        }
        return next.handle(context, request);
    }

    void validateRegistrationRequestObject(JsonValue registrationObject) {
        for (Validator<JsonValue> validator : registrationRequestObjectValidators) {
            validator.validate(registrationObject);
        }
    }

    /**
     * <a href="https://openid.net/specs/openid-financial-api-part-1-1_0.html#authorization-server">FAPI Baseline</a>
     * spec states that:
     * <ul>
     *     <li>5.2.2 8: shall require redirect URIs to be pre-registered; </li>
     *     <li>5.2.2 9: shall require the redirect_uri in the authorization request; </li>
     *     <li>5.2.2 20: shall require redirect URIs to use the https scheme; </li>
     * </ul>
     *
     * Note, we also check that the redirect_uri does not contain localhost as we don't want redirects to URIs on the
     * server
     * @param registrationObject
     */
    void validateRedirectUris(JsonValue registrationObject) {
        final List<String> redirectUris = registrationObject.get("redirect_uris").asList(String.class);
        if (redirectUris == null) {
            throw new ValidationException(DCRErrorCode.INVALID_REDIRECT_URI, "request object must contain redirect_uris field");
        }
        if (redirectUris.isEmpty()) {
            throw new ValidationException(DCRErrorCode.INVALID_REDIRECT_URI, "redirect_uris array must not be empty");
        }
        for (String uriString : redirectUris) {
            final URI redirectUri;
            try {
                redirectUri = new URI(uriString);
            } catch (URISyntaxException ex) {
                throw new ValidationException(DCRErrorCode.INVALID_REDIRECT_URI, "redirect_uri: " + uriString + " is not a valid URI");
            }
            if (!"https".equals(redirectUri.getScheme())) {
                throw new ValidationException(DCRErrorCode.INVALID_REDIRECT_URI, "redirect_uris must use https scheme");
            }

            if (redirectUri.getHost().contains("localhost")) {
                throw new ValidationException(DCRErrorCode.INVALID_REDIRECT_URI, "redirect_uris must not contain localhost");
            }
        }
    }

    /**
     * Validates that the response_types field contains only FAPI compliant response_type values, namely
     * "code" or "code id_token".
     * <p>
     * https://openid.net/specs/openid-financial-api-part-2-1_0.html#authorization-server specifies:
     * the authorization server shall require
     *
     *    1. the response_type value code id_token, or
     *    2. the response_type value code in conjunction with the response_mode value jwt
     * @param registrationObject
     */
    void validateResponseTypes(JsonValue registrationObject) {
        final List<String> responseTypesList = registrationObject.get("response_types").asList(String.class);
        if (responseTypesList == null || responseTypesList.isEmpty()) {
            throw new ValidationException(DCRErrorCode.INVALID_CLIENT_METADATA, "request object must contain field: response_types");
        }

        for (String responseTypes : responseTypesList) {
            // Convert the request responseTypes String into a set by splitting on whitespace
            final Set<String> responseTypesSet = Set.of(responseTypes.split(" "));
            if (!responseTypesSet.equals(RESPONSE_TYPE_CODE) && !responseTypesSet.equals(RESPONSE_TYPE_CODE_ID_TOKEN)) {
                throw new ValidationException(DCRErrorCode.INVALID_CLIENT_METADATA,
                        "Invalid response_types value: " + responseTypes + ", must be one of: \"code\" or \"code id_token\"");
            }
        }

    }

    /**
     * <p>
     * <a href="https://openid.net/specs/openid-financial-api-part-2-1_0.html#algorithm-considerations">
     *  Financial-grade API Security Profile 1.0 - Part 2: Advanced</a>, in section 5.2.2-14 states:
     *  </p>
     *  <p>>
     *  shall authenticate the confidential client using one of the following methods (this overrides FAPI Security Profile 1.0 - Part 1: Baseline clause 5.2.2-4):
     *  <ol>
     *     <li>tls_client_auth or self_signed_tls_client_auth as specified in section 2 of <a href="https://tools.ietf.org/html/rfc8705">MTLS</a>, or</li>
     *     <li>private_key_jwt as specified in section 9 of <a href="http://openid.net/specs/openid-connect-core-1_0.html">OIDC</a>;</li>
     *  </ol>
     *  </p>
     * @param registrationObject
     */
    void validateTokenEndpointAuthMethods(JsonValue registrationObject) {
        final String tokenEndpointAuthMethod = registrationObject.get("token_endpoint_auth_method").asString();
        if (tokenEndpointAuthMethod == null) {
            throw new ValidationException(DCRErrorCode.INVALID_CLIENT_METADATA, "request object must contain field: token_endpoint_auth_method");
        }
        if (!supportedTokenEndpointAuthMethods.contains(tokenEndpointAuthMethod)) {
            throw new ValidationException(DCRErrorCode.INVALID_CLIENT_METADATA, "token_endpoint_auth_method not supported, must be one of: "
                    + supportedTokenEndpointAuthMethods.stream().sorted().collect(Collectors.toList()));
        }
    }

    /**
     * Validate that values for signing fields are a supported signing algorithm.
     *
     * Some fields may be optional for certain types of request, therefore if a field in the
     * registrationObjectSigningFieldNames collection is not found in the registration request then it is skipped rather
     * than throwing an error. It is the job of the filter that implements the registration logic to reject requests
     * with missing fields.
     *
     * <a href="https://openid.net/specs/openid-financial-api-part-2-1_0.html#algorithm-considerations">
     *     Financial-grade API Security Profile 1.0 - Part 2: Advanced </a>  section 8.6 states:
     *
     * For JWS, both clients and authorization servers
     * <ol>
     *     <li>shall use PS256 or ES256 algorithms; </li>
     *     <li>should not use algorithms that use RSASSA-PKCS1-v1_5 (e.g. RS256); and </li>
     *     <li>shall not use none</li>
     * </ol>
     */
    void validateSigningAlgorithmUsed(JsonValue registrationObject) {
        for (String signingFieldName : registrationObjectSigningFieldNames) {
            final String signingAlg = registrationObject.get(signingFieldName).asString();
            if (signingAlg != null && !supportedSigningAlgorithms.contains(signingAlg)) {
                throw new ValidationException(DCRErrorCode.INVALID_CLIENT_METADATA, "request object field: "
                        + signingFieldName + ", must be one of: " + supportedSigningAlgorithms);
            }
        }
    }

    void setSupportedSigningAlgorithms(Collection<String> supportedSigningAlgorithms) {
        this.supportedSigningAlgorithms = new HashSet<>(supportedSigningAlgorithms);
    }

    void setSupportedTokenEndpointAuthMethods(Collection<String> supportedTokenEndpointAuthMethods) {
        this.supportedTokenEndpointAuthMethods = new HashSet<>(supportedTokenEndpointAuthMethods);
    }

    void setRegistrationObjectSigningFieldNames(Collection<String> registrationObjectSigningFieldNames) {
        this.registrationObjectSigningFieldNames = registrationObjectSigningFieldNames;
    }

    void setClientCertificateRetriever(CertificateRetriever certificateRetriever) {
        this.clientCertificateRetriever = certificateRetriever;
    }

    void setRegistrationRequestObjectSupplier(BiFunction<Context, Request, JsonValue> registrationRequestObjectSupplier) {
        this.registrationRequestObjectSupplier = registrationRequestObjectSupplier;
    }

    void setRegistrationRequestObjectValidators(List<Validator<JsonValue>> registrationRequestObjectValidators) {
        this.registrationRequestObjectValidators = registrationRequestObjectValidators;
    }

    /**
     * When configuring the requestObjectValidators (via the setter), callers can extend the validation rules applied by
     * first calling this method and then appending additional validators to the collection.
     *
     * @return list of validators that apply the default validation rules to the request object as per the spec.
     */
    public List<Validator<JsonValue>> getDefaultRequestObjectValidators() {
        return List.of(this::validateRedirectUris, this::validateResponseTypes, this::validateSigningAlgorithmUsed,
                       this::validateTokenEndpointAuthMethods);
    }

    /**
     * Supplies the Registration Request json object from a JWT contained within the Request.entity
     *
     * The JWT signing algo in the header is validated against the supported set of signing algorithms for FAPI.
     * No other validation is done at this point, it is assumed that Filters later in the chain will validate the sig etc
     */
    public static class RegistrationRequestObjectFromJwtSupplier implements BiFunction<Context, Request, JsonValue> {

        private final Set<String> supportedSigningAlgorithms;

        public RegistrationRequestObjectFromJwtSupplier(Collection<String> supportedSigningAlgorithms) {
            this.supportedSigningAlgorithms = new HashSet<>(supportedSigningAlgorithms);
        }

        @Override
        public JsonValue apply(Context context, Request request) {
            try {
                final String registrationRequestJwtString = request.getEntity().getString();
                final SignedJwt registrationRequestJwt = new JwtReconstruction().reconstructJwt(registrationRequestJwtString,
                                                                                                SignedJwt.class);
                LOGGER.debug("Registration Request JWT to validate: {}", registrationRequestJwtString);
                final JwsAlgorithm signingAlgo = registrationRequestJwt.getHeader().getAlgorithm();
                // This validation is being done here as outside the supplier we are not aware that a JWT existed
                if (signingAlgo == null || !supportedSigningAlgorithms.contains(signingAlgo.getJwaAlgorithmName())) {
                    throw new ValidationException(DCRErrorCode.INVALID_CLIENT_METADATA,
                            "DCR request JWT signed must be signed with one of: " + supportedSigningAlgorithms);
                }
                final JwtClaimsSet claimsSet = registrationRequestJwt.getClaimsSet();
                return claimsSet.toJsonValue();
            } catch (InvalidJwtException | IOException e) {
                LOGGER.warn("FAPI DCR failed: unable to extract registration object JWT from request", e);
                // These are not validation errors, so do not raise a validation exception, instead allow the filter to handle the null response
                return null;
            }
        }
    }

    /** Creates and initializes a FAPIAdvancedDCRValidationFilter */
    public static class Heaplet extends GenericHeaplet {

        private final Logger logger = LoggerFactory.getLogger(getClass());

        @Override
        public Object create() throws HeapException {
            final FAPIAdvancedDCRValidationFilter filter = new FAPIAdvancedDCRValidationFilter();

            final List<String> supportedSigningAlgorithms = config.get("supportedSigningAlgorithms")
                                                                   .as(evaluatedWithHeapProperties())
                                                                   .defaultTo(DEFAULT_SUPPORTED_JWS_ALGORITHMS)
                                                                   .asList(String.class);
            // Validate that if custom configuration was supplied, then that it is equal to or a subset of the values supported by the spec
            if (!DEFAULT_SUPPORTED_JWS_ALGORITHMS.containsAll(supportedSigningAlgorithms)) {
                throw new HeapException("supportedSigningAlgorithms config must be the same as (or a subset of): "
                        + DEFAULT_SUPPORTED_JWS_ALGORITHMS);
            }
            filter.setSupportedSigningAlgorithms(supportedSigningAlgorithms);

            final List<String> supportedTokenEndpointAuthMethods = config.get("supportedTokenEndpointAuthMethods")
                                                                         .as(evaluatedWithHeapProperties())
                                                                         .defaultTo(DEFAULT_SUPPORTED_TOKEN_ENDPOINT_AUTH_METHODS)
                                                                         .asList(String.class);
            if (!DEFAULT_SUPPORTED_TOKEN_ENDPOINT_AUTH_METHODS.containsAll(supportedTokenEndpointAuthMethods)) {
                throw new HeapException("supportedTokenEndpointAuthMethods config must be the same as (or a subset of): "
                        + DEFAULT_SUPPORTED_TOKEN_ENDPOINT_AUTH_METHODS);
            }
            filter.setSupportedTokenEndpointAuthMethods(supportedTokenEndpointAuthMethods);

            filter.setRegistrationObjectSigningFieldNames(config.get("registrationObjectSigningFieldNames")
                                                                .as(evaluatedWithHeapProperties())
                                                                .defaultTo(DEFAULT_REG_OBJ_SIGNING_FIELD_NAMES)
                                                                .asList(String.class));

            // certificateRetriever configuration is preferred to the deprecated clientTlsCertHeader configuration
            final JsonValue certificateRetrieverConfig = config.get("certificateRetriever");
            if (certificateRetrieverConfig.isNotNull()) {
                filter.setClientCertificateRetriever(certificateRetrieverConfig.as(requiredHeapObject(heap, CertificateRetriever.class)));
            } else {
                // Fallback to the config which only configures the HeaderCertificateRetriever
                final String clientCertHeaderName = config.get("clientTlsCertHeader").required().asString();
                logger.warn("{} config option clientTlsCertHeader is deprecated, use certificateRetriever instead. " +
                            "This option needs to contain a value which is a reference to a {} object on the heap",
                            FAPIAdvancedDCRValidationFilter.class.getSimpleName(), CertificateRetriever.class);
                filter.setClientCertificateRetriever(new HeaderCertificateRetriever(clientCertHeaderName));
            }

            final List<Validator<JsonValue>> requestObjectValidators = filter.getDefaultRequestObjectValidators();
            filter.setRegistrationRequestObjectValidators(requestObjectValidators);

            final BiFunction<Context, Request, JsonValue> registrationObjectSupplier = new RegistrationRequestObjectFromJwtSupplier(supportedSigningAlgorithms);
            filter.setRegistrationRequestObjectSupplier(registrationObjectSupplier);

            return filter;
        }
    }
}
