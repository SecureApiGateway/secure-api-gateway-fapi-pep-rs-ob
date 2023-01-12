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
package com.forgerock.sapi.gateway.fapi.v1;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.net.URISyntaxException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.util.Arrays;
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

import com.forgerock.sapi.gateway.dcr.ValidationException;
import com.forgerock.sapi.gateway.dcr.ValidationException.ErrorCode;
import com.forgerock.sapi.gateway.dcr.Validator;
import com.forgerock.sapi.gateway.dcr.ErrorResponseFactory;
import com.forgerock.sapi.gateway.fapi.FAPIUtils;
import com.forgerock.sapi.gateway.mtls.CertificateFromHeaderSupplier;

/**
 * Filter which implements the <a href="https://openid.net/specs/openid-financial-api-part-2-1_0.html">
 * Financial-grade API Security Profile 1.0 - Part 2: Advanced</a> spec validations required for DCR (Dynamic Client Registration).
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
 *             "clientTlsCertHeader"                    : String        [REQUIRED]
 *             "supportedSigningAlgorithms"             : String[]      [OPTIONAL]
 *             "supportedTokenEndpointAuthMethods"      : String[]      [OPTIONAL]
 *             "registrationObjectSigningFieldNames"    : String[]      [OPTIONAL]
 *         }
 *    }
 *    }
 * </pre>
 * clientTlsCertHeader is the name of the header to extract the client's MTLS cert from.
 * The header value must contain a PEM encoded, then URL encoded, x509 certificate.
 * This configuration is REQUIRED.
 * <p>
 * supportedSigningAlogrithms configures which JWS algorithms are supported for signing, see DEFAULT_SUPPORTED_JWS_ALGORITHMS for the default
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

    private static final List<String> RESPONSE_TYPE_CODE = List.of("code");
    private static final List<String> RESPONSE_TYPE_CODE_ID_TOKEN = List.of("code id_token");

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
     * Function which returns the client's PEM encoded x509 certificate which is used for MTLS as a String.
     */
    private BiFunction<Context, Request, String> clientTlsCertificateSupplier;

    /**
     * Function which validates a PEM encoded x509 certificate String
     */
    private Validator<String> certificateValidator;

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

    @Override
    public Promise<Response, NeverThrowsException> filter(Context context, Request request, Handler next) {
        if (!VALIDATABLE_HTTP_REQUEST_METHODS.contains(request.getMethod())) {
            return next.handle(context, request);
        }
        try {
            certificateValidator.validate(clientTlsCertificateSupplier.apply(context, request));

            final JsonValue registrationRequestObject = registrationRequestObjectSupplier.apply(context, request);
            if (registrationRequestObject == null) {
                throw new ValidationException(ErrorCode.INVALID_CLIENT_METADATA, "registration request entity is missing or malformed");
            }
            validateRegistrationRequestObject(registrationRequestObject);
        } catch (ValidationException ve) {
            LOGGER.debug("(" + FAPIUtils.getFapiInteractionIdForDisplay(context) + ") FAPI Validation failed", ve);
            return Promises.newResultPromise(errorResponseFactory.errorResponse(context, ve));
        } catch (RuntimeException re) {
            // Log that an unexpected RuntimeException occurred and throw it on
            LOGGER.warn("(" + FAPIUtils.getFapiInteractionIdForDisplay(context) + ") FAPI Validation failed due to unexpected RuntimeException", re);
            throw re;
        }
        return next.handle(context, request);
    }

    void validateRegistrationRequestObject(JsonValue registrationObject) {
        for (Validator<JsonValue> validator : registrationRequestObjectValidators) {
            validator.validate(registrationObject);
        }
    }

    void validateRedirectUris(JsonValue registrationObject) {
        final List<String> redirectUris = registrationObject.get("redirect_uris").asList(String.class);
        if (redirectUris == null) {
            throw new ValidationException(ErrorCode.INVALID_REDIRECT_URI, "request object must contain redirect_uris field");
        }
        if (redirectUris.isEmpty()) {
            throw new ValidationException(ErrorCode.INVALID_REDIRECT_URI, "redirect_uris array must not be empty");
        }
        for (String uriString : redirectUris) {
            final URI redirectUri;
            try {
                redirectUri = new URI(uriString);
            } catch (URISyntaxException ex) {
                throw new ValidationException(ErrorCode.INVALID_REDIRECT_URI, "redirect_uri: " + uriString + " is not a valid URI");
            }
            if (!"https".equals(redirectUri.getScheme())) {
                throw new ValidationException(ErrorCode.INVALID_REDIRECT_URI, "redirect_uris must use https scheme");
            }
        }
    }

    void validateResponseTypes(JsonValue registrationObject) {
        final List<String> responseTypes = registrationObject.get("response_types").asList(String.class);
        if (responseTypes == null || responseTypes.isEmpty()) {
            throw new ValidationException(ErrorCode.INVALID_CLIENT_METADATA, "request object must contain field: response_types");
        }
        if (responseTypes.equals(RESPONSE_TYPE_CODE)) {
            validateResponseTypeCode(registrationObject);
        } else if (responseTypes.equals(RESPONSE_TYPE_CODE_ID_TOKEN)) {
            validateResponseTypeCodeIdToken(registrationObject);
        } else {
            throw new ValidationException(ErrorCode.INVALID_CLIENT_METADATA, "response_types not supported, must be one of: "
                    + List.of(RESPONSE_TYPE_CODE, RESPONSE_TYPE_CODE_ID_TOKEN));
        }
    }

    private void validateResponseTypeCode(JsonValue registrationObject) {
        final String responseMode = registrationObject.get("response_mode").asString();
        if (responseMode == null) {
            throw new ValidationException(ErrorCode.INVALID_CLIENT_METADATA,
                    "request object must contain field: response_mode when response_types is: " + RESPONSE_TYPE_CODE);
        }
        final List<String> validResponseModesForResponseTypeCode = List.of("jwt");
        if (!validResponseModesForResponseTypeCode.contains(responseMode)) {
            throw new ValidationException(ErrorCode.INVALID_CLIENT_METADATA, "response_mode not supported, must be one of: "
                    + validResponseModesForResponseTypeCode);
        }
    }

    private void validateResponseTypeCodeIdToken(JsonValue registrationObject) {
        final String scopeClaim = registrationObject.get("scope").asString();
        if (scopeClaim == null) {
            throw new ValidationException(ErrorCode.INVALID_CLIENT_METADATA, "request must contain field: scope");
        }
        final List<String> scopes = Arrays.asList(scopeClaim.split(" "));
        if (!scopes.contains("openid")) {
            throw new ValidationException(ErrorCode.INVALID_CLIENT_METADATA,
                    "request object must include openid as one of the requested scopes when response_types is: " + RESPONSE_TYPE_CODE_ID_TOKEN);
        }
    }

    void validateTokenEndpointAuthMethods(JsonValue registrationObject) {
        final String tokenEndpointAuthMethod = registrationObject.get("token_endpoint_auth_method").asString();
        if (tokenEndpointAuthMethod == null) {
            throw new ValidationException(ErrorCode.INVALID_CLIENT_METADATA, "request object must contain field: token_endpoint_auth_method");
        }
        if (!supportedTokenEndpointAuthMethods.contains(tokenEndpointAuthMethod)) {
            throw new ValidationException(ErrorCode.INVALID_CLIENT_METADATA, "token_endpoint_auth_method not supported, must be one of: "
                    + supportedTokenEndpointAuthMethods.stream().sorted().collect(Collectors.toList()));
        }
    }

    /**
     * Validate that values for signing fields are a supported signing algorithm.
     *
     * Some fields may be optional for certain types of request, therefore if a field in the registrationObjectSigningFieldNames
     * collection is not found in the registration request then it is skipped rather than throwing an error.
     * It is the job of the filter that implements the registration logic to reject requests with missing fields.
     */
    void validateSigningAlgorithmUsed(JsonValue registrationObject) {
        for (String signingFieldName : registrationObjectSigningFieldNames) {
            final String signingAlg = registrationObject.get(signingFieldName).asString();
            if (signingAlg != null && !supportedSigningAlgorithms.contains(signingAlg)) {
                throw new ValidationException(ErrorCode.INVALID_CLIENT_METADATA, "request object field: " + signingFieldName
                        + ", must be one of: " + supportedSigningAlgorithms);
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

    void setClientTlsCertificateSupplier(BiFunction<Context, Request, String> clientTlsCertificateSupplier) {
        this.clientTlsCertificateSupplier = clientTlsCertificateSupplier;
    }

    void setCertificateValidator(Validator<String> certificateValidator) {
        this.certificateValidator = certificateValidator;
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
     * Default implementation of the ClientCertificateValidator.
     * This function takes a pem encoded certificate String and validates it.
     */
    public static class DefaultClientCertificateValidator implements Validator<String> {
        @Override
        public void validate(String certPem) {
            if (certPem == null) {
                throw new ValidationException(ErrorCode.INVALID_CLIENT_METADATA, "MTLS client certificate is missing or malformed");
            }
            final InputStream certStream = new ByteArrayInputStream(certPem.getBytes());
            try {
                final CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
                final Certificate certificate = certificateFactory.generateCertificate(certStream);
            } catch (CertificateException e) {
                throw new ValidationException(ErrorCode.INVALID_CLIENT_METADATA, "MTLS client certificate PEM supplied is invalid", e);
            }
        }
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
            final String fapiInteractionId = FAPIUtils.getFapiInteractionIdForDisplay(context);
            try {
                final String registrationRequestJwtString = request.getEntity().getString();
                final SignedJwt registrationRequestJwt = new JwtReconstruction().reconstructJwt(registrationRequestJwtString,
                                                                                                SignedJwt.class);
                LOGGER.debug("({}) Registration Request JWT to validate: {}", fapiInteractionId, registrationRequestJwtString);
                final JwsAlgorithm signingAlgo = registrationRequestJwt.getHeader().getAlgorithm();
                // This validation is being done here as outside the supplier we are not aware that a JWT existed
                if (signingAlgo == null || !supportedSigningAlgorithms.contains(signingAlgo.getJwaAlgorithmName())) {
                    throw new ValidationException(ErrorCode.INVALID_CLIENT_METADATA,
                            "DCR request JWT signed must be signed with one of: " + supportedSigningAlgorithms);
                }
                final JwtClaimsSet claimsSet = registrationRequestJwt.getClaimsSet();
                return claimsSet.toJsonValue();
            } catch (InvalidJwtException | IOException e) {
                LOGGER.warn("(" + fapiInteractionId + ") FAPI DCR failed: unable to extract registration object JWT from request", e);
                // These are not validation errors, so do not raise a validation exception, instead allow the filter to handle the null response
                return null;
            }
        }
    }

    /** Creates and initializes a FAPIAdvancedDCRValidationFilter */
    public static class Heaplet extends GenericHeaplet {

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

            final Validator<String> certificateValidator = new DefaultClientCertificateValidator();
            filter.setCertificateValidator(certificateValidator);

            final String clientCertHeaderName = config.get("clientTlsCertHeader").required().asString();
            final BiFunction<Context, Request, String> certificateSupplier = new CertificateFromHeaderSupplier(clientCertHeaderName);
            filter.setClientTlsCertificateSupplier(certificateSupplier);

            final List<Validator<JsonValue>> requestObjectValidators = filter.getDefaultRequestObjectValidators();
            filter.setRegistrationRequestObjectValidators(requestObjectValidators);

            final BiFunction<Context, Request, JsonValue> registrationObjectSupplier = new RegistrationRequestObjectFromJwtSupplier(supportedSigningAlgorithms);
            filter.setRegistrationRequestObjectSupplier(registrationObjectSupplier);

            return filter;
        }
    }
}
