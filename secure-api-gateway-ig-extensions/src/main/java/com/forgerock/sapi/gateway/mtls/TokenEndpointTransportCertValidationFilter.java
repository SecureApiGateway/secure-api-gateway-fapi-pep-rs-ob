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
package com.forgerock.sapi.gateway.mtls;

import static org.forgerock.openig.util.JsonValues.requiredHeapObject;

import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

import org.forgerock.http.Client;
import org.forgerock.http.Filter;
import org.forgerock.http.Handler;
import org.forgerock.http.protocol.Request;
import org.forgerock.http.protocol.Response;
import org.forgerock.http.protocol.Status;
import org.forgerock.json.JsonValue;
import org.forgerock.json.jose.common.JwtReconstruction;
import org.forgerock.json.jose.jws.SignedJwt;
import org.forgerock.openig.heap.GenericHeaplet;
import org.forgerock.openig.heap.HeapException;
import org.forgerock.services.context.Context;
import org.forgerock.util.AsyncFunction;
import org.forgerock.util.Reject;
import org.forgerock.util.promise.NeverThrowsException;
import org.forgerock.util.promise.Promise;
import org.forgerock.util.promise.Promises;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.forgerock.sapi.gateway.dcr.idm.ApiClientService;
import com.forgerock.sapi.gateway.dcr.idm.IdmApiClientDecoder;
import com.forgerock.sapi.gateway.dcr.idm.IdmApiClientService;
import com.forgerock.sapi.gateway.dcr.models.ApiClient;
import com.forgerock.sapi.gateway.fapi.FAPIUtils;
import com.forgerock.sapi.gateway.jwks.ApiClientJwkSetService;
import com.forgerock.sapi.gateway.jwks.DefaultApiClientJwkSetService;
import com.forgerock.sapi.gateway.jwks.JwkSetService;
import com.forgerock.sapi.gateway.trusteddirectories.TrustedDirectory;
import com.forgerock.sapi.gateway.trusteddirectories.TrustedDirectoryService;

/**
 * Filter to validate that the client's MTLS transport certificate is valid when making a request to the Authorisation
 * Server's token endpoint.
 *
 * This is a specialised version of {@link TransportCertValidationFilter}, it does the same
 * validation, but has been adapted to do its validation on the response path. By deferring the validation to the response
 * path, then we can be sure that we have an authenticated client.
 *
 * In order to get the resources needed to do the validaiton, the access_token is inspected and the client_id is retrieved
 * from the configurable accessTokenClientIdClaim. This is used to look up the {@link ApiClient} and their
 * {@link org.forgerock.json.jose.jwk.JWKSet}.
 *
 * A configurable {@link CertificateResolver} is used to resolve the client's MTLS certificate.
 *
 * This is then validated against the JWKSet for the ApiClient by using a {@link TransportCertValidator}.
 *
 * If the validation is successful the response is passed on along the filter chain. Otherwise, an error response is
 * returned with 400 BAD_REQUEST error code.
 *
 * See {@link Heaplet} for configuration options.
 */
public class TokenEndpointTransportCertValidationFilter implements Filter {

    static final String DEFAULT_ACCESS_TOKEN_CLIENT_ID_CLAIM = "aud";

    private final Logger logger = LoggerFactory.getLogger(getClass());

    /**
     * Name of the access_token JWT claim containing the OAuth 2 client_id
     */
    private final String accessTokenClientIdClaim;

    private final JwtReconstruction jwtReconstruction = new JwtReconstruction();

    /**
     * Resolver of the client's mTLS certificate
     */
    private final CertificateResolver certificateResolver;

    /**
     * Service which retrieves {@link ApiClient} data
     */
    private final ApiClientService apiClientService;

    /**
     * Service which retrieves {@link TrustedDirectory} configuration
     */
    private final TrustedDirectoryService trustedDirectoryService;

    /**
     * Service which retrieves the {@link org.forgerock.json.jose.jwk.JWKSet} for the {@link ApiClient}
     */
    private final ApiClientJwkSetService apiClientJwkSetService;

    /**
     * Validator which ensures that the client's mTLS certificate belongs to the ApiClient's {@link org.forgerock.json.jose.jwk.JWKSet}
     */
    private final TransportCertValidator transportCertValidator;

    public TokenEndpointTransportCertValidationFilter(ApiClientService apiClientService, TrustedDirectoryService trustedDirectoryService,
                                                      ApiClientJwkSetService apiClientJwkSetService, CertificateResolver certificateResolver,
                                                      TransportCertValidator transportCertValidator, String accessTokenClientIdClaim) {
        Reject.ifNull(apiClientService, "apiClientService must be provided");
        Reject.ifNull(trustedDirectoryService, "trustedDirectoryService must be provided");
        Reject.ifNull(apiClientJwkSetService, "apiClientJwkSetService must be provided");
        Reject.ifNull(certificateResolver, "certificateResolver must be provided");
        Reject.ifNull(transportCertValidator, "transportCertValidator must be provided");
        Reject.ifBlank(accessTokenClientIdClaim, "accessTokenClientIdClaim must be provided");
        this.apiClientService = apiClientService;
        this.trustedDirectoryService = trustedDirectoryService;
        this.apiClientJwkSetService = apiClientJwkSetService;
        this.certificateResolver = certificateResolver;
        this.transportCertValidator = transportCertValidator;
        this.accessTokenClientIdClaim = accessTokenClientIdClaim;
    }

    @Override
    public Promise<Response, NeverThrowsException> filter(Context context, Request request, Handler next) {
        final String fapiInteractionIdForDisplay = FAPIUtils.getFapiInteractionIdForDisplay(context);
        final X509Certificate clientCertificate;
        try {
             clientCertificate = certificateResolver.resolveCertificate(context, request);
        } catch (CertificateException e) {
            logger.error("({}) Failed to resolve client mtls certificate", fapiInteractionIdForDisplay, e);
            return Promises.newResultPromise(TransportCertValidationFilter.createErrorResponse(e.getMessage()));
        }

        // Defer cert validation until the response path, then we know that the client authenticated successfully
        return next.handle(context, request).thenAsync(response -> {
            // Allow errors to pass on up the chain
            if (!response.getStatus().isSuccessful()) {
                return Promises.newResultPromise(response);
            } else {
                return response.getEntity()
                               .getJsonAsync()
                               .then(this::getClientIdFromAccessToken)
                               .thenAsync(apiClientService::getApiClient, io -> {
                                   // Exception handler to keep the generics happy, converts Promise<T, IOException> => Promise<T, Exception>
                                   logger.warn("({}) IOException getting json from response", io);
                                   return Promises.newExceptionPromise(io);
                               })
                               .thenAsync(validateApiClientTransportCert(fapiInteractionIdForDisplay, clientCertificate, response),
                                          ex -> {
                                            // Top level exception handler
                                            logger.error("({}) Failed to validate client mtls cert", fapiInteractionIdForDisplay, ex);
                                            return Promises.newResultPromise(new Response(Status.INTERNAL_SERVER_ERROR));
                                          },
                                          rte -> {
                                              logger.error("({}) Failed to validate client mtls cert", fapiInteractionIdForDisplay, rte);
                                              return Promises.newResultPromise(new Response(Status.INTERNAL_SERVER_ERROR));
                                          });
            }
        });
    }

    private AsyncFunction<ApiClient, Response, NeverThrowsException> validateApiClientTransportCert(String fapiInteractionIdForDisplay,
                                                                                                    X509Certificate clientCertificate,
                                                                                                    Response response) {

        return apiClient -> {
            final TrustedDirectory trustedDirectory = trustedDirectoryService.getTrustedDirectoryConfiguration(apiClient);
            if (trustedDirectory == null) {
                logger.error("({}) Failed to get trusted directory for apiClient: {}", fapiInteractionIdForDisplay, apiClient);
                return Promises.newResultPromise(new Response(Status.INTERNAL_SERVER_ERROR));
            }

            return apiClientJwkSetService.getJwkSet(apiClient, trustedDirectory).then(jwkSet -> {
                try {
                    transportCertValidator.validate(clientCertificate, jwkSet);
                } catch (CertificateException ce) {
                    logger.error("({}) failed to validate that the supplied client certificate", ce);
                    return TransportCertValidationFilter.createErrorResponse(ce.getMessage());
                }
                // Successfully validated the client's cert, allow the original response to continue along the filter chain.
                logger.debug("({}) transport cert validated successfully", fapiInteractionIdForDisplay);
                return response;
            }, ex -> {
                logger.error("({}) Failed to get JWKS for apiClient: {}", fapiInteractionIdForDisplay, apiClient, ex);
                return new Response(Status.INTERNAL_SERVER_ERROR);
            });
        };
    }

    String getClientIdFromAccessToken(Object jsonValue) {
        final JsonValue json = JsonValue.json(jsonValue);
        final JsonValue accessToken = json.get("access_token");
        if (accessToken == null || accessToken.isNull()) {
            throw new IllegalStateException("Failed to get client_id: access_token is missing");
        }

        final SignedJwt accessTokenJwt = jwtReconstruction.reconstructJwt(accessToken.asString(), SignedJwt.class);
        final JsonValue clientId = accessTokenJwt.getClaimsSet().get(accessTokenClientIdClaim);
        if (clientId.isNull()) {
            throw new IllegalStateException("Failed to get client_id: access_token claims missing required '" + accessTokenClientIdClaim + "' claim");
        }
        return clientId.asString();
    }

    /**
     * Heaplet used to create {@link TransportCertValidationFilter} objects
     *
     * Mandatory fields:
     *  - clientTlsCertHeader: the name of the Request Header which contains the client's TLS cert
     *  - idmClientHandler: the clientHandler to use to call out to IDM (must be configured with the credentials required to query IDM)
     *  - idmGetApiClientBaseUri: the base uri used to build the IDM query to get the apiClient, the client_id is expected
     *                            to be appended to this uri (and some query params).
     *  - trustedDirectoryService: the name of a {@link TrustedDirectoryService} object on the heap
     *  - jwkSetService: the name of the service (defined in config on the heap) that can obtain JWK Sets from a jwk set url
     *  - transportCertValidator: the name of a {@link TransportCertValidator} object on the heap to use to validate the certs
     *
     *  Optional config:
     *  - accessTokenClientIdClaim: the name of the claim in the access_token that contains the clientId. The clientId is then used to
     *  fetch the ApiClient (and ApiClient's JWKS). Defaults to "aud"
     *
     * Example config:
     * {
     *           "comment": "Validate the MTLS transport cert",
     *           "name": "TokenEndpointTransportCertValidationFilter",
     *           "type": "TokenEndpointTransportCertValidationFilter",
     *           "config": {
     *             "clientTlsCertHeader": "ssl-client-cert",
     *             "idmClientHandler": "IDMClientHandler",
     *             "idmGetApiClientBaseUri": "https://&{identity.platform.fqdn}/openidm/managed/apiClient",
     *             "trustedDirectoryService": "TrustedDirectoriesService",
     *             "jwkSetService": "OBJwkSetService",
     *             "transportCertValidator": "TransportCertValidator"
     *           }
     * }
     */
    public static class Heaplet extends GenericHeaplet {

        @Override
        public Object create() throws HeapException {
            final Handler clientHandler = config.get("idmClientHandler").as(requiredHeapObject(heap, Handler.class));
            final Client httpClient = new Client(clientHandler);

            String idmGetApiClientBaseUri = config.get("idmGetApiClientBaseUri").required().asString();
            if (!idmGetApiClientBaseUri.endsWith("/")) {
                idmGetApiClientBaseUri = idmGetApiClientBaseUri + '/';
            }

            final ApiClientService apiClientService = new IdmApiClientService(httpClient, idmGetApiClientBaseUri, new IdmApiClientDecoder());

            final TrustedDirectoryService trustedDirectoryService = config.get("trustedDirectoryService")
                    .as(requiredHeapObject(heap, TrustedDirectoryService.class));


            final JwkSetService jwkSetService = config.get("jwkSetService").as(requiredHeapObject(heap, JwkSetService.class));
            final ApiClientJwkSetService apiClientJwkSetService = new DefaultApiClientJwkSetService(jwkSetService);

            final TransportCertValidator transportCertValidator = config.get("transportCertValidator").required()
                    .as(requiredHeapObject(heap, TransportCertValidator.class));

            final String clientCertHeaderName = config.get("clientTlsCertHeader").required().asString();
            final CertificateResolver certResolver = new HeaderCertificateResolver(clientCertHeaderName);

            final String accessTokenClientIdClaim =  config.get("accessTokenClientIdClaim")
                                                           .defaultTo(DEFAULT_ACCESS_TOKEN_CLIENT_ID_CLAIM).asString();

            return new TokenEndpointTransportCertValidationFilter(apiClientService, trustedDirectoryService,
                                                                  apiClientJwkSetService, certResolver,
                                                                  transportCertValidator, accessTokenClientIdClaim);

        }
    }
}
