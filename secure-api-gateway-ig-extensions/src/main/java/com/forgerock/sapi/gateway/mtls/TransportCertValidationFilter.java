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

import static org.forgerock.json.JsonValue.field;
import static org.forgerock.json.JsonValue.json;
import static org.forgerock.json.JsonValue.object;
import static org.forgerock.openig.util.JsonValues.requiredHeapObject;

import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.function.BiFunction;

import org.forgerock.http.Filter;
import org.forgerock.http.Handler;
import org.forgerock.http.protocol.Request;
import org.forgerock.http.protocol.Response;
import org.forgerock.http.protocol.Status;
import org.forgerock.json.jose.jwk.JWKSet;
import org.forgerock.openig.heap.GenericHeaplet;
import org.forgerock.openig.heap.HeapException;
import org.forgerock.services.context.AttributesContext;
import org.forgerock.services.context.Context;
import org.forgerock.util.Reject;
import org.forgerock.util.promise.NeverThrowsException;
import org.forgerock.util.promise.Promise;
import org.forgerock.util.promise.Promises;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.forgerock.sapi.gateway.dcr.ApiClient;
import com.forgerock.sapi.gateway.fapi.FAPIUtils;
import com.forgerock.sapi.gateway.jwks.FetchApiClientJwksFilter;

/**
 * Filter to validate that the client's MTLS transport certificate is valid.
 *
 * This filter depends on the {@link JWKSet} containing the keys for this {@link ApiClient} being present in
 * the {@link AttributesContext}.
 *
 * The certificate for the request is supplied by the pluggable clientTlsCertificateSupplier,
 * see {@link CertificateFromHeaderSupplier} for an example implementation (this is the default configured
 * by the {@link Heaplet})
 *
 * Once the {@link X509Certificate} and JWKSet have been obtained, then the filter delegates to a {@link TransportCertValidator}
 * to do the validation.
 * If the validator successfully validates the certificate, then the request is passed to the next filter in the chain,
 * otherwise a HTTP 400 response is returned.
 */
public class TransportCertValidationFilter implements Filter {

    private final Logger logger = LoggerFactory.getLogger(getClass());

    /**
     * Function which returns the client's PEM encoded x509 certificate which is used for MTLS as a String.
     */
    private final BiFunction<Context, Request, String> clientTlsCertificateSupplier;

    /**
     * Validator which checks if the client's MTLS certificate is valid.
     */
    private final TransportCertValidator transportCertValidator;

    public TransportCertValidationFilter(BiFunction<Context, Request, String> clientTlsCertificateSupplier,
                                         TransportCertValidator transportCertValidator) {
        Reject.ifNull(clientTlsCertificateSupplier, "clientTlsCertificate must be provided");
        Reject.ifNull(transportCertValidator, "transportCertValidator must be provided");
        this.clientTlsCertificateSupplier = clientTlsCertificateSupplier;
        this.transportCertValidator = transportCertValidator;
    }

    private Response createErrorResponse(String message) {
        return new Response(Status.BAD_REQUEST).setEntity(json(object(field("error_description", message))));
    }

    @Override
    public Promise<Response, NeverThrowsException> filter(Context context, Request request, Handler next) {
        logger.debug("({}) attempting to validate transport cert", FAPIUtils.getFapiInteractionIdForDisplay(context));
        final String clientCertPem = clientTlsCertificateSupplier.apply(context, request);
        if (clientCertPem == null) {
            return Promises.newResultPromise(createErrorResponse("client tls certificate not found"));
        }

        final X509Certificate certificate;
        try {
            certificate = parseCertificate(clientCertPem);
        } catch (CertificateException e) {
            logger.warn("("+  FAPIUtils.getFapiInteractionIdForDisplay(context) + ") transport cert not valid", e);
            return Promises.newResultPromise(createErrorResponse("client tls certificate could not be parsed as an X509 certificate"));
        }

        try {
            transportCertValidator.validate(certificate, getJwkSet(context));
            logger.debug("({}) transport cert validated successfully", FAPIUtils.getFapiInteractionIdForDisplay(context));
            return next.handle(context, request);
        } catch (CertificateException e) {
            logger.debug("({}) transport cert failed validation: not present in JWKS or present with wrong \"use\"",
                         FAPIUtils.getFapiInteractionIdForDisplay(context));
            return Promises.newResultPromise(createErrorResponse("client tls certificate not found in JWKS for software statement"));
        }
    }

    private JWKSet getJwkSet(Context context) {
        final JWKSet apiClientJwkSet = FetchApiClientJwksFilter.getApiClientJwkSetFromContext(context);
        if (apiClientJwkSet == null) {
            logger.error("({}) apiClientJwkSet not found in request context", FAPIUtils.getFapiInteractionIdForDisplay(context));
            throw new IllegalStateException("apiClientJwkSet not found in request context");
        }
        return apiClientJwkSet;
    }

    static X509Certificate parseCertificate(String cert) throws CertificateException {
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        Certificate certificate = cf.generateCertificate(new ByteArrayInputStream(cert.getBytes(StandardCharsets.UTF_8)));
        if (!(certificate instanceof X509Certificate)) {
            throw new CertificateException("client tls cert must be in X.509 format");
        }
        return (X509Certificate) certificate;
    }

    /**
     * Heaplet used to create {@link TransportCertValidationFilter} objects
     *
     * Mandatory fields:
     *  - clientTlsCertHeader: the name of the Request Header which contains the client's TLS cert
     *  - transportCertValidator: the name of a {@link TransportCertValidator} object on the heap to use to validate the certs
     *
     * Example config:
     * {
     *           "comment": "Validate the MTLS transport cert",
     *           "name": "TransportCertValidationFilter",
     *           "type": "TransportCertValidationFilter",
     *           "config": {
     *             "clientTlsCertHeader": "ssl-client-cert",
     *             "transportCertValidator": "TransportCertValidator"
     *           }
     * }
     */
    public static class Heaplet extends GenericHeaplet {

        @Override
        public Object create() throws HeapException {
            final String clientCertHeaderName = config.get("clientTlsCertHeader").required().asString();
            final TransportCertValidator transportCertValidator = config.get("transportCertValidator").required()
                                                                        .as(requiredHeapObject(heap, TransportCertValidator.class));
            final BiFunction<Context, Request, String> certificateSupplier = new CertificateFromHeaderSupplier(clientCertHeaderName);
            return new TransportCertValidationFilter(certificateSupplier, transportCertValidator);
        }
    }
}
