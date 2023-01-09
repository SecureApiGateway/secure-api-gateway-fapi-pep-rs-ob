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

import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.function.BiFunction;

import org.forgerock.http.protocol.Request;
import org.forgerock.services.context.Context;
import org.forgerock.util.Reject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.forgerock.sapi.gateway.fapi.FAPIUtils;

/**
 * Supplier which returns a certificate String as sourced from a Request Header.
 * <p>
 * The certificate value is expected to be URL encoded, this supplier will do the URL decode to supply the
 * certificate String.
 */
public class CertificateFromHeaderSupplier implements BiFunction<Context, Request, String> {

    private static final Logger LOGGER = LoggerFactory.getLogger(CertificateFromHeaderSupplier.class);

    private final String certificateHeaderName;

    public CertificateFromHeaderSupplier(String certificateHeaderName) {
        this.certificateHeaderName = Reject.checkNotBlank(certificateHeaderName);
    }

    @Override
    public String apply(Context context, Request request) {
        final String fapInteractionId = FAPIUtils.getFapiInteractionIdForDisplay(context);
        final String headerValue = request.getHeaders().getFirst(certificateHeaderName);
        if (headerValue == null) {
            LOGGER.debug("({}) No client cert could be found for header: {}", fapInteractionId, certificateHeaderName);
            return null;
        }
        try {
            final String certPem = URLDecoder.decode(headerValue, StandardCharsets.UTF_8);
            LOGGER.debug("({}) Found client cert: {}", fapInteractionId, certPem);
            return certPem;
        } catch (RuntimeException ex) {
            LOGGER.debug("(" + fapInteractionId + ") Failed to URL decode cert from header: " + certificateHeaderName, ex);
            return null;
        }
    }
}
