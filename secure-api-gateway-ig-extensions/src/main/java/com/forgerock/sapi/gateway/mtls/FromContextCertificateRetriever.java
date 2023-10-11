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

import static com.forgerock.sapi.gateway.mtls.AddCertificateToAttributesContextFilter.DEFAULT_CERTIFICATE_ATTRIBUTE;

import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

import org.forgerock.http.protocol.Request;
import org.forgerock.openig.heap.GenericHeaplet;
import org.forgerock.openig.heap.HeapException;
import org.forgerock.services.context.AttributesContext;
import org.forgerock.services.context.Context;
import org.forgerock.util.Reject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.forgerock.sapi.gateway.fapi.FAPIUtils;

/**
 * CertificateRetriever implementation which retrieves the certificate from the {@link org.forgerock.services.context.AttributesContext}.
 *
 * This retriever must only run after the {@link AddCertificateToAttributesContextFilter} has installed the certificate
 * into the context.
 */
public class FromContextCertificateRetriever implements CertificateRetriever {

    private final Logger logger = LoggerFactory.getLogger(getClass());

    private final String certificateAttribute;

    public FromContextCertificateRetriever(String certificateAttribute) {
        this.certificateAttribute = Reject.checkNotBlank(certificateAttribute, "certificateAttribute must be provided");
    }

    @Override
    public X509Certificate retrieveCertificate(Context context, Request request) throws CertificateException {
        final X509Certificate certificate = (X509Certificate) context.asContext(AttributesContext.class).getAttributes().get(certificateAttribute);
        if (certificate == null) {
            logger.debug("({}) No client cert could be found in attribute: {}",
                         FAPIUtils.getFapiInteractionIdForDisplay(context), certificateAttribute);
            throw new CertificateException("Client mTLS certificate not provided");
        }
        return certificate;
    }

    /**
     * Heaplet responsible for creating {@link FromContextCertificateRetriever} objects
     *
     * Optional fields:
     * - certificateAttributeName: the name of the attribute to store the certificate in, defaults to clientCertificate
     *
     * Example config:
     * {
     *       "name": "FromContextCertificateRetriever",
     *       "type": "FromContextCertificateRetriever",
     *       "config": {
     *         "certificateAttributeName": "clientCertificate"
     *       }
     * }
     */
    public static class Heaplet extends GenericHeaplet {
        @Override
        public Object create() throws HeapException {
            return new FromContextCertificateRetriever(config.get("certificateAttributeName")
                                                             .defaultTo(DEFAULT_CERTIFICATE_ATTRIBUTE).asString());
        }
    }
}
