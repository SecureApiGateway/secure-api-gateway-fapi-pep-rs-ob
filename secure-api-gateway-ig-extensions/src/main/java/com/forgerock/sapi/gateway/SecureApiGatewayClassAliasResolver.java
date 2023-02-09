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
package com.forgerock.sapi.gateway;

import java.util.HashMap;
import java.util.Map;

import org.forgerock.openig.alias.ClassAliasResolver;

import com.forgerock.sapi.gateway.dcr.idm.FetchApiClientFilter;
import com.forgerock.sapi.gateway.dcr.request.RegistrationRequestEntityValidatorFilter;
import com.forgerock.sapi.gateway.dcr.sigvalidation.RegistrationRequestJwtSignatureValidationFilter;
import com.forgerock.sapi.gateway.fapi.v1.FAPIAdvancedDCRValidationFilter;
import com.forgerock.sapi.gateway.jwks.FetchApiClientJwksFilter;
import com.forgerock.sapi.gateway.jwks.RestJwkSetService;
import com.forgerock.sapi.gateway.jwks.cache.caffeine.CaffeineCachingJwkSetService;
import com.forgerock.sapi.gateway.jws.RsaJwtSignatureValidator;
import com.forgerock.sapi.gateway.mtls.DefaultTransportCertValidator;
import com.forgerock.sapi.gateway.mtls.TransportCertValidationFilter;
import com.forgerock.sapi.gateway.trusteddirectories.FetchTrustedDirectoryFilter;
import com.forgerock.sapi.gateway.trusteddirectories.TrustedDirectoryService;

public class SecureApiGatewayClassAliasResolver implements ClassAliasResolver {
    private static final Map<String, Class<?>> ALIASES = new HashMap<>();

    static {
        ALIASES.put("FAPIAdvancedDCRValidationFilter", FAPIAdvancedDCRValidationFilter.class);
        ALIASES.put("CaffeineCachingJwkSetService", CaffeineCachingJwkSetService.class);
        ALIASES.put("RestJwkSetService", RestJwkSetService.class);
        ALIASES.put("RsaJwtSignatureValidator", RsaJwtSignatureValidator.class);
        ALIASES.put("TrustedDirectoriesService", TrustedDirectoryService.class);
        ALIASES.put("FetchApiClientFilter", FetchApiClientFilter.class);
        ALIASES.put("FetchTrustedDirectoryFilter", FetchTrustedDirectoryFilter.class);
        ALIASES.put("FetchApiClientJwksFilter", FetchApiClientJwksFilter.class);
        ALIASES.put("TransportCertValidationFilter", TransportCertValidationFilter.class);
        ALIASES.put("DefaultTransportCertValidator", DefaultTransportCertValidator.class);
        ALIASES.put("RegistrationRequestJwtSignatureValidationFilter", RegistrationRequestJwtSignatureValidationFilter.class);
        ALIASES.put("RegistrationRequestEntityValidatorFilter", RegistrationRequestEntityValidatorFilter.class);
    }

    /**
     * Get the class for a short name alias.
     *
     * @param alias Short name alias.
     * @return      The class, or null if the alias is not defined.
     */
    @Override
    public Class<?> resolve(final String alias) {
        return ALIASES.get(alias);
    }
}
