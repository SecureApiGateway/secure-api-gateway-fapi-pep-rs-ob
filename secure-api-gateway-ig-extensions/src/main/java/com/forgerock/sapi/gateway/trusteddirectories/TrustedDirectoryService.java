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
package com.forgerock.sapi.gateway.trusteddirectories;

import org.forgerock.json.jose.jwt.JwtClaimsSet;

import com.forgerock.sapi.gateway.dcr.models.ApiClient;

public interface TrustedDirectoryService {

    /**
     * Helper method to get the Trusted Directory for an ApiClient instance.
     * An ApiClient has been created from a Software Statement issued by a Trusted Directory.
     *
     * @param apiClient ApiClient to get {@link TrustedDirectory} for
     * @return The {@code TrustedDirectory} associated with the ApiClient's Software Statement issuer or null if
     * no value is held for the issuer.
     */
    default TrustedDirectory getTrustedDirectoryConfiguration(ApiClient apiClient) {
        final JwtClaimsSet ssaClaims = apiClient.getSoftwareStatementAssertion().getClaimsSet();
        final String issuer = ssaClaims.getIssuer();
        return getTrustedDirectoryConfiguration(issuer);
    }

    /**
     *
     * @param issuer - the value of the 'iss' field that is used by the Trusted Directory in Software Statement
     *               Assertions. For the Open Banking Directories for example, this will be "OpenBanking Ltd"
     * @return The {@code TrustedDirectory} associated with the issuer or null if no value is held for the provided
     * issuer
     */
    TrustedDirectory getTrustedDirectoryConfiguration(String issuer);
}
