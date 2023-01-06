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

import static org.assertj.core.api.AssertionsForClassTypes.assertThat;

import org.junit.jupiter.api.Test;

class TrustedDirectorySecureApiGatewayTest {

    private static final String testDirectoryFQDN = "https://saig.bigbank.com/jwkms/apiclient/jwks";
    TrustedDirectorySecureApiGateway trustedDirectory = new TrustedDirectorySecureApiGateway(testDirectoryFQDN);

    @Test
    void checkFieldValues() {
        // Given
        // When
        // Then
        assertThat(trustedDirectory.getIssuer()).isEqualTo(TrustedDirectorySecureApiGateway.issuer);
        assertThat(trustedDirectory.getDirectoryJwksUri()).isEqualTo(testDirectoryFQDN);
        assertThat(trustedDirectory.softwareStatementHoldsJwksUri()).isFalse();
        assertThat(trustedDirectory.getSoftwareStatementJwksUriClaimName()).isNull();
        assertThat(trustedDirectory.getSoftwareStatementJwksClaimName()).isEqualTo(TrustedDirectorySecureApiGateway.softwareStatementJwksClaimName);
        assertThat(trustedDirectory.getSoftwareStatementOrgIdClaimName()).isEqualTo(TrustedDirectorySecureApiGateway.softwareStatementOrgIdClaimName);
        assertThat(trustedDirectory.getSoftwareStatementSoftwareIdClaimName()).isEqualTo(TrustedDirectorySecureApiGateway.softwareStatementSoftwareIdClaimName);
    }
}