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
package com.forgerock.sapi.gateway.dcr.idm;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.net.URI;
import java.util.List;
import java.util.Map;

import org.forgerock.json.jose.jwk.JWKSet;
import org.forgerock.json.jose.jws.JwsHeader;
import org.forgerock.json.jose.jws.SignedJwt;
import org.forgerock.json.jose.jwt.JwtClaimsSet;
import org.junit.jupiter.api.Test;

import com.forgerock.sapi.gateway.dcr.models.ApiClient;
import com.forgerock.sapi.gateway.dcr.models.ApiClient.ApiClientBuilder;
import com.forgerock.sapi.gateway.dcr.models.ApiClientOrganisation;

public class ApiClientTest {

    /**
     * Default SSA to use in the ApiClientBuilder, this is SSA is useful when we need a value to be set but do not
     * depend on its contents
     */
    private static final SignedJwt EMPTY_SSA = new SignedJwt(new JwsHeader(), new JwtClaimsSet(Map.of()), new byte[0], new byte[0]);

    @Test
    public void failToBuildIfMandatoryFieldIsMissing() {
        assertEquals("oauth2ClientId must be configured", assertThrows(NullPointerException.class, () -> new ApiClientBuilder().build()).getMessage());
    }


    public static ApiClient createApiClientWithJwksUri(URI jwksUri) {
        return createBuilderWithTestValues().setJwksUri(jwksUri).build();
    }

    public static ApiClient createApiClientWithSoftwareStatementJwks(JWKSet jwkSet, String softwareStatementJwksClaimName) {
        final JwtClaimsSet claimsSet = new JwtClaimsSet();
        if (softwareStatementJwksClaimName != null) {
            claimsSet.setClaim(softwareStatementJwksClaimName, jwkSet.toJsonValue());
        }

        final ApiClientBuilder builder = createBuilderWithTestValues();
        builder.setSoftwareStatementAssertion(new SignedJwt(new JwsHeader(), claimsSet, new byte[0], new byte[0]));
        return builder.build();
    }

    public static ApiClientBuilder createBuilderWithTestValues() {
        return new ApiClientBuilder().setClientName("testClient")
                .setOauth2ClientId("1234-5678-9012-1234")
                .setSoftwareClientId("softwareClientId543")
                .setSoftwareStatementAssertion(EMPTY_SSA)
                .setJwksUri(null)
                .setRoles(List.of("AISP", "PISP", "CBPII"))
                .setJwks(new JWKSet())
                .setOrganisation(new ApiClientOrganisation("orgId123", "Test Organisation"));
    }
}
