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
package com.forgerock.sapi.gateway.dcr.models;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.forgerock.json.JsonValue;

import com.forgerock.sapi.gateway.common.jwt.JwtException;
import com.forgerock.sapi.gateway.dcr.sigvalidation.DCRTestHelpers;
import com.forgerock.sapi.gateway.trusteddirectories.TrustedDirectory;
import com.forgerock.sapi.gateway.trusteddirectories.TrustedDirectoryTestFactory;

public class SoftwareStatementTestFactory {
    private static final String ORG_ID = "Acme Inc.";
    private static final String SOFTWARE_ID ="Acme App";
    private static final String JWKS_URI = "https://jwks.com";
    private static final JsonValue JWKS_SET;
    private static final List<String> REDIRECT_URIS =
            List.of("https://domain1.io/callback", "https://domain2.io.callback");
    private static final List<String> ROLES = List.of("AISP", "PISP", "CBPII");

    static {
        try {
            JWKS_SET = DCRTestHelpers.getJwksJsonValue();
        } catch (JwtException e) {
            throw new RuntimeException("Failed to getJwksJsonValue", e);
        }
    }

    public static Map<String, Object> getValidJwksUriBasedSsaClaims(Map<String, Object> overrideSsaClaims){
        TrustedDirectory directory = TrustedDirectoryTestFactory.getJwksUriBasedTrustedDirectory();
        Map<String, Object> claims = new HashMap<>();
        claims.put("iss", directory.getIssuer());
        claims.put(directory.getSoftwareStatementOrgIdClaimName(), ORG_ID);
        claims.put(directory.getSoftwareStatementSoftwareIdClaimName(), SOFTWARE_ID);
        claims.put(directory.getSoftwareStatementJwksUriClaimName(), JWKS_URI);
        claims.put(directory.getSoftwareStatementRedirectUrisClaimName(), REDIRECT_URIS);
        claims.put(directory.getSoftwareStatementRolesClaimName(), ROLES);
        claims.putAll(overrideSsaClaims);
        return claims;
    };

    public static Map<String, Object> getValidJwksBasedSsaClaims(Map<String, Object> overrideSsaClaims) {
        TrustedDirectory directory = TrustedDirectoryTestFactory.getJwksBasedTrustedDirectory();

        Map<String, Object> claims = new HashMap<>();
        claims.put("iss", directory.getIssuer());
        claims.put(directory.getSoftwareStatementOrgIdClaimName(), ORG_ID);
        claims.put(directory.getSoftwareStatementSoftwareIdClaimName(), SOFTWARE_ID);
        claims.put(directory.getSoftwareStatementJwksClaimName(), JWKS_SET.getObject());
        claims.put(directory.getSoftwareStatementRedirectUrisClaimName(), REDIRECT_URIS);
        claims.put(directory.getSoftwareStatementRolesClaimName(), ROLES);
        claims.putAll(overrideSsaClaims);
        return claims;
    }
}
