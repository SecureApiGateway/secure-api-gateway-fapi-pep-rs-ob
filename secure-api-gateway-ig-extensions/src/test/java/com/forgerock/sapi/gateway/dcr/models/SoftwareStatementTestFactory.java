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

import static com.forgerock.sapi.gateway.trusteddirectories.TrustedDirectoryTest.getJwksUriBasedTrustedDirectory;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.util.Map;

import com.forgerock.sapi.gateway.dcr.request.DCRRegistrationRequestBuilderException;
import com.forgerock.sapi.gateway.jws.JwtDecoder;
import com.forgerock.sapi.gateway.trusteddirectories.TrustedDirectoryService;
import com.forgerock.sapi.gateway.util.CryptoUtils;
import com.nimbusds.jose.JWSAlgorithm;

public class SoftwareStatementTestFactory {

    public static SoftwareStatement getJwksUriBasedValidSoftwareStatement(Map<String, Object> ssaClaims) throws DCRRegistrationRequestBuilderException {
        TrustedDirectoryService trustedDirectoryService = mock(TrustedDirectoryService.class);
        when(trustedDirectoryService.getTrustedDirectoryConfiguration("JwksBasedTrustedDirectory"))
                .thenReturn(getJwksUriBasedTrustedDirectory());

        SoftwareStatement.Builder builder = new SoftwareStatement.Builder(trustedDirectoryService, new JwtDecoder());

        String b64EncodedJwtString  = CryptoUtils.createEncodedJwtString(ssaClaims, JWSAlgorithm.PS256);
        return builder.build("tx-id", b64EncodedJwtString);
    }


    public static String getJwksUriBasedValidb64EncodedSoftwareStatementString(Map<String, Object> ssaClaims) {
        TrustedDirectoryService trustedDirectoryService = mock(TrustedDirectoryService.class);
        when(trustedDirectoryService.getTrustedDirectoryConfiguration("JwksBasedTrustedDirectory"))
                .thenReturn(getJwksUriBasedTrustedDirectory());

        SoftwareStatement.Builder builder = new SoftwareStatement.Builder(trustedDirectoryService, new JwtDecoder());

        return CryptoUtils.createEncodedJwtString(ssaClaims, JWSAlgorithm.PS256);
    }
}
