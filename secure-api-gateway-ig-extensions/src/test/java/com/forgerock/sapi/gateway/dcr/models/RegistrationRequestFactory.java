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

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.net.MalformedURLException;
import java.net.URL;
import java.util.List;
import java.util.Map;

import com.forgerock.sapi.gateway.util.CryptoUtils;
import com.nimbusds.jose.JWSAlgorithm;

public class RegistrationRequestFactory {

    private static String JWKS_URI = "https://jwks.io";
    private static URL JWKS_URL;

    static {
        try {
            JWKS_URL = new URL(JWKS_URI);
        } catch (MalformedURLException e) {
            throw new RuntimeException(e);
        }
    }
    public static RegistrationRequest getRegRequestWithJwksUriSoftwareStatement() throws MalformedURLException {
        Map<String, Object> ssaClaims = Map.of();
        SoftwareStatement softwareStatement = mock(SoftwareStatement.class);
        when(softwareStatement.hasJwksUri()).thenReturn(true);
        when(softwareStatement.getJwksUri()).thenReturn(JWKS_URL);
        when(softwareStatement.getSignedJwt()).thenReturn(CryptoUtils.createSignedJwt(ssaClaims, JWSAlgorithm.PS256));
        String b64EncodedSoftwareStatement = CryptoUtils.createEncodedJwtString(ssaClaims, JWSAlgorithm.PS256);
        when(softwareStatement.getB64EncodedJwtString()).thenReturn(b64EncodedSoftwareStatement);

        Map<String, Object> regRequestClaims = Map.of("software_statement", b64EncodedSoftwareStatement);
        RegistrationRequest registrationRequest = mock(RegistrationRequest.class);
        when(registrationRequest.getSoftwareStatement()).thenReturn(softwareStatement);
        when(registrationRequest.getSignedJwt()).thenReturn(CryptoUtils.createSignedJwt(regRequestClaims, JWSAlgorithm.PS256));
        when(registrationRequest.getRedirectUris()).thenReturn(List.of(new URL("https://domain1.com/callback")));
        return registrationRequest;
    }


}
