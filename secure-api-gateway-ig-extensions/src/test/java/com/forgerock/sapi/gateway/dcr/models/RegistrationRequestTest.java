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

import static org.assertj.core.api.AssertionsForClassTypes.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.util.List;
import java.util.Map;
import java.util.Optional;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import com.forgerock.sapi.gateway.dcr.request.DCRRegistrationRequestBuilderException;
import com.forgerock.sapi.gateway.jws.JwtDecoder;
import com.forgerock.sapi.gateway.trusteddirectories.TrustedDirectory;
import com.forgerock.sapi.gateway.trusteddirectories.TrustedDirectoryService;
import com.forgerock.sapi.gateway.trusteddirectories.TrustedDirectoryTest;
import com.forgerock.sapi.gateway.util.CryptoUtils;
import com.nimbusds.jose.JWSAlgorithm;

public class RegistrationRequestTest {

    private static final String TX_ID = "tx_id";
    private static final TrustedDirectoryService directoryService = mock(TrustedDirectoryService.class);
    private static final RegistrationRequest.Builder requestBuilder;
    private static final TrustedDirectory trustedDirectory;

    static {
        trustedDirectory = TrustedDirectoryTest.getJwksUriBasedTrustedDirectory();
        when(directoryService.getTrustedDirectoryConfiguration(trustedDirectory.getIssuer()))
                .thenReturn(trustedDirectory);
        JwtDecoder jwtDecoder = new JwtDecoder();
        SoftwareStatement.Builder softwareStatementBuilder =
                new SoftwareStatement.Builder(directoryService, jwtDecoder);
        requestBuilder = new RegistrationRequest.Builder(softwareStatementBuilder, jwtDecoder);
    }

    private static RegistrationRequest getJwksUriBasedRegistrationrRequest()
            throws DCRRegistrationRequestBuilderException {
        Map<String, Object> ssaClaims = Map.of("iss", trustedDirectory.getIssuer(),
                trustedDirectory.getSoftwareStatementJwksUriClaimName(), "https://jwks_uri.com",
                trustedDirectory.getSoftwareStatementOrgIdClaimName(), "Acme Ltd",
                trustedDirectory.getSoftwareStatementSoftwareIdClaimName(), "Acme App",
                trustedDirectory.getSoftwareStatementRedirectUrisClaimName(), List.of("https://domain1.com/callback"));
        String b64EncodedSsaString = CryptoUtils.createEncodedJwtString(ssaClaims, JWSAlgorithm.PS256);
        Map<String, Object> regRequestClaims = Map.of("iss", "Acme App", "software_statement", b64EncodedSsaString,
                "redirect_uris", List.of("https://domain1.com/callback"));
        String b64EncodedRegRequestString = CryptoUtils.createEncodedJwtString(regRequestClaims, JWSAlgorithm.PS256);
        return requestBuilder.build(TX_ID, b64EncodedRegRequestString);
    }

    @BeforeEach
    void setup() {
        when(directoryService.getTrustedDirectoryConfiguration(trustedDirectory.getIssuer()))
                .thenReturn(trustedDirectory);
    }

    @Test
    void success_getSoftwareStatement() throws DCRRegistrationRequestBuilderException {
        // Given
        RegistrationRequest registrationRequest = getJwksUriBasedRegistrationrRequest();
        // When
        SoftwareStatement softwareStatement = registrationRequest.getSoftwareStatement();
        // Then
        assertThat(softwareStatement).isNotNull();
        assertThat(softwareStatement.getIssuer()).isEqualTo(trustedDirectory.getIssuer());
    }

    @Test
    void testToString() throws DCRRegistrationRequestBuilderException {
        // Given
        RegistrationRequest regRequest = getJwksUriBasedRegistrationrRequest();
        // When
        String output = regRequest.toString();
        assertThat(output).isNotNull();
        assertThat(output).contains("kid");
    }

    @Test
    void success_setResponseTypes() throws DCRRegistrationRequestBuilderException {
        // Given
        RegistrationRequest registrationRequest = getJwksUriBasedRegistrationrRequest();
        List<String> responseTypes = List.of("code", "code id_token");
        // When
        registrationRequest.setResponseTypes(responseTypes);
        // Then
        Optional<List<String>> actualResponseTypes = registrationRequest.getResponseTypes();
        assertThat(actualResponseTypes.isPresent()).isTrue();
        assertThat(actualResponseTypes.get()).isEqualTo(responseTypes);
    }
}