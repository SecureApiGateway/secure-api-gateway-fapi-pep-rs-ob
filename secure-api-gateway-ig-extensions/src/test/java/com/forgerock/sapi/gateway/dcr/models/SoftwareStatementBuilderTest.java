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
import static org.assertj.core.api.AssertionsForClassTypes.catchThrowableOfType;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.reset;
import static org.mockito.Mockito.when;

import java.net.MalformedURLException;
import java.net.URL;
import java.util.Map;

import org.forgerock.json.jose.jwk.JWKSet;
import org.forgerock.json.jose.jws.JwsHeader;
import org.forgerock.json.jose.jws.SignedJwt;
import org.forgerock.json.jose.jwt.JwtClaimsSet;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import com.forgerock.sapi.gateway.common.jwt.JwtException;
import com.forgerock.sapi.gateway.dcr.common.DCRErrorCode;
import com.forgerock.sapi.gateway.dcr.sigvalidation.DCRTestHelpers;
import com.forgerock.sapi.gateway.dcr.request.DCRRegistrationRequestBuilderException;
import com.forgerock.sapi.gateway.jws.JwtDecoder;
import com.forgerock.sapi.gateway.trusteddirectories.TrustedDirectory;
import com.forgerock.sapi.gateway.trusteddirectories.TrustedDirectoryOpenBankingTest;
import com.forgerock.sapi.gateway.trusteddirectories.TrustedDirectorySecureApiGateway;
import com.forgerock.sapi.gateway.trusteddirectories.TrustedDirectoryService;

class SoftwareStatementBuilderTest {

    private final TrustedDirectoryService trustedDirectoryService = mock(TrustedDirectoryService.class);
    private final JwtDecoder jwtDecoder = mock(JwtDecoder.class);
    private static final TrustedDirectory TRUSTED_DIRECTORY_OPEN_BANKING_TEST = new TrustedDirectoryOpenBankingTest();
    private static final TrustedDirectory DIRECTORY_SECURE_API_GATEWAY;
    private static final String KEY_ID = "key-id-value";
    private static final String ISSUER = "SSA_Issuer";
    private static final String ORG_ID = "Acme Inc.";
    private static final String SOFTWARE_ID ="Acme App";
    private static final String JWKS_URI = "https://jwks.com";
    private static final String SSA_JWT_STRING = "header.payload.sig";

    public static final String TX_ID = "tx_id";

    public SoftwareStatement.Builder builder;

    static {
        try {
            URL jwksUri = new URL("https://bankjwkms.com");
            DIRECTORY_SECURE_API_GATEWAY = new TrustedDirectorySecureApiGateway(jwksUri);
        } catch (MalformedURLException e) {
            throw new RuntimeException(e);
        }
    }


    @BeforeEach
    void setUp() throws DCRRegistrationRequestBuilderException {
         builder = new SoftwareStatement.Builder(trustedDirectoryService, jwtDecoder);
    }

    @AfterEach
    void tearDown() {
        reset(trustedDirectoryService, jwtDecoder);
    }

    @Test
    void successJwksUriBased_buildSoftwareStatement()
            throws DCRRegistrationRequestBuilderException, JwtException, MalformedURLException {
        // Given
        SignedJwt ssaJwt = mock(SignedJwt.class);
        JwsHeader ssaHeader = mock(JwsHeader.class);
        JwtClaimsSet claimsSet = getValidJwkUriBasedClaims();

        // When
        when(ssaJwt.getHeader()).thenReturn(ssaHeader);
        when(ssaHeader.getKeyId()).thenReturn(KEY_ID);
        when(jwtDecoder.getSignedJwt(SSA_JWT_STRING)).thenReturn(ssaJwt);
        when(ssaJwt.getClaimsSet()).thenReturn(claimsSet);
        when(trustedDirectoryService.getTrustedDirectoryConfiguration(ISSUER))
                .thenReturn(new TrustedDirectoryOpenBankingTest());


        SoftwareStatement softwareStatement = builder.build("tx_id", SSA_JWT_STRING);

        // Then
        assertThat(softwareStatement).isNotNull();
        assertThat(softwareStatement.getKeyId()).isEqualTo(KEY_ID);
        assertThat(softwareStatement.getOrgId()).isEqualTo(ORG_ID);
        assertThat(softwareStatement.getSoftwareId()).isEqualTo(SOFTWARE_ID);
        assertThat(softwareStatement.hasJwksUri()).isTrue();
        assertThat(softwareStatement.getJwksUri()).isEqualTo(new URL(JWKS_URI));
    }

    @Test
    void successJwksBased_buildSoftwareStatement() throws DCRRegistrationRequestBuilderException,
            JwtException, JwtException {
        // Given
        SignedJwt ssaJwt = mock(SignedJwt.class);
        JwsHeader ssaHeader = mock(JwsHeader.class);
        JwtClaimsSet claimsSet = getValidJwkBasedClaims();

        // When
        when(ssaJwt.getHeader()).thenReturn(ssaHeader);
        when(ssaHeader.getKeyId()).thenReturn(KEY_ID);
        when(jwtDecoder.getSignedJwt(SSA_JWT_STRING)).thenReturn(ssaJwt);
        when(ssaJwt.getClaimsSet()).thenReturn(claimsSet);
        when(trustedDirectoryService.getTrustedDirectoryConfiguration(ISSUER)).thenReturn(DIRECTORY_SECURE_API_GATEWAY);

        SoftwareStatement softwareStatement = builder.build(TX_ID, SSA_JWT_STRING);

        // Then
        assertThat(softwareStatement).isNotNull();
        assertThat(softwareStatement.getOrgId()).isEqualTo(ORG_ID);
        assertThat(softwareStatement.getSoftwareId()).isEqualTo(SOFTWARE_ID);
        assertThat(softwareStatement.hasJwksUri()).isFalse();
        JWKSet expectedJWkSet = JWKSet.parse(DCRTestHelpers.JWKS_JSON);
        assertThat(softwareStatement.getJwksSet()).isEqualTo(expectedJWkSet);
        assertThat(softwareStatement.getSignedJwt()).isEqualTo(ssaJwt);
    }

    @Test
    void failInvalidJwt_buildSoftwareStatement() throws JwtException, DCRRegistrationRequestBuilderException {
        // Given
        SignedJwt ssaJwt = mock(SignedJwt.class);
        JwsHeader ssaHeader = mock(JwsHeader.class);
        JwtClaimsSet claimsSet = getValidJwkUriBasedClaims();

        // When
        when(ssaJwt.getHeader()).thenReturn(ssaHeader);
        when(ssaHeader.getKeyId()).thenReturn(KEY_ID);
        when(jwtDecoder.getSignedJwt(SSA_JWT_STRING))
                .thenThrow(JwtException.class);

        DCRRegistrationRequestBuilderException exception = catchThrowableOfType(()->
                        builder.build(TX_ID, SSA_JWT_STRING),
                DCRRegistrationRequestBuilderException.class);
        // Then
        assertThat(exception).isNotNull();
        assertThat(exception.getErrorCode()).isEqualTo(DCRErrorCode.INVALID_SOFTWARE_STATEMENT);
    }

    @Test
    void failNoIssuerClaim_buildSoftwareStatement() throws JwtException, DCRRegistrationRequestBuilderException {
        // Given
        SignedJwt ssaJwt = mock(SignedJwt.class);
        JwtClaimsSet claimsSet = getValidJwkUriBasedClaims();

        // When
        when(jwtDecoder.getSignedJwt(SSA_JWT_STRING)).thenReturn(ssaJwt);
        when(ssaJwt.getClaimsSet()).thenReturn(new JwtClaimsSet(Map.of()));
        DCRRegistrationRequestBuilderException exception = catchThrowableOfType(()->
                builder.build(TX_ID, SSA_JWT_STRING), DCRRegistrationRequestBuilderException.class);
        // Then
        assertThat(exception).isNotNull();
        assertThat(exception.getErrorCode()).isEqualTo(DCRErrorCode.INVALID_SOFTWARE_STATEMENT);
    }

    @Test
    void failUnrecognisedIssuer_buildSoftwareStatement() throws JwtException, DCRRegistrationRequestBuilderException {
        // Given
        JwsHeader ssaHeader = mock(JwsHeader.class);
        SignedJwt ssaJwt = mock(SignedJwt.class);

        // When
        when(ssaJwt.getHeader()).thenReturn(ssaHeader);
        when(ssaHeader.getKeyId()).thenReturn(KEY_ID);
        when(jwtDecoder.getSignedJwt(SSA_JWT_STRING)).thenReturn(ssaJwt);
        when(ssaJwt.getClaimsSet()).thenReturn(new JwtClaimsSet(Map.of("iss", ISSUER)));
        DCRRegistrationRequestBuilderException exception = catchThrowableOfType(()->
                builder.build(TX_ID, SSA_JWT_STRING), DCRRegistrationRequestBuilderException.class);
        // Then
        assertThat(exception).isNotNull();
        assertThat(exception.getErrorCode()).isEqualTo(DCRErrorCode.UNAPPROVED_SOFTWARE_STATEMENT);
    }

    @Test
    void failNoOrgId_buildSoftwareStatement() throws JwtException, DCRRegistrationRequestBuilderException {
        // Given
        JwsHeader ssaHeader = mock(JwsHeader.class);
        SignedJwt ssaJwt = mock(SignedJwt.class);

        // When
        when(ssaJwt.getHeader()).thenReturn(ssaHeader);
        when(ssaHeader.getKeyId()).thenReturn(KEY_ID);
        when(jwtDecoder.getSignedJwt(SSA_JWT_STRING)).thenReturn(ssaJwt);

        when(ssaJwt.getClaimsSet()).thenReturn(new JwtClaimsSet(Map.of("iss", ISSUER)));
        when(trustedDirectoryService.getTrustedDirectoryConfiguration(ISSUER))
                .thenReturn(TRUSTED_DIRECTORY_OPEN_BANKING_TEST);
        DCRRegistrationRequestBuilderException exception = catchThrowableOfType(()->
                builder.build(TX_ID, SSA_JWT_STRING), DCRRegistrationRequestBuilderException.class);
        // Then
        assertThat(exception).isNotNull();
        assertThat(exception.getErrorCode()).isEqualTo(DCRErrorCode.INVALID_SOFTWARE_STATEMENT);
    }

    @Test
    void failNoSoftwareId_buildSoftwareStatement() throws JwtException, DCRRegistrationRequestBuilderException {
        // Given
        String jwtString = "header.payload.sig";
        JwsHeader ssaHeader = mock(JwsHeader.class);
        SignedJwt ssaJwt = mock(SignedJwt.class);

        // When
        when(ssaJwt.getHeader()).thenReturn(ssaHeader);
        when(ssaHeader.getKeyId()).thenReturn(KEY_ID);
        when(jwtDecoder.getSignedJwt(jwtString)).thenReturn(ssaJwt);

        when(ssaJwt.getClaimsSet()).thenReturn(new JwtClaimsSet(Map.of("iss", ISSUER, "org_id", ORG_ID)));
        when(trustedDirectoryService.getTrustedDirectoryConfiguration(ISSUER))
                .thenReturn(TRUSTED_DIRECTORY_OPEN_BANKING_TEST);
        DCRRegistrationRequestBuilderException exception = catchThrowableOfType(()->
                builder.build(TX_ID, SSA_JWT_STRING), DCRRegistrationRequestBuilderException.class);
        // Then
        assertThat(exception).isNotNull();
        assertThat(exception.getErrorCode()).isEqualTo(DCRErrorCode.INVALID_SOFTWARE_STATEMENT);
    }

    @Test
    void failNoJwksUri_buildSoftwareStatement() throws JwtException, DCRRegistrationRequestBuilderException {
        // Given
        String jwtString = "header.payload.sig";
        JwsHeader ssaHeader = mock(JwsHeader.class);
        SignedJwt ssaJwt = mock(SignedJwt.class);

        // When
        when(ssaJwt.getHeader()).thenReturn(ssaHeader);
        when(ssaHeader.getKeyId()).thenReturn(KEY_ID);
        when(jwtDecoder.getSignedJwt(jwtString)).thenReturn(ssaJwt);
        when(ssaJwt.getClaimsSet()).thenReturn(new JwtClaimsSet(Map.of("iss", ISSUER, "org_id", ORG_ID,
                TRUSTED_DIRECTORY_OPEN_BANKING_TEST.getSoftwareStatementJwksUriClaimName(), SOFTWARE_ID)));
        when(trustedDirectoryService.getTrustedDirectoryConfiguration(ISSUER))
                .thenReturn(TRUSTED_DIRECTORY_OPEN_BANKING_TEST);
        DCRRegistrationRequestBuilderException exception = catchThrowableOfType(()->
                builder.build(TX_ID, SSA_JWT_STRING), DCRRegistrationRequestBuilderException.class);
        // Then
        assertThat(exception).isNotNull();
        assertThat(exception.getErrorCode()).isEqualTo(DCRErrorCode.INVALID_SOFTWARE_STATEMENT);
    }

    @Test
    void failNoJwks_buildSoftwareStatement() throws JwtException, DCRRegistrationRequestBuilderException {
        // Given
        String jwtString = "header.payload.sig";
        JwsHeader ssaHeader = mock(JwsHeader.class);
        SignedJwt ssaJwt = mock(SignedJwt.class);
        // When
        when(ssaJwt.getHeader()).thenReturn(ssaHeader);
        when(ssaHeader.getKeyId()).thenReturn(KEY_ID);
        when(jwtDecoder.getSignedJwt(jwtString)).thenReturn(ssaJwt);
        when(ssaJwt.getClaimsSet()).thenReturn(new JwtClaimsSet(Map.of("iss", ISSUER, "org_id", ORG_ID,
                DIRECTORY_SECURE_API_GATEWAY.getSoftwareStatementSoftwareIdClaimName(), SOFTWARE_ID)));
        when(trustedDirectoryService.getTrustedDirectoryConfiguration(ISSUER))
                .thenReturn(DIRECTORY_SECURE_API_GATEWAY);
        DCRRegistrationRequestBuilderException exception = catchThrowableOfType(()->
                builder.build(TX_ID, SSA_JWT_STRING), DCRRegistrationRequestBuilderException.class);
        // Then
        assertThat(exception).isNotNull();
        assertThat(exception.getErrorCode()).isEqualTo(DCRErrorCode.INVALID_SOFTWARE_STATEMENT);
    }


    private JwtClaimsSet getValidJwkUriBasedClaims() {
        Map<String, Object> claims = Map.of("iss", ISSUER,
                TRUSTED_DIRECTORY_OPEN_BANKING_TEST.getSoftwareStatementOrgIdClaimName(), ORG_ID,
                TRUSTED_DIRECTORY_OPEN_BANKING_TEST.getSoftwareStatementSoftwareIdClaimName(), SOFTWARE_ID,
                TRUSTED_DIRECTORY_OPEN_BANKING_TEST.getSoftwareStatementJwksUriClaimName(), JWKS_URI);
        return  new JwtClaimsSet(claims);
    }

    private JwtClaimsSet getValidJwkBasedClaims() throws JwtException {
        Map<String, Object> claims = Map.of("iss", ISSUER,
                DIRECTORY_SECURE_API_GATEWAY.getSoftwareStatementOrgIdClaimName(), ORG_ID,
                DIRECTORY_SECURE_API_GATEWAY.getSoftwareStatementSoftwareIdClaimName(), SOFTWARE_ID,
                DIRECTORY_SECURE_API_GATEWAY.getSoftwareStatementJwksClaimName(),  DCRTestHelpers.getJwksJsonValue());
        return  new JwtClaimsSet(claims);
    }
}