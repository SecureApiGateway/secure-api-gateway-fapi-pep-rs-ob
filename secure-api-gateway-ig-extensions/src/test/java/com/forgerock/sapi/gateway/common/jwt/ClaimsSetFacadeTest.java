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
package com.forgerock.sapi.gateway.common.jwt;

import static org.assertj.core.api.AssertionsForClassTypes.assertThat;
import static org.assertj.core.api.AssertionsForClassTypes.catchThrowableOfType;

import java.net.MalformedURLException;
import java.net.URL;
import java.util.Map;

import org.forgerock.json.JsonValue;
import org.forgerock.json.jose.jwt.JwtClaimsSet;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class ClaimsSetFacadeTest {

    private ClaimsSetFacade claimSet;

    @BeforeEach
    void setUp() throws MalformedURLException {
        JwtClaimsSet claimsSet = new JwtClaimsSet(Map.of("claim1", "value1",
                "claim2", new URL("https://acme.com"), "iss", "jwt issuer",
                "jwks_uri", "https://jwks.com"));
        claimSet = new ClaimsSetFacade(claimsSet);
    }

    @AfterEach
    void tearDown() {
    }

    @Test
    void success_getStringClaim() throws JwtException {
        // Given
        // When
        String claim1Value = claimSet.getStringClaim("claim1");
        // Then
        assertThat(claim1Value).isEqualTo("value1");
    }

    @Test
    void throwsWhenClaimNotString_getStringClaim() {
        // Given
        // When
        JwtException exception = catchThrowableOfType(() -> claimSet.getStringClaim("claim2"), JwtException.class);
        // Then
        assertThat(exception).isNotNull();
    }

    @Test
    void throwsWhenClaimDoesNotExist_getStringClaim() {
        // Given
        // When
        JwtException exception = catchThrowableOfType(() -> claimSet.getStringClaim("claim3"), JwtException.class);
        // Then
        assertThat(exception).isNotNull();
    }

    @Test
    void throwsWhenInvalidArgument_getStringClaim() {
        // Given
        // When
        IllegalArgumentException exception = catchThrowableOfType(() -> claimSet.getStringClaim(""),
                IllegalArgumentException.class);
        // Then
        assertThat(exception).isNotNull();
    }

    @Test
    void success_getStringClaimAsURL() throws JwtException {
        // Given
        // When
        URL claimValue = claimSet.getStringClaimAsURL("jwks_uri");
        // Then
        assertThat(claimValue).isNotNull();
    }

    @Test
    void throwsWhenClaimNotUrl_getStringClaimAsURL() {
        // Given
        // When
        JwtException exception = catchThrowableOfType(() ->claimSet.getStringClaimAsURL("claim1"), JwtException.class);
        // Then
        assertThat(exception).isNotNull();
    }

    @Test
    void throwsWhenClaimDoesNotExist_getStringClaimAsURL() {
        // Given
        // When
        JwtException exception = catchThrowableOfType(() ->claimSet.getStringClaimAsURL("nonexistant"), JwtException.class);
        // Then
        assertThat(exception).isNotNull();
    }

    @Test
    void throwsWhenInvalidArgument_getStringClaimAsURL() {
        // Given
        // When
        IllegalArgumentException exception = catchThrowableOfType(() ->claimSet.getStringClaimAsURL(""),
                IllegalArgumentException.class);
        // Then
        assertThat(exception).isNotNull();
    }

    @Test
    void success_getJsonValueClaim() throws JwtException {
        // Given
        // When
        JsonValue value = claimSet.getJsonValueClaim("claim1");
        // Then
        assertThat(value).isNotNull();
    }

    @Test
    void throwsWhenClaimDoesNotExist_getJsonValueClaim() throws JwtException {
        // Given
        // When
        JwtException exception  = catchThrowableOfType(()->claimSet.getJsonValueClaim("nonExistent"), JwtException.class);
        // Then
        assertThat(exception).isNotNull();
    }

    @Test
    void throwsWhenInvalidArgument_getJsonValueClaim() throws JwtException {
        // Given
        // When
        IllegalArgumentException exception  = catchThrowableOfType(()->claimSet.getJsonValueClaim(""),
                IllegalArgumentException.class);
        // Then
        assertThat(exception).isNotNull();
    }

    @Test
    void success_getIssuer() throws JwtException {
        // Given
        // WHen
        String issuer = claimSet.getIssuer();
        // Then
        assertThat(issuer).isNotNull();
        assertThat(issuer).isNotEmpty();
    }

    @Test
    void throwsWhenClaimDoesNotExist_getIssuer(){
        // Given
        JwtClaimsSet claimsSet = new JwtClaimsSet(Map.of());
        ClaimsSetFacade emptyClaimSet = new ClaimsSetFacade(claimsSet);
        // When
        JwtException exception = catchThrowableOfType(emptyClaimSet::getIssuer, JwtException.class);
        // Then
        assertThat(exception).isNotNull();
    }
}