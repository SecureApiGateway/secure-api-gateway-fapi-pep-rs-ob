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
package com.forgerock.sapi.gateway.dcr;

import java.net.URI;
import java.util.Objects;

import org.forgerock.json.jose.jws.SignedJwt;

/**
 * Data object which represents a registered OAuth2 client.
 */
public class ApiClient {

    /**
     * The OAuth2 Client ID for this client. This is generated and assigned at registration.
     *
     * This ID can uniquely identify the ApiClient.
     */
    private String oauth2ClientId;

    /**
     * The Client ID for this client as defined in the software statement used to at registration (not necessarily unique).
     */
    private String softwareClientId;

    /**
     * Name of the client
     */
    private String clientName;

    /**
     * The URI of the JWKS which contains the certificates which can be used by this ApiClient for transport and
     * signing purposes.
     */
    private URI jwksUri;

    /**
     * The Software Statement Assertions (SSA), which is a signed JWT containing the Software Statement registered.
     */
    private SignedJwt softwareStatementAssertion;

    /**
     * The organisation that this client belongs to
     */
    private ApiClientOrganisation organisation;

    public ApiClient(){
    }

    public String getOauth2ClientId() {
        return oauth2ClientId;
    }

    public void setOauth2ClientId(String oauth2ClientId) {
        this.oauth2ClientId = oauth2ClientId;
    }

    public String getSoftwareClientId() {
        return softwareClientId;
    }

    public void setSoftwareClientId(String softwareClientId) {
        this.softwareClientId = softwareClientId;
    }

    public String getClientName() {
        return clientName;
    }

    public void setClientName(String clientName) {
        this.clientName = clientName;
    }

    public URI getJwksUri() {
        return jwksUri;
    }

    public void setJwksUri(URI jwksUri) {
        this.jwksUri = jwksUri;
    }

    public SignedJwt getSoftwareStatementAssertion() {
        return softwareStatementAssertion;
    }

    public void setSoftwareStatementAssertion(SignedJwt softwareStatementAssertion) {
        this.softwareStatementAssertion = softwareStatementAssertion;
    }

    public ApiClientOrganisation getOrganisation() {
        return organisation;
    }

    public void setOrganisation(ApiClientOrganisation organisation) {
        this.organisation = organisation;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        final ApiClient apiClient = (ApiClient) o;
        return Objects.equals(oauth2ClientId, apiClient.oauth2ClientId)
                && Objects.equals(softwareClientId, apiClient.softwareClientId)
                && Objects.equals(clientName, apiClient.clientName)
                && Objects.equals(jwksUri, apiClient.jwksUri)
                && Objects.equals(softwareStatementAssertion, apiClient.softwareStatementAssertion)
                && Objects.equals(organisation, apiClient.organisation);
    }

    @Override
    public int hashCode() {
        return Objects.hash(oauth2ClientId, softwareClientId, clientName, jwksUri, softwareStatementAssertion, organisation);
    }

    @Override
    public String toString() {
        return "ApiClient{" +
                "oauth2ClientId='" + oauth2ClientId + '\'' +
                ", softwareClientId='" + softwareClientId + '\'' +
                ", clientName='" + clientName + '\'' +
                ", jwksUri=" + jwksUri +
                ", softwareStatementAssertion=" + softwareStatementAssertion +
                ", organisation=" + organisation +
                '}';
    }
}
