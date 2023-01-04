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
package com.forgerock.sapi.gateway.dcr.idm;

import java.net.URI;

import org.forgerock.json.JsonValue;
import org.forgerock.json.JsonValueException;
import org.forgerock.json.jose.common.JwtReconstruction;
import org.forgerock.json.jose.jws.SignedJwt;

import com.forgerock.sapi.gateway.dcr.ApiClient;
import com.forgerock.sapi.gateway.dcr.ApiClientOrganisation;

/**
 * Decodes an {@link ApiClient} from a {@link JsonValue} returned by IDM
 */
public class IdmApiClientDecoder {

    /**
     * Decodes a json into an ApiClient.
     *
     * This method will throw a RuntimeException if decoding fails, for example if a required field is missing or if
     * there is a datatype mismatch.
     *
     * @param apiClientJson the json to decode
     * @return ApiClient
     * @throws JsonValueException
     */
    public ApiClient decode(JsonValue apiClientJson) {
        try {
            final ApiClient apiClient = new ApiClient();
            apiClient.setClientName(apiClientJson.get("name").as(this::requiredField).asString());
            apiClient.setOauth2ClientId(apiClientJson.get("oauth2ClientId").as(this::requiredField).asString());
            apiClient.setSoftwareClientId(apiClientJson.get("id").as(this::requiredField).asString());

            apiClient.setSoftwareStatementAssertion(apiClientJson.get("ssa").as(this::requiredField).as(
                    ssa -> {
                        final String jwtString = ssa.asString();
                        try {
                            return new JwtReconstruction().reconstructJwt(jwtString, SignedJwt.class);
                        } catch (RuntimeException rte) {
                            throw new JsonValueException(ssa, "failed to decode JWT, raw jwt string: " + jwtString, rte);
                        }
                    }));

            apiClient.setOrganisation(apiClientJson.get("apiClientOrg").as(this::requiredField).as(org -> {
                final JsonValue orgJson = JsonValue.json(org);
                final String orgId = orgJson.get("id").asString();
                final String orgName = orgJson.get("name").asString();
                return new ApiClientOrganisation(orgId, orgName);
            }));

            final JsonValue jwksUri = apiClientJson.get("jwksUri");
            if (jwksUri.isNotNull()) {
                apiClient.setJwksUri(jwksUri.as(jwks -> URI.create(jwks.asString())));
            }
            return apiClient;
        } catch (JsonValueException jve) {
            // These errors are expected and contain enough information to understand what when wrong e.g. missing required field
            throw jve;
        } catch (RuntimeException ex) {
            // Unexpected decode exception, dump the raw json to provide additional debug info
            throw new IllegalStateException("Unexpected exception thrown decoding apiClient, raw json: " + apiClientJson, ex);
        }
    }

    /**
     * Helper transformationFunction which validates that a particular field has a value.
     * If the field is null then a JsonValueException will be raised.
     */
    private JsonValue requiredField(JsonValue jsonValue) throws JsonValueException {
        if (jsonValue.isNull()) {
            throw new JsonValueException(jsonValue, "is a required field, failed to decode IDM ApiClient");
        }
        return jsonValue;
    }
}