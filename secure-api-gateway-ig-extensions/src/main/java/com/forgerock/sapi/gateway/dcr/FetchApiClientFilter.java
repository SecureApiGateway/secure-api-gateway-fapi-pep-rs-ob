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

import static org.forgerock.openig.util.JsonValues.requiredHeapObject;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.Map;

import org.forgerock.http.Client;
import org.forgerock.http.Filter;
import org.forgerock.http.Handler;
import org.forgerock.http.oauth2.OAuth2Context;
import org.forgerock.http.protocol.Request;
import org.forgerock.http.protocol.Response;
import org.forgerock.http.protocol.Status;
import org.forgerock.json.JsonValue;
import org.forgerock.json.jose.common.JwtReconstruction;
import org.forgerock.json.jose.jws.SignedJwt;
import org.forgerock.openig.heap.GenericHeaplet;
import org.forgerock.openig.heap.HeapException;
import org.forgerock.services.context.AttributesContext;
import org.forgerock.services.context.Context;
import org.forgerock.util.Reject;
import org.forgerock.util.promise.NeverThrowsException;
import org.forgerock.util.promise.Promise;
import org.forgerock.util.promise.Promises;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.forgerock.sapi.gateway.fapi.FAPIUtils;

/**
 * Fetches {@link ApiClient} data from IDM using the client_id identified from the access_token provided with this request.
 * The {@link ApiClient} retrieved is then made accessible via the AttributesContext as key: "apiClient", other filters
 * in the chain can then access this data using the context.
 *
 * This filter relies on the OAuth2Context being present, therefore it must be installed after a filter which adds this
 * context, such as OAuth2ResourceServerFilter.
 */
public class FetchApiClientFilter implements Filter {

    /**
     * The key to use to get the ApiClient from the AttributesContext
     */
    public static final String API_CLIENT_ATTR_KEY = "apiClient";

    /**
     * The default claim to use to extract the client_id from the access_token
     */
    private static final String DEFAULT_ACCESS_TOKEN_CLIENT_ID_CLAIM = "aud";
    private final Logger logger = LoggerFactory.getLogger(getClass());

    /**
     * The HTTP client to use when calling IDM.
     * Must be configured to provide credentials that allow access to the IDM REST API
     */
    private final Client httpClient;

    /**
     * The base uri to use in GET requests to IDM to query for the apiClient
     *
     * Of the form: https://$IDM_HOST/openidm/managed/$API_CLIENT_MANAGED_OBJECT_NAME
     */
    private final String idmGetApiClientBaseUri;

    /**
     * The claim in the access_token where the client_id can be found, see DEFAULT_ACCESS_TOKEN_CLIENT_ID_CLAIM
     */
    private final String accessTokenClientIdClaim;

    public FetchApiClientFilter(Client clientHandler, String idmGetApiClientBaseUri, String accessTokenClientIdClaim) {
        Reject.ifNull(clientHandler, "clientHandler must be provided");
        Reject.ifBlank(idmGetApiClientBaseUri, "idmGetApiClientBaseUri must be provided");
        Reject.ifBlank(accessTokenClientIdClaim, "accessTokenClientIdClaim must be provided");
        this.httpClient = clientHandler;
        this.idmGetApiClientBaseUri = idmGetApiClientBaseUri;
        this.accessTokenClientIdClaim = accessTokenClientIdClaim;
    }

    @Override
    public Promise<Response, NeverThrowsException> filter(Context context, Request request, Handler next) {
        final OAuth2Context oAuth2Context = context.asContext(OAuth2Context.class);
        final Map<String, Object> info = oAuth2Context.getAccessToken().getInfo();
        if (!info.containsKey(accessTokenClientIdClaim)) {
            logger.error("({}) access token is missing required " + accessTokenClientIdClaim + " claim", FAPIUtils.getFapiInteractionIdForDisplay(context));
            return Promises.newResultPromise(new Response(Status.INTERNAL_SERVER_ERROR));
        }
        final String clientId = (String)info.get(accessTokenClientIdClaim);

        return getApiClientFromIdm(clientId).thenAsync(apiClient -> {
            logger.debug("({}) adding apiClient: {} to AttributesContext[\"{}\"]", FAPIUtils.getFapiInteractionIdForDisplay(context), apiClient, API_CLIENT_ATTR_KEY);
            context.asContext(AttributesContext.class).getAttributes().put(API_CLIENT_ATTR_KEY, apiClient);
            return next.handle(context, request);
        }, ex -> {
            logger.error("(" + FAPIUtils.getFapiInteractionIdForDisplay(context) + ") failed to get apiClient from idm due to exception", ex);
            return Promises.newResultPromise(new Response(Status.INTERNAL_SERVER_ERROR));
        });
    }

    private Promise<ApiClient, Exception> getApiClientFromIdm(String clientId) {
        try {
            final Request getApiClientRequest = new Request().setMethod("GET")
                                                             .setUri(idmGetApiClientBaseUri + clientId + "?_fields=apiClientOrg,*");
            return httpClient.send(getApiClientRequest)
                             .thenAsync(response -> {
                                 if (!response.getStatus().isSuccessful()) {
                                     throw new Exception("Failed to get ApiClient from IDM, response status: " + response.getStatus());
                                 }
                                 return response.getEntity().getJsonAsync()
                                                            .then(json -> convertJsonObjectToApiClient(JsonValue.json(json)),
                                                                  ioe -> { throw new Exception("Failed to decode apiClient response json", ioe); });
                             }, nte -> Promises.newExceptionPromise(new Exception(nte)));
        } catch (URISyntaxException e) {
            return Promises.newExceptionPromise(new Exception(e));
        }
    }

    private ApiClient convertJsonObjectToApiClient(JsonValue apiClientJson) {
        final ApiClient apiClient = new ApiClient();
        apiClient.setClientName(apiClientJson.get("name").asString());
        apiClient.setOauth2ClientId(apiClientJson.get("oauth2ClientId").asString());
        apiClient.setSoftwareStatementAssertion(apiClientJson.get("ssa").as(ssa -> new JwtReconstruction().reconstructJwt(ssa.asString(), SignedJwt.class)));
        apiClient.setSoftwareClientId(apiClientJson.get("id").asString());
        apiClient.setJwksUri(apiClientJson.get("jwksUri").as(jwks -> URI.create(jwks.asString())));
        apiClient.setOrganisation(apiClientJson.get("apiClientOrg").as(org -> {
            final JsonValue orgJson = JsonValue.json(org);
            final String orgId = orgJson.get("id").asString();
            final String orgName = orgJson.get("name").asString();
            return new ApiClientOrganisation(orgId, orgName);
        }));
        return apiClient;
    }

    /**
     * Responsible for creating the {@link FetchApiClientFilter}
     *
     * Mandatory config:
     * - idmGetApiClientBaseUri: the base uri used to build the IDM query to get the apiClient, the client_id is expected
     * to be appended to this uri (and some query params).
     * - clientHandler: the clientHandler to use to call out to IDM (must be configured with the credentials required to
     * query IDM)
     *
     * Optional config:
     * - accessTokenClientIdClaim: name of the claim used to extract the client_id from the access_token, defaults to "aud"
     *
     * Example config:
     * {
     *           "comment": "Add ApiClient data to the context attributes",
     *           "name": "FetchApiClientFilter",
     *           "type": "FetchApiClientFilter",
     *           "config": {
     *             "idmGetApiClientBaseUri": "https://&{identity.platform.fqdn}/openidm/managed/apiClient",
     *             "clientHandler": "IDMClientHandler"
     *            }
     * }
     */
    public static class Heaplet extends GenericHeaplet {
        @Override
        public Object create() throws HeapException {
            final Handler clientHandler = config.get("clientHandler").as(requiredHeapObject(heap, Handler.class));
            final Client httpClient = new Client(clientHandler);

            String idmGetApiClientBaseUri = config.get("idmGetApiClientBaseUri").required().asString();
            if (!idmGetApiClientBaseUri.endsWith("/")) {
                idmGetApiClientBaseUri = idmGetApiClientBaseUri + '/';
            }
            final String accessTokenClientIdClaim = config.get("accessTokenClientIdClaim").defaultTo(DEFAULT_ACCESS_TOKEN_CLIENT_ID_CLAIM).asString();

            return new FetchApiClientFilter(httpClient, idmGetApiClientBaseUri, accessTokenClientIdClaim);
        }
    }
}
