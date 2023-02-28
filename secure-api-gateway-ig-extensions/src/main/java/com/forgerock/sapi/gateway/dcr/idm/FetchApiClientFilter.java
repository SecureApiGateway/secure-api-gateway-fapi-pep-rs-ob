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

import static org.forgerock.openig.util.JsonValues.requiredHeapObject;

import java.util.Map;

import org.forgerock.http.Client;
import org.forgerock.http.Filter;
import org.forgerock.http.Handler;
import org.forgerock.http.oauth2.OAuth2Context;
import org.forgerock.http.protocol.Request;
import org.forgerock.http.protocol.Response;
import org.forgerock.http.protocol.Status;
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

import com.forgerock.sapi.gateway.dcr.models.ApiClient;
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
     * The claim in the access_token where the client_id can be found, see DEFAULT_ACCESS_TOKEN_CLIENT_ID_CLAIM
     */
    private final String accessTokenClientIdClaim;

    /**
     * Service which can retrieve ApiClient data
     */
    private final IdmApiClientService idmApiClientService;

    /**
     * Utility method to retrieve an ApiClient object from a Context.
     * This method can be used by other filters to retrieve the ApiClient installed into the attributes context by
     * this filter.
     *
     * @param context the context to retrieve the ApiClient from
     * @return the ApiClient or null if it is not set in the context.
     */
    public static ApiClient getApiClientFromContext(Context context) {
        return (ApiClient) context.asContext(AttributesContext.class).getAttributes().get(API_CLIENT_ATTR_KEY);
    }

    public FetchApiClientFilter(IdmApiClientService idmApiClientService, String accessTokenClientIdClaim) {
        Reject.ifNull(idmApiClientService, "apiClientService must be provided");
        Reject.ifBlank(accessTokenClientIdClaim, "accessTokenClientIdClaim must be provided");
        this.accessTokenClientIdClaim = accessTokenClientIdClaim;
        this.idmApiClientService = idmApiClientService;
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

        return idmApiClientService.getApiClient(clientId).thenAsync(apiClient -> {
            logger.debug("({}) adding apiClient: {} to AttributesContext[\"{}\"]", FAPIUtils.getFapiInteractionIdForDisplay(context), apiClient, API_CLIENT_ATTR_KEY);
            context.asContext(AttributesContext.class).getAttributes().put(API_CLIENT_ATTR_KEY, apiClient);
            return next.handle(context, request);
        }, ex -> {
            logger.error("(" + FAPIUtils.getFapiInteractionIdForDisplay(context) + ") failed to get apiClient from idm due to exception", ex);
            return Promises.newResultPromise(new Response(Status.INTERNAL_SERVER_ERROR));
        }, rte -> {
            logger.error("(" + FAPIUtils.getFapiInteractionIdForDisplay(context) + ") failed to get apiClient from idm due to exception", rte);
            return Promises.newResultPromise(new Response(Status.INTERNAL_SERVER_ERROR));
        });
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

            final IdmApiClientService idmApiClientService = new IdmApiClientService(httpClient, idmGetApiClientBaseUri, new IdmApiClientDecoder());
            return new FetchApiClientFilter(idmApiClientService, accessTokenClientIdClaim);
        }
    }
}
