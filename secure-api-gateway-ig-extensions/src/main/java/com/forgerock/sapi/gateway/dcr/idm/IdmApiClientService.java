/*
 * Copyright © 2020-2024 ForgeRock AS (obst@forgerock.com)
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

import java.net.URISyntaxException;

import org.forgerock.http.Client;
import org.forgerock.http.protocol.Request;
import org.forgerock.http.protocol.Status;
import org.forgerock.json.JsonValue;
import org.forgerock.util.Reject;
import org.forgerock.util.promise.Promise;
import org.forgerock.util.promise.Promises;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.forgerock.sapi.gateway.dcr.idm.ApiClientService.ApiClientServiceException.ErrorCode;
import com.forgerock.sapi.gateway.dcr.models.ApiClient;

/**
 * ApiClientService implementation which retrieves ApiClient data from IDM
 */
public class IdmApiClientService implements ApiClientService {

    Logger log = LoggerFactory.getLogger(ApiClientService.class);
    /**
     * The base uri to use in GET requests to IDM to query for the apiClient
     *
     * Of the form: https://$IDM_HOST/openidm/managed/$API_CLIENT_MANAGED_OBJECT_NAME
     */
    private final String idmGetApiClientBaseUri;

    /**
     * The HTTP client to use when calling IDM.
     * Must be configured to provide credentials that allow access to the IDM REST API
     */
    private final Client httpClient;

    private final IdmApiClientDecoder idmApiClientDecoder;

    public IdmApiClientService(Client httpClient, String idmGetApiClientBaseUri, IdmApiClientDecoder idmApiClientDecoder) {
        Reject.ifNull(httpClient, "httpClient must be provided");
        Reject.ifBlank(idmGetApiClientBaseUri, "idmGetApiClientBaseUri must be provided");
        Reject.ifNull(idmApiClientDecoder, "idmApiClientDecoder must be provided");
        this.idmGetApiClientBaseUri = idmGetApiClientBaseUri;
        this.httpClient = httpClient;
        this.idmApiClientDecoder = idmApiClientDecoder;
    }

    @Override
    public Promise<ApiClient, ApiClientServiceException> getApiClient(String clientId) {
        Reject.ifBlank("clientId must be provided");
        try {
            final Request getApiClientRequest = new Request().setMethod("GET")
                                                             .setUri(idmGetApiClientBaseUri + clientId + "?_fields=apiClientOrg/*,*");
            return httpClient.send(getApiClientRequest)
                    .thenAsync(response -> {
                        if (response.getStatus() == Status.NOT_FOUND) {
                            throw new ApiClientServiceException(ErrorCode.NOT_FOUND, "ApiClient clientId: " + clientId + " not found");
                        }
                        else if (!response.getStatus().isSuccessful()) {
                            throw new ApiClientServiceException(ErrorCode.SERVER_ERROR, "Failed to get ApiClient from IDM, response status: " + response.getStatus());
                        }
                        return response.getEntity().getJsonAsync()
                                .then(json -> {
                                    final ApiClient apiClient;
                                    try {
                                        apiClient = idmApiClientDecoder.decode(JsonValue.json(json));
                                    } catch (RuntimeException ex) {
                                        throw new ApiClientServiceException(ErrorCode.DECODE_FAILED, "Failed to decode apiClient response json", ex);
                                    }
                                    if (apiClient.isDeleted()) {
                                        throw new ApiClientServiceException(ErrorCode.DELETED, "ApiClient clientId: " + clientId + " has been deleted");
                                    }
                                    return apiClient;
                                }, ioe -> { throw new ApiClientServiceException(ErrorCode.SERVER_ERROR, "Failed to get response json entity", ioe); });
                    }, nte -> Promises.newExceptionPromise(new ApiClientServiceException(ErrorCode.SERVER_ERROR, "Unexpected NeverThrowsException was thrown", nte)));
        } catch (URISyntaxException e) {
            return Promises.newExceptionPromise(new ApiClientServiceException(ErrorCode.SERVER_ERROR, "Failed to build request URI", e));
        }
    }
}
