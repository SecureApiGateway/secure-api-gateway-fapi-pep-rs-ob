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

import org.forgerock.openig.heap.HeapException;

import com.forgerock.sapi.gateway.dcr.idm.FetchApiClientFilter.BaseFetchApiClientHeaplet;

/**
 * Responsible for creating the {@link AuthorizeResponseFetchApiClientFilter}
 * <p>
 * Mandatory config:
 * - idmGetApiClientBaseUri: the base uri used to build the IDM query to get the apiClient, the client_id is expected
 * to be appended to this uri (and some query params).
 * - clientHandler: the clientHandler to use to call out to IDM (must be configured with the credentials required to
 * query IDM)
 * <p>
 * Example config:
 * <pre>{@code
 * {
 *   "comment": "Add ApiClient data to the context attributes for the AS /authorize route",
 *   "name": "AuthoriseResponseFetchApiClientFilter",
 *   "type": "AuthoriseResponseFetchApiClientFilter",
 *   "config": {
 *     "idmGetApiClientBaseUri": "https://&{identity.platform.fqdn}/openidm/managed/apiClient",
 *     "clientHandler": "IDMClientHandler"
 *   }
 * }
 * }</pre>
 */
public class AuthoriseResponseFetchApiClientFilterHeaplet extends BaseFetchApiClientHeaplet {

    @Override
    public Object create() throws HeapException {
        return new AuthorizeResponseFetchApiClientFilter(createApiClientService(), AuthorizeResponseFetchApiClientFilter.queryParamClientIdRetriever());
    }
}
