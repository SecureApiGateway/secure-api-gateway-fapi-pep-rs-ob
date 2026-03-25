/*
 * Copyright © 2020-2026 ForgeRock AS (obst@forgerock.com)
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
/*
 * Copy the IG bearer token to the token request so that it is accessible from the AM token
 * modification script. Longer term, AM modification script should have access to request headers.
 *
 * Until https://bugster.forgerock.org/jira/browse/OPENAM-18539 fixed,
 * we have to add the access token to the request URL rather than the form data in the request entity
 *
 */

def fapiInteractionId = request.getHeaders().getFirst("x-fapi-interaction-id");
if(fapiInteractionId == null) fapiInteractionId = "No x-fapi-interaction-id"
SCRIPT_NAME = "[AddGatewayAuthorization] (" + fapiInteractionId + ") - "

logger.debug(SCRIPT_NAME + "Running...")

def authHeader = request.getHeaders().getFirst("Authorization");

if (authHeader == null) {
    def message = "Token request authorization not available";
    logger.error(SCRIPT_NAME + message)
    Response response = new Response(Status.INTERNAL_SERVER_ERROR);
    response.entity = "{ \"error\":\"" + message + "\"}"
    return response
}

def splitHeader = authHeader.split(" ");

if (splitHeader.length != 2) {
    def message = "Token request authorization not available";
    logger.error(SCRIPT_NAME + message + " Header: " + authHeader);
    Response response = new Response(Status.INTERNAL_SERVER_ERROR);
    response.entity = "{ \"error\":\"" + message + "\"}";
    return response;
}

def bearerToken = splitHeader[1];

request.getUri().setQuery("gateway_authorization=" + bearerToken);

next.handle(context, request)
