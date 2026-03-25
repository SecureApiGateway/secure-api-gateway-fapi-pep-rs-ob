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
import static org.forgerock.http.protocol.Response.newResponsePromise

import static org.forgerock.json.JsonValue.field
import static org.forgerock.json.JsonValue.json
import static org.forgerock.json.JsonValue.object
import com.forgerock.sapi.gateway.rest.HttpHeaderNames

/**
 * This script is comparing the consentId from the request uri path versus the consentId from the provided access token.
 * By doing this comparison, we prevent resources being submitted with a token obtained for another consent.
 */

String fapiInteractionId = request.getHeaders().getFirst(HttpHeaderNames.X_FAPI_INTERACTION_ID);
if (fapiInteractionId == null) { fapiInteractionId = 'No ' + HttpHeaderNames.X_FAPI_INTERACTION_ID + ' header'}
SCRIPT_NAME = '[RequestPathConsentIdValidator] (' + fapiInteractionId + ') - '
logger.debug(SCRIPT_NAME + 'Running...')

// Get the intent id from the access token
def accessTokenIntentId = attributes.openbanking_intent_id

if (!accessTokenIntentId) {
    throw new IllegalStateException("openbanking_intent_id claim is missing from the attributes context");
}

// Get the intent Id from the uri
def requestIntentId = request.uri.pathElements[routeArgConsentIdPathElementIndex]

logger.debug(SCRIPT_NAME + 'Comparing token intent id {} with request intent id {}', accessTokenIntentId, requestIntentId)

// Compare the id's and only allow the filter chain to proceed if they exists and they match
if (requestIntentId && accessTokenIntentId == requestIntentId) {
    // Request is valid, allow it to pass
    return next.handle(context, request)
}
String message = 'consentId from the request does not match the openbanking_intent_id claim from the access token'
logger.error(SCRIPT_NAME + message)
Response errorResponse = new Response(Status.UNAUTHORIZED)
        .setEntity(json(object(field("error", message))))
return newResponsePromise(errorResponse)