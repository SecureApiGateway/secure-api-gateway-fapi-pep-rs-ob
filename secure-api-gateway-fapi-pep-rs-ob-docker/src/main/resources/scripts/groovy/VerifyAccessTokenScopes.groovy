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
/**
 * Validates the scopes from the access token against the allowed scopes.
 * The access tokens required for accessing the API must have at last one scope of 'allowedScopes'
 */
import static org.forgerock.http.protocol.Response.newResponsePromise
import static org.forgerock.json.JsonValue.field
import static org.forgerock.json.JsonValue.json
import static org.forgerock.json.JsonValue.object

def fapiInteractionId = request.getHeaders().getFirst("x-fapi-interaction-id")
if(fapiInteractionId == null) fapiInteractionId = "No x-fapi-interaction-id"
SCRIPT_NAME = "[VerifyAccessTokenScopes] (" + fapiInteractionId + ") - "

logger.debug(SCRIPT_NAME + "Running...")

def tokenScopes = contexts.oauth2.accessToken.info.scope
logger.info(SCRIPT_NAME + "Token Scopes: " + tokenScopes)
logger.info(SCRIPT_NAME + "Allowed Scopes: " + allowedScopes)

// Verify token scope contains at last one of allowed scopes
if (tokenScopes.any{allowedScopes.contains(it)}) { //true means there are common elements
    logger.info(SCRIPT_NAME + "Access Token Scopes verification success, API access allowed")
    return next.handle(context, request)
}
String message = "invalid_access_token_scope " +tokenScopes+ ", The access token required for accessing the API must have at last one of the following scopes: " + allowedScopes
logger.error(SCRIPT_NAME + message)
Response errorResponse = new Response(Status.UNAUTHORIZED)
        .setEntity(json(object(field("error", message))))
return newResponsePromise(errorResponse)
