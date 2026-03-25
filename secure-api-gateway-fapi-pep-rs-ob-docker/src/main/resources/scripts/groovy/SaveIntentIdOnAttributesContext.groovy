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
 * Gets the intent id from the access token claims and saves it on the attributes context
 */
import org.forgerock.http.protocol.*
import org.forgerock.http.util.Json

def fapiInteractionId = request.getHeaders().getFirst("x-fapi-interaction-id");
if(fapiInteractionId == null) fapiInteractionId = "No x-fapi-interaction-id";
SCRIPT_NAME = "[SaveIntentIdOnAttributesContext] (" + fapiInteractionId + ") - ";

logger.debug(SCRIPT_NAME + "Running...")

def intentId = JsonValue.json(Json.readJson(contexts.oauth2.accessToken.info.claims)).get("id_token").get("openbanking_intent_id").get("value").asString()
logger.info(SCRIPT_NAME + "Intent Id value: " + intentId)

if (!intentId) {
    Response response = new Response(Status.BAD_REQUEST)
    response.headers['Content-Type'] = "application/json"
    String message = 'Cannot parse openbanking_intent_id claim from the provided access token'
    logger.error(SCRIPT_NAME + message)
    response.entity = "{ \"error\":\"" + message + "\"}"
    return response
}

attributes.put('openbanking_intent_id', intentId)

next.handle(context, request)