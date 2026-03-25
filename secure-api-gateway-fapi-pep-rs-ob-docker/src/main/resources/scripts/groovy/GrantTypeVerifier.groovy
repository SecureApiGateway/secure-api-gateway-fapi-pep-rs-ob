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
import org.forgerock.http.protocol.*
import com.forgerock.sapi.gateway.rest.HttpHeaderNames

String fapiInteractionId = request.getHeaders().getFirst(HttpHeaderNames.X_FAPI_INTERACTION_ID);
if (fapiInteractionId == null) { fapiInteractionId = 'No ' + HttpHeaderNames.X_FAPI_INTERACTION_ID + ' header'}
SCRIPT_NAME = '[GrantTypeVerifier] (' + fapiInteractionId + ') - '
logger.debug(SCRIPT_NAME + 'Running...')

String tokenGrantType = contexts.oauth2.accessToken.info.grant_type
logger.debug(SCRIPT_NAME + 'Access token info: ' + contexts.oauth2.accessToken.info)
logger.debug(SCRIPT_NAME + 'Token grant type: ' + tokenGrantType)

if (allowedGrantType.contains(tokenGrantType) 
    || (allowedGrantType == 'authorization_code' && tokenGrantType == 'refresh_token')) {
    next.handle(context, request)
} else {
    Response response = new Response(Status.UNAUTHORIZED)
    String message = 'invalid_grant_type'
    logger.error(SCRIPT_NAME + message)
    response.headers['Content-Type'] = 'application/json'
    response.entity = "{ \"error\":\"" + message + "\"}"
    return response
}
